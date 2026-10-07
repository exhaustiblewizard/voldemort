#include "common/assert.h"
#include "common/common.h"
#include "common/logging/log.h"
#include "common/threads.h"
#include "kernel/fileSystem.h"
#include "kernel/memory.h"
#include "libs/libs.h"
#include "libs/virtualDisc.h"
#include "loader/symbolDatabase.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <array>
#include <cstdio>
#include <memory>
#include <vector>
#include <algorithm>

// libSceIpmi: PS5 processes talk to each other over IPMI (inter-process message interface); on real
// hardware IPMI::impl::ClientImpl/ServerImpl wrap sceIpmiMgr* kernel syscalls. Kyty HLEs at the
// wrapper level and co-hosts the guest executables in ONE process, so we bridge IPMI IN-PROCESS:
//   * Server::create reads the guest EventHandler* (Config+16) + service name (Config+25) and
//     registers name -> handler; runDispatcher just parks (requests are pushed synchronously below).
//   * Client::create copies the service name (Config+0); connect() binds the client to the server
//     with that name; invokeSyncMethod dispatches straight into the guest handler's
//     onSyncMethodDispatch vtable slot — the cross-process round-trip becomes an in-process call.
//   * The client vtable is laid out to match IPMI::impl::ClientImpl's real vtable (read from
//     libSceIpmi @0xC010): slot0 destroy, slot2 connect, slot3 disconnect, slot8 invokeSync(raw),
//     slot11 invokeSync(DataInfo); all other slots are safe no-ops.
// When no in-process server owns a name, we fall back to the old inert behaviour (success + empty
// output; callers pre-zero their buffers), so nothing regresses. See [[ipmi-inprocess-bridge-design]]
// and [[shellui-hle-progress]].

namespace Libs {
namespace Ipmi {

LIB_VERSION("Ipmi", 1, "Ipmi", 1, 1);

// --- In-process bridge state ------------------------------------------------------------------
// Server registry: server service-name -> guest EventHandler*. Populated by Server::create (which
// reads the handler + name out of the guest's Server::Config). A client's invokeSyncMethod looks up
// the connected server here and dispatches straight into the guest handler's vtable, collapsing the
// cross-process IPMI round-trip to an in-process virtual call. When no in-process server owns the
// name, we fall back to the old inert behaviour (empty, success) so nothing regresses.
static std::mutex                                  g_ipmi_mutex;
static std::unordered_map<std::string, void*>      g_server_handlers; // name -> EventHandler*
static std::unordered_map<std::string, void*>      g_server_objects;

// A fabricated Session* handed to guest EventHandler dispatch. Guests may read it or call Session
// virtuals for auth (e.g. getClientPid); a zeroed object with an all-no-op vtable keeps that safe.
static void* g_session_vtable[64];
static void* g_session_obj = nullptr;
static std::once_flag g_session_once;
static int64_t KYTY_SYSV_ABI SessionMethod(void* self, uint64_t a1, uint64_t a2, uint64_t a3,
                                           uint64_t a4, uint64_t a5) {
	(void)self; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
	return 0; // getClientPid()==0 etc.: benign
}
static void* GetSession() {
	std::call_once(g_session_once, [] {
		for (auto& s: g_session_vtable) {
			s = reinterpret_cast<void*>(&SessionMethod);
		}
		g_session_obj = std::calloc(1, 0x1000);
		if (g_session_obj != nullptr) {
			*reinterpret_cast<void**>(g_session_obj) = g_session_vtable;
		}
	});
	return g_session_obj;
}

// IPMI DataInfo/BufferInfo (verified in libSceIpmi ClientImpl::invokeSyncMethod).
struct DataInfo {
	const void* data;
	uint64_t    size;
};
struct BufferInfo {
	void*    buf;
	uint64_t capacity;
	uint64_t written;
};

// Native IME routes dispatch by Session*, and replies through Session virtuals,
// rather than the return value of its EventHandler. Keep guest-owned placement
// objects at their native 16-byte size; transport state belongs to the host.
struct AsyncReply {
	bool ready = false;
	int result = 0;
	std::vector<std::vector<uint8_t>> data;
};
struct SessionState {
	void* server = nullptr;
	void* user_data = nullptr;
	uint32_t next_ticket = 1;
	std::unordered_map<uint64_t, AsyncReply> replies;
};
static std::unordered_map<void*, std::shared_ptr<SessionState>> g_sessions;
static std::unordered_map<void*, void*> g_client_sessions;
static thread_local void* g_connecting_client = nullptr;
struct SyncRequest {
	void* session;
	BufferInfo* buffers;
	uint32_t count;
	int result = 0;
	bool replied = false;
};
static thread_local SyncRequest* g_sync_request = nullptr;
static constexpr int kIpmiInvalid = static_cast<int>(0x80020016u);
static constexpr int kIpmiPending = static_cast<int>(0x80020023u);
static void* g_live_session_vtable[18];
static std::once_flag g_live_session_once;

static std::shared_ptr<SessionState> FindSession(void* self) {
	std::lock_guard lock(g_ipmi_mutex);
	auto it = g_sessions.find(self);
	return it == g_sessions.end() ? nullptr : it->second;
}
static int KYTY_SYSV_ABI SessionDestroy(void* self) {
	std::lock_guard lock(g_ipmi_mutex);
	g_sessions.erase(self);
	for (auto it = g_client_sessions.begin(); it != g_client_sessions.end();) {
		if (it->second == self) { it = g_client_sessions.erase(it); } else { ++it; }
	}
	return 0; // The guest frees its placement block and reference-count userdata.
}
static int KYTY_SYSV_ABI SessionGetPid(void*) { return 100; }
static void* KYTY_SYSV_ABI SessionGetUserData(void* self) {
	auto state = FindSession(self);
	return state ? state->user_data : nullptr;
}
static void* KYTY_SYSV_ABI SessionGetServer(void* self) {
	auto state = FindSession(self);
	return state ? state->server : nullptr;
}
static int KYTY_SYSV_ABI SessionRespondSync(void* self, int result,
                                           const BufferInfo* data, uint32_t count) {
	auto* request = g_sync_request;
	if (!request || request->session != self || count > request->count || (count && !data)) {
		return kIpmiInvalid;
	}
	for (uint32_t i = 0; i < count; ++i) {
		if (data[i].written > request->buffers[i].capacity ||
		    (data[i].written && (!data[i].buf || !request->buffers[i].buf))) { return kIpmiInvalid; }
	}
	for (uint32_t i = 0; i < count; ++i) {
		if (data[i].written && data[i].buf != request->buffers[i].buf) {
			std::memmove(request->buffers[i].buf, data[i].buf, data[i].written);
		}
		request->buffers[i].written = data[i].written;
	}
	request->result = result;
	request->replied = true;
	return 0;
}
static int KYTY_SYSV_ABI SessionRespondSyncRaw(void* self, int result,
                                              const void* data, uint64_t size) {
	BufferInfo buffer {const_cast<void*>(data), size, size};
	return SessionRespondSync(self, result, &buffer, 1);
}
static uint64_t ReplyKey(uint32_t method, uint32_t ticket) {
	return (uint64_t(method) << 32) | ticket;
}
static int KYTY_SYSV_ABI SessionRespondAsync(void* self, uint32_t method, uint32_t ticket,
                                             int result, const DataInfo* data, uint32_t count) {
	if (count > 10 || (count && !data)) { return kIpmiInvalid; }
	AsyncReply reply;
	reply.ready = true;
	reply.result = result;
	for (uint32_t i = 0; i < count; ++i) {
		if (data[i].size > 16 * 1024 * 1024 || (data[i].size && !data[i].data)) { return kIpmiInvalid; }
		auto& bytes = reply.data.emplace_back(data[i].size);
		if (!bytes.empty()) { std::memcpy(bytes.data(), data[i].data, bytes.size()); }
	}
	std::lock_guard lock(g_ipmi_mutex);
	auto state = g_sessions.find(self);
	if (state == g_sessions.end()) { return kIpmiInvalid; }
	auto pending = state->second->replies.find(ReplyKey(method, ticket));
	if (pending == state->second->replies.end()) { return kIpmiInvalid; }
	pending->second = std::move(reply);
	return 0;
}
static int KYTY_SYSV_ABI SessionRespondAsyncRaw(void* self, uint32_t ticket, int result,
                                                const void* data, uint64_t size) {
	DataInfo info {data, size};
	return SessionRespondAsync(self, 0, ticket, result, &info, 1);
}
static void EnsureLiveSessionVtable() {
	std::call_once(g_live_session_once, [] {
		for (auto& slot : g_live_session_vtable) { slot = reinterpret_cast<void*>(&SessionMethod); }
		g_live_session_vtable[2] = reinterpret_cast<void*>(&SessionDestroy);
		g_live_session_vtable[3] = reinterpret_cast<void*>(&SessionGetPid);
		g_live_session_vtable[4] = reinterpret_cast<void*>(&SessionGetUserData);
		g_live_session_vtable[5] = reinterpret_cast<void*>(&SessionGetServer);
		g_live_session_vtable[6] = reinterpret_cast<void*>(&SessionRespondSync);
		g_live_session_vtable[7] = reinterpret_cast<void*>(&SessionRespondAsync);
		g_live_session_vtable[12] = reinterpret_cast<void*>(&SessionRespondSyncRaw);
		g_live_session_vtable[13] = reinterpret_cast<void*>(&SessionRespondAsyncRaw);
	});
}
static int KYTY_SYSV_ABI ServerCreateSession(void* self, void** out, void* user_data, void* memory) {
	if (!out || !memory || !g_connecting_client) { return kIpmiInvalid; }
	EnsureLiveSessionVtable();
	*static_cast<void**>(memory) = g_live_session_vtable;
	auto state = std::make_shared<SessionState>();
	state->server = self;
	state->user_data = user_data;
	{
		std::lock_guard lock(g_ipmi_mutex);
		g_sessions[memory] = std::move(state);
		g_client_sessions[g_connecting_client] = memory;
	}
	*out = memory;
	return 0;
}
static void* ClientSession(void* client) {
	std::lock_guard lock(g_ipmi_mutex);
	auto it = g_client_sessions.find(client);
	return it == g_client_sessions.end() ? nullptr : it->second;
}

// SceShellCore 7.00 psm_shared_dmem: methods 0x34560000..4.
// This shares the bookkeeping page, not a synthetic graphics-buffer address.
// PSM publishes its actual compositor allocation into that page itself.
struct PsmSharedDmemState {
	std::mutex mutex;
	std::string name;
	void* page = nullptr;
	std::array<bool, 3> locked {};
};
static PsmSharedDmemState g_psm_shared_dmem;
static constexpr int kPsmNotCreated = static_cast<int>(0x81668204u);
static constexpr int kPsmInvalid = static_cast<int>(0x81668206u);
static constexpr int kPsmBusy = static_cast<int>(0x81668201u);

static int PsmSharedDmemRequest(uint32_t method, const DataInfo* in,
                               uint32_t num_in, BufferInfo* out, uint32_t num_out) {
	Common::HostCriticalScope critical;
	if (!in || num_in == 0 || !in[0].data || in[0].size < 4) { return kPsmInvalid; }
	uint32_t type = 0;
	std::memcpy(&type, in[0].data, sizeof(type));
	if (type > 2) { return kPsmInvalid; }
	if (method < 0x34560000 || method > 0x34560004) { return static_cast<int>(0x800205c1u); }
	const bool reply = method == 0x34560000 || method == 0x34560002;
	if (reply && (!out || num_out != 1 || !out[0].buf || out[0].capacity < 32)) {
		return kPsmInvalid;
	}
	std::lock_guard lock(g_psm_shared_dmem.mutex);
	auto& state = g_psm_shared_dmem;
	if (method == 0x34560000) {
		if (in[0].size != 12) { return kPsmInvalid; }
		if (state.page) { return kPsmNotCreated; }
		char name[64];
		std::snprintf(name, sizeof(name), "/ScePsmSharedDmem_%08X", type);
		using namespace LibKernel::FileSystem;
		const int fd = KernelShmOpen(name, 0xa02, 0600);
		if (fd < 0) { return kPsmNotCreated; }
		int result = KernelFtruncate(fd, 0x100000);
		void* page = nullptr;
		if (result == 0) { result = KernelMapSharedMemory(fd, &page, 0x100000, 3, 1, 0); }
		KernelClose(fd);
		if (result != 0) { KernelShmUnlink(name); return kPsmNotCreated; }
		state.name = name;
		state.page = page;
		std::memset(page, 0, 0x100000);
	} else {
		if (!state.page) { return kPsmNotCreated; }
		if (method == 0x34560001) {
			if (in[0].size != 4 || num_in != 2 || in[1].size != 32) { return kPsmInvalid; }
			for (auto locked: state.locked) { if (locked) { return kPsmBusy; } }
			LibKernel::Memory::KernelMunmap(reinterpret_cast<uint64_t>(state.page), 0x100000);
			LibKernel::FileSystem::KernelShmUnlink(state.name.c_str());
			state.page = nullptr;
			state.name.clear();
			return 0;
		}
		if (method == 0x34560003) {
			if (state.locked[type]) { return kPsmBusy; }
			state.locked[type] = true;
			return 0;
		}
		if (!state.locked[type]) { return kPsmBusy; }
		if (method == 0x34560004) { state.locked[type] = false; return 0; }
	}
	// Native server writes PID and status at +16/+20; the client fills size/address
	// after opening and mapping the named object (eboot B0A120/B0A2C0).
	std::memset(out[0].buf, 0, 32);
	const uint32_t server_pid = 100; // current co-hosted guest process namespace
	std::memcpy(static_cast<char*>(out[0].buf) + 16, &server_pid, sizeof(server_pid));
	out[0].written = 32;
	return 0;
}

static bool IsPsmSharedDmemClient(void* self) {
	return self && std::strcmp(static_cast<char*>(self) + 0x10, "ScePsmSharedDmem") == 0;
}

// My client backing-object layout (guest treats it as an opaque IPMI::Client*; only my vtable
// methods touch these). vptr at +0, kid at +8 (mirrors ClientImpl+8), service name at +16, and the
// connected server's EventHandler* at +0x100.
static constexpr size_t kClientNameOff   = 0x10;
static constexpr size_t kClientNameCap   = 0x80;
static constexpr size_t kClientHandlerOff = 0x100;
static constexpr size_t kClientOwnedOff   = 0x108;
static constexpr size_t kClientSize       = 0x1000;

// Dispatch one synchronous method into the guest EventHandler. Handler vtable slot 2 (+0x10) is
// onSyncMethodDispatch(Session*, u32 method, const DataInfo* in, u32 numIn, BufferInfo* out,
// u32 numOut) — the canonical DataInfo dispatch (base impl is empty). Returns the handler result.
static int DispatchSync(void* client, void* handler, uint32_t method, const DataInfo* in, uint32_t num_in,
                        BufferInfo* out, uint32_t num_out) {
	auto** hv = *reinterpret_cast<void***>(handler);
	using Fn  = int(KYTY_SYSV_ABI*)(void*, void*, uint32_t, const DataInfo*, uint32_t, BufferInfo*,
                                   uint32_t);
	auto fn = reinterpret_cast<Fn>(hv[2]);
	void* session = ClientSession(client);
	if (!session) { return fn(handler, GetSession(), method, in, num_in, out, num_out); }
	SyncRequest request {session, out, num_out};
	auto* previous = g_sync_request;
	g_sync_request = &request;
	fn(handler, session, method, in, num_in, out, num_out);
	g_sync_request = previous;
	return request.replied ? request.result : kIpmiPending;
}

// Generic client virtual: up to 6 integer args, returns 0. Fills any slot we don't specialise.
static int64_t KYTY_SYSV_ABI ClientMethod(void* self, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                                          uint64_t a5) {
	(void)self; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
	return 0;
}

// slot 0: ClientImpl::destroy(). Free the backing object.
static int KYTY_SYSV_ABI ClientDisconnect(void* self);
static int64_t KYTY_SYSV_ABI ClientDestroy(void* self) {
	if (self != nullptr) {
		ClientDisconnect(self);
		*reinterpret_cast<void**>(static_cast<char*>(self) + kClientHandlerOff) = nullptr;
		if (static_cast<char*>(self)[kClientOwnedOff]) { std::free(self); }
	}
	return 0;
}
// slot 2: ClientImpl::connect(const void* arg, size_t argSize, int* outResult). Look up the server
// by this client's service name; connected or not, report success (empty fallback if absent).
static int KYTY_SYSV_ABI ClientConnect(void* self, const void* arg, uint64_t arg_size, int* out_result) {
	PRINT_NAME();
	int result = 0;
	if (self != nullptr) {
		const char* name = reinterpret_cast<char*>(self) + kClientNameOff;
		void*       handler = nullptr;
		void*       server = nullptr;
		{
			std::lock_guard<std::mutex> lock(g_ipmi_mutex);
			auto it = g_server_handlers.find(std::string(name));
			if (it != g_server_handlers.end()) {
				handler = it->second;
				server = g_server_objects[std::string(name)];
			}
		}
		// IME's native handler must register the new Session in its component
		// list before dispatch. Other services retain their existing bridge until
		// their connection/session contracts have been verified.
		if (handler && std::strcmp(name, "SceImeService") == 0 && !ClientSession(self)) {
			alignas(8) std::array<uint8_t, 336> config {};
			const uint32_t pid = 100;
			const uint64_t memory_size = 16;
			std::memcpy(config.data(), &pid, sizeof(pid));
			std::memcpy(config.data() + 328, &memory_size, sizeof(memory_size));
			using Connect = int(KYTY_SYSV_ABI*)(void*, void*, void*, const void*, uint64_t);
			auto connect = reinterpret_cast<Connect>((*static_cast<void***>(handler))[4]);
			void* previous = g_connecting_client;
			g_connecting_client = self;
			result = connect(handler, server, config.data(), arg, arg_size);
			g_connecting_client = previous;
			if (arg && arg_size == 24) {
				const auto* values = static_cast<const uint32_t*>(arg);
				LOGF("\t IME connect args=%08x %08x %08x %08x %08x %08x\n",
				     values[0], values[1], values[2], values[3], values[4], values[5]);
			}
			LOGF("\t IME connect result=0x%08x session=%p\n", static_cast<uint32_t>(result), ClientSession(self));
			if (result != 0) { handler = nullptr; }
		}
		*reinterpret_cast<void**>(reinterpret_cast<char*>(self) + kClientHandlerOff) = handler;
		LOGF("\t connect '%s' -> handler = 0x%016" PRIx64 "\n", name,
		     reinterpret_cast<uint64_t>(handler));
	}
	if (out_result != nullptr) {
		*out_result = result;
	}
	return 0;
}
// slot 3: ClientImpl::disconnect().
static int KYTY_SYSV_ABI ClientDisconnect(void* self) {
	if (self != nullptr) {
		void* session = ClientSession(self);
		void* handler = *reinterpret_cast<void**>(static_cast<char*>(self) + kClientHandlerOff);
		if (session && handler) {
			using Disconnect = void(KYTY_SYSV_ABI*)(void*, void*);
			auto disconnect = reinterpret_cast<Disconnect>((*static_cast<void***>(handler))[5]);
			disconnect(handler, session);
			std::lock_guard lock(g_ipmi_mutex);
			g_client_sessions.erase(self);
		}
		*reinterpret_cast<void**>(reinterpret_cast<char*>(self) + kClientHandlerOff) = nullptr;
	}
	return 0;
}
// slot 11: invokeSyncMethod(u32 method, const DataInfo* in, u32 numIn, int* outResult,
//                           BufferInfo* out, u32 numOut) -> 0 (transport), *outResult = handler ret.
static int KYTY_SYSV_ABI ClientInvokeSyncDataInfo(void* self, uint32_t method, const DataInfo* in,
                                                  uint32_t num_in, int* out_result, BufferInfo* out,
                                                  uint32_t num_out) {
	PRINT_NAME();
	void* handler = (self != nullptr)
	                    ? *reinterpret_cast<void**>(reinterpret_cast<char*>(self) + kClientHandlerOff)
	                    : nullptr;
	if (handler != nullptr) {
		int r = DispatchSync(self, handler, method, in, num_in, out, num_out);
		if (out_result != nullptr) {
			*out_result = r;
		}
		return 0;
	}
	if (IsPsmSharedDmemClient(self)) {
		const int result = PsmSharedDmemRequest(method, in, num_in, out, num_out);
		LOGF("\t PsmSharedDmem method=0x%08x result=0x%08x\n", method, static_cast<uint32_t>(result));
		if (out_result) { *out_result = result; }
		return 0;
	}
	// The wrapper expects UTF-8 JSON and a required-size result, including no disc.
	if (self && method == 0x150002 &&
	    std::strcmp(static_cast<char*>(self) + kClientNameOff, "SceMediaEventListnerIpc") == 0) {
		const auto json = VirtualDisc::InfoJson();
		const uint32_t required = static_cast<uint32_t>(json.size()+1);
		int result = 0;
		if (!out || !num_out || !out[0].buf || out[0].capacity < required) {
			result = static_cast<int>(0x81a80004u); // Wrapper retries this buffer-size error.
		} else {
			std::memcpy(out[0].buf,json.c_str(),required); out[0].written = required;
		}
		if (out && num_out > 1 && out[1].buf && out[1].capacity >= sizeof(required)) {
			std::memcpy(out[1].buf,&required,sizeof(required)); out[1].written = sizeof(required);
		}
		if (out_result) *out_result = result;
		LOGF("\t MediaEventListener GetDiscInfo: bytes=%u outputs=%u result=%08x\n",required,num_out,static_cast<unsigned>(result));
		return 0;
	}
	// No in-process server: empty success (callers pre-zero their out buffers).
	if (out != nullptr) {
		out->written = 0;
	}
	if (out_result != nullptr) {
		*out_result = 0;
	}
	return 0;
}
// slot 8: invokeSyncMethod raw (u32 method, const void* in, size_t inSize, int* outResult,
//         void* outBuf, size_t* outSize, size_t outCap). Wrap into DataInfo/BufferInfo and route to
//         the same DataInfo dispatch; report bytes written back through *outSize.
static int KYTY_SYSV_ABI ClientInvokeSyncRaw(void* self, uint32_t method, const void* in,
                                             uint64_t in_size, int* out_result, void* out_buf,
                                             uint64_t* out_size, uint64_t out_cap) {
	PRINT_NAME();
	void* handler = (self != nullptr)
	                    ? *reinterpret_cast<void**>(reinterpret_cast<char*>(self) + kClientHandlerOff)
	                    : nullptr;
	if (handler != nullptr) {
		DataInfo   di {in, in_size};
		BufferInfo bi {out_buf, out_cap, 0};
		int        r = DispatchSync(self, handler, method, &di, 1, &bi, 1);
		if (out_size != nullptr) {
			*out_size = bi.written;
		}
		if (out_result != nullptr) {
			*out_result = r;
		}
		return 0;
	}
	if (out_size != nullptr) {
		*out_size = 0;
	}
	if (out_result != nullptr) {
		*out_result = 0;
	}
	return 0;
}

// ClientImpl slots 12/13: start an async DataInfo call and poll its ticket.
// Replies are copied when the guest responds: IME often uses stack buffers.
static int KYTY_SYSV_ABI ClientInvokeAsync(void* self, uint32_t method, const DataInfo* in,
                                          uint32_t count, uint32_t* ticket, const void*) {
	if (!self || !ticket || (count && !in)) { return kIpmiInvalid; }
	void* session = ClientSession(self);
	void* handler = *reinterpret_cast<void**>(static_cast<char*>(self) + kClientHandlerOff);
	if (!session || !handler) { return kIpmiPending; }
	{
		std::lock_guard lock(g_ipmi_mutex);
		auto state = g_sessions.find(session);
		if (state == g_sessions.end()) { return kIpmiInvalid; }
		*ticket = state->second->next_ticket++;
		state->second->replies.emplace(ReplyKey(method, *ticket), AsyncReply {});
	}
	using Dispatch = void(KYTY_SYSV_ABI*)(void*, void*, uint32_t, uint32_t, const DataInfo*, uint32_t);
	auto dispatch = reinterpret_cast<Dispatch>((*static_cast<void***>(handler))[3]);
	dispatch(handler, session, *ticket, method, in, count);
	return 0;
}
static int KYTY_SYSV_ABI ClientPollAsync(void* self, uint32_t method, uint32_t ticket,
                                        int* result, BufferInfo* out, uint32_t count) {
	void* session = ClientSession(self);
	if (!session || !result || (count && !out)) { return kIpmiInvalid; }
	std::lock_guard lock(g_ipmi_mutex);
	auto state = g_sessions.find(session);
	if (state == g_sessions.end()) { return kIpmiInvalid; }
	auto pending = state->second->replies.find(ReplyKey(method, ticket));
	if (pending == state->second->replies.end() || !pending->second.ready) { return kIpmiPending; }
	auto& reply = pending->second;
	if (reply.data.size() > count) { return kIpmiInvalid; }
	for (size_t i = 0; i < reply.data.size(); ++i) {
		if (reply.data[i].size() > out[i].capacity || (!reply.data[i].empty() && !out[i].buf)) {
			return kIpmiInvalid;
		}
	}
	for (uint32_t i = 0; i < count; ++i) {
		out[i].written = i < reply.data.size() ? reply.data[i].size() : 0;
		if (out[i].written) { std::memcpy(out[i].buf, reply.data[i].data(), out[i].written); }
	}
	*result = reply.result;
	state->second->replies.erase(pending);
	return 0;
}
static int KYTY_SYSV_ABI ClientConnectTimeout(void* self, const void* arg, uint64_t size,
                                             int* result, const void*) {
	return ClientConnect(self, arg, size, result);
}

// Client vtable laid out to match IPMI::impl::ClientImpl's vtable (read from libSceIpmi @0xC010):
// slot0 destroy, slot2 connect, slot3 disconnect, slot8 invokeSync(raw), slot11 invokeSync(DataInfo).
// Every other slot is the generic no-op so poll/wait/getMsg/tryGet return "no data" safely.
static void* g_client_vtable[64];
static std::once_flag g_client_vtable_once;

static void EnsureClientVtable() {
	std::call_once(g_client_vtable_once, [] {
		for (auto& slot: g_client_vtable) {
			slot = reinterpret_cast<void*>(&ClientMethod);
		}
		g_client_vtable[0]  = reinterpret_cast<void*>(&ClientDestroy);
		g_client_vtable[2]  = reinterpret_cast<void*>(&ClientConnect);
		g_client_vtable[3]  = reinterpret_cast<void*>(&ClientDisconnect);
		g_client_vtable[8]  = reinterpret_cast<void*>(&ClientInvokeSyncRaw);
		g_client_vtable[11] = reinterpret_cast<void*>(&ClientInvokeSyncDataInfo);
		g_client_vtable[12] = reinterpret_cast<void*>(&ClientInvokeAsync);
		g_client_vtable[13] = reinterpret_cast<void*>(&ClientPollAsync);
		g_client_vtable[16] = reinterpret_cast<void*>(&ClientConnectTimeout);
	});
}

// Build a client. If a Config is given, copy its service name (Config offset 0, inline NUL-term
// char[]) so connect() can find the matching in-process server.
static void* MakeClient(const void* config = nullptr, void* storage = nullptr) {
	EnsureClientVtable();
	void* client = storage ? storage : std::calloc(1, kClientSize);
	if (client != nullptr) {
		if (storage) { std::memset(client, 0, kClientSize); }
		static_cast<char*>(client)[kClientOwnedOff] = storage == nullptr;
		*reinterpret_cast<void**>(client) = g_client_vtable;
		*reinterpret_cast<uint32_t*>(reinterpret_cast<char*>(client) + 8) = 0xFFFFFFFFu; // kid = -1
		if (config != nullptr) {
			const char* cfg_name = reinterpret_cast<const char*>(config);
			char*       dst      = reinterpret_cast<char*>(client) + kClientNameOff;
			std::strncpy(dst, cfg_name, kClientNameCap - 1);
			dst[kClientNameCap - 1] = '\0';
		}
	}
	return client;
}

// IPMI::Client::Config::Config(this): zero the config. Like the Server config, SceShellCore
// allocates this on the STACK (e.g. SceSl2 IPC client init) in a ~0x38-byte slot below the canary,
// so only zero a small header — a large memset smashes the stack canary (__stack_chk_fail). Our
// create() ignores the config contents and the guest sets the fields it needs afterwards.
static void KYTY_SYSV_ABI ConfigCtor(void* self) {
	if (self != nullptr) {
		std::memset(self, 0, 0x38);
	}
}
// IPMI::Client::Config::MsgQueueConfig::estimateMsgQueueSize(this, count, size)
static size_t KYTY_SYSV_ABI EstimateMsgQueueSize(void* self, size_t count, uint32_t size) {
	(void)self; (void)count; (void)size;
	return 0x10000;
}
// IPMI::Client::Config::estimateClientMemorySize(this)
static size_t KYTY_SYSV_ABI EstimateClientMemorySize(void* self) {
	(void)self;
	return 0x1000;
}
// IPMI::Client::create(Client** out, const Config*, void* mem1, void* mem2) -> 0. The Config's first
// bytes are the inline service name; MakeClient copies it so connect() can bind to the server.
static int KYTY_SYSV_ABI Create(void** out, const void* config, void* mem1, void* mem2) {
	PRINT_NAME();
	(void)mem1;
	if (!out || !mem2) { return static_cast<int>(0x80020016u); }
	// The caller owns the estimateClientMemorySize() block in mem2 and frees
	// it through its Mspace after destroy(). Preserve that allocator pairing.
	*out = MakeClient(config, mem2);
	return 0;
}

// --- IPMI Server side (SceShellCore is the SERVER for LNC/AppMgr/etc. services) ---
// SceShellCore creates IPMI servers (e.g. the LNC launch-control service) and spawns a dispatch
// thread that calls server->runDispatcher(work, size) — a virtual at vtable+16. Standalone there
// are no client processes yet, so the dispatcher has nothing to serve: it must simply PARK (a real
// dispatcher blocks until the server is stopped). We hand back a valid server object whose vtable
// slot 2 blocks and whose other slots return 0, so the dispatch thread stays alive instead of
// dereferencing an uninitialised m_server (create was previously an unresolved stub returning 0
// WITHOUT writing *out → null-deref in IPMI::impl::ServerImpl::runDispatcher).
static int64_t KYTY_SYSV_ABI ServerMethod(void* self, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                                          uint64_t a5) {
	(void)self; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
	return 0;
}
// vtable slot 2 (offset +16): runDispatcher(work, size). Park until process exit (no IPC peers).
static int64_t KYTY_SYSV_ABI ServerRunDispatcher(void* self, void* work, uint64_t size) {
	(void)self; (void)work; (void)size;
	for (;;) {
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
	return 0; // unreached
}
static void* g_server_vtable[64];
static bool  g_server_vtable_ready = false;
static void EnsureServerVtable() {
	if (!g_server_vtable_ready) {
		for (auto& slot: g_server_vtable) {
			slot = reinterpret_cast<void*>(&ServerMethod);
		}
		g_server_vtable[2] = reinterpret_cast<void*>(&ServerRunDispatcher); // vtable+16
		g_server_vtable[5] = reinterpret_cast<void*>(&ServerCreateSession);
		g_server_vtable_ready = true;
	}
}
static void* MakeServer() {
	EnsureServerVtable();
	void* server = std::calloc(1, 0x40000);
	if (server != nullptr) {
		*reinterpret_cast<void**>(server) = g_server_vtable;
	}
	return server;
}
// IPMI::Server::Config::Config(this): zero the config. IMPORTANT: SceShellCore allocates this
// Config on the STACK (e.g. LoginMgr/LNC ipc-server Initialize) in a small (~0x38-byte) slot right
// below the stack canary, so we must NOT over-write it — a large memset smashes the canary and
// trips __stack_chk_fail. Zero only a small header; our create()/estimate ignore the contents
// anyway, and the guest sets the fields it needs right after construction.
static void KYTY_SYSV_ABI ServerConfigCtor(void* self) {
	if (self != nullptr) {
		std::memset(self, 0, 0x38);
	}
}
// IPMI::Server::Config::estimateTempWorkingMemorySize(this)
static size_t KYTY_SYSV_ABI ServerEstimateTempMem(void* self) {
	(void)self;
	return 0x1000;
}
// IPMI::Server::create(Server** out, const Config*, void* mem, void* work) -> 0, writing a valid obj.
// The Config carries the guest EventHandler* at +16 and the inline service name at +25 (both verified
// in libSceIpmi). Register name -> handler so in-process clients (ClientConnect) can bind and
// dispatch straight into the guest handler.
static int KYTY_SYSV_ABI ServerCreate(void** out, const void* config, void* mem, void* work) {
	PRINT_NAME();
	(void)mem; (void)work;
	void* server = MakeServer();
	if (config != nullptr) {
		void*       handler = *reinterpret_cast<void* const*>(reinterpret_cast<const char*>(config) + 16);
		const char* name    = reinterpret_cast<const char*>(config) + 25;
		if (handler != nullptr && name[0] != '\0') {
			std::lock_guard<std::mutex> lock(g_ipmi_mutex);
			g_server_handlers[std::string(name)] = handler;
			g_server_objects[std::string(name)] = server;
			LOGF("\t register IPMI server '%s' -> handler = 0x%016" PRIx64 "\n", name,
			     reinterpret_cast<uint64_t>(handler));
		}
	}
	if (out != nullptr) {
		*out = server;
	}
	return 0;
}

// IPMI::Server::EventHandler base virtuals. The guest subclasses EventHandler and overrides the
// dispatch slots it cares about; slots it does NOT override point at these libSceIpmi base
// implementations (imported by NID — hence they showed up unresolved in the co-run). The real base
// onSyncMethodDispatch/onAsyncMethodDispatch are EMPTY (verified in libSceIpmi @0x1170), so a no-op
// is the correct behaviour: an un-handled method just returns nothing. Registering them removes the
// unresolved-stub spam and keeps un-overridden vtable slots safe. Signatures per aerolib:
//   onSyncMethodDispatch(Session*, u32 method, ... in, ... , ... out, ...)
//   onAsyncMethodDispatch(Session*, u32 method, u32, ...)
//   onSessionKilled(Session*); ~EventHandler()
static int64_t KYTY_SYSV_ABI EhOnSyncMethodDispatch(void* self, void* session, uint32_t method,
                                                    uint64_t a3, uint64_t a4, uint64_t a5,
                                                    uint64_t a6) {
	(void)self; (void)session; (void)method; (void)a3; (void)a4; (void)a5; (void)a6;
	return 0; // base: no handler for this method
}
static int64_t KYTY_SYSV_ABI EhOnAsyncMethodDispatch(void* self, void* session, uint32_t method,
                                                     uint32_t a3, uint64_t a4, uint64_t a5,
                                                     uint64_t a6) {
	(void)self; (void)session; (void)method; (void)a3; (void)a4; (void)a5; (void)a6;
	return 0;
}
static void KYTY_SYSV_ABI EhOnSessionKilled(void* self, void* session) {
	(void)self; (void)session;
}
static void KYTY_SYSV_ABI EhDtor(void* self) {
	(void)self; // trivial base dtor
}

LIB_DEFINE(InitIpmi_1) {
	LIB_FUNC("O1lQ2+do5r4", Ipmi::ConfigCtor);              // IPMI::Client::Config::Config()
	LIB_FUNC("yoVdeXZzPck", Ipmi::EstimateMsgQueueSize);    // ...MsgQueueConfig::estimateMsgQueueSize
	LIB_FUNC("CoVdeXZzPck", Ipmi::EstimateMsgQueueSize);    // (PS4)
	LIB_FUNC("Rih7HnIM3JQ", Ipmi::EstimateClientMemorySize); // ...Config::estimateClientMemorySize
	LIB_FUNC("Bih7HnIM3JQ", Ipmi::EstimateClientMemorySize); // (PS4)
	LIB_FUNC("0zsTiDhM0nU", Ipmi::Create);                  // IPMI::Client::create
	LIB_FUNC("EzsTiDhM0nU", Ipmi::Create);                  // (PS4)
	// --- IPMI Server side (SceShellCore hosts LNC/service IPMI servers) ---
	LIB_FUNC("vo2FiTXAekk", Ipmi::ServerConfigCtor);        // IPMI::Server::Config::Config()
	LIB_FUNC("u5IYJtq4D-4", Ipmi::ServerConfigCtor);        // IPMI::Server::Config::Config() (C2)
	LIB_FUNC("OXc1BksfEIg", Ipmi::ServerEstimateTempMem);   // ...Server::Config::estimateTempWorkingMemorySize
	LIB_FUNC("hoWSsRT0ktA", Ipmi::ServerCreate);            // IPMI::Server::create
	// IPMI::Server::EventHandler base virtuals (un-overridden vtable slots fall here — safe no-ops)
	LIB_FUNC("RQD5VVIt0Bw", Ipmi::EhOnSyncMethodDispatch);  // onSyncMethodDispatch(Session*,u32,DataInfo*,u32,BufferInfo*,u32)
	LIB_FUNC("iVUJ-VqTtek", Ipmi::EhOnSyncMethodDispatch);  // onSyncMethodDispatch(Session*,u32,void*,ulong,ulong,void*,ulong)
	LIB_FUNC("v7dRprTYrgU", Ipmi::EhOnAsyncMethodDispatch); // onAsyncMethodDispatch(Session*,u32,u32,DataInfo*,u32)
	LIB_FUNC("wQ9pO7tm3DU", Ipmi::EhOnAsyncMethodDispatch); // onAsyncMethodDispatch(Session*,u32,u32,void*,ulong,void*,ulong)
	LIB_FUNC("WemdQZJ8Ets", Ipmi::EhOnSessionKilled);       // onSessionKilled(Session*)
	LIB_FUNC("Z5i0--Vqfwg", Ipmi::EhDtor);                  // ~EventHandler()
}

} // namespace Ipmi

// sce::np::ipc::service_client::GetIpmiClient() lives in libSceNpManager and returns the shared
// IPMI client for the NP services; hand back an inert client so callers don't deref null.
namespace NpManagerIpc {
LIB_VERSION("NpManager", 1, "NpManager", 1, 1);
static void* KYTY_SYSV_ABI GetIpmiClient() {
	PRINT_NAME();
	return Ipmi::MakeClient();
}
LIB_DEFINE(InitNpManagerIpc_1) {
	LIB_FUNC("BKTdrR1+dN0", NpManagerIpc::GetIpmiClient); // sce::np::ipc::service_client::GetIpmiClient
	LIB_FUNC("hKTdrR1+dN0", NpManagerIpc::GetIpmiClient); // (variant)
}
} // namespace NpManagerIpc

} // namespace Libs
