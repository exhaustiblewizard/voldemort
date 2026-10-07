#include "common/assert.h"
#include "common/common.h"
#include "common/singleton.h"
#include "common/emulatorConfig.h"
#include "common/logging/log.h"
#include "libs/libs.h"
#include "libs/libUserService.h"
#include "libs/errno.h"
#include "loader/symbolDatabase.h"
#include "loader/runtimeLinker.h"
#include "loader/systemContent.h"
#include "kernel/fileSystem.h"
#include "kernel/pthread.h"
#include "libs/libRegMgr.h"
#include "libs/controller.h"
#include "libs/libMbus.h"
#include "libs/virtualDisc.h"
#include "libs/libAppDbShim.h"
#include "libs/kitProfile.h"
#include "libs/libLncUtil.h"
#include <map>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <atomic>
#include <SDL3/SDL.h>
#include <cstring>
#include <string>
#include <chrono>
#include <thread>
#include <array>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <fstream>
#include <deque>
#include <algorithm>

// Offline stubs for the PSN / online-service modules the ShellUI JSCd daemon links against.
// The emulator is forced-offline: initialisers succeed so the daemon proceeds, while queries
// that would require a live PSN connection report "not available". These are first-pass return
// values to get the console booting offline; the network redirect (local server) refines them.

namespace Libs {

// Generic "service unavailable / not connected" result for offline queries.
static constexpr int kOffline = static_cast<int>(0x80550006);

// libSceUrlConfigResolver "supplied buffer too short" result. Reversed from the JSCd callers
// (AppSettings::get sub_1C69E0, url-template builder sub_2411B0): each resolver getter is a
// two-call API. The caller probes with a 256-byte buffer; on this exact code it reads the
// required length from *outSize, reallocates, and calls again. Any other negative code is a
// hard error for the caller.
static constexpr int kUrlCfgBufferShort = static_cast<int>(0x80BA8090);

// Emit a NUL-terminated C-string per the UrlConfigResolver two-call buffer protocol. Used for
// getters whose callers strlen() the result (GetDeviceId / GetSysVer): the NUL is part of the
// reported/copied length.
static int UrlCfgWriteCStr(const char* s, void* buf, uint32_t bufSize, uint32_t* outSize) {
	const uint32_t need = static_cast<uint32_t>(std::strlen(s) + 1); // include NUL terminator
	if (outSize != nullptr) {
		*outSize = need;
	}
	if (buf == nullptr || bufSize < need) {
		return kUrlCfgBufferShort;
	}
	std::memcpy(buf, s, need);
	return 0;
}

namespace SystemServiceTelemetry2 {
LIB_VERSION("SystemServiceTelemetry2", 1, "SystemServiceTelemetry2", 1, 1);
static int KYTY_SYSV_ABI SetData2(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
	PRINT_NAME();
	(void)a; (void)b; (void)c; (void)d;
	return 0; // telemetry is a no-op offline
}
LIB_DEFINE(InitSystemServiceTelemetry2_1) {
	LIB_FUNC("83leZmsmmT4", SystemServiceTelemetry2::SetData2); // sceSystemServiceTelemetrySetData2
}
} // namespace SystemServiceTelemetry2

namespace RnpsAppMgr {
LIB_VERSION("RnpsAppMgr", 1, "RnpsAppMgr", 1, 1);
// Native libSceRnpsAppMgr::GetAppInfo sends a 1163-byte output iovec (ELF 0x950).
// RnpsAppMgrWrapper.AppInfo's MarshalAs attributes confirm each fixed ANSI string size.
struct AppInfo {
	char title_id[10];
	char version[64];
	uint8_t preinstalled;
	char path[64];
	char download_url[1024];
};
static_assert(sizeof(AppInfo) == 1163);
static_assert(offsetof(AppInfo, path) == 75);

static int KYTY_SYSV_ABI GetAppInfo(const char* app, void* info) {
	PRINT_NAME();
	LOGF("\t app = %s\n", (app != nullptr) ? app : "(null)");
	// Verified null-argument result from libSceRnpsAppMgr, ELF 0x17d0.
	constexpr int invalid_argument = static_cast<int>(0x81850003);
	if (app == nullptr || info == nullptr) { return invalid_argument; }
	const std::string title_id(app);
	if (title_id.size() != 9 || title_id.compare(0, 4, "NPXS") != 0 ||
	    title_id.find_first_not_of("0123456789", 4) != std::string::npos) {
		return invalid_argument;
	}
	for (const char* kind : {"apps", "bgs"}) {
		const std::string path = std::string("/system_ex/rnps/") + kind + "/" + title_id;
		std::ifstream manifest(LibKernel::FileSystem::GetRealFilename(path + "/manifest.json"));
		if (!manifest) { continue; }
		const auto data = nlohmann::json::parse(manifest, nullptr, false);
		if (!data.is_object() || !data.contains("titleId") || !data["titleId"].is_string() ||
		    data["titleId"].get<std::string>() != title_id ||
		    !data.contains("applicationVersion") || !data["applicationVersion"].is_string()) {
			return invalid_argument;
		}
		const auto version = data["applicationVersion"].get<std::string>();
		if (version.size() >= sizeof(AppInfo::version) || path.size() >= sizeof(AppInfo::path)) {
			return invalid_argument;
		}
		AppInfo installed {};
		std::memcpy(installed.title_id, title_id.c_str(), title_id.size() + 1);
		std::memcpy(installed.version, version.c_str(), version.size() + 1);
		installed.preinstalled = 1;
		std::memcpy(installed.path, path.c_str(), path.size() + 1);
		std::memcpy(info, &installed, sizeof(installed));
		LOGF("\t installed RNPS app: %s, version %s, path %s\n", app, installed.version, installed.path);
		return 0;
	}
	// No local installation exists; do not return a successful record with an empty path.
	return LibKernel::KERNEL_ERROR_ENOENT;
}
// MBO is the installed RN host/base bundle, not a network mailbox. The native
// AppMgr request returns two fixed 64-byte strings (version and installation path).
static int KYTY_SYSV_ABI GetMboInfo(void* info) {
	PRINT_NAME();
	if (info == nullptr) { return static_cast<int>(0x81850003); }
	AppInfo host {};
	const int result = GetAppInfo("NPXS40141", &host);
	if (result != 0) { return result; }
	struct MboInfo { char version[64]; char path[64]; };
	static_assert(sizeof(MboInfo) == 128);
	MboInfo installed {};
	std::memcpy(installed.version, host.version, sizeof(installed.version));
	std::memcpy(installed.path, host.path, sizeof(installed.path));
	std::memcpy(info, &installed, sizeof(installed));
	return 0;
}
static int KYTY_SYSV_ABI BlockAppInstall(uint64_t a, uint64_t b, uint64_t c) {
	PRINT_NAME();
	(void)a; (void)b; (void)c;
	return 0; // no install service to gate offline
}
static int KYTY_SYSV_ABI UnblockAppInstall(uint64_t a, uint64_t b, uint64_t c) {
	PRINT_NAME();
	(void)a; (void)b; (void)c;
	return 0;
}
// sceRnpsAppMgrIsBgsInstallReady(): a JSCd worker (sub_29DF0) polls this every 1ms until it returns
// non-zero, then fires its "BgsAppUpdateReadyCB" once. Offline the background-service install is
// already "present", so report ready (1) — this also stops the hot unresolved-stub poll spam. NID
// d+JHa2D36oA.
static int KYTY_SYSV_ABI IsBgsInstallReady() {
	return 1;
}
// sceRnpsAppMgrRemoveApp(const char* app): no install service offline; report success. NID Yrht530r9FI.
static int KYTY_SYSV_ABI RemoveApp(const char* app) {
	PRINT_NAME();
	LOGF("\t app = %s\n", (app != nullptr) ? app : "(null)");
	return 0;
}
LIB_DEFINE(InitRnpsAppMgr_1) {
	LIB_FUNC("9sYn+PCy608", RnpsAppMgr::GetMboInfo);        // sceRnpsAppMgrGetMboInfo
	LIB_FUNC("JgBgvkAFMwc", RnpsAppMgr::GetAppInfo);        // sceRnpsAppMgrGetAppInfo
	LIB_FUNC("6UbbC7GA9MI", RnpsAppMgr::BlockAppInstall);   // sceRnpsAppMgrBlockAppInstall
	LIB_FUNC("nfsELpNQ0fo", RnpsAppMgr::UnblockAppInstall); // sceRnpsAppMgrUnblockAppInstall
	LIB_FUNC("d+JHa2D36oA", RnpsAppMgr::IsBgsInstallReady); // sceRnpsAppMgrIsBgsInstallReady
	LIB_FUNC("Yrht530r9FI", RnpsAppMgr::RemoveApp);         // sceRnpsAppMgrRemoveApp
}
} // namespace RnpsAppMgr

namespace NpManagerInt {
LIB_VERSION("NpManager", 1, "NpManager", 1, 1);
// sceNpManagerIntGetNpEnv(char* env): writes the NP environment NAME as a C-string (the JSCd
// url-template builder sub_2411B0 strlen()s it and substitutes it for the <NPENV> token in
// service URLs). Reversed as a string output, NOT an int enum. Offline default: "np" (retail
// production environment).
static int KYTY_SYSV_ABI GetNpEnv(char* env) {
	PRINT_NAME();
	if (env != nullptr) {
		std::strcpy(env, "np");
	}
	return 0;
}
// sceNpAsmClientExtInitialize: NP application-services-manager client init; succeed offline.
static int KYTY_SYSV_ABI AsmClientExtInitialize(uint64_t a, uint64_t b, uint64_t c) {
	PRINT_NAME();
	(void)a; (void)b; (void)c;
	return 0;
}
LIB_DEFINE(InitNpManagerInt_1) {
	LIB_FUNC("BTRVfOx7K1c", NpManagerInt::GetNpEnv); // sceNpManagerIntGetNpEnv
	LIB_FUNC("kKCa1japBxI", NpManagerInt::AsmClientExtInitialize); // sceNpAsmClientExtInitialize
}
} // namespace NpManagerInt

namespace LncUtil {
LIB_VERSION("LncUtil", 1, "LncUtil", 1, 1);
static std::mutex event_mutex;
static std::deque<EventWire> shell_events;
static std::map<int32_t, EventWire> applications;
static int32_t focused_application = -1;
static int32_t controller_application = -1;

static nlohmann::json ReadLncMetadata(const std::filesystem::path& folder) {
	const auto path = Loader::FindApplicationMetadata(folder);
	if (path.extension() != ".sfo") {
		std::ifstream input(path);
		return nlohmann::json::parse(input, nullptr, false);
	}
	const auto fields = Loader::ReadParamSfo(path);
	auto text = [&](const char* key) {
		const auto it = fields.find(key);
		return it != fields.end() && std::holds_alternative<std::string>(it->second)
		    ? std::get<std::string>(it->second) : std::string();
	};
	// PSF ATTRIBUTE describes package capabilities, not LNC AppAttr flags.
	return {{"titleId", text("TITLE_ID")}, {"masterVersion", text("APP_VER")},
	        {"contentVersion", text("APP_VER")}, {"attribute", 0u},
	        {"applicationCategoryType", 0u}};
}

bool HasControllerFocus(const Loader::Program* program) {
	if (!program || !program->is_application) return true; // System input always observes PS.
	std::lock_guard lock(event_mutex);
	return controller_application == -1 || controller_application == program->unique_id;
}

bool IsSystemUiOverlaid(const Loader::Program* program) {
	if (!program || !program->is_application) return false;
	std::lock_guard lock(event_mutex);
	return focused_application != -1 && focused_application != program->unique_id;
}

void PostApplicationEvent(int32_t type, const Loader::Program* program, int32_t user_id) {
	if (!program || !program->is_application) return;
	const auto param = ReadLncMetadata(program->file_name.parent_path());
	if (!param.is_object()) return;
	EventWire event {};
	event.event_type = type;
	event.app_id = event.launch_request_app_id = program->unique_id;
	event.app_local_pid = 0x10000 + program->unique_id;
	event.app_type = 5; // EventMonitor.AppType.BigApp
	event.user_id = user_id;
	event.app_attribute = param.value("attribute", 0u);
	event.app_category_type = param.value("applicationCategoryType", 0u);
	auto copy = [](auto& output, const std::string& value) {
		std::memcpy(output, value.data(), std::min(value.size(), sizeof(output) - 1));
	};
	copy(event.title_id, param.value("titleId", std::string()));
	copy(event.path, "/app0/eboot.bin");
	copy(event.sce_sys_dir, "/app0/sce_sys");
	std::lock_guard lock(event_mutex);
	applications[event.app_id] = event;
	// LaunchStart opens the firmware container before the application identity
	// is assigned. Its AppId getter reads this very event: publishing the final
	// ID here makes AllocateApp skip Start at LaunchEnd, retaining the PS lock
	// and never connecting the application's canvas or starting splash polling.
	// Keep the registered identity for focus queries; only the start notification
	// carries the pending ID. LaunchEnd supplies the actual ID and PID.
	if (type == 1) {
		event.app_id = -1;
		event.app_local_pid = -1;
	}
	shell_events.push_back(event);
	LOGF("LncUtil: queued native application event type=%d app=%d pid=%d title=%s\n",
	     type, event.app_id, event.app_local_pid, event.title_id);
}
static int KYTY_SYSV_ABI SetAppFocus(int32_t app_id, uint64_t flags, uint64_t context_id) {
	std::lock_guard lock(event_mutex);
	if (app_id != -1 && !applications.contains(app_id)) return static_cast<int>(0x80940005u);
	EventWire event = app_id == -1 ? EventWire {} : applications.at(app_id);
	event.app_id = app_id;
	event.error_code = event.error_data = 0;
	event.check_flags = flags;
	event.context_id = context_id;
	event.event_type = 0x1001;
	shell_events.push_back(event);
	focused_application = app_id;
	event.event_type = 0x1002;
	shell_events.push_back(event);
	LOGF("LncUtil: app focus app=%d flags=%016llx context=%llu\n", app_id, flags, context_id);
	return 0;
}
static int KYTY_SYSV_ABI SetControllerFocus(int32_t app_id) {
	std::lock_guard lock(event_mutex);
	if (app_id != -1 && !applications.contains(app_id)) return static_cast<int>(0x80940005u);
	EventWire event = app_id == -1 ? EventWire {} : applications.at(app_id);
	event.app_id = app_id;
	event.error_code = event.error_data = 0;
	event.event_type = 0x1003;
	shell_events.push_back(event);
	controller_application = app_id;
	event.event_type = 0x1004;
	shell_events.push_back(event);
	LOGF("LncUtil: controller focus app=%d\n", app_id);
	return 0;
}
struct AppStatus {
	int32_t app_id;
	int32_t launch_request_app_id;
	int32_t app_type;
	uint32_t app_attribute;
	char title_id[16];
	uint32_t category;
	char app_version[6];
	char content_version[11];
	uint8_t system_ex;
	uint8_t common_dialog_initialized;
	uint8_t reserved;
};
static_assert(sizeof(AppStatus) == 56 && offsetof(AppStatus, app_type) == 8);

static int KYTY_SYSV_ABI GetAppStatus(AppStatus* status) {
	PRINT_NAME();
	if (status == nullptr) { return static_cast<int>(0x80940005u); }
	const auto* program = Loader::RuntimeLinker::GetCurrentProgram();
	if (program == nullptr) { return kOffline; }
	auto param = ReadLncMetadata(program->file_name.parent_path());
	if (!param.is_object()) { return kOffline; }
	AppStatus result {};
	result.app_id = static_cast<int32_t>(program->unique_id);
	result.launch_request_app_id = result.app_id;
	result.app_type = program->is_application ? 5 :
	    (param.value("titleId", std::string()) == "NPXS40087" ? 1 : 0);
	result.app_attribute = param.value("attribute", 0u);
	result.category = param.value("applicationCategoryType", 0u);
	auto text = [](auto& output, const std::string& value) {
		std::memcpy(output, value.data(), std::min(value.size(), sizeof(output) - 1));
	};
	text(result.title_id, param.value("titleId", std::string()));
	text(result.app_version, param.value("masterVersion", std::string()));
	text(result.content_version, param.value("contentVersion", std::string()));
	result.system_ex = result.category == 0x1000000;
	// Select the older wire ABI only for the explicitly staged legacy process.
	// Its managed P/Invoke wrapper allocates 36 bytes; copying FW7's 56-byte
	// record into that buffer overwrites the wrapper's saved output pointer.
	const size_t wire_size = param.value("kytyLncAppStatusSize", 56u) == 36 ? 36 : sizeof(result);
	std::memcpy(status, &result, wire_size);
	{
		std::lock_guard lock(event_mutex);
		auto& record = applications[result.app_id];
		record.app_id = record.launch_request_app_id = result.app_id;
		record.app_local_pid = Loader::RuntimeLinker::GetCurrentProcessId();
		record.app_type = result.app_type;
		record.app_attribute = result.app_attribute;
		record.app_category_type = result.category;
		std::memcpy(record.title_id, result.title_id, sizeof(record.title_id));
	}
	LOGF("\t app_id=%d type=%d title=%s bytes=%zu\n", result.app_id, result.app_type, result.title_id, wire_size);
	return 0;
}
// sceLncUtilGetEventForDaemon(...): the daemon polls for launch events; report "no event" offline.
static int KYTY_SYSV_ABI GetEventForDaemon(uint64_t a, uint64_t b, uint64_t c) {
	(void)a; (void)b; (void)c;
	return kOffline;
}
// ShellUI's LncProxy::UpdateEvent consumes this nonblocking receive result.
// A zero result promises a complete 5736-byte launch-control event. Until a
// launch-control producer supplies an event, report an empty receive instead
// of making EventMonitor dispatch the untouched buffer as event type zero.
// Native libSceSystemService::getEventForShellUI passes through the IPC
// receive status; its null-output error is 0x80940005.
static int KYTY_SYSV_ABI GetEventForShellUI(void* event) {
	if (event == nullptr) { return static_cast<int>(0x80940005u); }
	std::lock_guard lock(event_mutex);
	if (shell_events.empty()) return LibKernel::KERNEL_ERROR_EAGAIN;
	LOGF("LncUtil: deliver event type=%d app=%d pid=%d title=%s\n", shell_events.front().event_type,
	     shell_events.front().app_id, shell_events.front().app_local_pid, shell_events.front().title_id);
	std::memcpy(event, &shell_events.front(), sizeof(EventWire));
	shell_events.pop_front();
	return 0;
}
// sceLncUtilInitialize(): launch-control util init; succeed offline. NID f-Q8Nd33FBc.
static int KYTY_SYSV_ABI Initialize(uint64_t a, uint64_t b, uint64_t c) {
	PRINT_NAME();
	(void)a; (void)b; (void)c;
	return 0;
}
// sceLncUtilRegisterDaemon(...): register this process as a launchable daemon with LNC; the daemon
// then polls GetEventForDaemon for launch commands. Accept and report success. NID V25-9U+YauY.
static int KYTY_SYSV_ABI RegisterDaemon(uint64_t a, uint64_t b, uint64_t c) {
	PRINT_NAME();
	(void)a; (void)b; (void)c;
	return 0;
}
static void PostLaunchFailure(const char* title, int32_t user_id, int32_t error) {
	// AppLauncher discards LaunchApp's synchronous result. Its game container
	// is opened by LaunchStart and unwound by a failed LaunchEnd. Publish the
	// complete lifecycle even when validation fails before creating a process.
	// Never register a nonexistent application or transfer input/display focus.
	EventWire event {};
	event.event_type = 1;
	event.app_id = event.launch_request_app_id = event.app_local_pid = -1;
	event.app_type = 5;
	event.user_id = user_id;
	std::memcpy(event.title_id, title, std::min(std::strlen(title), sizeof(event.title_id) - 1));
	std::strcpy(event.path, "/app0/eboot.bin");
	std::strcpy(event.sce_sys_dir, "/app0/sce_sys");
	std::lock_guard lock(event_mutex);
	shell_events.push_back(event);
	event.event_type = 2;
	event.error_code = error;
	shell_events.push_back(event);
	LOGF("LncUtil: queued failed launch lifecycle title=%s user=%08x error=%08x\n",
	     event.title_id, user_id, static_cast<unsigned>(error));
}
// Native SystemService +nRJUD-7qCk takes (titleId, null-terminated argv,
// LaunchAppParam*). The legacy managed parameter starts with uint32 size,
// int32 userId; only read fields covered by that declared size.
static int KYTY_SYSV_ABI LaunchApp(const char* title, const char* const* argv, const void* param) {
	Common::HostCriticalScope host;
	if (!title || !param) return static_cast<int>(0x80940005u);
	uint32_t size = 0;
	std::memcpy(&size, param, sizeof(size));
	if (size < 8) return static_cast<int>(0x80940005u);
	int32_t user_id = -1;
	std::memcpy(&user_id, static_cast<const char*>(param) + 4, sizeof(user_id));
	int result;
	if (argv && argv[0] && argv[0][0]) {
		LOGF("LncUtil: launch with guest arguments is not implemented\n");
		result = LibKernel::KERNEL_ERROR_ENOTSUP;
	} else {
		result = VirtualDisc::Launch(title, user_id);
	}
	if (result < 0 && result != static_cast<int>(0x80940005u)) PostLaunchFailure(title, user_id, result);
	LOGF("LncUtil: LaunchApp title=%s user=%08x paramSize=%u result=%08x\n", title, user_id, size, static_cast<unsigned>(result));
	return result;
}
LIB_DEFINE(InitLncUtil_1) {
	LIB_FUNC("DxRki7T2E44", LncUtil::GetAppStatus);       // sceLncUtilGetAppStatus
	LIB_FUNC("v7DYuX0G5TQ", LncUtil::SetAppFocus);
	LIB_FUNC("P7DYuX0G5TQ", LncUtil::SetAppFocus);
	LIB_FUNC("X8gYbyLG1wk", LncUtil::SetControllerFocus);
	LIB_FUNC("yUh0BIPbhVo", LncUtil::GetEventForDaemon);  // sceLncUtilGetEventForDaemon
	LIB_FUNC("ZucoOmNsb7w", LncUtil::GetEventForShellUI);
	LIB_FUNC("f-Q8Nd33FBc", LncUtil::Initialize);         // sceLncUtilInitialize
	LIB_FUNC("V25-9U+YauY", LncUtil::RegisterDaemon);     // sceLncUtilRegisterDaemon
	LIB_FUNC("+nRJUD-7qCk", LncUtil::LaunchApp);
}
} // namespace LncUtil

namespace AppDbShellCoreClient {
namespace {
using ReadStep1 = int(KYTY_SYSV_ABI*)(const char*,const char*,const char* const*,int,int64_t*,int32_t*);
using ReadStep2 = int(KYTY_SYSV_ABI*)(int64_t,char*);
std::atomic<ReadStep1> native_read1 {nullptr};
std::atomic<ReadStep2> native_read2 {nullptr};
std::mutex read_mutex;
std::map<uint64_t,std::string> pending_reads;
constexpr uint64_t handle_prefix = 0x4b59545900000000ULL;
uint32_t next_read = 1;
int KYTY_SYSV_ABI ReadAppInfo1(const char* title,const char* metadata_id,const char* const* props,
                             int count,int64_t* handle,int32_t* length) {
	std::string metadata;
	{
		Common::HostCriticalScope host;
		if (!title || !handle || !length || count < 0 || count > 256 || (count && !props))
			return static_cast<int>(0x80f10001u);
		metadata = VirtualDisc::MetadataJson(title);
		if (!metadata.empty()) {
			try {
				if (count) {
					auto json = nlohmann::json::parse(metadata);
					auto& fields = json["field_list"];
					fields.erase(std::remove_if(fields.begin(),fields.end(),[&](const auto& value) {
						const auto key = value.at("key").template get<std::string>();
						for (int i=0;i<count;++i) if (props[i] && key==props[i]) return false;
						return true;
					}),fields.end());
					metadata=json.dump();
				}
				std::lock_guard lock(read_mutex);
				if (pending_reads.size() >= 256) return LibKernel::KERNEL_ERROR_EAGAIN;
				const uint64_t id = handle_prefix | next_read++;
				pending_reads.emplace(id,metadata);
				*handle=static_cast<int64_t>(id); *length=static_cast<int32_t>(metadata.size()+1);
				LOGF("AppDb: metadata title=%s bytes=%d handle=%016llx\n",title,*length,static_cast<unsigned long long>(id));
				return 0;
			} catch (const std::exception& ex) {
				LOGF("AppDb: metadata read failed: %s\n",ex.what());
				return LibKernel::KERNEL_ERROR_EIO;
			}
		}
	}
	const auto native=native_read1.load();
	return native ? native(title,metadata_id,props,count,handle,length) : LibKernel::KERNEL_ERROR_ENOENT;
}
int KYTY_SYSV_ABI ReadAppInfo2(int64_t handle,char* output) {
	if ((static_cast<uint64_t>(handle)&0xffffffff00000000ULL)==handle_prefix) {
		Common::HostCriticalScope host;
		std::lock_guard lock(read_mutex);
		const auto found=pending_reads.find(static_cast<uint64_t>(handle));
		if (!output || found==pending_reads.end()) return static_cast<int>(0x80f10001u);
		std::memcpy(output,found->second.c_str(),found->second.size()+1);
		pending_reads.erase(found); return 0;
	}
	const auto native=native_read2.load();
	return native ? native(handle,output) : LibKernel::KERNEL_ERROR_EINVAL;
}
}
uint64_t ResolveManagedReadShim(const char* symbol,uint64_t native) {
	if (std::strcmp(symbol,"ReadAppInfoStep1")==0) {
		native_read1.store(reinterpret_cast<ReadStep1>(native)); return reinterpret_cast<uint64_t>(&ReadAppInfo1);
	}
	if (std::strcmp(symbol,"ReadAppInfoStep2")==0) {
		native_read2.store(reinterpret_cast<ReadStep2>(native)); return reinterpret_cast<uint64_t>(&ReadAppInfo2);
	}
	return native;
}
const PInvokeLibrary* AdaptManagedReadTable(const PInvokeLibrary* table) {
	Common::HostCriticalScope host;
	if (!table) return nullptr;
	struct Bundle {
		std::vector<PInvokeLibrary> libraries;
		std::vector<std::vector<PInvokeEntry>> functions;
	};
	static std::mutex tables_mutex;
	static std::vector<std::unique_ptr<Bundle>> retained;
	auto copy=std::make_unique<Bundle>();
	for (size_t i=0;i<256;++i) {
		copy->libraries.push_back(table[i]);
		if (!table[i].name) break;
	}
	if (copy->libraries.back().name) return table;
	copy->functions.resize(copy->libraries.size());
	bool changed=false;
	for (size_t index=0; index+1<copy->libraries.size(); ++index) {
		const bool app_db=std::strcmp(table[index].name,"libSceAppDbWrapper.a")==0;
		const bool kit=std::strcmp(table[index].name,"libSceVshKernelWrapper.a")==0;
		if ((!app_db && !kit) || !table[index].functions) continue;
		auto& functions=copy->functions[index];
		for (size_t i=0;i<4096;++i) {
			const auto entry=table[index].functions[i];
			functions.push_back(entry);
			if (!entry.name) break;
			if (app_db) functions.back().address=ResolveManagedReadShim(entry.name,entry.address);
			else if (std::strcmp(entry.name,"sceSblPupExpirationGetStatus")==0) {
				functions.back().address=reinterpret_cast<uint64_t>(&KitProfile::PupExpirationGetStatus);
			}
		}
		if (functions.back().name) return table;
		copy->libraries[index].functions=functions.data();
		changed=true;
		LOGF("Managed P/Invoke: adapted %s\n",table[index].name);
	}
	if (!changed) return table;
	const auto* adapted=copy->libraries.data();
	std::lock_guard lock(tables_mutex); retained.push_back(std::move(copy));
	return adapted;
}
int KYTY_SYSV_ABI RegisterManagedReadTable(const PInvokeLibrary* table) {
	using Register = int(KYTY_SYSV_ABI*)(const PInvokeLibrary*);
	Register native=nullptr;
	{
		Common::HostCriticalScope host;
		auto* linker=Common::Singleton<Loader::RuntimeLinker>::Instance();
		for (const auto* path : {"/kyty/common_ex/lib/libScePsm.sprx","/system_ex/common_ex/lib/libScePsm.sprx"}) {
			auto* program=linker->FindProgramByFileName(LibKernel::FileSystem::GetRealFilename(path));
			if (!program || !program->export_symbols) continue;
			const auto* symbol=program->export_symbols->FindByNid("MEuF5zm-r4o",Loader::SymbolType::Func);
			if (symbol) { native=reinterpret_cast<Register>(symbol->vaddr); break; }
		}
	}
	if (!native) { LOGF("AppDb: native P/Invoke table registrar not loaded\n"); return LibKernel::KERNEL_ERROR_ENOSYS; }
	return native(AdaptManagedReadTable(table));
}
LIB_VERSION("AppDbShellCoreClient", 1, "AppDbShellCoreClient", 1, 0);
// App-database (ShellCore) client queries. Offline there is no ShellCore app DB; report success
// with empty results so callers proceed. NIDs 1rdpvtPYXUg / 0PevQGrqaXQ / faNkQhATfVw.
static int KYTY_SYSV_ABI Query0(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
	PRINT_NAME();
	(void)a; (void)b; (void)c; (void)d;
	return 0;
}
LIB_DEFINE(InitAppDbShellCoreClient_1) {
	LIB_FUNC("1rdpvtPYXUg", AppDbShellCoreClient::Query0);
	LIB_FUNC("0PevQGrqaXQ", AppDbShellCoreClient::Query0);
	LIB_FUNC("faNkQhATfVw", AppDbShellCoreClient::Query0);
}
} // namespace AppDbShellCoreClient

namespace UsbStorageForShellUI {
LIB_VERSION("UsbStorageForShellUI", 1, "UsbStorage", 1, 0);
// sceUsbStorageInit: no USB mass storage offline; report success. NID BDDZwF5kuTc.
static int KYTY_SYSV_ABI Init(uint64_t a, uint64_t b, uint64_t c) {
	PRINT_NAME();
	(void)a; (void)b; (void)c;
	return 0;
}
LIB_DEFINE(InitUsbStorageForShellUI_1) {
	LIB_FUNC("BDDZwF5kuTc", UsbStorageForShellUI::Init); // sceUsbStorageInit
}
} // namespace UsbStorageForShellUI

namespace AppMessaging {
LIB_VERSION("AppMessaging", 1, "AppMessaging", 1, 1);
// The daemon's main loop non-blocking-polls for shell messages/event-flags. Offline there is never
// anything queued, so report "empty" so the loop idles instead of processing garbage.
static int KYTY_SYSV_ABI TryGetEventFlag(uint64_t a, uint64_t b, uint64_t c) {
	(void)a; (void)b; (void)c;
	return kOffline;
}
static int KYTY_SYSV_ABI TryReceiveMsg(uint64_t a, uint64_t b, uint64_t c) {
	(void)a; (void)b; (void)c;
	return kOffline;
}
LIB_DEFINE(InitAppMessaging_1) {
	LIB_FUNC("iKNXKsUtOjY", AppMessaging::TryGetEventFlag); // sceAppMessagingTryGetEventFlag
	LIB_FUNC("ZVRXXqj1n80", AppMessaging::TryReceiveMsg);   // sceAppMessagingTryReceiveMsg
}
} // namespace AppMessaging

namespace UrlConfigResolver {
LIB_VERSION("UrlConfigResolver", 1, "UrlConfigResolver", 1, 1);

// Native libSceUrlConfigResolver ELF 0x350/0x1520: read the sandbox's JSON cache,
// choose the registry-specific scheme map, match URI/prefix/scheme, then select
// the corresponding app's JSON config. A fabricated `rnps` object changes ShellUI's
// plugin dispatch, so missing routes must fail rather than impersonate RNPS apps.
static int KYTY_SYSV_ABI GetAppConfig(const char* app, int flags, void* buf, uint32_t bufSize, uint32_t* outSize,
                                      uint64_t a6) {
	PRINT_NAME();
	(void)a6;
	if (buf != nullptr) { std::memset(buf, 0, bufSize); }
	if (outSize != nullptr) { *outSize = 0; }
	if (app == nullptr) { return -2135261056; }
	LOGF("\t app = %s\n", app);
	const std::string cache_path = std::string("/") + LibKernel::FileSystem::KernelGetFsSandboxRandomWord() +
	                               "/priv/cache/urlconfig/urlconfig_cache.json";
	std::ifstream cache(LibKernel::FileSystem::GetRealFilename(cache_path));
	if (!cache) { return LibKernel::KERNEL_ERROR_ENOENT; }
	const auto root = nlohmann::json::parse(cache, nullptr, false);
	if (!root.is_object()) {
		return -2135261054;
	}
	// Installed caches can retain the server response envelope. Both carry the
	// same app/variant and scheme tables; preserve their routing data verbatim.
	const auto payload = root.find(root.contains("urlconfig") ? "urlconfig" : "response");
	if (payload == root.end() || !payload->is_object()) { return -2135261054; }
	const auto& config = *payload;
	if (!config.contains("scheme")) { return -2135261053; }
	if (!config["scheme"].is_object()) { return -2135261052; }
	char selector[17] {};
	const int registry_result = RegMgr::GetStr(0x19800000, selector, sizeof(selector));
	if (registry_result < 0) { return registry_result; }
	const auto selected = [&](const nlohmann::json& value) -> const nlohmann::json* {
		auto it = value.find(selector);
		if (it != value.end() && !it->is_null()) { return &*it; }
		it = value.find("default");
		return it != value.end() && !it->is_null() ? &*it : nullptr;
	};
	const auto* schemes = selected(config["scheme"]);
	if (schemes == nullptr) { return -2135261051; }
	if (!schemes->is_object()) { return -2135261050; }
	if (!config.contains("app")) { return -2135261046; }
	if (!config["app"].is_object()) { return -2135261045; }
	const std::string uri(app);
	const auto colon = uri.find(':');
	const nlohmann::json* route = nullptr;
	const auto lookup = [&](const std::string& key) -> const nlohmann::json* {
		auto it = schemes->find(key);
		return it != schemes->end() ? &*it : nullptr;
	};
	if (colon != std::string::npos && colon + 1 < uri.size()) {
		std::string prefix = uri.substr(0, uri.find('?', colon + 1));
		while (!prefix.empty()) {
			route = lookup(prefix);
			if (route != nullptr) { break; }
			const auto slash = prefix.rfind('/');
			if (slash == std::string::npos) { break; }
			prefix.resize(slash);
		}
	}
	if (route == nullptr) { route = lookup(uri.substr(0, colon)); }
	if (route == nullptr && (flags & 0xff) != 0) { route = lookup("default"); }
	if (route == nullptr) { return -2135261049; }
	if (!route->is_string() || !route->get_ref<const std::string&>().starts_with("app:")) {
		return -2135261047;
	}
	const auto& apps = config["app"];
	auto entry = apps.find(route->get_ref<const std::string&>().substr(4));
	if (entry == apps.end()) { entry = apps.find("default"); }
	if (entry == apps.end()) { return -2135261044; }
	if (!entry->is_object()) { return -2135261043; }
	const auto* result = selected(*entry);
	if (result == nullptr) { return -2135261042; }
	if (!result->is_object()) { return -2135261041; }
	// Opt-in diagnostic boot: optional notification, agent, capture, trophy and checkout Open methods
	// return normally if their route is unavailable. Keep the signed cache
	// intact and let genuinely decoded copies run when supplied later.
	const auto& environment = Config::GetGuestEnvironment();
	const auto limited = environment.find("KYTY_SKIP_ENCRYPTED_OVERLAYS");
	const auto kit_limited = environment.find("KYTY_SKIP_ENCRYPTED_KIT_APPS");
	const bool skip_overlays = limited != environment.end() && limited->second == "1";
	const bool skip_kit_apps = kit_limited != environment.end() && kit_limited->second == "1";
	if ((skip_overlays || skip_kit_apps) && result->contains("rnps") &&
	    (*result)["rnps"].is_object()) {
		const auto title_entry = (*result)["rnps"].find("titleId");
		if (title_entry != (*result)["rnps"].end() && title_entry->is_string()) {
			const auto& title = title_entry->get_ref<const std::string&>();
			const bool overlay = title == "NPXS40011" || title == "NPXS40048" ||
			                     title == "NPXS40024" || title == "NPXS40062" ||
			                     title == "NPXS40025";
			const bool kit_app = title == "NPXS40075" || title == "NPXS40097";
			if ((skip_overlays && overlay) || (skip_kit_apps && kit_app)) {
				std::ifstream bundle(LibKernel::FileSystem::GetRealFilename(
				    "/system_ex/rnps/apps/" + title + "/application.ps.bundle"), std::ios::binary);
				char header[8] {};
				bundle.read(header, sizeof(header));
				if (!bundle || std::memcmp(header, "RNPSHEDR", sizeof(header)) == 0) {
					LOGF("\t RNPS diagnostic: optional app unavailable without decoded JS: %s\n", title.c_str());
					return -2135261049;
				}
			}
		}
	}
	const auto json = result->dump();
	return UrlCfgWriteCStr(json.c_str(), buf, bufSize, outSize);
}

// sceUrlConfigResolverGetDeviceId(void* buf, uint32_t bufSize, uint32_t* outSize, ...): the
// url-template builder (sub_2411B0) strlen()s the result and substitutes it for <DEVICE_ID>.
// Offline placeholder device id (stable so future local-server correlation is possible).
static int KYTY_SYSV_ABI GetDeviceId(void* buf, uint32_t bufSize, uint32_t* outSize, uint64_t a4) {
	PRINT_NAME();
	(void)a4;
	return UrlCfgWriteCStr("0000000000000000000000000000000000000000", buf, bufSize, outSize);
}

// sceUrlConfigResolverGetSysVer(void* buf, uint32_t bufSize, uint32_t* outSize, ...): substituted
// for <SYS_VER> in service URLs by sub_2411B0. Matches the compiled SDK version (0x09000005).
static int KYTY_SYSV_ABI GetSysVer(void* buf, uint32_t bufSize, uint32_t* outSize, uint64_t a4) {
	PRINT_NAME();
	(void)a4;
	return UrlCfgWriteCStr("09.000.000", buf, bufSize, outSize);
}

LIB_DEFINE(InitUrlConfigResolver_1) {
	LIB_FUNC("MTEBJdi3YNQ", UrlConfigResolver::GetAppConfig); // sceUrlConfigResolverGetAppConfig
	LIB_FUNC("Y00mcdiTiOA", UrlConfigResolver::GetDeviceId);  // sceUrlConfigResolverGetDeviceId
	LIB_FUNC("Syu+Sbd7R4s", UrlConfigResolver::GetSysVer);    // sceUrlConfigResolverGetSysVer
}
} // namespace UrlConfigResolver

namespace BgsStorage {
LIB_VERSION("BgsStorage", 1, "BgsStorage", 1, 1);
// sceBgsStorageInitialize: the daemon aborts if init fails, so report success offline.
static int KYTY_SYSV_ABI Initialize(uint64_t a, uint64_t b, uint64_t c) {
	PRINT_NAME();
	(void)a; (void)b; (void)c;
	return 0;
}
LIB_DEFINE(InitBgsStorage_1) {
	LIB_FUNC("PQqTvPT8G2E", BgsStorage::Initialize); // sceBgsStorageInitialize
}
} // namespace BgsStorage

namespace HttpCache {
LIB_VERSION("HttpCache", 1, "HttpCache", 1, 1);
static int KYTY_SYSV_ABI Init(uint64_t a, uint64_t b, uint64_t c) {
	PRINT_NAME();
	(void)a; (void)b; (void)c;
	return 0; // cache init succeeds
}
LIB_DEFINE(InitHttpCache_1) {
	LIB_FUNC("cZp79Bc6ovs", HttpCache::Init); // sceHttpCacheInit
}
} // namespace HttpCache

namespace RnpsBundle {
LIB_VERSION("RnpsBundle", 1, "RnpsBundle", 1, 1);
static int KYTY_SYSV_ABI InitEx(uint64_t a, uint64_t b, uint64_t c) {
	PRINT_NAME();
	(void)a; (void)b; (void)c;
	return 0; // bundle init succeeds
}
// sceRnpsBundleInit: the older (pre-Hermes JSCd) bundle-service entry point; succeed offline.
static int KYTY_SYSV_ABI Init(uint64_t a, uint64_t b, uint64_t c) {
	PRINT_NAME();
	(void)a; (void)b; (void)c;
	return 0;
}
LIB_DEFINE(InitRnpsBundle_1) {
	LIB_FUNC("hwS49XQ5OuA", RnpsBundle::InitEx); // sceRnpsBundleInitEx
	LIB_FUNC("K2u0v4WEueU", RnpsBundle::Init);   // sceRnpsBundleInit
}
} // namespace RnpsBundle

namespace NpWebApi2 {
LIB_VERSION("NpWebApi2", 1, "NpWebApi2", 1, 1);
static int KYTY_SYSV_ABI IntInitialize(uint64_t a, uint64_t b, uint64_t c) {
	PRINT_NAME();
	(void)a; (void)b; (void)c;
	return 0; // WebApi context init succeeds
}
LIB_DEFINE(InitNpWebApi2_1) {
	LIB_FUNC("zXaFo7euxsQ", NpWebApi2::IntInitialize); // sceNpWebApi2IntInitialize
}
} // namespace NpWebApi2

namespace ShellCoreUtil {
LIB_VERSION("ShellCoreUtil", 1, "ShellCoreUtil", 1, 1);
// sceShellCoreUtilTickHeartBeat: the daemon pings ShellCore every main-loop tick. Offline there is
// no ShellCore process to notify; report success so the loop proceeds.
static int KYTY_SYSV_ABI TickHeartBeat(uint64_t a, uint64_t b) {
	(void)a; (void)b;
	return 0;
}
static int KYTY_SYSV_ABI GetFreeSizeOfUserPartition(uint64_t* available, uint64_t* total) {
	PRINT_NAME();
	if (!available || !total) { return LibKernel::KERNEL_ERROR_EFAULT; }
	*available = 0;
	*total = 0;
	std::error_code error;
	const auto info = std::filesystem::space(
	    LibKernel::FileSystem::GetRealFilename("/system_data"), error);
	if (error) { return LibKernel::KERNEL_ERROR_EIO; }
	*available = info.available;
	*total = info.capacity;
	return 0;
}
// Managed Utility.EjectDisc sends /dev/cd. Native libSceSystemService's
// 8+CmlQdq7u8 export takes one UTF-8 string and returns the request status.
static int KYTY_SYSV_ABI RequestEjectDevice(const char* device) {
	Common::HostCriticalScope host;
	if (!device) { return static_cast<int>(0x80e30005u); }
	if (std::strcmp(device, "/dev/cd") != 0) { return LibKernel::KERNEL_ERROR_ENOTSUP; }
	std::string error;
	if (!VirtualDisc::Eject(&error)) {
		LOGF("VirtualDisc: eject request failed: %s\n", error.c_str());
		return LibKernel::KERNEL_ERROR_EIO;
	}
	return 0;
}
LIB_DEFINE(InitShellCoreUtil_1) {
	LIB_FUNC("DWVv0MlE1sw", ShellCoreUtil::TickHeartBeat); // sceShellCoreUtilTickHeartBeat
	LIB_FUNC("ZbY5LxmH6uA", ShellCoreUtil::GetFreeSizeOfUserPartition);
	LIB_FUNC("8+CmlQdq7u8", ShellCoreUtil::RequestEjectDevice);
}
} // namespace ShellCoreUtil

namespace AppInstUtil {
LIB_VERSION("AppInstUtil", 1, "AppInstUtil", 1, 1);
// sceAppInstUtilInitialize: app-install utility init. Offline there is no install service to talk
// to; report success so the daemon's storage/telemetry setup proceeds. NID 540lotO7oHE.
static int KYTY_SYSV_ABI Initialize(uint64_t a, uint64_t b, uint64_t c) {
	PRINT_NAME();
	(void)a; (void)b; (void)c;
	return 0;
}
LIB_DEFINE(InitAppInstUtil_1) {
	LIB_FUNC("540lotO7oHE", AppInstUtil::Initialize); // sceAppInstUtilInitialize
}
} // namespace AppInstUtil

namespace SystemLogger2 {
LIB_VERSION("SystemLogger2NativeQueueClient", 1, "SystemLogger2NativeQueueClient", 1, 1);
// sceSystemLogger2NativeQueueClientInitialize: telemetry log-queue client init. No logger process
// offline; report success (the daemon logs locally regardless). NID cUL8DS6BoQU.
static int KYTY_SYSV_ABI QueueClientInitialize(uint64_t a, uint64_t b, uint64_t c) {
	PRINT_NAME();
	(void)a; (void)b; (void)c;
	return 0;
}
LIB_DEFINE(InitSystemLogger2_1) {
	LIB_FUNC("cUL8DS6BoQU", SystemLogger2::QueueClientInitialize); // sceSystemLogger2NativeQueueClientInitialize
}
} // namespace SystemLogger2

// Main SystemLogger2 library (separate from the NativeQueueClient sub-library above). It is a
// system-telemetry sink: on real hardware events go to the SceSystemLogger2 collector process. The
// emulator is offline with no collector, so every entry point is a safe no-op — Initialize/Set*
// succeed, GetTimestamp writes a real monotonic timestamp (callers embed it in the event struct
// then hand it to SetEventAsync, which drops it), and the *Func getters return a valid no-op
// function pointer so a call through the cached pointer is safe. Low priority (pure telemetry); this
// just clears the unresolved-stub spam. All NIDs from aerolib.csv.
namespace SystemLogger2Main {
LIB_VERSION("SystemLogger2", 1, "SystemLogger2", 1, 1);

// sceSystemLogger2GetTimestamp(void* out): write a 64-bit timestamp (microseconds). The event
// structs reserve 8 bytes for it; writing more would be unsafe.
static int KYTY_SYSV_ABI GetTimestamp(void* out) {
	if (out != nullptr) {
		const auto now = std::chrono::duration_cast<std::chrono::microseconds>(
		                     std::chrono::steady_clock::now().time_since_epoch())
		                     .count();
		std::memcpy(out, &now, sizeof(uint64_t));
	}
	return 0;
}
// Generic no-op event/log sink: never dereferences its args, returns success.
static int KYTY_SYSV_ABI EventSink(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
	(void)a; (void)b; (void)c; (void)d;
	return 0;
}
static int KYTY_SYSV_ABI Initialize(uint64_t a, uint64_t b, uint64_t c) {
	PRINT_NAME();
	(void)a; (void)b; (void)c;
	return 0;
}
static int KYTY_SYSV_ABI Terminate() { return 0; }
// sceSystemLogger2GetTimestampFunc(): returns a pointer to a timestamp getter. Hand back our own so
// a call through the cached pointer stays safe.
static void* KYTY_SYSV_ABI GetTimestampFunc() {
	return reinterpret_cast<void*>(&GetTimestamp);
}
// sceSystemLogger2SetEventAsyncFunc(): returns a pointer to an event sink; hand back our no-op.
static void* KYTY_SYSV_ABI SetEventAsyncFunc() {
	return reinterpret_cast<void*>(&EventSink);
}
// Availability probe: report "not available" so callers skip logging entirely.
static int KYTY_SYSV_ABI IsAvailableMonitor() { return 0; }

LIB_DEFINE(InitSystemLogger2Main_1) {
	LIB_FUNC("1-1uDZ4tiFA", SystemLogger2Main::Initialize);          // sceSystemLogger2Initialize
	LIB_FUNC("bfDcj2PJL6g", SystemLogger2Main::Terminate);          // sceSystemLogger2Terminate
	LIB_FUNC("Eq47KM+iAJg", SystemLogger2Main::Terminate);          // sceSystemLogger2TerminateWithResourceRelease
	LIB_FUNC("cwLEmQa8OFg", SystemLogger2Main::GetTimestamp);       // sceSystemLogger2GetTimestamp
	LIB_FUNC("7MrZ4fUL76M", SystemLogger2Main::GetTimestampFunc);   // sceSystemLogger2GetTimestampFunc
	LIB_FUNC("ZNlFA5YKy4A", SystemLogger2Main::GetTimestamp);       // sceSystemLogger2GameGetTimestamp
	LIB_FUNC("hX5OlI45fC4", SystemLogger2Main::EventSink);          // sceSystemLogger2SetEventAsync
	LIB_FUNC("FCD1HduAwWQ", SystemLogger2Main::EventSink);          // sceSystemLogger2SetEventAsyncEx
	LIB_FUNC("Ip2u86xeayk", SystemLogger2Main::EventSink);          // sceSystemLogger2SetEventAsyncEx2
	LIB_FUNC("qZZwXQ7+njU", SystemLogger2Main::EventSink);          // sceSystemLogger2SetEventAsyncInternal
	LIB_FUNC("tZA8or2+EJU", SystemLogger2Main::SetEventAsyncFunc);  // sceSystemLogger2SetEventAsyncFunc
	LIB_FUNC("R4jTtQ-5puM", SystemLogger2Main::EventSink);          // sceSystemLogger2SetRnpsEventAsync
	LIB_FUNC("AAqtvm0YEss", SystemLogger2Main::EventSink);          // sceSystemLogger2GameSetEvent
	LIB_FUNC("XP7S05gKWoM", SystemLogger2Main::EventSink);          // sceSystemLogger2SetLog
	LIB_FUNC("e-TjHAkKilQ", SystemLogger2Main::EventSink);          // sceSystemLogger2SetLogAsync
	LIB_FUNC("lRL0zzmbcU0", SystemLogger2Main::EventSink);          // sceSystemLogger2SetPeripheralConnectionLog
	LIB_FUNC("dZ-zZ+N9aAo", SystemLogger2Main::EventSink);          // sceSystemLogger2SetAsyncPeripheralConnectionLog
	LIB_FUNC("4uCnFlufL8Y", SystemLogger2Main::EventSink);          // sceSystemLogger2ShellCoreCacheData
	LIB_FUNC("jRyyoYtmwT4", SystemLogger2Main::EventSink);          // sceSystemLogger2UtilAppendPackageInfo
	LIB_FUNC("8yksjlr+Uuk", SystemLogger2Main::EventSink);          // sceSystemLogger2GetEventStatus
	LIB_FUNC("BkKGVG3extk", SystemLogger2Main::IsAvailableMonitor); // sceSystemLogger2IsAvailableMonitor
	// Two more SystemLogger2 telemetry entry points the shell hits once Initialize succeeds (not in
	// aerolib.csv; treated as event sinks — pure telemetry, safe no-ops).
	LIB_FUNC("PcjxaaFQATU", SystemLogger2Main::EventSink);
	LIB_FUNC("ZrNsRT4x6tU", SystemLogger2Main::EventSink);
}
} // namespace SystemLogger2Main

namespace Mbus {
LIB_VERSION("Mbus", 1, "Mbus", 1, 1);
constexpr int kInvalidEvent = static_cast<int>(0x809b0080u);
constexpr int kEventCancelled = static_cast<int>(0x809b0088u);
struct DeviceEvent {
	uint32_t type;
	uint32_t reserved;
	uint64_t device_id;
	uint8_t payload[64];
};
static_assert(sizeof(DeviceEvent) == 80);
struct EventQueue {
	std::mutex mutex;
	std::condition_variable changed;
	bool closed = false;
	uint32_t mask = 0;
	size_t capacity = 32;
	std::deque<DeviceEvent> events;
	using Received = void(KYTY_SYSV_ABI*)(uint32_t, void*, const DeviceEvent*);
	Received received = nullptr;
	void* user = nullptr;
	LibKernel::Pthread worker = nullptr;
};
static std::mutex g_event_mutex;
static std::array<std::shared_ptr<EventQueue>, 8> g_events;
static int g_controller_user = 0; // Native unassigned owner; LoginMgr binds after onboarding/login.
static uint64_t g_controller_device = UINT64_MAX;
static int g_device_generation = 0;
static bool g_auto_login = false;

struct CallbackWorker {
	uint32_t handle;
	std::shared_ptr<EventQueue> queue;
};
static void* KYTY_SYSV_ABI DispatchCallbacks(void* arg) {
	std::unique_ptr<CallbackWorker> context(static_cast<CallbackWorker*>(arg));
	const auto& queue = context->queue;
	std::unique_lock lock(queue->mutex);
	for (;;) {
		queue->changed.wait(lock, [&] { return queue->closed || !queue->events.empty(); });
		if (queue->closed) { break; }
		const DeviceEvent event = queue->events.front();
		queue->events.pop_front();
		lock.unlock();
		LOGF("Mbus callback: handle=%u type=0x%x device=%" PRIu64 "\n",
		     context->handle, event.type, event.device_id);
		queue->received(context->handle, queue->user, &event);
		lock.lock();
	}
	return nullptr;
}

static void PublishDeviceEvent(const DeviceEvent& event) {
	std::lock_guard lock(g_event_mutex);
	for (const auto& queue: g_events) {
		if (!queue || (queue->mask & event.type) == 0) { continue; }
		{
			std::lock_guard queue_lock(queue->mutex);
			if (queue->closed) { continue; }
			// The native callback path bypasses the bounded receive ring.
			if (!queue->received && queue->events.size() == queue->capacity) { queue->events.pop_front(); }
			queue->events.push_back(event);
		}
		queue->changed.notify_all();
	}
}
void ControllerConnectionChanged(uint64_t device_id, bool connected) {
	{
		std::lock_guard lock(g_event_mutex);
		g_controller_device = connected ? device_id : UINT64_MAX;
		g_controller_user = connected && g_auto_login && UserService::IsLoggedIn(Config::GetUserId())
		    ? Config::GetUserId() : 0;
		++g_device_generation;
	}
	PublishDeviceEvent({connected ? 1u : 2u, 0, device_id, {}});
	LOGF("Mbus controller %s: device=%" PRIu64 "\n", connected ? "connected" : "disconnected", device_id);
}
// Native extended device/condition record, verified against libSceMbus and PSM.
struct DeviceInfo {
	uint64_t id;
	int32_t transport;
	int32_t type;
	uint32_t flags;
	int32_t function_count;
	struct Function {int32_t type, reserved, state, reserved2;} functions[11];
	int32_t user_id;
	uint8_t reserved[52];
};
static_assert(sizeof(DeviceInfo) == 256);
static_assert(offsetof(DeviceInfo, user_id) == 200);

static DeviceInfo CurrentControllerInfo(int id) {
	DeviceInfo device {};
	device.id = id >= 0 ? static_cast<uint64_t>(id) : UINT64_MAX;
	auto* host_pad = id >= 0 ? SDL_GetGamepadFromID(static_cast<SDL_JoystickID>(id)) : nullptr;
	// Native Mbus connection types: USB=0, Bluetooth=1. Type 4 is Remote Play.
	device.transport = host_pad && SDL_GetGamepadConnectionState(host_pad) == SDL_JOYSTICK_CONNECTION_WIRELESS
	    ? 1 : 0;
	device.type = 2;
	device.function_count = 1;
	device.functions[0] = {0, 0, 0, 0}; // Native controller function, enabled (state zero).
	std::lock_guard lock(g_event_mutex);
	device.user_id = g_controller_device == device.id ? g_controller_user : 0;
	return device;
}
static int KYTY_SYSV_ABI GetDeviceInfo(uint64_t id, DeviceInfo* info, uint32_t size) {
	const int physical = Controller::GetPhysicalControllerId();
	if (!info || size != sizeof(DeviceInfo) || physical < 0 || id != static_cast<uint64_t>(physical)) {
		return kInvalidEvent;
	}
	*info = CurrentControllerInfo(physical);
	return OK;
}
static int KYTY_SYSV_ABI BindDeviceWithUserId(uint64_t id, int32_t user) {
	const int physical = Controller::GetPhysicalControllerId();
	if (physical < 0 || id != static_cast<uint64_t>(physical) || user < 0) { return kInvalidEvent; }
	{
		std::lock_guard lock(g_event_mutex);
		g_controller_device = id;
		if (g_controller_user == user) { return OK; }
		g_controller_user = user;
		++g_device_generation;
	}
	DeviceEvent event {0x10, 0, id, {}};
	// Owner-change records carry bus/type at +16/+20 and the new owner at +28.
	const DeviceInfo device = CurrentControllerInfo(physical);
	std::memcpy(event.payload, &device.transport, sizeof(device.transport));
	std::memcpy(event.payload + 4, &device.type, sizeof(device.type));
	std::memcpy(event.payload + 12, &user, sizeof(user));
	PublishDeviceEvent(event);
	LOGF("Mbus controller assigned: device=%" PRIu64 " user=0x%x\n", id, user);
	return OK;
}
static int KYTY_SYSV_ABI SetAutoLoginMode(uint32_t mode) {
	if (mode > 1) { return kInvalidEvent; }
	std::lock_guard lock(g_event_mutex);
	g_auto_login = mode != 0;
	return OK;
}

static int KYTY_SYSV_ABI ConvertToLocalDeviceId2(uint64_t id, uint32_t bus, uint64_t* local) {
	const int physical = Controller::GetPhysicalControllerId();
	if (!local || bus != 0 || physical < 0 || id != static_cast<uint64_t>(physical)) {
		return kInvalidEvent;
	}
	// Host instance IDs represent local bus-zero devices and already have
	// their remote bus tag (the upper 16 bits of the native ID) cleared.
	*local = id;
	return OK;
}

static void KYTY_SYSV_ABI DeviceInfoInit(void* data, uint32_t size) {
	if (data == nullptr) { return; }
	std::memset(data, 0, size);
	if (size >= 16) { std::memset(data, 0xff, 16); }
	if (size >= 204) {
		const int32_t any_user = -1;
		std::memcpy(static_cast<uint8_t*>(data) + 200, &any_user, sizeof(any_user));
	}
}

static int KYTY_SYSV_ABI GetDeviceInfoByCondition(const DeviceInfo* condition, int start,
                                                 DeviceInfo* data, int capacity,
                                                 int* total, int* generation, int stride) {
	constexpr int invalid = static_cast<int>(0x809b0080u);
	if (!condition || start < 0 || capacity < 0 || (!data && capacity != 0) || stride != 256) {
		return invalid;
	}
	const int id = Controller::GetPhysicalControllerId();
	const DeviceInfo device = CurrentControllerInfo(id);
	if (condition->function_count < 0 || condition->function_count > 11) { return invalid; }
	bool functions_match = true;
	for (int i = 0; i < condition->function_count; ++i) {
		const auto& requested = condition->functions[i];
		bool found = false;
		for (int j = 0; j < device.function_count; ++j) {
			const auto& available = device.functions[j];
			if ((requested.type == -1 || requested.type == available.type) &&
			    (requested.state == -1 || requested.state == available.state)) {
				found = true;
				break;
			}
		}
		functions_match &= found;
	}
	const bool match = id >= 0 && functions_match &&
	    (condition->id == UINT64_MAX || condition->id == device.id) &&
	    (condition->transport == -1 || condition->transport == device.transport) &&
	    (condition->type == -1 || condition->type == device.type) &&
	    (condition->user_id == -1 || condition->user_id == device.user_id);
	if (total) { *total = match ? 1 : 0; }
	if (generation) {
		std::lock_guard lock(g_event_mutex);
		*generation = g_device_generation;
	}
	const int count = match && start == 0 && capacity > 0 ? 1 : 0;
	if (count) { *data = device; }
	// Bounded boot diagnostics: show the actual native discovery conditions.
	static std::atomic<unsigned> queries {0};
	if (queries.fetch_add(1, std::memory_order_relaxed) < 24) {
		LOGF("Mbus controller query: physical=%d type=%d user=0x%x transport=%d -> %d\n",
		     id, condition->type, condition->user_id, condition->transport, count);
	}
	return count;
}
// sceMbusInit: the media/message-bus subsystem SceShellCore brings up early. Succeed offline.
// NID wRPXMGtkOq0.
static int KYTY_SYSV_ABI Init(uint64_t a, uint64_t b, uint64_t c) {
	PRINT_NAME();
	(void)a; (void)b; (void)c;
	return 0;
}
// Verified in libSceMbus: handles 0..7; blocking receive waits on a condition
// variable when the 80-byte event ring is empty. Host hotplug wakes these
// receivers so PSM rescans the device bus after its initial enumeration.
static int KYTY_SYSV_ABI EventCreate(uint32_t mask, void* buffer, int capacity,
                                    const void* callbacks, void* user) {
	LOGF("Mbus EventCreate: mask=0x%x callbacks=%p user=%p\n", mask, callbacks, user);
	if (mask == 0 || (buffer != nullptr && capacity <= 0)) { return kInvalidEvent; }
	std::lock_guard lock(g_event_mutex);
	for (size_t i = 0; i < g_events.size(); ++i) {
		if (!g_events[i]) {
			g_events[i] = std::make_shared<EventQueue>();
			g_events[i]->mask = mask;
			g_events[i]->capacity = buffer != nullptr ? static_cast<size_t>(capacity) : 32;
			// Native callback record: overflow notification at +0, received at +8.
			if (callbacks) {
				std::memcpy(&g_events[i]->received, static_cast<const uint8_t*>(callbacks) + 8, 8);
			}
			g_events[i]->user = user;
			if (g_events[i]->received) {
				auto* context = new CallbackWorker {static_cast<uint32_t>(i), g_events[i]};
				// Guest callbacks require an emulated stack, TLS and process ownership.
				// Never execute them on SDL's host event thread.
				const int result = LibKernel::PthreadCreate(&g_events[i]->worker, nullptr,
				    DispatchCallbacks, context, "SceMbusEventCallback");
				if (result != OK) {
					delete context;
					g_events[i].reset();
					return result;
				}
			}
			return static_cast<int>(i);
		}
	}
	return static_cast<int>(0x809b00ffu);
}
static int KYTY_SYSV_ABI EventReceive(uint32_t handle, void* events, int capacity, int wait) {
	if (handle >= g_events.size()) { return kInvalidEvent; }
	if (capacity < 0 || (capacity > 0 && events == nullptr)) { return kInvalidEvent; }
	std::shared_ptr<EventQueue> queue;
	{
		std::lock_guard lock(g_event_mutex);
		queue = g_events[handle];
	}
	if (!queue) { return 0; } // Matches the native inactive-handle path.
	std::unique_lock lock(queue->mutex);
	if (wait != 0) { queue->changed.wait(lock, [&] { return queue->closed || !queue->events.empty(); }); }
	if (queue->closed) { return kEventCancelled; }
	const int count = std::min(capacity, static_cast<int>(queue->events.size()));
	for (int i = 0; i < count; ++i) {
		std::memcpy(static_cast<uint8_t*>(events) + 80 * i, &queue->events.front(), 80);
		queue->events.pop_front();
	}
	if (count) { LOGF("Mbus controller event delivered: handle=%u count=%d\n", handle, count); }
	return count;
}
static int KYTY_SYSV_ABI EventDestroy(uint32_t handle) {
	if (handle >= g_events.size()) { return kInvalidEvent; }
	std::shared_ptr<EventQueue> queue;
	{
		std::lock_guard lock(g_event_mutex);
		queue = g_events[handle];
		if (!queue) { return kInvalidEvent; }
		// Close before releasing the handle so an old waiter cannot attach to a replacement.
		std::lock_guard queue_lock(queue->mutex);
		queue->closed = true;
		g_events[handle].reset();
	}
	queue->changed.notify_all();
	if (queue->worker) {
		if (queue->worker == LibKernel::PthreadSelfOrNull()) {
			LibKernel::PthreadDetach(queue->worker);
		} else {
			LibKernel::PthreadJoin(queue->worker, nullptr);
		}
	}
	return OK;
}
static void KYTY_SYSV_ABI EventCallbackFuncsInit(void* callbacks, uint32_t size) {
	if (callbacks != nullptr) { std::memset(callbacks, 0, size); }
}
LIB_DEFINE(InitMbus_1) {
	LIB_FUNC("edYHYROxzx4", DeviceInfoInit);
	LIB_FUNC("KRL-S9qBqXw", GetDeviceInfoByCondition);
	LIB_FUNC("RsKVKhSWt28", GetDeviceInfo);
	LIB_FUNC("Cpo6sQmnZgU", BindDeviceWithUserId);
	LIB_FUNC("wpm6Yq7c4YE", SetAutoLoginMode);
	LIB_FUNC("wxmyc+71ijI", ConvertToLocalDeviceId2);
	LIB_FUNC("wRPXMGtkOq0", Mbus::Init); // sceMbusInit
	LIB_FUNC("c08SEHicDNU", EventCreate);
	LIB_FUNC("puHrnP8V-dY", EventReceive);
	LIB_FUNC("AcARz3iay1I", EventDestroy);
	LIB_FUNC("HgPSJ1kcnHM", EventCallbackFuncsInit);
}
} // namespace Mbus

namespace Remoteplay {
LIB_VERSION("Remoteplay", 1, "Remoteplay", 1, 1);
// ShellUI's IME tests this exact result before switching to the remote keyboard.
// A successful empty stub incorrectly enters that mode and then consumes
// uninitialized events every frame (native eboot 0x54f40b / 0x54eb35).
static int KYTY_SYSV_ABI ImeOpen(int user_id) {
	(void)user_id;
	return static_cast<int>(0x80fc0102); // No Remote Play connection.
}
static int KYTY_SYSV_ABI ImeGetEvent(void* event) {
	(void)event;
	return static_cast<int>(0x80fc0104); // No pending event; do not touch the output.
}
static int KYTY_SYSV_ABI GetPrimaryUserId(int* user_id) {
	if (!user_id) { return LibKernel::KERNEL_ERROR_EINVAL; }
	*user_id = -1;
	return static_cast<int>(0x80fc0102);
}
LIB_DEFINE(InitRemoteplay_1) {
	LIB_FUNC("C3r2zT5ebMg", ImeOpen);
	LIB_FUNC("cMk57DZXe6c", ImeGetEvent);
	LIB_FUNC("pHzEzRZw3AE", GetPrimaryUserId);
}
} // namespace Remoteplay

namespace SysCore {
LIB_VERSION("SysCore", 1, "SysCore", 1, 1);
// The co-hosted process has the same application identity exposed by LncUtil.
// In particular IME uses this output to authorize an IPMI client. A successful
// empty stub leaves a random application ID on the guest's stack.
static int KYTY_SYSV_ABI ApplicationGetAppId(int pid, int* app_id) {
	if (!app_id) { return LibKernel::KERNEL_ERROR_EINVAL; }
	*app_id = -1;
	if (pid != 100 && pid != 0) { return LibKernel::KERNEL_ERROR_ESRCH; }
	const auto* program = Loader::RuntimeLinker::GetCurrentProgram();
	if (!program || program->unique_id < 0) { return LibKernel::KERNEL_ERROR_ESRCH; }
	*app_id = program->unique_id;
	return OK;
}
// sceApplicationInitializeForShellCore: SysCore app-context init for ShellCore; succeed offline.
// NID 9PCBPZcDU7Q.
static int KYTY_SYSV_ABI ApplicationInitializeForShellCore(uint64_t a, uint64_t b, uint64_t c) {
	PRINT_NAME();
	(void)a; (void)b; (void)c;
	return 0;
}
// sceSysCoreReceiveEvent(SysCoreEvent* out): blocking receive of a SysCore event. NID 0YmjfSJ8X98.
// Reversed from the LNC SysCore event handler (sub_5E0350 @ lnc_syscore_event_handler.cpp): the
// caller does `if (sceSysCoreReceiveEvent(&event) == 0) { switch(event.eventId){...} }` — a return
// of 0 means "event received, process it". The previous unresolved stub returned 0 WITHOUT filling
// `event`, so the handler switch-processed an UNINITIALISED event (garbage eventId/payload) and
// smashed the heap. Offline there are no SysCore events, so return NON-ZERO ("no event"); sleep a
// little so the handler's retry loop idles instead of busy-spinning.
static int KYTY_SYSV_ABI ReceiveEvent(void* out) {
	(void)out;
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	return kOffline; // non-zero -> caller loops without processing a garbage event
}
LIB_DEFINE(InitSysCore_1) {
	LIB_FUNC("e-ODUaoHXiY", SysCore::ApplicationGetAppId);
	LIB_FUNC("9PCBPZcDU7Q", SysCore::ApplicationInitializeForShellCore); // sceApplicationInitializeForShellCore
	LIB_FUNC("0YmjfSJ8X98", SysCore::ReceiveEvent);                      // sceSysCoreReceiveEvent
}
} // namespace SysCore

} // namespace Libs
