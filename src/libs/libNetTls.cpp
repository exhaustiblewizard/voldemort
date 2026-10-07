#include "common/assert.h"
#include "common/common.h"
#include "common/logging/log.h"
#include "libs/libs.h"
#include "loader/symbolDatabase.h"
#include "libs/localNetwork.h"
#include "common/threads.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <deque>
#include <future>
#include <string>
#include <thread>
#include <vector>

// Minimal HLE for the LibreSSL3 and libcurl modules used by the ShellUI JSCd daemon.
// The optional local-network bridge serves guest transfers through a loopback HTTP
// backend. Without it, transfers retain the offline connection-failure behavior.

namespace Libs {

// ---- LibreSSL3 ----
namespace LibreSsl {

LIB_VERSION("LibreSSl3", 1, "LibreSSl3", 1, 1);

static int KYTY_SYSV_ABI SceLibreSslInitEx2(const void* config, int reserved) {
	PRINT_NAME();
	LOGF("\t config = %p, reserved = %d\n", config, reserved);
	return 0; // success
}

static int KYTY_SYSV_ABI SceLibreSslTerm() {
	PRINT_NAME();
	return 0;
}

// --- Minimal OpenSSL/LibreSSL BIO + cert-bundle surface ---
// The ShellUI "libNativeExtensions" boot step loads a default CA bundle via
//   bio = BIO_new(BIO_s_file()); BIO_ctrl(bio, BIO_C_SET_FILENAME, FP_READ, path);
//   stack = PEM_X509_INFO_read_bio(bio, ...); if (!stack) abort();
// (reversed: JSCd sub_3E70 / sub_4110). Offline we have no TLS stack and the CA bundle file is
// absent, but the loader ABORTS unless BIO_new + PEM_X509_INFO_read_bio both return non-null. So
// we hand back valid opaque handles and an EMPTY-but-non-null cert stack: the daemon logs
// "Loaded 0 default certs" and proceeds instead of aborting. Real TLS is out of scope offline
// (the planned local server will terminate TLS itself).
static uint8_t g_bio_file_method = 0; // address serves as the BIO_s_file() method token
static uint8_t g_cert_stack      = 0; // address serves as a non-null empty STACK_OF(X509_INFO)

static void* KYTY_SYSV_ABI BIO_s_file() { return &g_bio_file_method; }
static void* KYTY_SYSV_ABI BIO_new(void* method) {
	(void)method;
	return std::malloc(64); // opaque non-null BIO
}
static int64_t KYTY_SYSV_ABI BIO_ctrl(void* bio, int cmd, int64_t larg, void* parg) {
	(void)bio; (void)cmd; (void)larg; (void)parg;
	return 1; // accept SET_FILENAME etc.
}
static int KYTY_SYSV_ABI BIO_free(void* bio) {
	std::free(bio);
	return 1;
}
// PEM_X509_INFO_read_bio(bio, STACK_OF(X509_INFO)* sk, pem_password_cb*, void* u):
// returns sk (append) or a fresh stack. Always non-null so the caller doesn't abort.
static void* KYTY_SYSV_ABI PEM_X509_INFO_read_bio(void* bio, void* sk, void* cb, void* u) {
	(void)bio; (void)cb; (void)u;
	return (sk != nullptr) ? sk : &g_cert_stack;
}
static int KYTY_SYSV_ABI OPENSSL_sk_num(const void* st) {
	(void)st;
	return 0; // empty cert set offline
}
static void* KYTY_SYSV_ABI OPENSSL_sk_value(const void* st, int i) {
	(void)st; (void)i;
	return nullptr;
}

LIB_DEFINE(InitLibreSsl_1) {
	LIB_FUNC("xoRfQxAhHjk", LibreSsl::SceLibreSslInitEx2);
	LIB_FUNC("n2fSRzuTEY4", LibreSsl::SceLibreSslTerm);
	LIB_FUNC("jA8zOzBRX28", LibreSsl::BIO_s_file);
	LIB_FUNC("ARlY6zhSacE", LibreSsl::BIO_new);
	LIB_FUNC("RHpq9hQfTj8", LibreSsl::BIO_ctrl);
	LIB_FUNC("lpJ3zhgftCg", LibreSsl::BIO_free);
	LIB_FUNC("z2Sl4DL-zCc", LibreSsl::PEM_X509_INFO_read_bio);
	LIB_FUNC("omT5ldW9X3E", LibreSsl::OPENSSL_sk_num);  // sk_num
	LIB_FUNC("izfIVmcJB4o", LibreSsl::OPENSSL_sk_value); // sk_value
}

} // namespace LibreSsl

// ---- libcurl ----
namespace Curl {

LIB_VERSION("libcurl", 1, "libcurl", 1, 1);

enum : int {
	CURLE_OK               = 0,
	CURLE_COULDNT_CONNECT  = 7, // reported for transfers while forced-offline
	CURLM_OK               = 0,
};

struct CurlSList {
	char*      data;
	CurlSList* next;
};

using WriteCallback = size_t(KYTY_SYSV_ABI *)(char*, size_t, size_t, void*);
struct Easy {
	std::string url, custom_method;
	const void* post = nullptr;
	int64_t post_size = -1;
	bool use_post = false, head = false, started = false;
	CurlSList* headers = nullptr;
	WriteCallback write = nullptr, header = nullptr;
	void* write_arg = nullptr;
	void* header_arg = nullptr;
	void* private_arg = nullptr;
	int64_t status = 0;
	std::future<LocalNetwork::Response> pending;
};
struct Message {
	int type = 1; // CURLMSG_DONE; x64 guest layout includes natural pointer padding.
	Easy* easy = nullptr;
	union { void* pointer; int result; } data {};
};
static_assert(sizeof(Message) == 24);
struct Multi {
	std::vector<Easy*> handles;
	std::deque<Message> messages;
	Message delivered;
};

static auto RequestHeaders(const Easy& easy) {
	std::vector<std::pair<std::string, std::string>> result;
	for (auto* item = easy.headers; item; item = item->next) {
		if (!item->data) continue;
		std::string text(item->data);
		const auto colon = text.find(':');
		if (colon != std::string::npos) result.emplace_back(text.substr(0, colon), text.substr(colon + 1));
	}
	return result;
}
static std::string Method(const Easy& easy) {
	return !easy.custom_method.empty() ? easy.custom_method : easy.head ? "HEAD" : easy.use_post ? "POST" : "GET";
}
static size_t PostSize(const Easy& easy) {
	return !easy.post ? 0 : easy.post_size >= 0 ? static_cast<size_t>(easy.post_size) : std::strlen(static_cast<const char*>(easy.post));
}
static int Deliver(Easy& easy, LocalNetwork::Response response) {
	if (!response.completed) return CURLE_COULDNT_CONNECT;
	easy.status = response.status;
	if (easy.header) {
		size_t start = 0;
		while (start < response.headers.size()) {
			const auto end = response.headers.find("\r\n", start);
			const auto count = end == std::string::npos ? response.headers.size() - start : end + 2 - start;
			Common::HostCriticalPause guest;
			if (easy.header(response.headers.data() + start, 1, count, easy.header_arg) != count) return 23;
			start += count;
		}
	}
	if (easy.write && !response.body.empty()) {
		Common::HostCriticalPause guest;
		if (easy.write(response.body.data(), 1, response.body.size(), easy.write_arg) != response.body.size()) return 23;
	}
	return CURLE_OK;
}

// Opaque easy/multi/share handles: a distinct non-null token the guest passes back to us.
static void* NewHandle(uint64_t tag) {
	return new uint64_t(tag);
}
static void DeleteHandle(void* handle) {
	delete static_cast<uint64_t*>(handle);
}

static int KYTY_SYSV_ABI GlobalInit(int64_t flags) {
	PRINT_NAME();
	LOGF("\t flags = 0x%" PRIx64 "\n", flags);
	return CURLE_OK;
}

static void* KYTY_SYSV_ABI EasyInit() {
	Common::HostCriticalScope scope;
	PRINT_NAME();
	return new Easy;
}

static int KYTY_SYSV_ABI EasySetopt(void* handle, int option, uint64_t value) {
	Common::HostCriticalScope scope;
	if (!handle) return 43;
	auto& easy = *static_cast<Easy*>(handle);
	switch (option) {
		case 10002: easy.url = value ? reinterpret_cast<const char*>(value) : ""; break;
		case 10036: easy.custom_method = value ? reinterpret_cast<const char*>(value) : ""; break;
		case 10015: easy.post = reinterpret_cast<void*>(value); easy.use_post = true; break;
		case 60: case 30120: easy.post_size = static_cast<int64_t>(value); break;
		case 47: easy.use_post = value != 0; break;
		case 44: easy.head = value != 0; break;
		case 10023: easy.headers = reinterpret_cast<CurlSList*>(value); break;
		case 20011: easy.write = reinterpret_cast<WriteCallback>(value); break;
		case 10001: easy.write_arg = reinterpret_cast<void*>(value); break;
		case 20079: easy.header = reinterpret_cast<WriteCallback>(value); break;
		case 10029: easy.header_arg = reinterpret_cast<void*>(value); break;
		case 10103: easy.private_arg = reinterpret_cast<void*>(value); break;
		default: break;
	}
	return CURLE_OK;
}

static int KYTY_SYSV_ABI EasyGetinfo(void* handle, int info, void* out) {
	Common::HostCriticalScope scope;
	if (!handle || !out) return 43;
	auto& easy = *static_cast<Easy*>(handle);
	if (out != nullptr) {
		*static_cast<uint64_t*>(out) = 0; // getinfo results are long/pointer/double sized
		if (info == 0x200002) *static_cast<int64_t*>(out) = easy.status;
		if (info == 0x100015) *static_cast<void**>(out) = easy.private_arg;
		if (info == 0x100001) *static_cast<const char**>(out) = easy.url.c_str();
	}
	return CURLE_OK;
}

static int KYTY_SYSV_ABI EasyPerform(void* handle) {
	PRINT_NAME();
	Common::HostCriticalScope scope;
	if (!handle) return 43;
	auto& easy = *static_cast<Easy*>(handle);
	return Deliver(easy, LocalNetwork::Exchange(Method(easy), easy.url, easy.post, PostSize(easy), RequestHeaders(easy)));
}

static void KYTY_SYSV_ABI EasyCleanup(void* handle) {
	PRINT_NAME();
	Common::HostCriticalScope scope;
	delete static_cast<Easy*>(handle);
}

static const char* KYTY_SYSV_ABI EasyStrerror(int code) {
	switch (code) { case 0: return "No error"; case 7: return "Could not connect";
	case 23: return "Write callback failed"; case 43: return "Invalid argument";
	default: return "Unsupported curl operation"; }
}

static void* KYTY_SYSV_ABI MultiInit() {
	Common::HostCriticalScope scope;
	PRINT_NAME();
	return new Multi;
}

static int KYTY_SYSV_ABI MultiSetopt(void* /*mh*/, int /*option*/, uint64_t /*value*/) {
	return CURLM_OK;
}

static int KYTY_SYSV_ABI MultiAddHandle(void* mh, void* eh) {
	Common::HostCriticalScope scope;
	if (!mh || !eh) return 1;
	auto& handles = static_cast<Multi*>(mh)->handles;
	if (std::find(handles.begin(), handles.end(), eh) != handles.end()) return 7;
	static_cast<Easy*>(eh)->started = false;
	handles.push_back(static_cast<Easy*>(eh));
	return CURLM_OK;
}

static int KYTY_SYSV_ABI MultiRemoveHandle(void* mh, void* eh) {
	Common::HostCriticalScope scope;
	if (!mh || !eh) return 1;
	auto& multi = *static_cast<Multi*>(mh);
	std::erase(multi.handles, static_cast<Easy*>(eh));
	std::erase_if(multi.messages, [eh](const Message& message) { return message.easy == eh; });
	return CURLM_OK;
}

static int KYTY_SYSV_ABI MultiPerform(void* mh, int* running_handles) {
	Common::HostCriticalScope scope;
	if (!mh || !running_handles) return 1;
	*running_handles = 0;
	auto& multi = *static_cast<Multi*>(mh);
	for (auto* easy : multi.handles) {
		if (!easy->started) {
			easy->started = true;
			const auto count = PostSize(*easy);
			if (count > 16 * 1024 * 1024) { Message message; message.easy = easy; message.data.result = 43; multi.messages.push_back(message); continue; }
			std::string body = count ? std::string(static_cast<const char*>(easy->post), count) : "";
			easy->pending = std::async(std::launch::async, [method=Method(*easy), url=easy->url, body=std::move(body), headers=RequestHeaders(*easy)] {
				return LocalNetwork::Exchange(method, url, body.data(), body.size(), headers);
			});
		}
		if (easy->pending.valid()) {
			if (easy->pending.wait_for(std::chrono::seconds(0)) != std::future_status::ready) { ++*running_handles; continue; }
			Message message; message.easy = easy;
			message.data.result = Deliver(*easy, easy->pending.get());
			multi.messages.push_back(message);
		}
	}
	return CURLM_OK;
}

static int KYTY_SYSV_ABI MultiPoll(void* mh, void* /*extra_fds*/, unsigned int extra_nfds,
                                   int timeout_ms, int* numfds) {
	Common::HostCriticalScope scope;
	if (!mh || timeout_ms < 0 || extra_nfds != 0) return 1;
	if (numfds) *numfds = 0;
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	for (;;) {
		bool pending = false;
		for (auto* easy : static_cast<Multi*>(mh)->handles) {
			if (!easy->pending.valid()) continue;
			if (easy->pending.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
				if (numfds) *numfds = 1;
				return CURLM_OK;
			}
			pending = true;
		}
		if (!pending || std::chrono::steady_clock::now() >= deadline) return CURLM_OK;
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

static int KYTY_SYSV_ABI MultiFdset(void* /*mh*/, void* /*read*/, void* /*write*/, void* /*exc*/, int* max_fd) {
	if (max_fd != nullptr) {
		*max_fd = -1;
	}
	return CURLM_OK;
}

static int KYTY_SYSV_ABI MultiTimeout(void* /*mh*/, int64_t* timeout_ms) {
	if (timeout_ms != nullptr) {
		*timeout_ms = 10;
	}
	return CURLM_OK;
}

static void* KYTY_SYSV_ABI MultiInfoRead(void* mh, int* msgs_in_queue) {
	Common::HostCriticalScope scope;
	if (!mh || !msgs_in_queue) return nullptr;
	auto& multi = *static_cast<Multi*>(mh);
	if (multi.messages.empty()) { *msgs_in_queue = 0; return nullptr; }
	multi.delivered = multi.messages.front(); multi.messages.pop_front();
	*msgs_in_queue = static_cast<int>(multi.messages.size());
	return &multi.delivered;
}

static int KYTY_SYSV_ABI MultiWakeup(void* /*mh*/) {
	return CURLM_OK;
}

static int KYTY_SYSV_ABI MultiCleanup(void* mh) {
	PRINT_NAME();
	Common::HostCriticalScope scope;
	delete static_cast<Multi*>(mh);
	return CURLM_OK;
}

static const char* KYTY_SYSV_ABI MultiStrerror(int /*code*/) {
	return "offline";
}

static void* KYTY_SYSV_ABI ShareInit() {
	PRINT_NAME();
	return NewHandle(0x7368617265000000ULL); // "share"
}

static int KYTY_SYSV_ABI ShareSetopt(void* /*sh*/, int /*option*/, uint64_t /*value*/) {
	return CURLE_OK;
}

static int KYTY_SYSV_ABI ShareCleanup(void* sh) {
	PRINT_NAME();
	DeleteHandle(sh);
	return CURLE_OK;
}

static CurlSList* KYTY_SYSV_ABI SlistAppend(CurlSList* list, const char* data) {
	Common::HostCriticalScope scope;
	auto* node = new CurlSList {};
	node->data = (data != nullptr ? ::strdup(data) : nullptr);
	node->next = nullptr;
	if (list == nullptr) {
		return node;
	}
	CurlSList* tail = list;
	while (tail->next != nullptr) {
		tail = tail->next;
	}
	tail->next = node;
	return list;
}

static void KYTY_SYSV_ABI SlistFreeAll(CurlSList* list) {
	Common::HostCriticalScope scope;
	while (list != nullptr) {
		CurlSList* next = list->next;
		::free(list->data);
		delete list;
		list = next;
	}
}

static char* KYTY_SYSV_ABI PushheaderBynum(void* /*handle*/, uint64_t /*num*/) {
	return nullptr;
}

static char* KYTY_SYSV_ABI PushheaderByname(void* /*handle*/, const char* /*name*/) {
	return nullptr;
}

LIB_DEFINE(InitCurl_1) {
	LIB_FUNC("I38s92i-Xjk", Curl::GlobalInit);
	LIB_FUNC("NUbq2aNGojo", Curl::EasyInit);
	LIB_FUNC("DiBmbfiH8J4", Curl::EasySetopt);
	LIB_FUNC("ZhOwNq3lcpk", Curl::EasyGetinfo);
	LIB_FUNC("7KQckhaDi18", Curl::EasyPerform);
	LIB_FUNC("HD+IPUl76Hs", Curl::EasyCleanup);
	LIB_FUNC("NGTkAHTkViY", Curl::EasyStrerror);
	LIB_FUNC("wXEc3+fNcO4", Curl::MultiInit);
	LIB_FUNC("hGv08dyfsNQ", Curl::MultiSetopt);
	LIB_FUNC("mQBD4RanvTc", Curl::MultiAddHandle);
	LIB_FUNC("7ShPrvjazws", Curl::MultiRemoveHandle);
	LIB_FUNC("9cpxUNV97mM", Curl::MultiPerform);
	LIB_FUNC("H49qutQi9a0", Curl::MultiPoll);
	LIB_FUNC("SyLtMxQlS6M", Curl::MultiFdset);
	LIB_FUNC("lxail8CxrHk", Curl::MultiTimeout);
	LIB_FUNC("ea8LaHOKFDA", Curl::MultiInfoRead);
	LIB_FUNC("TdLam7xSzmY", Curl::MultiWakeup);
	LIB_FUNC("xyRRwQMH5ug", Curl::MultiCleanup);
	LIB_FUNC("Dfdbc8trvZg", Curl::MultiStrerror);
	LIB_FUNC("KBTWh1VVa-8", Curl::ShareInit);
	LIB_FUNC("b3SWcncY+A0", Curl::ShareSetopt);
	LIB_FUNC("5b-D80m2TKc", Curl::ShareCleanup);
	LIB_FUNC("MDgMnL6At94", Curl::SlistAppend);
	LIB_FUNC("k76sC3mIVw4", Curl::SlistFreeAll);
	LIB_FUNC("+0geDEimyvE", Curl::PushheaderBynum);
	LIB_FUNC("qB5W5ljFCIk", Curl::PushheaderByname);
}

} // namespace Curl

} // namespace Libs
