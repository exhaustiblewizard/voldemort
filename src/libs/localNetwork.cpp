#include "libs/localNetwork.h"
#include "common/emulatorConfig.h"
#include "common/threads.h"
#include <array>
#include <limits>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>
#endif

namespace Libs::LocalNetwork {
bool Enabled() { return Config::GetLocalNetworkPort() != 0; }

#ifdef _WIN32
namespace {
struct Handle {
    HINTERNET value;
    ~Handle() { if (value) WinHttpCloseHandle(value); }
};
std::wstring Wide(const std::string& text) {
    if (text.empty()) return {};
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                         static_cast<int>(text.size()), nullptr, 0);
    if (length <= 0) return {};
    std::wstring result(length, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                        static_cast<int>(text.size()), result.data(), length);
    return result;
}
}
#endif

Response Exchange(const std::string& method, const std::string& url,
                  const void* data, size_t size,
                  const std::vector<std::pair<std::string, std::string>>& headers) {
    Response result;
    if (!Enabled() || (size && !data) || size > 16 * 1024 * 1024 ||
        method.empty() || method.find_first_of("\r\n ") != std::string::npos ||
        url.find_first_of("\r\n") != std::string::npos) return result;
#ifdef _WIN32
    // No guest locks/callbacks cross WinHTTP, and no endpoint can escape loopback.
    Common::HostCriticalScope scope;
    std::string path = url;
    const auto scheme = url.find("://");
    if (scheme != std::string::npos) {
        const auto start = url.find_first_of("/?#", scheme + 3);
        path = start == std::string::npos ? "/" : url.substr(start);
    }
    if (path.empty() || path[0] != '/') path.insert(path.begin(), '/');
    if (const auto fragment = path.find('#'); fragment != std::string::npos) path.resize(fragment);
    const auto verb = Wide(method), object = Wide(path);
    if (verb.empty() || object.empty()) return result;
    Handle session{WinHttpOpen(L"KytyLocalNetwork/1", WINHTTP_ACCESS_TYPE_NO_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)};
    if (!session.value) return result;
    WinHttpSetTimeouts(session.value, 2000, 2000, 2000, 2000);
    Handle connection{WinHttpConnect(session.value, L"127.0.0.1", Config::GetLocalNetworkPort(), 0)};
    if (!connection.value) return result;
    Handle request{WinHttpOpenRequest(connection.value, verb.c_str(), object.c_str(), nullptr,
                                    WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0)};
    if (!request.value) return result;
    DWORD disabled = WINHTTP_DISABLE_REDIRECTS;
    WinHttpSetOption(request.value, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled));
    std::string outgoing = "X-Kyty-Original-URL: " + url + "\r\n";
    for (const auto& [name, value] : headers) {
        if (name.empty() || name.find_first_of("\r\n:") != std::string::npos ||
            value.find_first_of("\r\n") != std::string::npos) return result;
        // Host and body framing belong to the local transport.
        if (_stricmp(name.c_str(), "Host") && _stricmp(name.c_str(), "Content-Length") &&
            _stricmp(name.c_str(), "Transfer-Encoding")) outgoing += name + ": " + value + "\r\n";
    }
    const auto wide_headers = Wide(outgoing);
    if (!WinHttpSendRequest(request.value, wide_headers.c_str(), static_cast<DWORD>(wide_headers.size()),
                            size ? const_cast<void*>(data) : WINHTTP_NO_REQUEST_DATA,
                            static_cast<DWORD>(size), static_cast<DWORD>(size), 0) ||
        !WinHttpReceiveResponse(request.value, nullptr)) return result;
    DWORD status = 0, length = sizeof(status);
    if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &length, WINHTTP_NO_HEADER_INDEX)) return result;
    length = 0;
    WinHttpQueryHeaders(request.value, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
                        nullptr, &length, WINHTTP_NO_HEADER_INDEX);
    if (length && length < 1024 * 1024) {
        std::wstring raw(length / sizeof(wchar_t), L'\0');
        if (WinHttpQueryHeaders(request.value, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
                                raw.data(), &length, WINHTTP_NO_HEADER_INDEX)) {
            while (!raw.empty() && raw.back() == L'\0') raw.pop_back();
            const int bytes = WideCharToMultiByte(CP_UTF8, 0, raw.data(), static_cast<int>(raw.size()), nullptr, 0, nullptr, nullptr);
            result.headers.resize(bytes);
            WideCharToMultiByte(CP_UTF8, 0, raw.data(), static_cast<int>(raw.size()), result.headers.data(), bytes, nullptr, nullptr);
        }
    }
    std::array<char, 16384> buffer{};
    for (;;) {
        DWORD count = 0;
        if (!WinHttpReadData(request.value, buffer.data(), static_cast<DWORD>(buffer.size()), &count)) return {};
        if (!count) break;
        if (result.body.size() + count > 16 * 1024 * 1024) return {};
        result.body.append(buffer.data(), count);
    }
    result.status = static_cast<int>(status);
    result.completed = true;
#endif
    return result;
}
}
