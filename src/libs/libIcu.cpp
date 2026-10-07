#include "common/abi.h"
#include "libs/libs.h"
#include "loader/symbolDatabase.h"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <icu.h>

namespace Libs::Icu {
LIB_VERSION("Icu", 1, "Icu", 1, 0);

// The guest uses these handles opaquely. Keep both creation and destruction in
// the same host ICU, and bridge each entry point from SysV to the Windows ABI.
// In particular, returning zero from ubrk_next never reaches UBRK_DONE and
// hangs ShellUI's input filter (native eboot 0x536dea).
struct HostApi {
	HMODULE module = LoadLibraryExW(L"icu.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
#define ICU_PROC(name) decltype(&::name) name = module ? reinterpret_cast<decltype(&::name)>(GetProcAddress(module, #name)) : nullptr
	ICU_PROC(utext_openUChars);
	ICU_PROC(utext_close);
	ICU_PROC(uloc_getDefault);
	ICU_PROC(ubrk_open);
	ICU_PROC(ubrk_setUText);
	ICU_PROC(ubrk_first);
	ICU_PROC(ubrk_next);
	ICU_PROC(ubrk_close);
#undef ICU_PROC
};
static HostApi& Api() { static HostApi api; return api; }
static void Unsupported(UErrorCode* status) {
	if (status && U_SUCCESS(*status)) { *status = U_UNSUPPORTED_ERROR; }
}
static UText* KYTY_SYSV_ABI OpenUChars(UText* text, const UChar* chars, int64_t length, UErrorCode* status) {
	if (!status) { return nullptr; }
	if (const auto fn = Api().utext_openUChars) { return fn(text, chars, length, status); }
	Unsupported(status);
	return nullptr;
}
static UText* KYTY_SYSV_ABI CloseText(UText* text) {
	if (const auto fn = Api().utext_close) { return fn(text); }
	return nullptr;
}
static const char* KYTY_SYSV_ABI DefaultLocale() {
	if (const auto fn = Api().uloc_getDefault) { return fn(); }
	return "en_US";
}
static UBreakIterator* KYTY_SYSV_ABI OpenBreak(UBreakIteratorType type, const char* locale,
	                                          const UChar* text, int32_t length, UErrorCode* status) {
	if (!status) { return nullptr; }
	if (const auto fn = Api().ubrk_open) { return fn(type, locale, text, length, status); }
	Unsupported(status);
	return nullptr;
}
static void KYTY_SYSV_ABI SetText(UBreakIterator* iter, UText* text, UErrorCode* status) {
	if (!status || U_FAILURE(*status)) { return; }
	if (!iter || !text) { *status = U_ILLEGAL_ARGUMENT_ERROR; return; }
	if (const auto fn = Api().ubrk_setUText) { fn(iter, text, status); return; }
	Unsupported(status);
}
static int32_t KYTY_SYSV_ABI First(UBreakIterator* iter) {
	return iter && Api().ubrk_first ? Api().ubrk_first(iter) : UBRK_DONE;
}
static int32_t KYTY_SYSV_ABI Next(UBreakIterator* iter) {
	return iter && Api().ubrk_next ? Api().ubrk_next(iter) : UBRK_DONE;
}
static void KYTY_SYSV_ABI CloseBreak(UBreakIterator* iter) {
	if (iter && Api().ubrk_close) { Api().ubrk_close(iter); }
}
LIB_DEFINE(InitIcu_1) {
	LIB_FUNC("o9+yMOok2Zs", OpenUChars);
	LIB_FUNC("m1nD9D9LmP0", DefaultLocale);
	LIB_FUNC("NfGO57hqUEw", OpenBreak);
	LIB_FUNC("qQMUbG5L6oE", SetText);
	LIB_FUNC("cL3dlqTcRqk", First);
	LIB_FUNC("4Uj1DZGlHTw", Next);
	LIB_FUNC("2NaZ-stsAv0", CloseText);
	LIB_FUNC("-Hc6XkAq-eU", CloseBreak);
}
} // namespace Libs::Icu
#else
namespace Libs::Icu {
void InitIcu_1(Loader::SymbolDatabase*) {}
}
#endif
