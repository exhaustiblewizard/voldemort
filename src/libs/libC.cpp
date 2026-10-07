#include "common/abi.h"
#include "common/assert.h"
#include "common/common.h"
#include "common/emulatorConfig.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "common/stringUtils.h"
#include "common/virtualMemory.h"
#include "graphics/host_gpu/hostMemory.h"
#include "kernel/fileSystem.h"
#include "kernel/memory.h"
#include "kernel/pthread.h"
#include "libs/errno.h"
#include "libs/guestPrintf.h"
#include "libs/libs.h"
#include "libs/vaContext.h"
#include "loader/runtimeLinker.h"
#include "loader/symbolDatabase.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <condition_variable>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <exception>
#if defined(_WIN32)
#include <malloc.h>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif
#include <fmt/format.h>
#include <list>
#include <map>
#include <mutex>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace Libs {

extern "C" KYTY_SYSV_ABI int kyty_guest_sigprocmask(int how, const void* set, void* old);

// Native FreeBSD jmp_buf: RIP, RBX, RSP, RBP, R12-R15, x87/MXCSR, sigset.
// Keep the caller's actual stack frame; a host CRT jmp_buf has a different ABI.
extern "C" __attribute__((naked, returns_twice)) KYTY_SYSV_ABI int kyty_guest_setjmp(void*) {
	asm volatile(
	    "movq (%rsp), %rax\n\t"
	    "movq %rax, 0(%rdi)\n\t"
	    "movq %rbx, 8(%rdi)\n\t"
	    "movq %rsp, 16(%rdi)\n\t"
	    "movq %rbp, 24(%rdi)\n\t"
	    "movq %r12, 32(%rdi)\n\t"
	    "movq %r13, 40(%rdi)\n\t"
	    "movq %r14, 48(%rdi)\n\t"
	    "movq %r15, 56(%rdi)\n\t"
	    "fnstcw 64(%rdi)\n\t"
	    "stmxcsr 68(%rdi)\n\t"
	    "leaq 72(%rdi), %rdx\n\t"
	    "movl $1, %edi\n\t"
	    "xorl %esi, %esi\n\t"
	    "subq $8, %rsp\n\t"
	    "call kyty_guest_sigprocmask\n\t"
	    "addq $8, %rsp\n\t"
	    "xorl %eax, %eax\n\t"
	    "retq\n\t");
}

extern "C" __attribute__((naked, noreturn)) KYTY_SYSV_ABI void kyty_guest_longjmp(void*, int) {
	asm volatile(
	    "pushq %rdi\n\t"
	    "pushq %rsi\n\t"
	    "leaq 72(%rdi), %rsi\n\t"
	    "movl $3, %edi\n\t"
	    "xorl %edx, %edx\n\t"
	    "subq $8, %rsp\n\t"
	    "call kyty_guest_sigprocmask\n\t"
	    "addq $8, %rsp\n\t"
	    "popq %rsi\n\t"
	    "popq %rdx\n\t"
	    "stmxcsr -4(%rsp)\n\t"
	    "movl 68(%rdx), %eax\n\t"
	    "andl $-64, %eax\n\t"
	    "movl -4(%rsp), %edi\n\t"
	    "andl $63, %edi\n\t"
	    "orl %eax, %edi\n\t"
	    "movl %edi, -4(%rsp)\n\t"
	    "ldmxcsr -4(%rsp)\n\t"
	    "movl %esi, %eax\n\t"
	    "testl %eax, %eax\n\t"
	    "jnz 1f\n\t"
	    "incl %eax\n\t"
	    "1: movq 0(%rdx), %rcx\n\t"
	    "movq 8(%rdx), %rbx\n\t"
	    "movq 16(%rdx), %rsp\n\t"
	    "movq 24(%rdx), %rbp\n\t"
	    "movq 32(%rdx), %r12\n\t"
	    "movq 40(%rdx), %r13\n\t"
	    "movq 48(%rdx), %r14\n\t"
	    "movq 56(%rdx), %r15\n\t"
	    "fldcw 64(%rdx)\n\t"
	    "movq %rcx, (%rsp)\n\t"
	    "retq\n\t");
}

namespace {
std::mutex g_guest_environment_mutex;
std::map<Loader::Program*, std::map<std::string, std::string>> g_guest_environment;
std::mutex g_aligned_allocation_mutex;
std::unordered_map<void*, std::pair<void*, size_t>> g_aligned_allocations;

// Native firmware packs heap pointers into 40-bit fields (AgcCompositor's
// HashTable is one such user). The Windows CRT heap can exceed that range.
// Keep guest allocations in bounded VM arenas; host C++ containers use the CRT.
std::mutex g_guest_heap_mutex;
std::map<uintptr_t, size_t> g_guest_heap_free;
std::unordered_map<void*, size_t> g_guest_heap_allocations;

void* AllocateGuestHeap(size_t size) {
	constexpr size_t alignment = alignof(std::max_align_t);
	if (size == 0) { size = 1; }
	if (size > SIZE_MAX - (alignment - 1)) { return nullptr; }
	size = (size + alignment - 1) & ~(alignment - 1);
	std::lock_guard<std::mutex> lock(g_guest_heap_mutex);
	for (;;) {
		for (auto it = g_guest_heap_free.begin(); it != g_guest_heap_free.end(); ++it) {
			if (it->second < size) { continue; }
			const auto address = it->first;
			const auto remaining = it->second - size;
			g_guest_heap_free.erase(it);
			if (remaining != 0) { g_guest_heap_free.emplace(address + size, remaining); }
			auto* result = reinterpret_cast<void*>(address);
			g_guest_heap_allocations.emplace(result, size);
			return result;
		}
		constexpr size_t granularity = 0x10000;
		if (size > SIZE_MAX - (granularity - 1)) { return nullptr; }
		const size_t arena_size = std::max(size_t(4 * 1024 * 1024),
		                                 (size + granularity - 1) & ~(granularity - 1));
		uint64_t arena = 0;
		if (Libs::LibKernel::Memory::IsInitialized()) {
			// The guest address space reserves placeholders across the low ranges.
			// Allocate through its manager so the new mapping replaces a placeholder
			// and participates in the guest's memory accounting and lifetime.
			void* mapped = nullptr;
			if (Libs::LibKernel::Memory::KernelMapNamedFlexibleMemory(
			        &mapped, arena_size, 3, 16 << 24, "libc heap") != 0) { return nullptr; }
			arena = reinterpret_cast<uint64_t>(mapped);
		} else {
			constexpr uint64_t hint = KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS ? 0 : 0x40000000;
			arena = Common::VirtualMemory::AllocAligned(
			    hint, arena_size, Common::VirtualMemory::Mode::ReadWrite, granularity);
		}
		if (arena == 0 || arena == UINT64_MAX) { return nullptr; }
		if (arena >= (uint64_t(1) << 40) || arena_size > (uint64_t(1) << 40) - arena) {
			Common::VirtualMemory::Free(arena);
			return nullptr;
		}
		g_guest_heap_free.emplace(arena, arena_size);
	}
}

size_t GuestHeapSize(void* ptr) {
	std::lock_guard<std::mutex> lock(g_guest_heap_mutex);
	auto it = g_guest_heap_allocations.find(ptr);
	return it != g_guest_heap_allocations.end() ? it->second : 0;
}

bool ReleaseGuestHeap(void* ptr) {
	std::lock_guard<std::mutex> lock(g_guest_heap_mutex);
	const auto allocation = g_guest_heap_allocations.find(ptr);
	if (allocation == g_guest_heap_allocations.end()) { return false; }
	auto address = reinterpret_cast<uintptr_t>(ptr);
	auto size = allocation->second;
	g_guest_heap_allocations.erase(allocation);
	auto next = g_guest_heap_free.lower_bound(address);
	if (next != g_guest_heap_free.end() && address + size == next->first) {
		size += next->second;
		next = g_guest_heap_free.erase(next);
	}
	if (next != g_guest_heap_free.begin()) {
		auto previous = std::prev(next);
		if (previous->first + previous->second == address) {
			address = previous->first;
			size += previous->second;
			g_guest_heap_free.erase(previous);
		}
	}
	g_guest_heap_free.emplace(address, size);
	return true;
}

void FreeGuestAllocation(void* ptr) {
	void* allocation = ptr;
	{
		std::lock_guard<std::mutex> lock(g_aligned_allocation_mutex);
		if (auto it = g_aligned_allocations.find(ptr); it != g_aligned_allocations.end()) {
			allocation = it->second.first;
			g_aligned_allocations.erase(it);
		}
	}
	if (!ReleaseGuestHeap(allocation)) { std::free(allocation); }
}
}

namespace LibKernel {
void KernelDispatchPendingSignalForCurrentThread();
} // namespace LibKernel

namespace LibC {

LIB_VERSION("libc", 1, "libc", 1, 1);

static uint32_t g_need_flag = 1;

using cxa_destructor_func_t = KYTY_SYSV_ABI void (*)(void*);
using atexit_func_t         = KYTY_SYSV_ABI void (*)();

struct CxaDestructor {
	cxa_destructor_func_t destructor_func;
	void*                 destructor_object;
	void*                 module_id;
};

struct CContext {
	std::list<CxaDestructor> cxa;
	std::list<atexit_func_t> atexit;
};

struct InitEnvParams {
	int         argc;
	uint32_t    pad;
	const char* argv[3];
};

static int                g_argc = 0;
static const char* const* g_argv = nullptr;
static const char* const* g_envp = nullptr;

int GetArgc() {
	return g_argc;
}

const char** GetArgv() {
	return const_cast<const char**>(g_argv);
}

static KYTY_SYSV_ABI void exit(int code) {
	PRINT_NAME();

	::exit(code);
}

static void PrintAbortStringCandidate(const char* name, uint64_t addr) {
	if (!Graphics::HostMemoryIsReadable(addr)) {
		return;
	}

	const auto* ptr = reinterpret_cast<const char*>(static_cast<uintptr_t>(addr));
	char        buf[257] {};
	size_t      len = 0;

	for (; len < sizeof(buf) - 1 && Graphics::HostMemoryIsReadable(addr + len); len++) {
		const auto c = static_cast<unsigned char>(ptr[len]);
		if (c == 0) {
			break;
		}
		if (!std::isprint(c) && c != '\n' && c != '\r' && c != '\t') {
			return;
		}
		buf[len] = static_cast<char>(c);
	}

	if (len >= 4) {
		LOGF("\t %s string = \"%s\"\n", name, buf);
	}
}

static void PrintAbortWideStringCandidate(const char* name, uint64_t addr) {
	if (!Graphics::HostMemoryIsReadable(addr)) {
		return;
	}

	const auto* ptr = reinterpret_cast<const uint16_t*>(static_cast<uintptr_t>(addr));
	char        buf[257] {};
	size_t      len = 0;

	for (;
	     len < sizeof(buf) - 1 && Graphics::HostMemoryIsReadable(addr + len * sizeof(uint16_t) + 1);
	     len++) {
		const auto c = ptr[len];
		if (c == 0) {
			break;
		}
		if (c > 0x7f ||
		    (!std::isprint(static_cast<unsigned char>(c)) && c != '\n' && c != '\r' && c != '\t')) {
			return;
		}
		buf[len] = static_cast<char>(c);
	}

	if (len >= 4) {
		LOGF("\t %s u16 = \"%s\"\n", name, buf);
	}
}

static void PrintAbortBytesCandidate(const char* name, uint64_t addr) {
	if (!Graphics::HostMemoryIsReadable(addr)) {
		return;
	}

	uint8_t bytes[64] {};
	size_t  len = 0;

	for (; len < sizeof(bytes) && Graphics::HostMemoryIsReadable(addr + len); len++) {
		bytes[len] = *reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(addr + len));
	}

	if (len == 0) {
		return;
	}

	LOGF("\t %s bytes =", name);
	for (size_t i = 0; i < len; i++) {
		LOGF(" %02" PRIx8, bytes[i]);
	}
	LOGF("\n");
}

static void PrintAbortPointerCandidate(const char* name, uint64_t addr) {
	PrintAbortStringCandidate(name, addr);
	PrintAbortWideStringCandidate(name, addr);
	PrintAbortBytesCandidate(name, addr);
}

static bool LooksLikeAbortPointer(uint64_t addr) {
	return Graphics::HostMemoryIsReadable(addr) && addr >= 0x10000;
}

static void PrintAbortPointerArrayCandidate(const char* name, uint64_t addr) {
	if (!LooksLikeAbortPointer(addr)) {
		return;
	}

	for (int i = 0; i < 8; i++) {
		const auto slot_addr = addr + static_cast<uint64_t>(i) * sizeof(uint64_t);
		if (!Graphics::HostMemoryIsReadable(slot_addr)) {
			break;
		}

		const auto value = *reinterpret_cast<const uint64_t*>(static_cast<uintptr_t>(slot_addr));
		if (!LooksLikeAbortPointer(value)) {
			continue;
		}

		LOGF("\t %s[%d] = 0x%016" PRIx64 "\n", name, i, value);
		const auto child_name = fmt::format("{}[{}]", name, i);
		PrintAbortPointerCandidate(child_name.c_str(), value);
	}
}

[[noreturn]] static KYTY_SYSV_ABI void abort(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                             uint64_t arg3, uint64_t arg4, uint64_t arg5) {
	PRINT_NAME();

	uint64_t rbp = 0;
	uint64_t rsp = 0;
	// This assembly is x86-64-specific, not Windows-specific.
#if defined(__x86_64__) || defined(_M_X64)
	asm volatile("movq %%rbp, %0" : "=r"(rbp));
	asm volatile("movq %%rsp, %0" : "=r"(rsp));
#endif

	const auto ret = reinterpret_cast<uint64_t>(__builtin_return_address(0));

	LOGF("Guest abort diagnostics:\n"
	     "\t return = 0x%016" PRIx64 "\n"
	     "\t rbp    = 0x%016" PRIx64 "\n"
	     "\t rsp    = 0x%016" PRIx64 "\n"
	     "\t arg0   = 0x%016" PRIx64 "\n"
	     "\t arg1   = 0x%016" PRIx64 "\n"
	     "\t arg2   = 0x%016" PRIx64 "\n"
	     "\t arg3   = 0x%016" PRIx64 "\n"
	     "\t arg4   = 0x%016" PRIx64 "\n"
	     "\t arg5   = 0x%016" PRIx64 "\n",
	     ret, rbp, rsp, arg0, arg1, arg2, arg3, arg4, arg5);

	PrintAbortPointerCandidate("arg0", arg0);
	PrintAbortPointerCandidate("arg1", arg1);
	PrintAbortPointerCandidate("arg2", arg2);
	PrintAbortPointerCandidate("arg3", arg3);
	PrintAbortPointerCandidate("arg4", arg4);
	PrintAbortPointerCandidate("arg5", arg5);
	PrintAbortPointerArrayCandidate("arg0", arg0);
	PrintAbortPointerArrayCandidate("arg1", arg1);
	PrintAbortPointerArrayCandidate("arg2", arg2);
	PrintAbortPointerArrayCandidate("arg3", arg3);
	PrintAbortPointerArrayCandidate("arg4", arg4);
	PrintAbortPointerArrayCandidate("arg5", arg5);

	if (rbp != 0) {
		Common::Singleton<Loader::RuntimeLinker>::Instance()->StackTrace(rbp, rsp);
	}

	if (rsp != 0) {
		LOGF("Guest abort stack words:\n");
		auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
		for (int i = 0; i < 16; i++) {
			const auto addr = rsp + static_cast<uint64_t>(i) * sizeof(uint64_t);
			if (!Graphics::HostMemoryIsReadable(addr)) {
				break;
			}
			const auto value   = *reinterpret_cast<const uint64_t*>(static_cast<uintptr_t>(addr));
			auto*      program = linker->FindProgramByAddr(value);
			if (program != nullptr) {
				auto module_name = Common::PathToString(program->file_name.filename());
				LOGF("\t [%02d] 0x%016" PRIx64 " %s+0x%016" PRIx64 "\n", i, value,
				     module_name.c_str(), value - program->base_vaddr);
			} else {
				LOGF("\t [%02d] 0x%016" PRIx64 "\n", i, value);
			}
			PrintAbortPointerCandidate(fmt::format("stack[{:02d}]", i).c_str(), value);
			PrintAbortPointerArrayCandidate(fmt::format("stack[{:02d}]", i).c_str(), value);
		}
	}

	EXIT("Guest abort()\n");
	std::abort();
}

static KYTY_SYSV_ABI int* libc_error() {
	PRINT_NAME();

	return Posix::GetErrorAddr();
}

static KYTY_SYSV_ABI void init_env(const InitEnvParams* params) {
	PRINT_NAME();

	if (params == nullptr) {
		g_argc = 0;
		g_argv = nullptr;
		g_envp = nullptr;
		return;
	}

	constexpr int argv_capacity = static_cast<int>(sizeof(params->argv) / sizeof(params->argv[0]));

	EXIT_NOT_IMPLEMENTED(params->argc < 0 || params->argc >= argv_capacity);

	g_argc = params->argc;
	g_argv = params->argv;
	g_envp = params->argv + params->argc + 1;

	LOGF("\t argc = %d\n"
	     "\t argv = 0x%016" PRIx64 "\n"
	     "\t envp = 0x%016" PRIx64 "\n",
	     g_argc, reinterpret_cast<uint64_t>(g_argv), reinterpret_cast<uint64_t>(g_envp));

	for (int i = 0; i < g_argc; i++) {
		LOGF("\t argv[%d] = %s\n", i, g_argv[i] != nullptr ? g_argv[i] : "<null>");
	}
}

static KYTY_SYSV_ABI int atexit(atexit_func_t func) {
	PRINT_NAME();

	if (func != nullptr) {
		Common::Singleton<CContext>::Instance()->atexit.push_front(func);
	}

	return 0;
}

static KYTY_SYSV_ABI int libc_printf(VA_ARGS) {
	VA_CONTEXT(ctx); // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init)

	PRINT_NAME();

	return GetGuestPrintfCtxFunc()(&ctx);
}

static KYTY_SYSV_ABI int puts(const char* s) {
	PRINT_NAME();

	return GetGuestPrintfStdFunc()("%s\n", s);
}

static KYTY_SYSV_ABI int setenv(const char* name, const char* value, int overwrite) {
	PRINT_NAME();

	LOGF("\t name      = %s\n"
	     "\t value     = %s\n"
	     "\t overwrite = %d\n",
	     (name != nullptr ? name : "<null>"), (value != nullptr ? value : "<null>"), overwrite);

	if (name == nullptr || value == nullptr || name[0] == '\0' ||
	    std::strchr(name, '=') != nullptr) {
		*Posix::GetErrorAddr() = Posix::POSIX_EINVAL;
		return -1;
	}

	std::lock_guard lock(g_guest_environment_mutex);
	auto& environment = g_guest_environment.try_emplace(Loader::RuntimeLinker::GetCurrentProgram(),
	                                                  Config::GetGuestEnvironment()).first->second;
	if (overwrite != 0 || !environment.contains(name)) {
		environment[name] = value;
	}
	return 0;
}

static KYTY_SYSV_ABI int64_t libc_time(int64_t* timer) {
	const auto now = static_cast<int64_t>(std::time(nullptr));
	if (timer != nullptr) {
		*timer = now;
	}
	return now;
}

static KYTY_SYSV_ABI double libc_difftime(int64_t time1, int64_t time0) {
	return std::difftime(static_cast<std::time_t>(time1), static_cast<std::time_t>(time0));
}

struct GuestTm {
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
};

static_assert(sizeof(GuestTm) == 36);

static GuestTm ToGuestTm(const std::tm& time) {
	return {time.tm_sec,  time.tm_min,  time.tm_hour, time.tm_mday, time.tm_mon,
	        time.tm_year, time.tm_wday, time.tm_yday, time.tm_isdst};
}

static std::tm ToHostTm(const GuestTm& time) {
	std::tm result {};
	result.tm_sec   = time.tm_sec;
	result.tm_min   = time.tm_min;
	result.tm_hour  = time.tm_hour;
	result.tm_mday  = time.tm_mday;
	result.tm_mon   = time.tm_mon;
	result.tm_year  = time.tm_year;
	result.tm_wday  = time.tm_wday;
	result.tm_yday  = time.tm_yday;
	result.tm_isdst = time.tm_isdst;
	return result;
}

static KYTY_SYSV_ABI GuestTm* libc_gmtime(const int64_t* timer) {
	if (timer == nullptr) {
		return nullptr;
	}

	thread_local GuestTm result {};
	std::tm              host_result {};
	const auto           t = static_cast<std::time_t>(*timer);

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (_gmtime64_s(&host_result, &t) != 0) {
		return nullptr;
	}
#else
	if (gmtime_r(&t, &host_result) == nullptr) {
		return nullptr;
	}
#endif

	result = ToGuestTm(host_result);
	return &result;
}

static KYTY_SYSV_ABI GuestTm* libc_localtime(const int64_t* timer) {
	if (timer == nullptr) {
		return nullptr;
	}

	thread_local GuestTm result {};
	std::tm              host_result {};
	const auto           t = static_cast<std::time_t>(*timer);

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (_localtime64_s(&host_result, &t) != 0) {
		return nullptr;
	}
#else
	if (localtime_r(&t, &host_result) == nullptr) {
		return nullptr;
	}
#endif

	result = ToGuestTm(host_result);
	return &result;
}

static KYTY_SYSV_ABI int64_t libc_mktime(GuestTm* timeptr) {
	if (timeptr == nullptr) {
		return -1;
	}

	auto host_time = ToHostTm(*timeptr);

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	const auto result = static_cast<int64_t>(_mktime64(&host_time));
#else
	const auto result = static_cast<int64_t>(std::mktime(&host_time));
#endif

	*timeptr = ToGuestTm(host_time);
	return result;
}

static KYTY_SYSV_ABI size_t libc_strftime(char* str, size_t count, const char* format,
                                          const GuestTm* timeptr) {
	if (str == nullptr || format == nullptr || timeptr == nullptr) {
		return 0;
	}

	const auto host_time = ToHostTm(*timeptr);
#if defined(_WIN32)
	// Windows narrow strftime emits %Z in the system ANSI code page. Mono
	// interprets guest libc strings as UTF-8, so a Cyrillic timezone name can
	// make GetTimeZoneData return null strings. Format through Unicode instead.
	if (count == 0) { return 0; }
	const int format_size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, format, -1, nullptr, 0);
	if (format_size <= 0) { str[0] = 0; return 0; }
	std::vector<wchar_t> wide_format(static_cast<size_t>(format_size));
	MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, format, -1, wide_format.data(), format_size);
	std::vector<wchar_t> wide_result(count);
	const auto length = std::wcsftime(wide_result.data(), count, wide_format.data(), &host_time);
	if (length == 0 || length > static_cast<size_t>(INT_MAX)) { str[0] = 0; return 0; }
	const int utf8_size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide_result.data(),
	                                        static_cast<int>(length), nullptr, 0, nullptr, nullptr);
	if (utf8_size <= 0 || static_cast<size_t>(utf8_size) >= count) { str[0] = 0; return 0; }
	WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide_result.data(), static_cast<int>(length),
	                    str, utf8_size, nullptr, nullptr);
	str[utf8_size] = 0;
	return static_cast<size_t>(utf8_size);
#else
	return std::strftime(str, count, format, &host_time);
#endif
}

static KYTY_SYSV_ABI void catchReturnFromMain(int status) {
	PRINT_NAME();

	uint64_t ret_addr = reinterpret_cast<uint64_t>(__builtin_return_address(0));
	uint64_t rsp      = 0;
	uint64_t rbp      = 0;
#if defined(__x86_64__) || defined(_M_X64)
	asm volatile("movq %%rsp, %0\n\t"
	             "movq %%rbp, %1\n\t"
	             : "=r"(rsp), "=r"(rbp));
#endif

	LOGF("\t status     = %d\n"
	     "\t ret_addr   = 0x%016" PRIx64 "\n"
	     "\t rsp        = 0x%016" PRIx64 "\n"
	     "\t rbp        = 0x%016" PRIx64 "\n",
	     status, ret_addr, rsp, rbp);
	if (rsp != 0) {
		auto* stack = reinterpret_cast<const uint64_t*>(rsp);
		for (uint32_t i = 0; i < 12; i++) {
			LOGF("\t stack[%02" PRIu32 "] = 0x%016" PRIx64 "\n", i, stack[i]);
		}
	}

	::printf("return from main = %d\n", status);
}

using execute_once_func_t = KYTY_SYSV_ABI int (*)(void*, void*, void**);

static std::mutex              g_execute_once_mutex;
static std::condition_variable g_execute_once_cv;

static KYTY_SYSV_ABI int std_execute_once(int* flag, execute_once_func_t func, void* arg) {
	PRINT_NAME();

	if (flag == nullptr || func == nullptr) {
		return 0;
	}

	constexpr int once_init    = 0;
	constexpr int once_done    = 1;
	constexpr int once_running = 2;

	{
		std::unique_lock lock(g_execute_once_mutex);
		while (*flag == once_running) {
			g_execute_once_cv.wait_for(lock, std::chrono::microseconds(10000));
			if (*flag == once_running) {
				lock.unlock();
				LibKernel::KernelDispatchPendingSignalForCurrentThread();
				lock.lock();
			}
		}
		if (*flag == once_done) {
			return 1;
		}
		*flag = once_running;
	}

	void* callback_context = nullptr;
	int   result           = func(nullptr, arg, &callback_context);

	{
		std::lock_guard lock(g_execute_once_mutex);
		*flag = (result != 0 ? once_done : once_init);
	}
	g_execute_once_cv.notify_all();

	return result;
}

static KYTY_SYSV_ABI int cxa_atexit(cxa_destructor_func_t func, void* arg, void* d) {
	PRINT_NAME();

	auto* cc = Common::Singleton<CContext>::Instance();

	CxaDestructor c {};
	c.destructor_func   = func;
	c.destructor_object = arg;
	c.module_id         = d;

	cc->cxa.push_back(c);

	return 0;
}

void KYTY_SYSV_ABI cxa_finalize(void* d) {
	PRINT_NAME();

	auto* cc = Common::Singleton<CContext>::Instance();

	for (auto i = cc->cxa.rbegin(); i != cc->cxa.rend(); ++i) {
		auto& c = *i;
		if ((d == nullptr || c.module_id == d) && c.destructor_func != nullptr) {
			auto* func        = c.destructor_func;
			auto* object      = c.destructor_object;
			c.destructor_func = nullptr;
			func(object);
		}
	}
}

} // namespace LibC

namespace LibcInternalExt {

LIB_VERSION("LibcInternalExt", 1, "LibcInternal", 1, 1);

static uint64_t g_mspace_atomic_id_mask = 0;
static uint64_t g_mstate_table[64]      = {0};

using thread_atexit_destructor_t = KYTY_SYSV_ABI void (*)(void*);

struct ThreadAtexitDestructor {
	thread_atexit_destructor_t destructor;
	void*                      object;
};

static thread_local std::vector<ThreadAtexitDestructor> g_thread_atexit_destructors;

struct Info {
	uint64_t  size;
	uint32_t  unknown1;
	uint32_t  unknown2;
	uint64_t* mspace_atomic_id_mask;
	uint64_t* mstate_table;
};

void KYTY_SYSV_ABI LibcHeapGetTraceInfo(Info* info) {
	PRINT_NAME();

	EXIT_NOT_IMPLEMENTED(info->size != 32);

	info->mspace_atomic_id_mask = &g_mspace_atomic_id_mask;
	info->mstate_table          = g_mstate_table;
}

int KYTY_SYSV_ABI LibcInternalExtCxaThreadAtexit(thread_atexit_destructor_t destructor,
                                                 void* object, void* /*module_id*/) {
	PRINT_NAME();

	g_thread_atexit_destructors.push_back({destructor, object});

	return 0;
}

void RunThreadAtexitDestructors() {
	while (!g_thread_atexit_destructors.empty()) {
		auto destructor = g_thread_atexit_destructors.back();
		g_thread_atexit_destructors.pop_back();

		if (destructor.destructor != nullptr) {
			destructor.destructor(destructor.object);
		}
	}
}

LIB_DEFINE(InitLibcInternalExt_1) {
	LIB_FUNC("NWtTN10cJzE", LibcInternalExt::LibcHeapGetTraceInfo);
	LIB_FUNC("qBS714-Jr3g", LibcInternalExt::LibcInternalExtCxaThreadAtexit);
}

} // namespace LibcInternalExt

namespace LibcInternal {

LIB_VERSION("LibcInternal", 1, "LibcInternal", 1, 1);

static uint32_t g_need_flag = 1;

int KYTY_SYSV_ABI vprintf(const char* str, VaList* c) {
	PRINT_NAME();

	return GetGuestVprintfFunc()(str, c);
}

static KYTY_SYSV_ABI int snprintf(VA_ARGS) {
	VA_CONTEXT(ctx); // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init)

	PRINT_NAME();

	return GetGuestSnprintfCtxFunc()(&ctx);
}

// sprintf_s(char* buf, rsize_t size, const char* fmt, ...): same argument layout as snprintf, so
// it reuses the guest formatter (bounded write into buf).
static KYTY_SYSV_ABI int sprintf_s(VA_ARGS) {
	VA_CONTEXT(ctx); // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init)

	PRINT_NAME();

	return GetGuestSnprintfCtxFunc()(&ctx);
}

static KYTY_SYSV_ABI int sprintf(VA_ARGS) {
	VA_CONTEXT(ctx);
	return GetGuestSprintfCtxFunc()(&ctx);
}

int KYTY_SYSV_ABI fflush(FILE* stream) {
	PRINT_NAME();

	EXIT_NOT_IMPLEMENTED(stream != nullptr && stream != stdout && stream != stderr);

	return ::fflush(stream);
}

void* KYTY_SYSV_ABI memset(void* s, int c, size_t n) {
	PRINT_NAME();

	return ::memset(s, c, n);
}

void* KYTY_SYSV_ABI memcpy(void* dest, const void* src, size_t n) {
	return ::memcpy(dest, src, n);
}

void* KYTY_SYSV_ABI memmove(void* dest, const void* src, size_t n) {
	return ::memmove(dest, src, n);
}

int KYTY_SYSV_ABI memcmp(const void* s1, const void* s2, size_t n) {
	return ::memcmp(s1, s2, n);
}

int KYTY_SYSV_ABI strcmp(const char* s1, const char* s2) {
	return ::strcmp(s1, s2);
}

int KYTY_SYSV_ABI strncmp(const char* s1, const char* s2, size_t n) {
	return ::strncmp(s1, s2, n);
}

int KYTY_SYSV_ABI strncasecmp(const char* s1, const char* s2, size_t n) {
	// The guest libc currently exposes the C locale. Fold ASCII and compare unsigned
	// bytes; do not let the Windows host's locale change native protocol matching.
	for (size_t i = 0; i < n; ++i) {
		const auto fold = [](unsigned char c) { return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c; };
		const int a = fold(static_cast<unsigned char>(s1[i]));
		const int b = fold(static_cast<unsigned char>(s2[i]));
		if (a != b || a == 0) { return a - b; }
	}
	return 0;
}

size_t KYTY_SYSV_ABI strlen(const char* s) {
	return ::strlen(s);
}

// This console's LibcInternal wchar_t is UTF-16 (also used by native IME).
size_t KYTY_SYSV_ABI wcslen(const uint16_t* s) {
	const auto* end = s;
	while (*end) { ++end; }
	return static_cast<size_t>(end - s);
}
uint16_t* KYTY_SYSV_ABI wcsncat(uint16_t* dest, const uint16_t* src, size_t count) {
	auto* end = dest + wcslen(dest);
	for (size_t i = 0; i < count && src[i]; ++i) { *end++ = src[i]; }
	*end = 0;
	return dest;
}
size_t KYTY_SYSV_ABI wcsnlen_s(const uint16_t* s, size_t count) {
	if (!s) { return 0; }
	size_t length = 0;
	while (length < count && s[length]) { ++length; }
	return length;
}
uint16_t* KYTY_SYSV_ABI wcsncpy(uint16_t* dest, const uint16_t* src, size_t count) {
	size_t i = 0;
	for (; i < count && src[i]; ++i) { dest[i] = src[i]; }
	for (; i < count; ++i) { dest[i] = 0; }
	return dest;
}
uint16_t* KYTY_SYSV_ABI wmemcpy(uint16_t* dest, const uint16_t* src, size_t count) {
	if (count != 0) { std::memcpy(dest, src, count * sizeof(uint16_t)); }
	return dest;
}

char* KYTY_SYSV_ABI strcpy(char* dest, const char* src) {
	return ::strcpy(dest, src);
}

char* KYTY_SYSV_ABI strdup(const char* source) {
	const size_t size = std::strlen(source) + 1;
	auto* copy = static_cast<char*>(AllocateGuestHeap(size));
	if (copy == nullptr) {
		*Posix::GetErrorAddr() = Posix::POSIX_ENOMEM;
		return nullptr;
	}
	std::memcpy(copy, source, size);
	return copy;
}

char* KYTY_SYSV_ABI strncpy(char* dest, const char* src, size_t count) {
	return ::strncpy(dest, src, count);
}

char* KYTY_SYSV_ABI strcat(char* dest, const char* src) {
	return ::strcat(dest, src);
}

char* KYTY_SYSV_ABI strncat(char* dest, const char* src, size_t count) {
	return ::strncat(dest, src, count);
}

// C11 Annex K bounds-checked string ops. The 2nd arg is the DESTINATION SIZE (not src!). These were
// previously mis-registered to the plain strcpy/strncpy (which read the size as the src pointer) —
// AgcCompositor's strcpy_s(sun_path, 0x68, path) then did strlen(0x68) -> host crash. errno_t return
// (0 = ok, non-zero = error); on error dest is emptied where a valid dest buffer exists.
int KYTY_SYSV_ABI strcpy_s(char* dest, size_t destsz, const char* src) {
	if (dest == nullptr || destsz == 0) {
		return Posix::POSIX_EINVAL;
	}
	if (src == nullptr) {
		dest[0] = '\0';
		return Posix::POSIX_EINVAL;
	}
	const size_t len = ::strlen(src);
	if (len + 1 > destsz) {
		dest[0] = '\0';
		return Posix::POSIX_ERANGE;
	}
	std::memcpy(dest, src, len + 1);
	return 0;
}
int KYTY_SYSV_ABI strncpy_s(char* dest, size_t destsz, const char* src, size_t count) {
	if (dest == nullptr || destsz == 0) {
		return Posix::POSIX_EINVAL;
	}
	if (src == nullptr) {
		dest[0] = '\0';
		return Posix::POSIX_EINVAL;
	}
	size_t copy = 0;
	while (copy < count && src[copy] != '\0') {
		++copy;
	}
	if (copy + 1 > destsz) {
		dest[0] = '\0';
		return Posix::POSIX_ERANGE;
	}
	std::memcpy(dest, src, copy);
	dest[copy] = '\0';
	return 0;
}
int KYTY_SYSV_ABI strcat_s(char* dest, size_t destsz, const char* src) {
	if (dest == nullptr || destsz == 0 || src == nullptr) {
		return Posix::POSIX_EINVAL;
	}
	const size_t dlen = ::strnlen(dest, destsz);
	if (dlen == destsz) {
		return Posix::POSIX_EINVAL; // dest not NUL-terminated within destsz
	}
	const size_t slen = ::strlen(src);
	if (dlen + slen + 1 > destsz) {
		dest[0] = '\0';
		return Posix::POSIX_ERANGE;
	}
	std::memcpy(dest + dlen, src, slen + 1);
	return 0;
}
int KYTY_SYSV_ABI strncat_s(char* dest, size_t destsz, const char* src, size_t count) {
	if (dest == nullptr || destsz == 0 || src == nullptr) {
		return Posix::POSIX_EINVAL;
	}
	const size_t dlen = ::strnlen(dest, destsz);
	if (dlen == destsz) {
		return Posix::POSIX_EINVAL;
	}
	size_t slen = 0;
	while (slen < count && src[slen] != '\0') {
		++slen;
	}
	if (dlen + slen + 1 > destsz) {
		dest[0] = '\0';
		return Posix::POSIX_ERANGE;
	}
	std::memcpy(dest + dlen, src, slen);
	dest[dlen + slen] = '\0';
	return 0;
}

const char* KYTY_SYSV_ABI strchr(const char* s, int c) {
	return ::strchr(s, c);
}

char* KYTY_SYSV_ABI strrchr(const char* s, int c) {
	return const_cast<char*>(::strrchr(s, c));
}

char* KYTY_SYSV_ABI strstr(const char* haystack, const char* needle) {
	static int log_count = 0;
	if (log_count++ < 8) {
		LOGF("LibcInternal::strstr(\"%s\", \"%s\")\n", (haystack != nullptr ? haystack : "<null>"),
		     (needle != nullptr ? needle : "<null>"));
	}
	return const_cast<char*>(::strstr(haystack, needle));
}

// The guest uses LP64 even on Windows. Preserve its separate errno on success.
template <bool Unsigned>
auto ParseInteger64(const char* str, char** endptr, int base, int* error = nullptr,
                    bool set_invalid_errno = true) {
	if (error != nullptr) { *error = 0; }
	using Result = std::conditional_t<Unsigned, uint64_t, int64_t>;
	if (base != 0 && (base < 2 || base > 36)) {
		if (endptr != nullptr) { *endptr = const_cast<char*>(str); }
		if (error != nullptr) { *error = Posix::POSIX_EINVAL; }
		if (set_invalid_errno) { *Posix::GetErrorAddr() = Posix::POSIX_EINVAL; }
		return Result {0};
	}
	const int saved_errno = errno;
	errno = 0;
	Result result;
	if constexpr (Unsigned) { result = std::strtoull(str, endptr, base); }
	else { result = std::strtoll(str, endptr, base); }
	const int conversion_errno = errno;
	errno = saved_errno;
	if (conversion_errno == ERANGE) {
		*Posix::GetErrorAddr() = Posix::POSIX_ERANGE;
		if (error != nullptr) { *error = Posix::POSIX_ERANGE; }
	}
	return result;
}

int64_t KYTY_SYSV_ABI strtoll(const char* str, char** endptr, int base) {
	return ParseInteger64<false>(str, endptr, base);
}

uint64_t KYTY_SYSV_ABI strtoull(const char* str, char** endptr, int base) {
	return ParseInteger64<true>(str, endptr, base);
}

uint64_t KYTY_SYSV_ABI Stoullx(const char* str, char** endptr, int base, int* error) {
	return ParseInteger64<true>(str, endptr, base, error, false);
}

uint64_t KYTY_SYSV_ABI Stoull(const char* str, char** endptr, int base) {
	return Stoullx(str, endptr, base, nullptr);
}

int64_t KYTY_SYSV_ABI strtol(const char* str, char** endptr, int base) {
	static int log_count = 0;
	if (log_count++ < 16) {
		LOGF("LibcInternal::strtol(\"%s\", base=%d)\n", (str != nullptr ? str : "<null>"), base);
	}
	return strtoll(str, endptr, base);
}

uint64_t KYTY_SYSV_ABI strtoul(const char* str, char** endptr, int base) {
	static int log_count = 0;
	if (log_count++ < 16) {
		LOGF("LibcInternal::strtoul(\"%s\", base=%d)\n", (str != nullptr ? str : "<null>"), base);
	}
	return strtoull(str, endptr, base);
}

int KYTY_SYSV_ABI atoi(const char* str) {
	return ::atoi(str);
}

// Math functions use the guest's errno, not the Windows CRT's thread-local errno.
template <typename F>
auto GuestMath(F operation) {
	const int saved_errno = errno;
	errno = 0;
	auto result = operation();
	const int math_errno = errno;
	errno = saved_errno;
	if (math_errno == EDOM) { *Posix::GetErrorAddr() = Posix::POSIX_EDOM; }
	if (math_errno == ERANGE) { *Posix::GetErrorAddr() = Posix::POSIX_ERANGE; }
	return result;
}

// Verified against the native _Stod/_Stodx: pten is a signed LP64 decimal
// exponent; the optional error output uses bit 0 for a range error.
double KYTY_SYSV_ABI Stodx(const char* str, char** endptr, int64_t pten, int* error) {
	if (error != nullptr) { *error = 0; }
	const int saved_errno = errno;
	errno = 0;
	long double value = std::strtold(str, endptr);
	if (pten != 0 && value != 0 && std::isfinite(value)) {
		value *= std::pow(10.0L, static_cast<long double>(pten));
	}
	const double result = static_cast<double>(value);
	const bool range_error = errno == ERANGE ||
	    (std::isfinite(value) && (!std::isfinite(result) || (result == 0 && value != 0)));
	errno = saved_errno;
	if (range_error) {
		*Posix::GetErrorAddr() = Posix::POSIX_ERANGE;
		if (error != nullptr) { *error = 1; }
	}
	return result;
}

double KYTY_SYSV_ABI Stod(const char* str, char** endptr, int64_t pten) {
	return Stodx(str, endptr, pten, nullptr);
}

float KYTY_SYSV_ABI tanf(float x) { return GuestMath([&] { return std::tan(x); }); }
float KYTY_SYSV_ABI acosf(float x) { return GuestMath([&] { return std::acos(x); }); }
float KYTY_SYSV_ABI atan2f(float y, float x) { return GuestMath([&] { return std::atan2(y, x); }); }
float KYTY_SYSV_ABI expf(float x) { return GuestMath([&] { return std::exp(x); }); }
float KYTY_SYSV_ABI powf(float x, float y) { return GuestMath([&] { return std::pow(x, y); }); }
double KYTY_SYSV_ABI pow(double x, double y) { return GuestMath([&] { return std::pow(x, y); }); }
double KYTY_SYSV_ABI log(double x) { return GuestMath([&] { return std::log(x); }); }
float KYTY_SYSV_ABI fmodf(float x, float y) { return GuestMath([&] { return std::fmod(x, y); }); }
double KYTY_SYSV_ABI modf(double x, double* integral) { return std::modf(x, integral); }
float KYTY_SYSV_ABI modff(float x, float* integral) { return std::modf(x, integral); }
double KYTY_SYSV_ABI frexp(double x, int* exponent) { return std::frexp(x, exponent); }
float KYTY_SYSV_ABI frexpf(float x, int* exponent) { return std::frexp(x, exponent); }

float KYTY_SYSV_ABI sinf(float x) {
	return std::sin(x);
}

float KYTY_SYSV_ABI cosf(float x) {
	return std::cos(x);
}

void KYTY_SYSV_ABI sincosf(float x, float* sinp, float* cosp) {
	if (sinp != nullptr) {
		*sinp = std::sin(x);
	}
	if (cosp != nullptr) {
		*cosp = std::cos(x);
	}
}

double KYTY_SYSV_ABI sin(double x) {
	return std::sin(x);
}

double KYTY_SYSV_ABI cos(double x) {
	return std::cos(x);
}

void KYTY_SYSV_ABI sincos(double x, double* sinp, double* cosp) {
	if (sinp != nullptr) {
		*sinp = std::sin(x);
	}
	if (cosp != nullptr) {
		*cosp = std::cos(x);
	}
}

int KYTY_SYSV_ABI LibcHeapErrorReportForGame(uint64_t msp, uint64_t ptr, uint64_t error,
                                             uint64_t arg3, uint64_t arg4, uint64_t arg5) {
	PRINT_NAME();

	LOGF("\t temporary: heap error report ignored, msp=0x%016" PRIx64 ", ptr=0x%016" PRIx64
	     ", error=0x%016" PRIx64 ", args=(0x%016" PRIx64 ",0x%016" PRIx64 ",0x%016" PRIx64 ")\n",
	     msp, ptr, error, arg3, arg4, arg5);

	return 0;
}

// ---- Dinkumware C++ runtime bits exported by libSceLibcInternal.sprx ----
// System apps (e.g. ShellUI / NPXS40000) dynamically import operator new/delete and the C11
// thread ("_Mtx_*") family from libSceLibcInternal rather than statically linking their own libc,
// so the emulator must HLE them. The guest treats a mutex slot opaquely: _Mtx_init* allocates our
// handle and stores the pointer into the caller's storage, and every other _Mtx_* receives that
// handle back by value. Because both ends are our code, we fully own the handle layout.

void* KYTY_SYSV_ABI operator_new(size_t size) {
	// operator new must never return nullptr for a zero-sized request.
	return AllocateGuestHeap(size);
}

void KYTY_SYSV_ABI operator_delete(void* ptr) {
	FreeGuestAllocation(ptr);
}

// Sized operator delete / delete[] (C++14): the size argument is advisory; free ignores it.
void KYTY_SYSV_ABI operator_delete_sized(void* ptr, size_t /*size*/) {
	FreeGuestAllocation(ptr);
}

// C allocation family, sharing the bounded heap with operator new/delete.
void* KYTY_SYSV_ABI libc_malloc(size_t size) {
	void* result = AllocateGuestHeap(size);
	if (result == nullptr) { *Posix::GetErrorAddr() = Posix::POSIX_ENOMEM; }
	return result;
}

void KYTY_SYSV_ABI libc_free(void* ptr) {
	FreeGuestAllocation(ptr);
}

void* KYTY_SYSV_ABI libc_calloc(size_t nmemb, size_t size) {
	if (size != 0 && nmemb > SIZE_MAX / size) {
		*Posix::GetErrorAddr() = Posix::POSIX_ENOMEM; return nullptr;
	}
	const auto total = nmemb * size;
	void* result = libc_malloc(total);
	if (result != nullptr) { std::memset(result, 0, total); }
	return result;
}

void* KYTY_SYSV_ABI libc_realloc(void* ptr, size_t size) {
	if (ptr == nullptr) { return libc_malloc(size); }
	size_t aligned_size = 0;
	bool aligned = false;
	{
		std::lock_guard<std::mutex> lock(g_aligned_allocation_mutex);
		if (auto it = g_aligned_allocations.find(ptr); it != g_aligned_allocations.end()) {
			aligned_size = it->second.second;
			aligned = true;
		}
	}
	const auto heap_size = GuestHeapSize(ptr);
	if (aligned || heap_size != 0) {
		if (size == 0) {
			FreeGuestAllocation(ptr);
			return nullptr;
		}
		void* replacement = libc_malloc(size);
		if (replacement != nullptr) {
			std::memcpy(replacement, ptr, std::min(size, aligned ? aligned_size : heap_size));
			FreeGuestAllocation(ptr);
		}
		return replacement;
	}
	return std::realloc(ptr, size);
}

void* KYTY_SYSV_ABI libc_memalign(size_t alignment, size_t size) {
	if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
		*Posix::GetErrorAddr() = Posix::POSIX_EINVAL;
		return nullptr;
	}
	const size_t allocation_size = size != 0 ? size : 1;
	if (allocation_size > SIZE_MAX - (alignment - 1)) {
		*Posix::GetErrorAddr() = Posix::POSIX_ENOMEM;
		return nullptr;
	}
	void* allocation = AllocateGuestHeap(allocation_size + alignment - 1);
	if (allocation == nullptr) {
		*Posix::GetErrorAddr() = Posix::POSIX_ENOMEM;
		return nullptr;
	}
	const auto address = (reinterpret_cast<uintptr_t>(allocation) + alignment - 1) & ~(alignment - 1);
	void* aligned = reinterpret_cast<void*>(address);
	{
		std::lock_guard<std::mutex> lock(g_aligned_allocation_mutex);
		g_aligned_allocations.emplace(aligned, std::make_pair(allocation, size));
	}
	return aligned;
}

void* KYTY_SYSV_ABI operator_new_aligned(size_t size, size_t alignment) {
	return libc_memalign(alignment, size);
}

void* KYTY_SYSV_ABI operator_new_aligned_nothrow(size_t size, size_t alignment, const void*) {
	return libc_memalign(alignment, size);
}

void KYTY_SYSV_ABI operator_delete_aligned(void* pointer, size_t /*alignment*/) {
	FreeGuestAllocation(pointer);
}

void KYTY_SYSV_ABI operator_delete_aligned_sized(void* pointer, size_t /*size*/, size_t /*alignment*/) {
	FreeGuestAllocation(pointer);
}

void KYTY_SYSV_ABI operator_delete_aligned_nothrow(void* pointer, size_t /*alignment*/, const void*) {
	FreeGuestAllocation(pointer);
}

// posix_memalign(void** memptr, size_t alignment, size_t size): allocate `size` bytes aligned to
// `alignment` (a power of two, multiple of sizeof(void*)), store the pointer in *memptr, return 0;
// on failure return the errno (EINVAL/ENOMEM) WITHOUT touching *memptr. NID cVSk9y8URbc. SceSysCore's
// registry/boot paths call this and immediately write through *memptr, so an unresolved stub (which
// left *memptr uninitialised) caused a null/garbage write crash — the recurring uninit-out trap.
int KYTY_SYSV_ABI libc_posix_memalign(void** memptr, size_t alignment, size_t size) {
	if (memptr == nullptr) {
		return Posix::POSIX_EINVAL;
	}
	// alignment must be a power of two and a multiple of sizeof(void*).
	if (alignment < sizeof(void*) || (alignment & (alignment - 1)) != 0) {
		return Posix::POSIX_EINVAL;
	}
	void* p = libc_memalign(alignment, size);
	if (p == nullptr) {
		return Posix::POSIX_ENOMEM;
	}
	*memptr = p;
	return 0;
}

// perror(const char* msg): print `msg: <errno string>` to stderr. We just log it. NID EMutwaQ34Jo.
void KYTY_SYSV_ABI libc_perror(const char* msg) {
	LOGF("perror: %s\n", (msg != nullptr) ? msg : "(null)");
}

// strsep(char** stringp, const char* delim): extract the next token from *stringp up to any delim
// char, NUL-terminate it in place, advance *stringp past the delimiter, return the token (or the
// remainder). Returns nullptr when *stringp is nullptr. NID cJWGxiQPmDQ. Standard BSD semantics.
char* KYTY_SYSV_ABI libc_strsep(char** stringp, const char* delim) {
	if (stringp == nullptr || *stringp == nullptr) {
		return nullptr;
	}
	char* start = *stringp;
	char* s     = start;
	for (;;) {
		char c = *s++;
		if (delim != nullptr) {
			for (const char* d = delim; *d != '\0'; ++d) {
				if (c == *d) {
					if (c == '\0') {
						*stringp = nullptr;
					} else {
						s[-1]    = '\0';
						*stringp = s;
					}
					return start;
				}
			}
		}
		if (c == '\0') {
			*stringp = nullptr;
			return start;
		}
	}
}

// malloc_usable_size(void* ptr): the actual usable capacity of a block from the plain malloc family
// The JSCd libreSsl/redis allocators query this to size in-place growth. Both
// ordinary and aligned guest blocks report their actual usable size. NID NDcSfcYZRC8.
size_t KYTY_SYSV_ABI libc_malloc_usable_size(void* ptr) {
	if (ptr == nullptr) {
		return 0;
	}
	{
		std::lock_guard<std::mutex> lock(g_aligned_allocation_mutex);
		if (auto it = g_aligned_allocations.find(ptr); it != g_aligned_allocations.end()) {
			return it->second.second;
		}
	}
	if (auto size = GuestHeapSize(ptr); size != 0) { return size; }
#if defined(_WIN32)
	return _msize(ptr);
#else
	return malloc_usable_size(ptr);
#endif
}

// strerror(int errnum): the JSCd error paths strerror(errno) then strlen/print the result, so it
// MUST return a non-null C-string (the unresolved stub returned NULL -> guest null-deref crash).
// NID RIa6GnWp+iU. Guest errno numbers differ from the host's, so return a stable generic message.
const char* KYTY_SYSV_ABI libc_strerror(int errnum) {
	static thread_local char buf[64];
	std::snprintf(buf, sizeof(buf), "Unknown error %d", errnum);
	return buf;
}

// BSD strlcpy(dst, src, size): size-bounded copy, always NUL-terminates (unless size==0), returns
// strlen(src). NID SfQIZcqvvms. Used across the vsh/ShellCore code for safe string handling.
size_t KYTY_SYSV_ABI libc_strlcpy(char* dst, const char* src, size_t size) {
	const char* s = (src != nullptr) ? src : "";
	size_t srclen = std::strlen(s);
	if (size != 0 && dst != nullptr) {
		size_t n = (srclen < size - 1) ? srclen : size - 1;
		std::memcpy(dst, s, n);
		dst[n] = '\0';
	}
	return srclen;
}

// rand/srand retain their own state; BSD random/srandom use a separate generator.
static std::atomic<uint32_t> g_rand_state{1};
static uint32_t RandNext() {
	uint32_t x = g_rand_state.load(std::memory_order_relaxed);
	x = x * 1103515245u + 12345u;
	g_rand_state.store(x, std::memory_order_relaxed);
	return (x >> 16) & 0x7fffu; // RAND_MAX = 0x7fff
}
int KYTY_SYSV_ABI libc_rand() { return static_cast<int>(RandNext()); }
void KYTY_SYSV_ABI libc_srand(unsigned int seed) { g_rand_state.store(seed ? seed : 1, std::memory_order_relaxed); }
// FW7 LibcInternal random: 31-word additive feedback, separation 3, 31-bit
// output. The initial state below is the native library's default seed state.
static std::mutex g_random_mutex;
static std::array<uint32_t, 31> g_random_state {
	2568305073u, 379960547u, 1735697613u, 1040273694u, 1313901226u, 1627687941u,
	4115662359u, 2221633813u, 1780058412u, 2305464239u, 3678992694u, 344556628u,
	939512070u, 3045851036u, 1507946756u, 3482421833u, 154635395u, 1388815473u,
	2368290473u, 525320961u, 3285938622u, 968117788u, 4171517689u, 1284210865u,
	435012392u, 2277460957u, 3383902437u, 3924708123u, 1132637927u, 1398500161u,
	4089365978u};
static size_t g_random_front = 3;
static size_t g_random_rear = 0;
static uint32_t RandomNextLocked() {
	const auto sum = g_random_state[g_random_front] + g_random_state[g_random_rear];
	g_random_state[g_random_front] = sum;
	g_random_front = (g_random_front + 1) % g_random_state.size();
	g_random_rear = (g_random_rear + 1) % g_random_state.size();
	return sum >> 1;
}
int64_t KYTY_SYSV_ABI libc_random() {
	std::lock_guard lock(g_random_mutex);
	return RandomNextLocked();
}
void KYTY_SYSV_ABI libc_srandom(unsigned int seed) {
	std::lock_guard lock(g_random_mutex);
	g_random_state[0] = seed;
	int32_t word = std::bit_cast<int32_t>(seed);
	for (size_t i = 1; i < g_random_state.size(); ++i) {
		if (word == 0) { word = 123459876; }
		int64_t next = 16807ll * (word % 127773) - 2836ll * (word / 127773);
		if (next < 0) { next += 0x7fffffff; }
		word = static_cast<int32_t>(next);
		g_random_state[i] = static_cast<uint32_t>(word);
	}
	g_random_front = 3;
	g_random_rear = 0;
	for (size_t i = 0; i < 10 * g_random_state.size(); ++i) { RandomNextLocked(); }
}
int KYTY_SYSV_ABI libc_isnanf(float value) {
	const auto bits = std::bit_cast<uint32_t>(value);
	return (bits & 0x7f800000u) == 0x7f800000u && (bits & 0x007fffffu) != 0;
}
int KYTY_SYSV_ABI libc_isinff(float value) {
	return (std::bit_cast<uint32_t>(value) & 0x7fffffffu) == 0x7f800000u;
}
// std::random_device: return a full 32-bit nondeterministic-ish value (mix the LCG with the clock).
unsigned int KYTY_SYSV_ABI libc_random_device() {
	uint32_t t = static_cast<uint32_t>(
	    std::chrono::steady_clock::now().time_since_epoch().count());
	return (RandNext() << 17) ^ (RandNext() << 2) ^ t;
}

// Guest sscanf (NID 1Pk0qZQGeWo). Previously unresolved -> a no-op that left the caller's output
// variables UNINITIALISED; SceShellCore uses those as sizes/indices, which leads to out-of-bounds
// heap writes. Implement a real parser over Kyty's guest-varargs infra. Supports whitespace, literal
// match, %d/%i/%u/%o/%x, length mods (hh/h/l/ll), %f/%e/%g, %s, %c, %n,
// scansets (including the SVG viewBox separator format), string widths, and '*' suppression.
static int kyty_sscanf_internal(const char* str, const char* fmt, VaList* va) {
	if (str == nullptr || fmt == nullptr) {
		return -1;
	}
	const char* s        = str;
	const char* f        = fmt;
	int         assigned = 0;
	auto        is_ws    = [](char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'; };
	while (*f != '\0') {
		if (is_ws(*f)) {
			while (is_ws(*s)) s++;
			f++;
			continue;
		}
		if (*f != '%') {
			if (*s != *f) break;
			s++;
			f++;
			continue;
		}
		f++; // consume '%'
		if (*f == '%') {
			if (*s != '%') break;
			s++;
			f++;
			continue;
		}
		bool suppress = false;
		if (*f == '*') {
			suppress = true;
			f++;
		}
		int  width     = 0;
		bool has_width = false;
		while (*f >= '0' && *f <= '9') {
			width = width * 10 + (*f - '0');
			f++;
			has_width = true;
		}
		int lenmod = 0; // 0=int 1=long 2=longlong 3=short 4=char
		while (*f == 'l' || *f == 'h' || *f == 'j' || *f == 'z' || *f == 't' || *f == 'L') {
			if (*f == 'l') lenmod = (lenmod == 1 ? 2 : 1);
			else if (*f == 'h') lenmod = (lenmod == 3 ? 4 : 3);
			f++;
		}
		const char conv = *f;
		if (conv == '\0') break;
		f++;
		if (conv == 'n') { // chars consumed so far; not counted as an assignment
			if (!suppress) *VaArg_ptr<int>(va) = static_cast<int>(s - str);
			continue;
		}
		if (conv == 'c') {
			const int cnt = has_width ? width : 1;
			char*     out = suppress ? nullptr : VaArg_ptr<char>(va);
			int       i   = 0;
			for (; i < cnt && *s != '\0'; i++, s++) {
				if (out != nullptr) out[i] = *s;
			}
			if (i < cnt) break; // not enough input
			if (!suppress) assigned++;
			continue;
		}
		if (conv == 's') {
			while (is_ws(*s)) s++;
			if (*s == '\0') break;
			char* out = suppress ? nullptr : VaArg_ptr<char>(va);
			int   n   = 0;
			while (*s != '\0' && !is_ws(*s) && (!has_width || n < width)) {
				if (out != nullptr) out[n] = *s;
				s++;
				n++;
			}
			if (out != nullptr) out[n] = '\0';
			if (!suppress) assigned++;
			continue;
		}
		if (conv == '[') {
			// Unlike %s, a scanset does not skip leading input whitespace. The firmware
			// uses %*[%%, \t] between viewBox coordinates; '%' is literal inside a set.
			bool members[256] = {};
			const bool negate = *f == '^';
			if (negate) f++;
			if (*f == ']') {
				members[static_cast<unsigned char>(*f++)] = true;
			}
			while (*f != '\0' && *f != ']') {
				const auto first = static_cast<unsigned char>(*f++);
				if (*f == '-' && f[1] != '\0' && f[1] != ']' &&
				    first <= static_cast<unsigned char>(f[1])) {
					f++;
					const auto last = static_cast<unsigned char>(*f++);
					for (unsigned value = first; value <= last; value++) members[value] = true;
				} else {
					members[first] = true;
				}
			}
			if (*f != ']') return assigned;
			f++;
			const char* begin = s;
			int n = 0;
			while (*s != '\0' && (!has_width || n < width) &&
			       members[static_cast<unsigned char>(*s)] != negate) {
				s++;
				n++;
			}
			if (n == 0) break;
			if (!suppress) {
				char* out = VaArg_ptr<char>(va);
				std::memcpy(out, begin, static_cast<size_t>(n));
				out[n] = '\0';
				assigned++;
			}
			continue;
		}
		// numeric conversions
		while (is_ws(*s)) s++;
		char* end = nullptr;
		if (conv == 'f' || conv == 'e' || conv == 'g' || conv == 'F' || conv == 'E' || conv == 'G' ||
		    conv == 'a') {
			double v = std::strtod(s, &end);
			if (end == s) break;
			if (!suppress) {
				if (lenmod >= 1) *VaArg_ptr<double>(va) = v;
				else *VaArg_ptr<float>(va) = static_cast<float>(v);
			}
			s = end;
			if (!suppress) assigned++;
			continue;
		}
		int base = 10;
		bool is_unsigned = false;
		switch (conv) {
			case 'd':
			case 'i': base = (conv == 'i' ? 0 : 10); break;
			case 'u': base = 10; is_unsigned = true; break;
			case 'o': base = 8; is_unsigned = true; break;
			case 'x':
			case 'X': base = 16; is_unsigned = true; break;
			case 'p': base = 16; is_unsigned = true; lenmod = 2; break;
			default: return assigned; // unknown conversion
		}
		unsigned long long uv = 0;
		long long          sv = 0;
		if (is_unsigned) uv = std::strtoull(s, &end, base);
		else sv = std::strtoll(s, &end, base);
		if (end == s) break;
		if (!suppress) {
			void* p = VaArg_ptr<void>(va);
			switch (lenmod) {
				case 4: *reinterpret_cast<int8_t*>(p)  = static_cast<int8_t>(is_unsigned ? (long long)uv : sv); break;
				case 3: *reinterpret_cast<int16_t*>(p) = static_cast<int16_t>(is_unsigned ? (long long)uv : sv); break;
				case 1:
				case 2: *reinterpret_cast<int64_t*>(p) = static_cast<int64_t>(is_unsigned ? (long long)uv : sv); break;
				default: *reinterpret_cast<int32_t*>(p) = static_cast<int32_t>(is_unsigned ? (long long)uv : sv); break;
			}
		}
		s = end;
		if (!suppress) assigned++;
	}
	return assigned;
}
static int KYTY_SYSV_ABI kyty_sscanf_std(VA_ARGS) {
	VA_CONTEXT(ctx); // NOLINT
	const char* str = VaArg_ptr<const char>(&ctx.va_list);
	const char* fmt = VaArg_ptr<const char>(&ctx.va_list);
	return kyty_sscanf_internal(str, fmt, &ctx.va_list);
}



// Dinkumware _Thrd_result codes: success, nomem, timedout, busy, error.
enum { KMtxSuccess = 0, KThrdTimedout = 2, KMtxBusy = 3, KMtxError = 4 };

struct GuestXtime {
	int64_t sec;
	int64_t nsec;
};

// The C11-thread (_Mtx_*/_Cnd_*) family libSceLibcInternal exports is, on the real firmware, a thin
// shim over the ScePthread mutex/cond API: the _Mtx_t / _Cnd_t the guest embeds inline inside
// std::mutex / std::condition_variable IS a ScePthreadMutex / ScePthreadCond handle slot, and every
// _Mtx_*/_Cnd_* call receives a POINTER to that slot. Verified against libSceLibcInternal
// (_Mtx_init_with_name -> scePthreadMutexInit(&slot,...), _Mtx_lock -> scePthreadMutexLock(&slot),
// _Cnd_wait -> scePthreadCondWait(&slot,&mslot)). So forward straight to KytyPS5's own pthread
// implementation, which owns the handle stored in the slot. (The previous reimplementation treated
// the slot pointer itself as the handle — an off-by-one indirection that corrupted the object and
// crashed worker threads inside condition_variable waits.)

static int MapThrd(int r) {
	return (r == 0) ? KMtxSuccess : KMtxError;
}

int KYTY_SYSV_ABI Mtx_init_with_name(void* mtx, int type, const char* name) {
	if (mtx == nullptr) {
		return KMtxError;
	}
	auto* m = static_cast<LibKernel::PthreadMutex*>(mtx);
	*m      = nullptr;
	LibKernel::PthreadMutexattr attr = nullptr;
	if (LibKernel::PthreadMutexattrInit(&attr) != 0) {
		return KMtxError;
	}
	if ((type & 0x104) != 0) {
		LibKernel::PthreadMutexattrSettype(&attr, 2); // PTHREAD_MUTEX_RECURSIVE
	}
	const int r = LibKernel::PthreadMutexInit(m, &attr, name);
	LibKernel::PthreadMutexattrDestroy(&attr);
	return MapThrd(r);
}

int KYTY_SYSV_ABI Mtx_init(void* mtx, int type) {
	return Mtx_init_with_name(mtx, type, nullptr);
}

int KYTY_SYSV_ABI Mtx_destroy(void* mtx) {
	return MapThrd(LibKernel::PthreadMutexDestroy(static_cast<LibKernel::PthreadMutex*>(mtx)));
}

int KYTY_SYSV_ABI Mtx_lock(void* mtx) {
	return MapThrd(LibKernel::PthreadMutexLock(static_cast<LibKernel::PthreadMutex*>(mtx)));
}

int KYTY_SYSV_ABI Mtx_unlock(void* mtx) {
	return MapThrd(LibKernel::PthreadMutexUnlock(static_cast<LibKernel::PthreadMutex*>(mtx)));
}

int KYTY_SYSV_ABI Mtx_trylock(void* mtx) {
	const int r = LibKernel::PthreadMutexTrylock(static_cast<LibKernel::PthreadMutex*>(mtx));
	return (r == 0) ? KMtxSuccess : KMtxBusy;
}

int KYTY_SYSV_ABI Cnd_init_with_name(void* cnd, const char* name) {
	if (cnd == nullptr) {
		return KMtxError;
	}
	auto* c = static_cast<LibKernel::PthreadCond*>(cnd);
	*c      = nullptr;
	return MapThrd(LibKernel::PthreadCondInit(c, nullptr, name));
}

int KYTY_SYSV_ABI Cnd_init(void* cnd) {
	return Cnd_init_with_name(cnd, nullptr);
}

int KYTY_SYSV_ABI Cnd_destroy(void* cnd) {
	return MapThrd(LibKernel::PthreadCondDestroy(static_cast<LibKernel::PthreadCond*>(cnd)));
}

int KYTY_SYSV_ABI Cnd_signal(void* cnd) {
	return MapThrd(LibKernel::PthreadCondSignal(static_cast<LibKernel::PthreadCond*>(cnd)));
}

int KYTY_SYSV_ABI Cnd_broadcast(void* cnd) {
	return MapThrd(LibKernel::PthreadCondBroadcast(static_cast<LibKernel::PthreadCond*>(cnd)));
}

int KYTY_SYSV_ABI Cnd_wait(void* cnd, void* mtx) {
	return MapThrd(LibKernel::PthreadCondWait(static_cast<LibKernel::PthreadCond*>(cnd),
	                                          static_cast<LibKernel::PthreadMutex*>(mtx)));
}

int KYTY_SYSV_ABI Cnd_timedwait(void* cnd, void* mtx, const GuestXtime* abstime) {
	auto* c = static_cast<LibKernel::PthreadCond*>(cnd);
	auto* m = static_cast<LibKernel::PthreadMutex*>(mtx);
	if (abstime == nullptr) {
		return MapThrd(LibKernel::PthreadCondWait(c, m));
	}
	LibKernel::KernelTimespec ts {};
	ts.tv_sec  = abstime->sec;
	ts.tv_nsec = abstime->nsec;
	const int r = LibKernel::PthreadCondTimedwaitAbs(c, m, &ts);
	return (r == 0) ? KMtxSuccess : KThrdTimedout; // caller re-checks its predicate on wake
}

uint32_t KYTY_SYSV_ABI Atomic_fetch_sub_4(volatile uint32_t* target, uint32_t value, int /*order*/) {
	EXIT_NOT_IMPLEMENTED(target == nullptr);
	std::atomic_ref<uint32_t> ref(*const_cast<uint32_t*>(target));
	return ref.fetch_sub(value);
}

int KYTY_SYSV_ABI bcmp(const void* a, const void* b, size_t n) {
	if (n == 0) {
		return 0;
	}
	return std::memcmp(a, b, n);
}

void* KYTY_SYSV_ABI memchr(const void* s, int c, size_t n) {
	return const_cast<void*>(std::memchr(s, c, n));
}

// ---- Dinkumware std::thread launch shim (std::_Pad) ----
// std::thread starts a thread via a heap _LaunchPad<Callable> deriving from _Pad. The base _Pad
// (which libSceLibcInternal owns) provides the create/handshake plumbing; the derived _Go()
// (guest code, vtable slot 0) copies the callable, calls _Release() to let the launcher return,
// then invokes it. Layout: vptr@0x00, our sync handle@0x08; the derived callable lives at 0x20.
struct PadSync {
	std::mutex              m;
	std::condition_variable cv;
	bool                    started = false;
};

static void* KYTY_SYSV_ABI PadThreadEntry(void* pad) {
	auto* self   = static_cast<void* const*>(pad);
	auto* vtable = static_cast<void* const*>(self[0]);
	auto  go     = reinterpret_cast<void(KYTY_SYSV_ABI*)(void*)>(vtable[0]); // _Go
	go(pad);
	return nullptr;
}

void KYTY_SYSV_ABI Pad_ctor(void** self) {
	self[1] = new PadSync; // 0x08: sync handle
	self[2] = nullptr;     // 0x10
	self[3] = nullptr;     // 0x18
}

// std::_Pad::_Pad(const char* name) — the NAMED _Pad constructor (NID uhnb6dnXOnc). SceShellCore
// creates named std::threads via this overload; it was unresolved, so self[1] (the PadSync handle)
// was left UNINITIALISED and Pad_dtor's `delete self[1]` freed a garbage pointer -> heap corruption
// (Pad_dtor kept showing up in the crash). Same as Pad_ctor; the name is only a thread label.
void KYTY_SYSV_ABI Pad_ctor_named(void** self, const char* name) {
	(void)name;
	self[1] = new PadSync;
	self[2] = nullptr;
	self[3] = nullptr;
}

void KYTY_SYSV_ABI Pad_dtor(void** self) {
	delete static_cast<PadSync*>(self[1]);
}

void KYTY_SYSV_ABI Pad_Release(void** self) {
	auto* sync = static_cast<PadSync*>(self[1]);
	EXIT_NOT_IMPLEMENTED(sync == nullptr);
	{
		std::lock_guard<std::mutex> lock(sync->m);
		sync->started = true;
	}
	sync->cv.notify_all();
}

void KYTY_SYSV_ABI Pad_Launch(void** self, LibKernel::Pthread* out_thread) {
	auto* sync = static_cast<PadSync*>(self[1]);
	EXIT_NOT_IMPLEMENTED(sync == nullptr);
	LibKernel::Pthread thread = nullptr;
	LibKernel::PthreadCreate(&thread, nullptr, &PadThreadEntry, self, "std::thread");
	if (out_thread != nullptr) {
		*out_thread = thread;
	}
	// Block until _Go has taken ownership of the callable (via _Release) so the caller may safely
	// destroy the stack-resident _Pad.
	std::unique_lock<std::mutex> lock(sync->m);
	sync->cv.wait(lock, [sync] { return sync->started; });
}

// std::_Pad::_Launch(const char* name, pthread** out) — NAMED launch overload (NID PBbZjsL6nfc).
// Same handshake as Pad_Launch; the name becomes the guest thread label.
void KYTY_SYSV_ABI Pad_Launch_named(void** self, const char* name, LibKernel::Pthread* out_thread) {
	auto* sync = static_cast<PadSync*>(self[1]);
	EXIT_NOT_IMPLEMENTED(sync == nullptr);
	LibKernel::Pthread thread = nullptr;
	LibKernel::PthreadCreate(&thread, nullptr, &PadThreadEntry, self,
	                         (name != nullptr) ? name : "std::thread");
	if (out_thread != nullptr) {
		*out_thread = thread;
	}
	std::unique_lock<std::mutex> lock(sync->m);
	sync->cv.wait(lock, [sync] { return sync->started; });
}

// std::_Pad::_Launch(const char* name, pthread_attr** attr, pthread** out) — the attr-taking
// launch overload (NID H7-7Z3ixv-w = _ZNSt4_Pad7_LaunchEPKcPP12pthread_attrPP7pthread).
// SceShellCore uses it for threads with a custom stack size / priority. Same handshake as the
// other overloads; forward the caller's attribute handle (*attr) to PthreadCreate so the guest's
// stack-size/priority request is honoured. Was unresolved -> the launch returned without starting
// the thread and without the _Release handshake, so the callable was never run (and the stack
// _Pad could be destroyed while still referenced).
void KYTY_SYSV_ABI Pad_Launch_attr(void** self, const char* name, LibKernel::PthreadAttr* attr,
                                   LibKernel::Pthread* out_thread) {
	auto* sync = static_cast<PadSync*>(self[1]);
	EXIT_NOT_IMPLEMENTED(sync == nullptr);
	LibKernel::Pthread     thread    = nullptr;
	LibKernel::PthreadAttr attr_copy = (attr != nullptr) ? *attr : nullptr;
	LibKernel::PthreadCreate(&thread, (attr_copy != nullptr) ? &attr_copy : nullptr, &PadThreadEntry,
	                         self, (name != nullptr) ? name : "std::thread");
	if (out_thread != nullptr) {
		*out_thread = thread;
	}
	std::unique_lock<std::mutex> lock(sync->m);
	sync->cv.wait(lock, [sync] { return sync->started; });
}

// putchar(int c): write one character to guest stdout. Route through the guest printf sink so it
// lands with the rest of the guest's output. NID m5wN+SwZOR4.
static int KYTY_SYSV_ABI putchar(int c) {
	GetGuestPrintfStdFunc()("%c", c);
	return c;
}

// vsnprintf(char* s, size_t n, const char* fmt, va_list ap): bounded formatted write driven by an
// already-initialised guest va_list. Reuses the guest formatter (same engine as snprintf/vprintf).
// NID Q2V+iqvjgC0 — heavily used by SceShellCore's own string formatting.
static int KYTY_SYSV_ABI vsnprintf(char* s, size_t n, const char* fmt, VaList* ap) {
	return GetGuestVsnprintfFunc()(s, n, fmt, ap);
}

// strnlen(s, maxlen): bounded string length. NID 5jNubw4vlAA.
static size_t KYTY_SYSV_ABI strnlen(const char* s, size_t maxlen) {
	if (s == nullptr) {
		return 0;
	}
	size_t i = 0;
	while (i < maxlen && s[i] != '\0') {
		i++;
	}
	return i;
}

// qsort(base, nmemb, size, cmp): the comparator is a GUEST function pointer, so it must be invoked
// through the SysV ABI — the host CRT ::qsort would call it with the wrong (MS x64) convention on
// Windows. Sort an index permutation with the guest comparator, then materialise it, so we never
// pass a SysV callback into host code. NID AEJdIVZTEmo.
using qsort_cmp_t = int(KYTY_SYSV_ABI*)(const void*, const void*);
static void* KYTY_SYSV_ABI bsearch(const void* key, const void* base, size_t count,
                                  size_t size, qsort_cmp_t compare) {
	if (base == nullptr || count == 0 || size == 0 || compare == nullptr) {
		return nullptr;
	}
	const auto* first = static_cast<const uint8_t*>(base);
	while (count != 0) {
		const size_t half = count / 2;
		const auto* element = first + half * size;
		// Font table lookups pass a guest comparator. The host CRT would invoke
		// it with the Windows ABI instead of the console's SysV ABI.
		const int order = compare(key, element);
		if (order == 0) {
			return const_cast<uint8_t*>(element);
		}
		if (order > 0) {
			first = element + size;
			count -= half + 1;
		} else {
			count = half;
		}
	}
	return nullptr;
}

static void KYTY_SYSV_ABI qsort(void* base, size_t nmemb, size_t size, qsort_cmp_t cmp) {
	if (base == nullptr || nmemb < 2 || size == 0 || cmp == nullptr) {
		return;
	}
	auto*               b = static_cast<uint8_t*>(base);
	std::vector<size_t> idx(nmemb);
	for (size_t i = 0; i < nmemb; i++) {
		idx[i] = i;
	}
	// stable_sort keeps qsort's "equal elements retain relative order" behaviour that some callers
	// (metadata list builders) lean on, and never invokes cmp on a partially-moved element.
	std::stable_sort(idx.begin(), idx.end(),
	                 [&](size_t x, size_t y) { return cmp(b + x * size, b + y * size) < 0; });
	std::vector<uint8_t> tmp(nmemb * size);
	for (size_t i = 0; i < nmemb; i++) {
		std::memcpy(tmp.data() + i * size, b + idx[i] * size, size);
	}
	std::memcpy(b, tmp.data(), nmemb * size);
}

// operator new(size_t, const std::nothrow_t&): non-throwing allocation; return nullptr on failure
// rather than throwing. Shares the guest heap with operator_new. NID ryUxD-60bKM.
static void* KYTY_SYSV_ABI operator_new_nothrow(size_t size, const void* /*nothrow_tag*/) {
	return AllocateGuestHeap(size);
}
//
// A std::locale holds a pointer to a reference-counted _Locimp (facet map).
// The _Locimp begins with a locale::facet whose vtable is
// { destroy, delete, retain, release }. Guest code obtains the global/classic
// locale via _Getgloballocale()/_Init() and then adjusts its refcount by
// calling retain (vtable +0x10) / release (vtable +0x18) through that vtable
// (see the ShellUI static initializer at eboot 0x7456). Layout and refcount
// semantics mirror the AnyPS5 libc reimplementation.
// ---------------------------------------------------------------------------

struct LocaleFacet;

struct LocaleFacetVtable {
	void (KYTY_SYSV_ABI* destroy)(LocaleFacet* self);
	void (KYTY_SYSV_ABI* delete_object)(LocaleFacet* self);
	void (KYTY_SYSV_ABI* retain)(LocaleFacet* self);
	LocaleFacet* (KYTY_SYSV_ABI* release)(LocaleFacet* self);
};

struct LocaleFacet {
	const LocaleFacetVtable* vtable;
	uint32_t                 references;
	uint32_t                 reserved;
};

struct LocaleImpl {
	LocaleFacet   base;
	LocaleFacet** facets;
	uint64_t      facet_count;
	uint32_t      category;
	bool          transparent;
	const char*   name;
};

static void KYTY_SYSV_ABI LocaleDestroyClassic(LocaleFacet* /*self*/) {
	// The classic locale is immortal and must never be destroyed.
	EXIT_NOT_IMPLEMENTED(true);
}

static void KYTY_SYSV_ABI LocaleRetainClassic(LocaleFacet* self) {
	EXIT_NOT_IMPLEMENTED(self == nullptr);
	std::atomic_ref<uint32_t> references(self->references);
	auto                      count = references.load();
	do {
		EXIT_NOT_IMPLEMENTED(count == 0 || count == 0xFFFFFFFFu);
	} while (!references.compare_exchange_weak(count, count + 1));
}

static LocaleFacet* KYTY_SYSV_ABI LocaleReleaseClassic(LocaleFacet* self) {
	EXIT_NOT_IMPLEMENTED(self == nullptr);
	std::atomic_ref<uint32_t> references(self->references);
	auto                      count = references.load();
	// Classic locale is immortal: a release that would drop the last reference keeps it.
	do {
		if (count <= 1) {
			return nullptr;
		}
	} while (!references.compare_exchange_weak(count, count - 1));
	return nullptr;
}

static const LocaleFacetVtable g_locale_classic_vtable {LocaleDestroyClassic, LocaleDestroyClassic, LocaleRetainClassic,
                                                        LocaleReleaseClassic};
static LocaleFacet*            g_locale_classic_facets[1] {};
static LocaleImpl              g_locale_classic {{&g_locale_classic_vtable, 1, 0}, g_locale_classic_facets, 1, 0, false, "C"};

// Exported guest object std::_sceLibcClassicLocale: a pointer variable holding the _Locimp*.
// The guest imports its address (a LocaleImpl**) and double-dereferences to reach the _Locimp vtable.
static LocaleImpl* g_locale_classic_ptr = &g_locale_classic;

// Dinkumware static locale::_Init(bool) returns the global _Locimp; the caller copies it.
LocaleImpl* KYTY_SYSV_ABI locale_Init() {
	return &g_locale_classic;
}

LocaleImpl* KYTY_SYSV_ABI locale_Getgloballocale() {
	return &g_locale_classic;
}

// ---- Dinkumware ctype tables and locale/runtime helpers (classic "C" locale only) ----

// Dinkumware ctype tables are indexed [-1 .. 255]; slot 0 holds the EOF entry and the
// exported pointer is biased by +1 so that ptr[-1] addresses it.
static constexpr std::array<int16_t, 257> MakeClassificationTable() {
	std::array<int16_t, 257> table {};
	for (unsigned int value = 0; value < 256; ++value) {
		int16_t mask = 0;
		if (value < 32 || value == 127) { mask |= 0x80; }
		if (value == ' ') { mask |= 0x04; }
		if (value >= '\t' && value <= '\r') { mask |= 0x40; }
		if (value >= 'A' && value <= 'Z') { mask |= 0x02; }
		if (value >= 'a' && value <= 'z') { mask |= 0x10; }
		if (value >= '0' && value <= '9') { mask |= 0x20; }
		if ((value >= '0' && value <= '9') || (value >= 'A' && value <= 'F') || (value >= 'a' && value <= 'f')) { mask |= 0x01; }
		if (value >= 33 && value <= 126 && (mask & 0x232) == 0) { mask |= 0x08; }
		table[value + 1] = mask;
	}
	return table;
}

static constexpr std::array<int16_t, 257> MakeCaseTable(bool upper) {
	std::array<int16_t, 257> table {};
	table[0] = -1;
	for (unsigned int value = 0; value < 256; ++value) {
		auto converted = value;
		if (upper && value >= 'a' && value <= 'z') { converted -= 'a' - 'A'; }
		if (!upper && value >= 'A' && value <= 'Z') { converted += 'a' - 'A'; }
		table[value + 1] = static_cast<int16_t>(converted);
	}
	return table;
}

static constexpr auto g_ctype_classify_table = MakeClassificationTable();
static constexpr auto g_ctype_lower_table    = MakeCaseTable(false);
static constexpr auto g_ctype_upper_table    = MakeCaseTable(true);

const int16_t* KYTY_SYSV_ABI locale_Getpctype() {
	return g_ctype_classify_table.data() + 1;
}

const int16_t* KYTY_SYSV_ABI locale_Getptolower() {
	return g_ctype_lower_table.data() + 1;
}

const int16_t* KYTY_SYSV_ABI locale_Getptoupper() {
	return g_ctype_upper_table.data() + 1;
}

// std::locale::facet::_Register() — facets self-manage their lifetime here, so this is a no-op guard.
void KYTY_SYSV_ABI locale_facet_Register(LocaleFacet* self) {
	EXIT_NOT_IMPLEMENTED(self == nullptr);
}

// std::_Locinfo storage is a 64-byte POD block; only the classic "C" locale is supported.
struct LocinfoStorage {
	alignas(uint64_t) unsigned char bytes[64];
};

void KYTY_SYSV_ABI locale_Locinfo_ctor(LocinfoStorage* self, const char* name) {
	EXIT_NOT_IMPLEMENTED(self == nullptr);
	EXIT_NOT_IMPLEMENTED(name != nullptr && std::strcmp(name, "C") != 0 && std::strcmp(name, "") != 0);
	std::memset(self, 0, sizeof(LocinfoStorage));
}

void KYTY_SYSV_ABI locale_Locinfo_dtor(LocinfoStorage* self) {
	EXIT_NOT_IMPLEMENTED(self == nullptr);
}

// _Locksyslock/_Unlocksyslock: a single recursive lock covers every syslock category.
static std::recursive_mutex g_syslock;

void KYTY_SYSV_ABI Locksyslock(int /*type*/) {
	g_syslock.lock();
}

void KYTY_SYSV_ABI Unlocksyslock(int /*type*/) {
	g_syslock.unlock();
}

uint32_t KYTY_SYSV_ABI Atomic_fetch_add_4(volatile uint32_t* target, uint32_t value, int /*order*/) {
	EXIT_NOT_IMPLEMENTED(target == nullptr);
	std::atomic_ref<uint32_t> ref(*const_cast<uint32_t*>(target));
	return ref.fetch_add(value);
}

// _Atomic_load_4(const volatile _Uint4_t* obj, int order): atomic 32-bit load. Critical — the
// Dinkumware runtime reads shared_ptr/exception/thread refcounts through this; an unresolved stub
// returned 0 for every load, corrupting refcount logic and crashing worker threads mid-unwind.
uint32_t KYTY_SYSV_ABI Atomic_load_4(const volatile uint32_t* obj, int /*order*/) {
	EXIT_NOT_IMPLEMENTED(obj == nullptr);
	std::atomic_ref<uint32_t> ref(*const_cast<uint32_t*>(obj));
	return ref.load();
}

// _Atomic_store_4(volatile _Uint4_t* obj, _Uint4_t value, int order): atomic 32-bit store.
void KYTY_SYSV_ABI Atomic_store_4(volatile uint32_t* obj, uint32_t value, int /*order*/) {
	EXIT_NOT_IMPLEMENTED(obj == nullptr);
	std::atomic_ref<uint32_t> ref(*const_cast<uint32_t*>(obj));
	ref.store(value);
}

// std::terminate(): must NOT return. The guest calls it on unrecoverable C++ errors; an unresolved
// stub returned 0 and execution ran on into garbage. Route to the host terminate path.
[[noreturn]] void KYTY_SYSV_ABI StdTerminate() {
	PRINT_NAME();
	std::terminate();
}

[[noreturn]] void KYTY_SYSV_ABI PureVirtual() {
	LOGF_COLOR(Log::Color::Red, "Guest __cxa_pure_virtual: call through an abstract C++ vtable\n");
	StdTerminate();
}

// _Thrd_sleep(const xtime* target, xtime* remaining): the daemon's main loop sleeps to an ABSOLUTE
// xtime (sec/nsec since epoch) each tick — reversed from libSceLibcInternal (xtime_get + diff +
// nanosleep). Sleep the remaining delta.
void KYTY_SYSV_ABI Thrd_sleep(const GuestXtime* target, GuestXtime* /*remaining*/) {
	if (target == nullptr) {
		return;
	}
	const auto    now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
	const int64_t tgt_ns = target->sec * 1000000000LL + target->nsec;
	const int64_t diff   = tgt_ns - static_cast<int64_t>(now_ns);
	if (diff > 0) {
		std::this_thread::sleep_for(std::chrono::nanoseconds(diff));
	}
}

// _Xtime_get_ticks(): reversed as `gettimeofday -> tv_usec + 1000000*tv_sec`, i.e. current time in
// MICROSECONDS. Used for timing/timeouts throughout the runtime.
int64_t KYTY_SYSV_ABI Xtime_get_ticks() {
	return std::chrono::duration_cast<std::chrono::microseconds>(
	           std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

// _Atomic_compare_exchange_weak_4(obj, expected, desired, success_order, failure_order).
bool KYTY_SYSV_ABI Atomic_compare_exchange_weak_4(volatile uint32_t* obj, uint32_t* expected, uint32_t desired,
                                                  int /*success*/, int /*failure*/) {
	EXIT_NOT_IMPLEMENTED(obj == nullptr || expected == nullptr);
	std::atomic_ref<uint32_t> ref(*const_cast<uint32_t*>(obj));
	return ref.compare_exchange_weak(*expected, desired);
}

char* KYTY_SYSV_ABI Getenv(const char* name) {
	if (name == nullptr) {
		return nullptr;
	}
	std::lock_guard lock(g_guest_environment_mutex);
	auto& environment = g_guest_environment.try_emplace(Loader::RuntimeLinker::GetCurrentProgram(),
	                                                  Config::GetGuestEnvironment()).first->second;
	auto it = environment.find(name);
	return it == environment.end() ? nullptr : it->second.data();
}

char* KYTY_SYSV_ABI strtok_r(char* text, const char* delimiters, char** saved) {
	if (saved == nullptr || delimiters == nullptr) {
		*Posix::GetErrorAddr() = Posix::POSIX_EINVAL;
		return nullptr;
	}
	if (text == nullptr) {
		text = *saved;
	}
	if (text == nullptr) {
		return nullptr;
	}
	text += std::strspn(text, delimiters);
	if (*text == '\0') {
		*saved = text;
		return nullptr;
	}
	char* end = text + std::strcspn(text, delimiters);
	if (*end != '\0') {
		*end++ = '\0';
	}
	*saved = end;
	return text;
}

int KYTY_SYSV_ABI strcasecmp(const char* left, const char* right) {
	for (;;) {
		const auto a = static_cast<unsigned char>(*left++);
		const auto b = static_cast<unsigned char>(*right++);
		const int folded_a = a >= 'A' && a <= 'Z' ? a + ('a' - 'A') : a;
		const int folded_b = b >= 'A' && b <= 'Z' ? b + ('a' - 'A') : b;
		if (folded_a != folded_b || a == 0) {
			return folded_a - folded_b;
		}
	}
}

struct GuestDirectory {
	int descriptor;
	std::array<char, 4096> entries {};
	size_t position = 0;
	size_t size = 0;
};

GuestDirectory* KYTY_SYSV_ABI opendir(const char* path) {
	int fd = LibKernel::FileSystem::KernelOpen(path, 0x20000, 0);
	if (fd < 0) {
		*Posix::GetErrorAddr() = LibKernel::KernelToPosix(fd);
		return nullptr;
	}
	auto* directory = new (std::nothrow) GuestDirectory {fd};
	if (directory == nullptr) {
		LibKernel::FileSystem::KernelClose(fd);
		*Posix::GetErrorAddr() = Posix::POSIX_ENOMEM;
	}
	return directory;
}

char* KYTY_SYSV_ABI readdir(GuestDirectory* directory) {
	if (directory == nullptr) {
		*Posix::GetErrorAddr() = Posix::POSIX_EBADF;
		return nullptr;
	}
	if (directory->position == directory->size) {
		const auto count = LibKernel::FileSystem::KernelGetdents(
		    directory->descriptor, directory->entries.data(), static_cast<int>(directory->entries.size()));
		if (count <= 0) {
			if (count < 0) {
				*Posix::GetErrorAddr() = LibKernel::KernelToPosix(count);
			}
			return nullptr;
		}
		directory->position = 0;
		directory->size = static_cast<size_t>(count);
	}
	char* entry = directory->entries.data() + directory->position;
	uint16_t length = 0;
	if (directory->size - directory->position >= 8) {
		std::memcpy(&length, entry + 4, sizeof(length));
	}
	if (length < 9 || length > directory->size - directory->position) {
		*Posix::GetErrorAddr() = Posix::POSIX_EIO;
		return nullptr;
	}
	directory->position += length;
	return entry;
}

int KYTY_SYSV_ABI closedir(GuestDirectory* directory) {
	if (directory == nullptr) {
		*Posix::GetErrorAddr() = Posix::POSIX_EBADF;
		return -1;
	}
	const int result = LibKernel::FileSystem::KernelClose(directory->descriptor);
	delete directory;
	if (result != OK) {
		*Posix::GetErrorAddr() = LibKernel::KernelToPosix(result);
		return -1;
	}
	return 0;
}

// _Thrd_id(): current thread handle (reversed as scePthreadSelf()).
LibKernel::Pthread KYTY_SYSV_ABI Thrd_id() {
	return LibKernel::PthreadSelf();
}

// _Thrd_join(thr, res): join a C11 thread, storing its result code. Reversed as pthread_join.
int KYTY_SYSV_ABI Thrd_join(LibKernel::Pthread thr, int* res) {
	void* ret = nullptr;
	LibKernel::PthreadJoin(thr, &ret);
	if (res != nullptr) {
		*res = static_cast<int>(reinterpret_cast<intptr_t>(ret));
	}
	return 0; // _Thrd_success
}

// Itanium exception refcount (reversed from libSceLibcInternal): the reference count is an int64 at
// offset -128 from the thrown object; the destructor pointer is at -112. On the last release we run
// the destructor. We intentionally do NOT free the exception header here (the allocator that
// produced it is not necessarily ours) — leaking a spent exception is safe; freeing across
// allocators is not.
void KYTY_SYSV_ABI Cxa_increment_exception_refcount(void* thrown) {
	if (thrown != nullptr) {
		auto* rc = reinterpret_cast<volatile int64_t*>(reinterpret_cast<char*>(thrown) - 128);
		std::atomic_ref<int64_t> ref(*const_cast<int64_t*>(rc));
		ref.fetch_add(1);
	}
}

void KYTY_SYSV_ABI Cxa_decrement_exception_refcount(void* thrown) {
	if (thrown == nullptr) {
		return;
	}
	auto* rc = reinterpret_cast<volatile int64_t*>(reinterpret_cast<char*>(thrown) - 128);
	std::atomic_ref<int64_t> ref(*const_cast<int64_t*>(rc));
	if (ref.fetch_sub(1) == 1) {
		auto dtor = *reinterpret_cast<void(KYTY_SYSV_ABI**)(void*)>(reinterpret_cast<char*>(thrown) - 112);
		if (dtor != nullptr) {
			dtor(thrown);
		}
	}
}

bool KYTY_SYSV_ABI uncaught_exception() {
	return std::uncaught_exceptions() != 0;
}

// ---- std::num_put<char> facet vtable ----
// Dinkumware facets share the locale::facet management vtable {destroy,delete,retain,release}
// at object-vtable indices 0..3, followed by the do_put virtuals. The guest installs
// (&vtable[2]) as the facet's vptr, so the exported array is biased by two RTTI slots.
static void KYTY_SYSV_ABI FacetDestroy(LocaleFacet* self) {
	EXIT_NOT_IMPLEMENTED(self == nullptr);
}
static void KYTY_SYSV_ABI FacetDelete(LocaleFacet* /*self*/) {
	// Registered facets are immortal for the classic locale; deletion would be a leak-free no-op.
}
static void KYTY_SYSV_ABI FacetRetain(LocaleFacet* self) {
	EXIT_NOT_IMPLEMENTED(self == nullptr);
	std::atomic_ref<uint32_t> references(self->references);
	references.fetch_add(1);
}
static LocaleFacet* KYTY_SYSV_ABI FacetRelease(LocaleFacet* self) {
	EXIT_NOT_IMPLEMENTED(self == nullptr);
	std::atomic_ref<uint32_t> references(self->references);
	auto                      count = references.load();
	while (count > 0 && !references.compare_exchange_weak(count, count - 1)) {
	}
	return nullptr;
}
// std::num_put<char> passes/returns an ostreambuf_iterator by value (two eightbytes: a
// state word and the streambuf pointer). do_put (object-vtable slot 6, exported index 8)
// currently writes nothing and returns the iterator unchanged, keeping the stream in a good
// (non-failed) state; formatted numeric output is not yet emitted into the guest streambuf.
struct GuestOStreamIter {
	uint64_t state;
	uint64_t streambuf;
};

// Dinkumware ios_base::fmtflags bits, reversed from libSceLibcInternal num_put::do_put/_Iput:
//   basefield = flags & 0x70 (0x20=oct, 0x40=hex, else dec); 0x80=showbase; 0x200=uppercase;
//   0x400=showpos; adjustfield = flags & 0x0E (0x02=internal, 0x08=left, else right).
// Field width lives at ios_base+0x20 and is reset to 0 after the field is emitted.
namespace numflag {
constexpr uint32_t kBaseMask = 0x70, kOct = 0x20, kHex = 0x40;
constexpr uint32_t kShowbase = 0x80, kUppercase = 0x200, kShowpos = 0x400;
constexpr uint32_t kAdjustMask = 0x0E, kInternal = 0x02, kLeft = 0x08;
} // namespace numflag

// Write a byte through the guest streambuf's overflow virtual (object-vtable slot 4, +0x20).
static void StreamPutc(void* sb, uint8_t ch) {
	auto* vtable   = *reinterpret_cast<void* const* const*>(sb);
	auto  overflow = reinterpret_cast<int(KYTY_SYSV_ABI*)(void*, int)>(vtable[4]);
	overflow(sb, ch);
}

// Emit `text` padded to ios_base width with `fill`, honouring the adjustfield, then reset width.
static GuestOStreamIter EmitField(void* sb, void* ios, char fill, const char* text, size_t len,
                                  size_t internal_prefix) {
	auto*      flags_p = reinterpret_cast<uint32_t*>(static_cast<char*>(ios) + 0x18);
	auto*      width_p = reinterpret_cast<int32_t*>(static_cast<char*>(ios) + 0x20);
	const auto flags   = *flags_p;
	const auto width   = *width_p > 0 ? static_cast<size_t>(*width_p) : 0;
	const auto pad     = width > len ? width - len : 0;
	const auto adjust  = flags & numflag::kAdjustMask;

	if (pad != 0 && adjust == numflag::kInternal && internal_prefix <= len) {
		for (size_t i = 0; i < internal_prefix; i++) { StreamPutc(sb, static_cast<uint8_t>(text[i])); }
		for (size_t i = 0; i < pad; i++) { StreamPutc(sb, static_cast<uint8_t>(fill)); }
		for (size_t i = internal_prefix; i < len; i++) { StreamPutc(sb, static_cast<uint8_t>(text[i])); }
	} else if (pad != 0 && adjust != numflag::kLeft) { // right-justify (default)
		for (size_t i = 0; i < pad; i++) { StreamPutc(sb, static_cast<uint8_t>(fill)); }
		for (size_t i = 0; i < len; i++) { StreamPutc(sb, static_cast<uint8_t>(text[i])); }
	} else { // left-justify or no padding
		for (size_t i = 0; i < len; i++) { StreamPutc(sb, static_cast<uint8_t>(text[i])); }
		for (size_t i = 0; i < pad; i++) { StreamPutc(sb, static_cast<uint8_t>(fill)); }
	}

	*width_p = 0;
	return {0, reinterpret_cast<uint64_t>(sb)};
}

// Build the printf conversion for an integer field from the ios_base flags (always 64-bit width).
static int BuildIntFormat(uint32_t flags, bool is_signed, char* out) {
	char* p = out;
	*p++    = '%';
	if ((flags & numflag::kShowpos) != 0) { *p++ = '+'; }
	if ((flags & numflag::kShowbase) != 0) { *p++ = '#'; }
	*p++ = 'l';
	*p++ = 'l';
	const auto base = flags & numflag::kBaseMask;
	if (base == numflag::kOct) {
		*p++ = 'o';
	} else if (base == numflag::kHex) {
		*p++ = (flags & numflag::kUppercase) != 0 ? 'X' : 'x';
	} else {
		*p++ = is_signed ? 'd' : 'u';
	}
	*p = '\0';
	return static_cast<int>(p - out);
}

static size_t IntPrefixLen(const char* buf, size_t len) {
	// Length of a leading sign and/or 0x/0 base prefix (used for internal padding).
	size_t i = 0;
	if (i < len && (buf[i] == '+' || buf[i] == '-')) { i++; }
	if (i + 1 < len && buf[i] == '0' && (buf[i + 1] | 0x20) == 'x') { i += 2; }
	return i;
}

static GuestOStreamIter DoPutInteger(void* /*self*/, uint64_t /*state*/, void* sb, void* ios, uint32_t fill,
                                     uint64_t val, bool is_signed) {
	EXIT_NOT_IMPLEMENTED(sb == nullptr || ios == nullptr);
	const auto flags = *reinterpret_cast<uint32_t*>(static_cast<char*>(ios) + 0x18);
	char       fmt[8];
	BuildIntFormat(flags, is_signed, fmt);
	char buf[80];
	int  n = is_signed ? std::snprintf(buf, sizeof(buf), fmt, static_cast<long long>(val))
	                   : std::snprintf(buf, sizeof(buf), fmt, static_cast<unsigned long long>(val));
	if (n < 0) { n = 0; }
	return EmitField(sb, ios, static_cast<char>(fill), buf, static_cast<size_t>(n),
	                 IntPrefixLen(buf, static_cast<size_t>(n)));
}

static GuestOStreamIter KYTY_SYSV_ABI DoPutBool(void* self, uint64_t state, void* sb, void* ios, uint32_t fill,
                                                uint64_t val) {
	// boolalpha (flags & 0x4000) renders true/false; otherwise fall through to numeric 1/0.
	const auto flags = *reinterpret_cast<uint32_t*>(static_cast<char*>(ios) + 0x18);
	if ((flags & 0x4000) != 0) {
		const char* text = (val != 0) ? "true" : "false";
		return EmitField(sb, ios, static_cast<char>(fill), text, std::strlen(text), 0);
	}
	return DoPutInteger(self, state, sb, ios, fill, val != 0 ? 1 : 0, false);
}

static GuestOStreamIter KYTY_SYSV_ABI DoPutSigned(void* self, uint64_t state, void* sb, void* ios, uint32_t fill,
                                                  uint64_t val) {
	return DoPutInteger(self, state, sb, ios, fill, val, true);
}

static GuestOStreamIter KYTY_SYSV_ABI DoPutUnsigned(void* self, uint64_t state, void* sb, void* ios, uint32_t fill,
                                                    uint64_t val) {
	return DoPutInteger(self, state, sb, ios, fill, val, false);
}

static GuestOStreamIter KYTY_SYSV_ABI DoPutDouble(void* /*self*/, uint64_t /*state*/, void* sb, void* ios,
                                                  uint32_t fill, double val) {
	EXIT_NOT_IMPLEMENTED(sb == nullptr || ios == nullptr);
	const auto flags = *reinterpret_cast<uint32_t*>(static_cast<char*>(ios) + 0x18);
	const auto prec  = *reinterpret_cast<int32_t*>(static_cast<char*>(ios) + 0x1C);
	const auto floatfield = flags & 0x3000; // 0x1000=scientific, 0x2000=fixed
	char       conv       = 'g';
	if (floatfield == 0x1000) { conv = (flags & numflag::kUppercase) ? 'E' : 'e'; }
	else if (floatfield == 0x2000) { conv = 'f'; }
	else if (floatfield == 0x3000) { conv = (flags & numflag::kUppercase) ? 'A' : 'a'; }
	char fmt[8] = {'%', '.', '*', conv, '\0'};
	char buf[512];
	int  n = std::snprintf(buf, sizeof(buf), fmt, prec > 0 ? prec : 6, val);
	if (n < 0) { n = 0; }
	return EmitField(sb, ios, static_cast<char>(fill), buf, static_cast<size_t>(n), 0);
}

static GuestOStreamIter KYTY_SYSV_ABI DoPutPtr(void* /*self*/, uint64_t /*state*/, void* sb, void* ios, uint32_t fill,
                                               uint64_t val) {
	EXIT_NOT_IMPLEMENTED(sb == nullptr || ios == nullptr);
	char buf[32];
	int  n = std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(val));
	if (n < 0) { n = 0; }
	return EmitField(sb, ios, static_cast<char>(fill), buf, static_cast<size_t>(n), 0);
}

// _ZTVSt7num_putIcSt19ostreambuf_iteratorIcSt11char_traitsIcEEE — layout mirrors libSceLibcInternal:
// object-vtable slots 0..3 = facet management, 4..11 = do_put(bool,long,ulong,ll,ull,double,ldouble,ptr).
static const uintptr_t g_num_put_char_vtable[16] {
    0,                                          // [0] offset-to-top
    0,                                          // [1] typeinfo (unused by the guest here)
    reinterpret_cast<uintptr_t>(&FacetDestroy), // [2] destroy
    reinterpret_cast<uintptr_t>(&FacetDelete),  // [3] delete
    reinterpret_cast<uintptr_t>(&FacetRetain),  // [4] retain
    reinterpret_cast<uintptr_t>(&FacetRelease), // [5] release
    reinterpret_cast<uintptr_t>(&DoPutBool),     // [6] do_put(bool)
    reinterpret_cast<uintptr_t>(&DoPutSigned),   // [7] do_put(long)
    reinterpret_cast<uintptr_t>(&DoPutUnsigned), // [8] do_put(unsigned long)
    reinterpret_cast<uintptr_t>(&DoPutSigned),   // [9] do_put(long long)
    reinterpret_cast<uintptr_t>(&DoPutUnsigned), // [10] do_put(unsigned long long)
    reinterpret_cast<uintptr_t>(&DoPutDouble),   // [11] do_put(double)
    reinterpret_cast<uintptr_t>(&DoPutDouble),   // [12] do_put(long double)
    reinterpret_cast<uintptr_t>(&DoPutPtr),      // [13] do_put(const void*)
    0, 0,
};

// std::num_put<char>::id and the shared locale::id counter (guest-writable globals).
static uint64_t g_num_put_char_id = 0;
static int32_t  g_locale_id_cnt   = 0;

// Native codecvt<char,char,_Mbstatet> is an identity conversion facet.
// Its do_in/do_out return noconv (3) and leave both iterators at their starts;
// the filebuf then transfers the bytes itself. Layout follows FW7.00's vtable.
static void KYTY_SYSV_ABI CodecvtDelete(LocaleFacet* self) { FreeGuestAllocation(self); }
static bool KYTY_SYSV_ABI CodecvtAlwaysNoConv(const void*) { return true; }
static int KYTY_SYSV_ABI CodecvtEncoding(const void*) { return 1; }
static int KYTY_SYSV_ABI CodecvtConvert(const void*, void*, const char* from, const char*,
                                        const char** from_next, char* to, char*, char** to_next) {
	*from_next = from;
	*to_next = to;
	return 3;
}
static int KYTY_SYSV_ABI CodecvtUnshift(const void*, void*, char* to, char*, char** to_next) {
	*to_next = to;
	return 0;
}
static int KYTY_SYSV_ABI CodecvtLength(const void*, void*, const char* from,
                                       const char* end, size_t maximum) {
	return static_cast<int>(std::min(static_cast<size_t>(end - from), maximum));
}
static const uintptr_t g_codecvt_char_vtable[13] {
    0, 0, reinterpret_cast<uintptr_t>(&FacetDestroy), reinterpret_cast<uintptr_t>(&CodecvtDelete),
    reinterpret_cast<uintptr_t>(&FacetRetain), reinterpret_cast<uintptr_t>(&FacetRelease),
    reinterpret_cast<uintptr_t>(&CodecvtAlwaysNoConv), reinterpret_cast<uintptr_t>(&CodecvtEncoding),
    reinterpret_cast<uintptr_t>(&CodecvtEncoding), reinterpret_cast<uintptr_t>(&CodecvtConvert),
    reinterpret_cast<uintptr_t>(&CodecvtConvert), reinterpret_cast<uintptr_t>(&CodecvtUnshift),
    reinterpret_cast<uintptr_t>(&CodecvtLength),
};
static uint64_t g_codecvt_char_id = 0;
static int64_t g_bad_file_offset = -1;
static std::array<uint64_t, 3> g_initial_file_position {};

// Dinkumware std::ios_base layout (verified against the guest ostringstream constructor
// sub_25B10: locale** at +0x38, width int32 at +0x20, fill char lives at basic_ios+0x50).
struct GuestIosBase {
	const void*  vtable;          // 0x00
	int64_t      standard_stream; // 0x08
	int32_t      state;           // 0x10  _Mystate
	int32_t      exceptions;      // 0x14  _Except
	int32_t      flags;           // 0x18  _Fmtfl
	int32_t      precision;       // 0x1C  _Prec
	int32_t      width;           // 0x20  _Wide
	uint32_t     reserved;        // 0x24
	void*        storage;         // 0x28  iarray
	void*        callbacks;       // 0x30  event callbacks
	LocaleImpl** locale;          // 0x38
};
static_assert(sizeof(GuestIosBase) == 0x40);
static_assert(offsetof(GuestIosBase, flags) == 0x18);
static_assert(offsetof(GuestIosBase, width) == 0x20);
static_assert(offsetof(GuestIosBase, locale) == 0x38);

// std::setw(int) returns a Dinkumware _Smanip<streamsize> = { void(*pfun)(ios_base&,streamsize), arg }.
// operator<<(ostream&, _Smanip) invokes pfun(ios_base, arg), which sets ios_base::width.
struct GuestSmanip {
	void*   pfun;
	int64_t arg;
};
static void KYTY_SYSV_ABI ManipSetw(GuestIosBase* ios, int64_t width) {
	EXIT_NOT_IMPLEMENTED(ios == nullptr);
	ios->width = static_cast<int32_t>(width);
}
GuestSmanip KYTY_SYSV_ABI setw(int64_t n) {
	return {reinterpret_cast<void*>(&ManipSetw), n};
}

// ---- Itanium C++ ABI thread-safe local static initialization guards ----
// A single global RECURSIVE mutex serializes guard acquisitions; the guard's low byte records
// "initialized". Recursion is required because a guarded constructor may itself initialize
// another function-local static on the same thread (nested guards) — a non-recursive lock would
// self-deadlock (which std::mutex reports by throwing, terminating the process).
static std::recursive_mutex g_cxa_guard_mutex;

int KYTY_SYSV_ABI cxa_guard_acquire(uint64_t* guard) {
	EXIT_NOT_IMPLEMENTED(guard == nullptr);
	if ((*reinterpret_cast<volatile uint8_t*>(guard)) != 0) {
		return 0; // already initialized
	}
	g_cxa_guard_mutex.lock();
	if ((*reinterpret_cast<volatile uint8_t*>(guard)) != 0) {
		g_cxa_guard_mutex.unlock();
		return 0;
	}
	return 1; // caller performs the initialization, holding the lock until release/abort
}

void KYTY_SYSV_ABI cxa_guard_release(uint64_t* guard) {
	EXIT_NOT_IMPLEMENTED(guard == nullptr);
	*reinterpret_cast<volatile uint8_t*>(guard) = 1;
	g_cxa_guard_mutex.unlock();
}

void KYTY_SYSV_ABI cxa_guard_abort(uint64_t* guard) {
	EXIT_NOT_IMPLEMENTED(guard == nullptr);
	g_cxa_guard_mutex.unlock();
}

// std::set_terminate(handler) — store the guest handler, return the previous one.
using TerminateHandler = void(KYTY_SYSV_ABI*)();
static std::atomic<TerminateHandler> g_terminate_handler {nullptr};

TerminateHandler KYTY_SYSV_ABI set_terminate(TerminateHandler handler) {
	return g_terminate_handler.exchange(handler);
}

// std::ios_base::~ios_base(). Streams built here own no iarray/callback storage and reference
// the immortal classic locale, so releasing them is a no-op beyond clearing the locale slot.
void KYTY_SYSV_ABI ios_base_dtor(GuestIosBase* self) {
	EXIT_NOT_IMPLEMENTED(self == nullptr);
	self->locale = nullptr;
}

// The native Dinkumware filebuf aliases FILE's buffer pointers directly. Never hand
// it a host CRT FILE: the pointer offsets and position record are different.
struct GuestFile {
	uint16_t flags = 0;
	uint16_t reserved = 0;
	int32_t descriptor = -1;
	char* buffer_begin = nullptr; // +8
	char* buffer_end = nullptr;   // +16
	char* get_next = nullptr;     // +24
	char* get_end = nullptr;      // +32
	char* put_end = nullptr;      // +40: no exposed output buffering
	std::array<uint8_t, 96> native_tail {};
	FILE* host = nullptr;
	std::recursive_mutex mutex;
	std::array<char, 16384> buffer {};
	size_t refill_size = buffer.size();
	void ClearBuffer() { get_next = get_end = put_end = buffer_begin; }
};
static_assert(offsetof(GuestFile, host) == 144);

static int64_t HostTell(FILE* file) {
#if defined(_WIN32)
	return ::_ftelli64(file);
#else
	return ::ftello(file);
#endif
}
static int HostSeek(FILE* file, int64_t offset, int origin) {
#if defined(_WIN32)
	return ::_fseeki64(file, offset, origin);
#else
	return ::fseeko(file, offset, origin);
#endif
}
static bool IsHostStdio(const void* file) { return file == stdin || file == stdout || file == stderr; }
static GuestFile* AsGuestFile(void* file) { return static_cast<GuestFile*>(file); }
static int64_t GuestFileTell(GuestFile* file) {
	const auto physical = HostTell(file->host);
	return physical < 0 ? -1 : physical - (file->get_end - file->get_next);
}
static int GuestFileSyncRead(GuestFile* file) {
	const auto position = GuestFileTell(file);
	if (position < 0 || HostSeek(file->host, position, SEEK_SET) != 0) { return -1; }
	file->ClearBuffer();
	return 0;
}
void KYTY_SYSV_ABI Lockfile(void* stream) {
	if (stream != nullptr && !IsHostStdio(stream)) { AsGuestFile(stream)->mutex.lock(); }
}
void KYTY_SYSV_ABI Unlockfile(void* stream) {
	if (stream != nullptr && !IsHostStdio(stream)) { AsGuestFile(stream)->mutex.unlock(); }
}
int KYTY_SYSV_ABI FileGetc(void* stream) {
	if (stream == nullptr) { return EOF; }
	if (IsHostStdio(stream)) { return ::fgetc(static_cast<FILE*>(stream)); }
	auto* file = AsGuestFile(stream);
	std::lock_guard lock(file->mutex);
	if (file->get_next == file->get_end) {
		const auto count = ::fread(file->buffer_begin, 1, file->refill_size, file->host);
		file->get_next = file->buffer_begin;
		file->get_end = file->buffer_begin + count;
		if (count == 0) { return EOF; }
	}
	return static_cast<unsigned char>(*file->get_next++);
}
int KYTY_SYSV_ABI FileUngetc(int ch, void* stream) {
	if (stream == nullptr || ch == EOF) { return EOF; }
	if (IsHostStdio(stream)) { return ::ungetc(ch, static_cast<FILE*>(stream)); }
	auto* file = AsGuestFile(stream);
	std::lock_guard lock(file->mutex);
	if (file->get_next > file->buffer_begin) {
		*--file->get_next = static_cast<char>(ch);
		return static_cast<unsigned char>(ch);
	}
	if (GuestFileSyncRead(file) != 0) { return EOF; }
	return ::ungetc(ch, file->host);
}
int KYTY_SYSV_ABI FileSeek(void* stream, int64_t offset, int origin) {
	if (stream == nullptr || origin < SEEK_SET || origin > SEEK_END) { return -1; }
	if (IsHostStdio(stream)) { return HostSeek(static_cast<FILE*>(stream), offset, origin); }
	auto* file = AsGuestFile(stream);
	std::lock_guard lock(file->mutex);
	if (origin == SEEK_CUR) { offset -= file->get_end - file->get_next; }
	const int result = HostSeek(file->host, offset, origin);
	if (result == 0) { file->ClearBuffer(); }
	return result;
}
// Firmware fpos_t is an int64 offset plus sixteen bytes of multibyte state.
int KYTY_SYSV_ABI FileGetpos(void* stream, void* output) {
	if (stream == nullptr || output == nullptr) { return -1; }
	int64_t position;
	if (IsHostStdio(stream)) { position = HostTell(static_cast<FILE*>(stream)); }
	else {
		auto* file = AsGuestFile(stream);
		std::lock_guard lock(file->mutex);
		position = GuestFileTell(file);
	}
	if (position < 0) { return -1; }
	std::memset(output, 0, 24);
	std::memcpy(output, &position, sizeof(position));
	return 0;
}
int KYTY_SYSV_ABI FileSetpos(void* stream, const void* input) {
	if (input == nullptr) { return -1; }
	int64_t position;
	std::memcpy(&position, input, sizeof(position));
	return FileSeek(stream, position, SEEK_SET);
}
int KYTY_SYSV_ABI FileSetbuf(void* stream, char* buffer, int mode, size_t size) {
	if (stream == nullptr || mode < 0 || mode > 2) { return -1; }
	if (IsHostStdio(stream)) { return ::setvbuf(static_cast<FILE*>(stream), buffer, mode, size); }
	auto* file = AsGuestFile(stream);
	std::lock_guard lock(file->mutex);
	if (GuestFileSyncRead(file) != 0) { return -1; }
	file->buffer_begin = buffer != nullptr && size > 0 && mode != 2 ? buffer : file->buffer.data();
	file->refill_size = mode == 2 ? 1 : (buffer != nullptr && size > 0 ? size : file->buffer.size());
	file->buffer_end = file->buffer_begin + file->refill_size;
	file->ClearBuffer();
	return 0;
}
int KYTY_SYSV_ABI FileClose(void* stream) {
	if (stream == nullptr) { return EOF; }
	if (IsHostStdio(stream)) { return ::fclose(static_cast<FILE*>(stream)); }
	auto* file = AsGuestFile(stream);
	const int result = ::fclose(file->host);
	delete file;
	return result;
}

// ---- stdio ----
uint64_t KYTY_SYSV_ABI fwrite(const void* ptr, uint64_t size, uint64_t nmemb, FILE* stream) {
	EXIT_NOT_IMPLEMENTED(ptr == nullptr && size * nmemb != 0);
	EXIT_NOT_IMPLEMENTED(stream != stdout && stream != stderr);
	return ::fwrite(ptr, size, nmemb, stream);
}

int KYTY_SYSV_ABI fputc(int c, FILE* stream) {
	EXIT_NOT_IMPLEMENTED(stream != stdout && stream != stderr);
	return ::fputc(c, stream);
}

int KYTY_SYSV_ABI fputs(const char* text, FILE* stream) {
	EXIT_NOT_IMPLEMENTED(text == nullptr);
	EXIT_NOT_IMPLEMENTED(stream != stdout && stream != stderr);
	const int result = ::fputs(text, stream);
	::fflush(stream);
	return result;
}

static KYTY_SYSV_ABI int fprintf(VA_ARGS) {
	VA_CONTEXT(ctx); // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
	PRINT_NAME();

	// fprintf(FILE*, fmt, ...): the format is the second argument and the varargs follow it,
	// so advance the va cursor past the FILE* before handing it to the guest formatter.
	auto* stream = reinterpret_cast<FILE*>(ctx.reg_save_area.gp[0]);
	EXIT_NOT_IMPLEMENTED(stream != stdout && stream != stderr);
	const auto* fmt = reinterpret_cast<const char*>(ctx.reg_save_area.gp[1]);
	ctx.va_list.gp_offset = offsetof(VaRegSave, gp) + sizeof(uint64_t) * 2; // skip FILE* and fmt
	return GetGuestVprintfFunc()(fmt, &ctx.va_list);
}

// std::_Fiopen(name, openmode, prot): the Dinkumware filebuf open helper. Resolves the guest
// path to its host location and opens a stdio stream, returning nullptr when the file cannot be
// opened (so basic_filebuf::open reports failure gracefully instead of using a bogus handle).
GuestFile* KYTY_SYSV_ABI Fiopen(const char* name, int mode, int /*prot*/) {
	PRINT_NAME();
	if (name == nullptr) {
		return nullptr;
	}

	// Dinkumware ios_base::openmode bits.
	enum : int {
		kIn = 0x01, kOut = 0x02, kAte = 0x04, kApp = 0x08, kTrunc = 0x10,
		kNoReplace = 0x20, kNoCreate = 0x40, kBinary = 0x80,
	};
	const bool binary = (mode & kBinary) != 0;
	const int  base   = (mode & (kIn | kOut | kApp | kTrunc)) |
	                   ((mode & kApp) != 0 ? kOut : 0) | ((mode & kNoReplace) != 0 ? kIn : 0);

	const char* fmode = nullptr;
	switch (base) {
		case kIn: fmode = "r"; break;
		case kOut:
		case kOut | kTrunc: fmode = "w"; break;
		case kApp:
		case kOut | kApp: fmode = "a"; break;
		case kIn | kOut: fmode = "r+"; break;
		case kIn | kOut | kTrunc: fmode = "w+"; break;
		case kIn | kApp:
		case kIn | kOut | kApp: fmode = "a+"; break;
		default: return nullptr; // invalid open mode
	}

	char mode_buf[4] = {};
	std::snprintf(mode_buf, sizeof(mode_buf), "%s%s", fmode, binary ? "b" : "");

	const auto real = LibKernel::FileSystem::GetRealFilename(name);
	LOGF("\t name = %s -> %s, mode = 0x%x (%s)\n", name, real.string().c_str(), mode, mode_buf);
	// Match the native no-create probe without creating or truncating a missing file.
	if ((mode & kNoCreate) != 0 && (base & (kOut | kApp)) != 0) {
		FILE* probe = ::fopen(real.string().c_str(), "r");
		if (probe == nullptr) { return nullptr; }
		::fclose(probe);
	}
	FILE* file = ::fopen(real.string().c_str(), mode_buf);
	if (file != nullptr && (mode & kAte) != 0 && ::fseek(file, 0, SEEK_END) != 0) {
		::fclose(file);
		return nullptr;
	}
	if (file == nullptr) { return nullptr; }
	auto* guest = new GuestFile;
	guest->flags = static_cast<uint16_t>(base & (kIn | kOut));
	guest->host = file;
	guest->buffer_begin = guest->buffer.data();
	guest->buffer_end = guest->buffer.data() + guest->buffer.size();
	guest->ClearBuffer();
	return guest;
}

// ---- sceLibcMspace* : per-heap allocators ----
// The guest creates named heaps (optionally over a reserved region) and allocates from them.
// Mspace blocks use the same bounded arenas as guest malloc. Each block carries
// a header so free/realloc/usable-size work for
// any requested alignment.
namespace Mspace {

struct BlockHeader {
	void*  base; // original guest heap pointer
	size_t size; // usable payload size
};

static void* Allocate(size_t size, size_t align) {
	if (align < alignof(std::max_align_t)) {
		align = alignof(std::max_align_t);
	}
	const size_t overhead = sizeof(BlockHeader) + align;
	if (size > SIZE_MAX - overhead) { return nullptr; }
	void*        raw      = AllocateGuestHeap(size + overhead);
	if (raw == nullptr) {
		return nullptr;
	}
	auto addr    = reinterpret_cast<uintptr_t>(raw) + sizeof(BlockHeader);
	addr         = (addr + (align - 1)) & ~(align - 1);
	auto* payload = reinterpret_cast<void*>(addr);
	reinterpret_cast<BlockHeader*>(payload)[-1] = {raw, size};
	return payload;
}

static void Release(void* payload) {
	if (payload != nullptr) {
		FreeGuestAllocation(reinterpret_cast<BlockHeader*>(payload)[-1].base);
	}
}

void* KYTY_SYSV_ABI Create(const char* name, void* base, size_t capacity, uint32_t flag) {
	PRINT_NAME();
	LOGF("\t name = %s, base = %p, capacity = 0x%zx, flag = 0x%" PRIx32 "\n", (name != nullptr ? name : "<null>"),
	     base, capacity, flag);
	// Return a distinct, non-null opaque handle; allocations are serviced from the host heap.
	return new uint64_t(0x4D5350414345ULL); // "MSPACE"
}

int KYTY_SYSV_ABI Destroy(void* ms) {
	PRINT_NAME();
	delete static_cast<uint64_t*>(ms);
	return 0;
}

void* KYTY_SYSV_ABI Malloc(void* /*ms*/, size_t size) {
	return Allocate(size != 0 ? size : 1, alignof(std::max_align_t));
}

void* KYTY_SYSV_ABI Calloc(void* /*ms*/, size_t nelem, size_t size) {
	const size_t total = nelem * size;
	void*        p     = Allocate(total != 0 ? total : 1, alignof(std::max_align_t));
	if (p != nullptr) {
		std::memset(p, 0, total);
	}
	return p;
}

void* KYTY_SYSV_ABI Memalign(void* /*ms*/, size_t align, size_t size) {
	return Allocate(size != 0 ? size : 1, align);
}

int KYTY_SYSV_ABI PosixMemalign(void* /*ms*/, void** out, size_t align, size_t size) {
	if (out == nullptr) {
		return Posix::POSIX_EINVAL;
	}
	*out = Allocate(size != 0 ? size : 1, align);
	return *out != nullptr ? 0 : Posix::POSIX_ENOMEM;
}

void* KYTY_SYSV_ABI Realloc(void* /*ms*/, void* ptr, size_t size) {
	if (ptr == nullptr) {
		return Allocate(size != 0 ? size : 1, alignof(std::max_align_t));
	}
	const size_t old_size = reinterpret_cast<BlockHeader*>(ptr)[-1].size;
	if (size == 0) {
		Release(ptr);
		return nullptr;
	}
	void* p = Allocate(size, alignof(std::max_align_t));
	if (p != nullptr) {
		std::memcpy(p, ptr, old_size < size ? old_size : size);
		Release(ptr);
	}
	return p;
}

void* KYTY_SYSV_ABI Reallocalign(void* /*ms*/, void* ptr, size_t size, size_t align) {
	if (ptr == nullptr) {
		return Allocate(size != 0 ? size : 1, align);
	}
	const size_t old_size = reinterpret_cast<BlockHeader*>(ptr)[-1].size;
	if (size == 0) {
		Release(ptr);
		return nullptr;
	}
	void* p = Allocate(size, align);
	if (p != nullptr) {
		std::memcpy(p, ptr, old_size < size ? old_size : size);
		Release(ptr);
	}
	return p;
}

void KYTY_SYSV_ABI Free(void* /*ms*/, void* ptr) {
	Release(ptr);
}

size_t KYTY_SYSV_ABI MallocUsableSize(void* ptr) {
	return ptr != nullptr ? reinterpret_cast<BlockHeader*>(ptr)[-1].size : 0;
}

// SceLibcMallocManagedSize: {u16 size; u16 version; u32 reserved1; size_t maxSystemSize;
// size_t currentSystemSize; size_t currentInuseSize;} (40 bytes). The caller pre-sets size/version;
// we fill the size fields. CRITICAL: SceShellCore's BGFT worker-pool init derives a std::vector
// max_size from currentSystemSize (`sceLibcMspaceMallocStatsFast(...).currentSystemSize >> 3`); the
// old no-op left it 0, so growing the vector to 5 workers threw std::length_error("vector<T> too
// long") -> ud2. Report a generous mspace capacity so max_size is ample.
struct SceLibcMallocManagedSize {
	uint16_t size;
	uint16_t version;
	uint32_t reserved1;
	size_t   maxSystemSize;
	size_t   currentSystemSize;
	size_t   currentInuseSize;
};

static void FillManagedSize(void* stats) {
	if (stats == nullptr) {
		return;
	}
	auto* s              = reinterpret_cast<SceLibcMallocManagedSize*>(stats);
	s->reserved1         = 0;
	s->maxSystemSize     = size_t {256} * 1024 * 1024; // ample: bounds vector max_size, not real usage
	s->currentSystemSize = size_t {256} * 1024 * 1024;
	s->currentInuseSize  = 0;
}

int KYTY_SYSV_ABI MallocStats(void* /*ms*/, void* stats) {
	FillManagedSize(stats);
	return 0;
}

int KYTY_SYSV_ABI MallocStatsFast(void* /*ms*/, void* stats) {
	FillManagedSize(stats);
	return 0;
}

int KYTY_SYSV_ABI IsHeapEmpty(void* /*ms*/) {
	return 0;
}

} // namespace Mspace

// ---- std::cout / std::cerr / std::clog backed by host stdio ----
// The guest imports these as fully-constructed std::ostream objects (libSceLibcInternal would
// normally build them). We fabricate an ostream whose rdbuf is a minimal streambuf writing to a
// host FILE*. Object/vtable offsets are reversed from the guest's operator<< (sub_4BC0),
// flush (sub_59E0), widen (sub_5940) and put (sub_5790).

// std::ctype<char>::id — guest-writable; use_facet() (sub_66E0) lazily assigns it from _Id_cnt.
static uint64_t g_ctype_char_id = 0;

// Minimal streambuf: the put area is kept empty so every byte flows through overflow()/xsputn().
struct HostStreamBuf {
	const void* vtable;         // 0x00
	uint64_t    reserved0[7];   // 0x08..0x3F
	uint8_t**   put_next_ptr;   // 0x40  -> &put_next (indirect put pointer, Dinkumware layout)
	uint64_t    reserved1[3];   // 0x48..0x5F
	int*        put_end_ptr;    // 0x60  -> &put_end
	uint8_t*    put_next;       // backing slot, kept null to force overflow()
	int         put_end;        // backing slot
	FILE*       target;         // destination host stream
};
static_assert(offsetof(HostStreamBuf, put_next_ptr) == 0x40);
static_assert(offsetof(HostStreamBuf, put_end_ptr) == 0x60);

static int KYTY_SYSV_ABI StreamBufOverflow(HostStreamBuf* self, int ch) {
	EXIT_NOT_IMPLEMENTED(self == nullptr || self->target == nullptr);
	if (ch == -1) {
		return 0; // traits::not_eof(eof)
	}
	return ::fputc(static_cast<unsigned char>(ch), self->target);
}
static int64_t KYTY_SYSV_ABI StreamBufXsputn(HostStreamBuf* self, const char* buf, int64_t count) {
	EXIT_NOT_IMPLEMENTED(self == nullptr || self->target == nullptr);
	if (buf == nullptr || count <= 0) {
		return 0;
	}
	return static_cast<int64_t>(::fwrite(buf, 1, static_cast<size_t>(count), self->target));
}
static int KYTY_SYSV_ABI StreamBufSync(HostStreamBuf* self) {
	EXIT_NOT_IMPLEMENTED(self == nullptr || self->target == nullptr);
	return ::fflush(self->target);
}
static int64_t KYTY_SYSV_ABI StreamBufNoop(HostStreamBuf* /*self*/) {
	return 0; // sentry / destructor / unused virtuals
}

// basic_streambuf<char> vtable: only overflow(+0x20), xsputn(+0x50), sync(+0x70) and the
// sentry slot (+0x10) are exercised by the guest; the rest are safe no-ops.
static const uintptr_t g_streambuf_vtable[16] {
    reinterpret_cast<uintptr_t>(&StreamBufNoop),     reinterpret_cast<uintptr_t>(&StreamBufNoop),     // [0][1] dtors
    reinterpret_cast<uintptr_t>(&StreamBufNoop),     reinterpret_cast<uintptr_t>(&StreamBufNoop),     // [2] sentry [3]
    reinterpret_cast<uintptr_t>(&StreamBufOverflow), reinterpret_cast<uintptr_t>(&StreamBufNoop),     // [4] overflow [5]
    reinterpret_cast<uintptr_t>(&StreamBufNoop),     reinterpret_cast<uintptr_t>(&StreamBufNoop),     // [6][7]
    reinterpret_cast<uintptr_t>(&StreamBufNoop),     reinterpret_cast<uintptr_t>(&StreamBufNoop),     // [8][9]
    reinterpret_cast<uintptr_t>(&StreamBufXsputn),   reinterpret_cast<uintptr_t>(&StreamBufNoop),     // [10] xsputn [11]
    reinterpret_cast<uintptr_t>(&StreamBufNoop),     reinterpret_cast<uintptr_t>(&StreamBufNoop),     // [12][13]
    reinterpret_cast<uintptr_t>(&StreamBufSync),     reinterpret_cast<uintptr_t>(&StreamBufNoop),     // [14] sync [15]
};

// std::ostream / basic_ios (virtual base offset 0, so the ios_base fields live in this object).
struct HostOStream {
	const void*  vtable;      // 0x00  (*(vtable-0x18) == 0 => ios_base subobject is at +0)
	uint64_t     reserved08;  // 0x08
	int32_t      state;       // 0x10
	int32_t      exceptions;  // 0x14
	int32_t      flags;       // 0x18
	int32_t      precision;   // 0x1C
	int32_t      width;       // 0x20
	uint32_t     reserved24;  // 0x24
	void*        storage;     // 0x28
	void*        callbacks;   // 0x30
	LocaleImpl** locale;      // 0x38
	void*        rdbuf;       // 0x40
	void*        tie;         // 0x48
	uint8_t      fill;        // 0x50
	uint8_t      reserved51[47];
};
static_assert(offsetof(HostOStream, locale) == 0x38);
static_assert(offsetof(HostOStream, rdbuf) == 0x40);
static_assert(offsetof(HostOStream, fill) == 0x50);

// ostream vtable storage: index 0 (== vtable_ptr-0x18) holds the virtual-base offset (0).
static uintptr_t g_ostream_vtable_storage[8] {};
static void KYTY_SYSV_ABI OStreamVirtualStub() {
	EXIT_NOT_IMPLEMENTED(true);
}

static HostStreamBuf g_cout_sb {};
static HostStreamBuf g_cerr_sb {};
static HostOStream   g_cout {};
static HostOStream   g_cerr {};
static HostOStream   g_clog {};

static void InitStdStream(HostOStream& os, HostStreamBuf& sb, FILE* target) {
	sb.vtable       = g_streambuf_vtable;
	sb.put_next     = nullptr;
	sb.put_end      = 0;
	sb.put_next_ptr = &sb.put_next;
	sb.put_end_ptr  = &sb.put_end;
	sb.target       = target;

	os.vtable    = &g_ostream_vtable_storage[3]; // -> storage[0] visible at (vtable-0x18) == vbase 0
	os.state     = 0;
	os.flags     = 0;
	os.precision = 6;
	os.width     = 0;
	os.locale    = &g_locale_classic_ptr;
	os.rdbuf     = &sb;
	os.tie       = nullptr;
	os.fill      = ' ';
}

static void InitStdStreams() {
	g_ostream_vtable_storage[0] = 0; // virtual-base offset
	for (auto& slot : {3, 4, 5, 6, 7}) {
		g_ostream_vtable_storage[slot] = reinterpret_cast<uintptr_t>(&OStreamVirtualStub);
	}
	InitStdStream(g_cout, g_cout_sb, stdout);
	InitStdStream(g_cerr, g_cerr_sb, stderr);
	InitStdStream(g_clog, g_cerr_sb, stderr);
}

int KYTY_SYSV_ABI FilesystemStat(const char* path, int* permissions, int* error) {
	LibKernel::FileSystem::FileStat attributes {};
	const int result = LibKernel::FileSystem::KernelStat(path, &attributes);
	if (error != nullptr) {
		*error = result == 0 ? 0 : ((static_cast<uint32_t>(result) & 0xffff0000u) == 0x80020000u ? result & 0xffff : 1);
	}
	if (result != 0) {
		// Firmware treats these lookup failures as file_type::not_found.
		const uint32_t offset = static_cast<uint32_t>(result) + 2147352574u;
		return offset <= 61 && ((0x2000000000140001ull >> offset) & 1) != 0 ? -1 : 0;
	}
	if (permissions != nullptr) { *permissions = attributes.st_mode & 0xfff; }
	constexpr int types[] = {6, 5, 8, 2, 8, 4, 8, 1, 8, 3, 8, 7};
	const uint32_t index = (attributes.st_mode & 0xf000u) - 0x1000u;
	return index < 0xc000u ? types[index >> 12] : 8;
}

LIB_DEFINE(InitLibcInternal_1) {
	LibcInternalExt::InitLibcInternalExt_1(s);
	LibcInternal::InitStdStreams();

	LIB_OBJECT("ZT4ODD2Ts9o", &LibcInternal::g_need_flag);
	LIB_OBJECT("2sWzhYqFH4E", stdout);
	LIB_OBJECT("H8AprKeZtNg", stderr); // std::_Stderr

	LIB_FUNC("GMpvxPFW924", LibcInternal::vprintf);
	LIB_FUNC("MUjC4lbHrK4", LibcInternal::fflush);
	LIB_FUNC("8zTFvBIAIN8", LibcInternal::memset);
	LIB_FUNC("Q3VBxCXhUHs", LibcInternal::memcpy);
	LIB_FUNC("+P6FRGH4LfA", LibcInternal::memmove);
	LIB_FUNC("DfivPArhucg", LibcInternal::memcmp);
	LIB_FUNC("aesyjrHVWy4", LibcInternal::strncmp);
	LIB_FUNC("pXvbDfchu6k", LibcInternal::strncasecmp);
	LIB_FUNC("Ovb2dSJOAuE", LibcInternal::strcmp);
	LIB_FUNC("enqPGLfmVNU", LibcInternal::strtok_r);
	LIB_FUNC("AV6ipCNa4Rw", LibcInternal::strcasecmp);
	LIB_FUNC("kiZSXIWd9vg", LibcInternal::strcpy);
	LIB_FUNC("g7zzzLDYGw0", LibcInternal::strdup);
	LIB_FUNC("8KeeeFcEdls", LibcInternal::FilesystemStat);
	LIB_FUNC("ay3uROQAc5A", LibcInternal::opendir);
	LIB_FUNC("lybyyKtP54c", LibcInternal::readdir);
	LIB_FUNC("XepdqehVYe4", LibcInternal::closedir);
	LIB_FUNC("j4ViWNHEgww", LibcInternal::strlen);
	LIB_FUNC("WkkeywLJcgU", LibcInternal::wcslen);
	LIB_FUNC("pA9N3VIgEZ4", LibcInternal::wcsncat);
	LIB_FUNC("K+v+cnmGoH4", LibcInternal::wcsnlen_s);
	LIB_FUNC("0nV21JjYCH8", LibcInternal::wcsncpy);
	LIB_FUNC("fL3O02ypZFE", LibcInternal::wmemcpy);
	LIB_FUNC("5Xa2ACNECdo", LibcInternal::strcpy_s);
	LIB_FUNC("YNzNkJzYqEg", LibcInternal::strncpy_s);
	LIB_FUNC("K+gcnFFJKVc", LibcInternal::strcat_s);
	LIB_FUNC("NC4MSB+BRQg", LibcInternal::strncat_s);
	LIB_FUNC("6sJWiWSRuqk", LibcInternal::strncpy);
	LIB_FUNC("kHg45qPC6f0", LibcInternal::strncat);
	LIB_FUNC("Ls4tzzhimqQ", LibcInternal::strcat);
	LIB_FUNC("ob5xAW4ln-0", LibcInternal::strchr);
	LIB_FUNC("9yDWMxEFdJU", LibcInternal::strrchr);
	LIB_FUNC("viiwFMaNamA", LibcInternal::strstr);
	LIB_FUNC("mXlxhmLNMPg", LibcInternal::strtol);
	LIB_FUNC("VOBg+iNwB-4", LibcInternal::strtoll);
	LIB_FUNC("gNQ1V2vfXDE", kyty_guest_setjmp);
	LIB_FUNC("lKEN2IebgJ0", kyty_guest_longjmp);
	LIB_FUNC("5OqszGpy7Mg", LibcInternal::strtoull);
	LIB_FUNC("q+9E0X3aWpU", LibcInternal::Stoull);
	LIB_FUNC("pSpDCDyxkaY", LibcInternal::Stoullx);
	LIB_FUNC("XORecIx0t+c", LibcInternal::Stoullx);
	LIB_FUNC("QxmSHBCuKTk", LibcInternal::strtoul);
	LIB_FUNC("zlfEH8FmyUA", LibcInternal::strtoul);
	LIB_FUNC("fPxypibz2MY", LibcInternal::atoi);
	LIB_FUNC("Q4rRL34CEeE", LibcInternal::sinf);
	LIB_FUNC("c41UEHVtiEA", LibcInternal::Stod);
	LIB_FUNC("QlcJbyd6jxM", LibcInternal::Stodx);
	LIB_FUNC("ZE6RNL+eLbk", LibcInternal::tanf);
	LIB_FUNC("QI-x0SL8jhw", LibcInternal::acosf);
	LIB_FUNC("EH-x713A99c", LibcInternal::atan2f);
	LIB_FUNC("8zsu04XNsZ4", LibcInternal::expf);
	LIB_FUNC("1D0H2KNjshE", LibcInternal::powf);
	LIB_FUNC("9LCjpWyQ5Zc", LibcInternal::pow);
	LIB_FUNC("rtV7-jWC6Yg", LibcInternal::log);
	LIB_FUNC("88Vv-AzHVj8", LibcInternal::fmodf);
	LIB_FUNC("0WMHDb5Dt94", LibcInternal::modf);
	LIB_FUNC("3+UPM-9E6xY", LibcInternal::modff);
	LIB_FUNC("kA-TdiOCsaY", LibcInternal::frexp);
	LIB_FUNC("aaDMGGkXFxo", LibcInternal::frexpf);
	LIB_FUNC("-P6FNMzk2Kc", LibcInternal::cosf);
	LIB_FUNC("pztV4AF18iI", LibcInternal::sincosf);
	LIB_FUNC("H8ya2H00jbI", LibcInternal::sin);
	LIB_FUNC("2WE3BTYVwKM", LibcInternal::cos);
	LIB_FUNC("jMB7EFyu30Y", LibcInternal::sincos);
	LIB_FUNC("eLdDw6l0-bU", LibcInternal::snprintf);
	LIB_FUNC("3BytPOQgVKc", LibcInternal::snprintf); // PS5 snprintf_s uses (buf, size, fmt, ...)

	LIB_FUNC("L1SBTkC+Cvw", LibC::abort);
	LIB_FUNC("tsvEmnenz48", LibC::cxa_atexit);
	LIB_FUNC("H2e8t5ScQGc", LibC::cxa_finalize);
	LIB_FUNC("DiGVep5yB5w", LibC::std_execute_once);

	LIB_FUNC("al3JzFI9MQ0", LibcInternal::LibcHeapErrorReportForGame);

	// operator new / operator delete
	LIB_FUNC("fJnpuVVBbKk", LibcInternal::operator_new);
	LIB_FUNC("z+P+xCnWLBk", LibcInternal::operator_delete);
	LIB_FUNC("hdm0YfMa7TQ", LibcInternal::operator_new);          // operator new[] (_Znam, PS5)
	LIB_FUNC("Bdm0YfMa7TQ", LibcInternal::operator_new);          // operator new[] (_Znam, PS4)
	LIB_FUNC("MLWl90SFWNE", LibcInternal::operator_delete);       // operator delete[] (_ZdaPv)
	LIB_FUNC("FOt55ZNaVJk", LibcInternal::operator_delete_sized); // operator delete[](void*,size_t)
	LIB_FUNC("FYDzBVE5mZs", LibcInternal::operator_delete_sized); // operator delete(void*,size_t)
	LIB_FUNC("lYDzBVE5mZs", LibcInternal::operator_delete_sized); // (variant)
	LIB_FUNC("ryUxD-60bKM", LibcInternal::operator_new_nothrow);  // operator new(size_t,nothrow_t)
	LIB_FUNC("Jh5qUcwiSEk", LibcInternal::operator_new_nothrow);  // operator new[](size_t,nothrow_t)
	LIB_FUNC("3yxLpdKD0RA", LibcInternal::operator_new_aligned);
	LIB_FUNC("kn-rKRB0pfY", LibcInternal::operator_new_aligned);
	LIB_FUNC("iQXBbJbfT5k", LibcInternal::operator_new_aligned_nothrow);
	LIB_FUNC("s2eGsgUF9vk", LibcInternal::operator_new_aligned_nothrow);
	LIB_FUNC("bZx+FFSlkUM", LibcInternal::operator_delete_aligned);
	LIB_FUNC("v09ZcAhZzSc", LibcInternal::operator_delete_aligned);
	LIB_FUNC("nwujzxOPXzQ", LibcInternal::operator_delete_aligned_sized);
	LIB_FUNC("Y1RR+IQy6Pg", LibcInternal::operator_delete_aligned_sized);
	LIB_FUNC("Dt9kllUFXS0", LibcInternal::operator_delete_aligned_nothrow);
	LIB_FUNC("dH3ucvQhfSY", LibcInternal::operator_delete_aligned_nothrow);

	// string / format / sort helpers
	LIB_FUNC("Q2V+iqvjgC0", LibcInternal::vsnprintf); // vsnprintf
	LIB_FUNC("5jNubw4vlAA", LibcInternal::strnlen);   // strnlen
	LIB_FUNC("DQbtGaBKlaw", LibcInternal::strnlen);   // strnlen_s: null is length zero
	LIB_FUNC("AEJdIVZTEmo", LibcInternal::qsort);     // qsort
	LIB_FUNC("NesIgTmfF0Q", LibcInternal::bsearch);
	LIB_FUNC("m5wN+SwZOR4", LibcInternal::putchar);   // putchar

	// std::_Pad::_Launch(const char*, pthread_attr**, pthread**)
	LIB_FUNC("H7-7Z3ixv-w", LibcInternal::Pad_Launch_attr);

	// Dinkumware C11 mutex family
	LIB_FUNC("YaHc3GS7y7g", LibcInternal::Mtx_init);
	LIB_FUNC("tgioGpKtmbE", LibcInternal::Mtx_init_with_name);
	LIB_FUNC("5Lf51jvohTQ", LibcInternal::Mtx_destroy);
	LIB_FUNC("iS4aWbUonl0", LibcInternal::Mtx_lock);
	LIB_FUNC("gTuXQwP9rrs", LibcInternal::Mtx_unlock);
	LIB_FUNC("k6pGNMwJB08", LibcInternal::Mtx_trylock);
	// Dinkumware condition variables
	LIB_FUNC("SreZybSRWpU", LibcInternal::Cnd_init);
	LIB_FUNC("CreZybSRWpU", LibcInternal::Cnd_init);
	LIB_FUNC("2B+V3qCqz4s", LibcInternal::Cnd_init_with_name);
	LIB_FUNC("GB+V3qCqz4s", LibcInternal::Cnd_init_with_name);
	LIB_FUNC("7yMFgcS8EPA", LibcInternal::Cnd_destroy);
	LIB_FUNC("LyMFgcS8EPA", LibcInternal::Cnd_destroy);
	LIB_FUNC("0uuqgRz9qfo", LibcInternal::Cnd_signal);
	LIB_FUNC("EuuqgRz9qfo", LibcInternal::Cnd_signal);
	LIB_FUNC("VsP3daJgmVA", LibcInternal::Cnd_broadcast);
	LIB_FUNC("FsP3daJgmVA", LibcInternal::Cnd_broadcast);
	LIB_FUNC("vEaqE-7IZYc", LibcInternal::Cnd_wait);
	LIB_FUNC("PEaqE-7IZYc", LibcInternal::Cnd_wait);
	LIB_FUNC("McaImWKXong", LibcInternal::Cnd_timedwait);
	// misc libc
	LIB_FUNC("2HnmKiLmV6s", LibcInternal::Atomic_fetch_sub_4); // _Atomic_fetch_sub_4
	LIB_FUNC("5TjaJwkLWxE", LibcInternal::bcmp);               // bcmp
	LIB_FUNC("8u8lPzUEq+U", LibcInternal::memchr);             // memchr
	LIB_FUNC("xEszJVGpybs", LibcInternal::sprintf_s);          // sprintf_s
	LIB_FUNC("tcVi5SivF7Q", LibcInternal::sprintf);
	// Dinkumware std::thread launch shim (std::_Pad)
	LIB_FUNC("dGYo9mE8K2A", LibcInternal::Pad_ctor);
	LIB_FUNC("NGYo9mE8K2A", LibcInternal::Pad_ctor);
	LIB_FUNC("uhnb6dnXOnc", LibcInternal::Pad_ctor_named);   // std::_Pad::_Pad(const char*)
	LIB_FUNC("PBbZjsL6nfc", LibcInternal::Pad_Launch_named); // std::_Pad::_Launch(const char*, pthread**)
	LIB_FUNC("gjLRZgfb3i0", LibcInternal::Pad_dtor);
	LIB_FUNC("AjLRZgfb3i0", LibcInternal::Pad_dtor);
	LIB_FUNC("xZqiZvmcp9k", LibcInternal::Pad_Launch);
	LIB_FUNC("BZqiZvmcp9k", LibcInternal::Pad_Launch);
	LIB_FUNC("a-z7wxuYO2E", LibcInternal::Pad_Release);
	LIB_FUNC("K-z7wxuYO2E", LibcInternal::Pad_Release);

	// Dinkumware std::locale internals (classic "C" locale only)
	LIB_FUNC("9rMML086SEE", LibcInternal::locale_Init);            // std::locale::_Init()
	LIB_FUNC("hEQ2Yi4PJXA", LibcInternal::locale_Getgloballocale); // std::locale::_Getgloballocale()
	LIB_OBJECT("Qoo175Ig+-k", &LibcInternal::g_locale_classic_ptr); // std::_sceLibcClassicLocale
	LIB_FUNC("sUP1hBaouOw", LibcInternal::locale_Getpctype);        // _Getpctype
	LIB_FUNC("1uJgoVq3bQU", LibcInternal::locale_Getptolower);      // _Getptolower
	LIB_FUNC("rcQCUr0EaRU", LibcInternal::locale_Getptoupper);      // _Getptoupper
	LIB_FUNC("QW2jL1J5rwY", LibcInternal::locale_facet_Register);   // std::locale::facet::_Register()
	LIB_FUNC("hqi8yMOCmG0", LibcInternal::locale_Locinfo_ctor);     // std::_Locinfo::_Locinfo(char const*)
	LIB_FUNC("p6LrHjIQMdk", LibcInternal::locale_Locinfo_dtor);     // std::_Locinfo::~_Locinfo()
	LIB_FUNC("kALvdgEv5ME", LibcInternal::Locksyslock);             // _Locksyslock
	LIB_FUNC("9nf8joUTSaQ", LibcInternal::Unlocksyslock);           // _Unlocksyslock
	LIB_FUNC("iPBqs+YUUFw", LibcInternal::Atomic_fetch_add_4);      // _Atomic_fetch_add_4
	LIB_FUNC("cjZEuzHkgng", LibcInternal::Atomic_load_4);           // _Atomic_load_4
	LIB_FUNC("HMRMLOwOFIQ", LibcInternal::Atomic_store_4);          // _Atomic_store_4
	LIB_FUNC("qYhnoevd9bI", LibcInternal::StdTerminate);            // std::terminate
	LIB_FUNC("zr094EQ39Ww", LibcInternal::PureVirtual);             // __cxa_pure_virtual
	LIB_FUNC("jfRI3snge3o", LibcInternal::Thrd_sleep);              // _Thrd_sleep
	LIB_FUNC("Cj+Fw5q1tUo", LibcInternal::Xtime_get_ticks);         // _Xtime_get_ticks
	LIB_FUNC("0AgCOypbQ90", LibcInternal::Atomic_compare_exchange_weak_4); // _Atomic_compare_exchange_weak_4
	LIB_FUNC("MmbQukfxYJM", LibcInternal::Getenv);                  // getenv (libSceLibcInternal)
	LIB_FUNC("smbQukfxYJM", LibcInternal::Getenv);                  // getenv
	LIB_FUNC("np6xXcXEnXE", LibcInternal::Thrd_id);                 // _Thrd_id
	LIB_FUNC("YvmY5Jf0VYU", LibcInternal::Thrd_join);               // _Thrd_join
	LIB_FUNC("PsrRUg671K0", LibcInternal::Cxa_increment_exception_refcount); // __cxa_increment_exception_refcount
	LIB_FUNC("MQFPAqQPt1s", LibcInternal::Cxa_decrement_exception_refcount); // __cxa_decrement_exception_refcount
	LIB_FUNC("Q1BL70XVV0o", LibcInternal::uncaught_exception);      // std::uncaught_exception()
	LIB_OBJECT("1kZFcktOm+s", const_cast<uintptr_t*>(LibcInternal::g_num_put_char_vtable)); // _ZTVSt7num_put...
	LIB_OBJECT("E14mW8pVpoE", &LibcInternal::g_num_put_char_id);    // std::num_put<char>::id
	LIB_OBJECT("H4fcpQOpc08", &LibcInternal::g_locale_id_cnt);      // std::locale::id::_Id_cnt
	LIB_OBJECT("Cv+zC4EjGMA", &LibcInternal::g_ctype_char_id);      // std::ctype<char>::id
	LIB_OBJECT("aK1Ymf-NhAs", const_cast<uintptr_t*>(LibcInternal::g_codecvt_char_vtable));
	LIB_OBJECT("eVFYZnYNDo0", &LibcInternal::g_codecvt_char_id);
	LIB_OBJECT("FQ9NFbBHb5Y", &LibcInternal::g_bad_file_offset);
	LIB_OBJECT("wiR+rIcbnlc", LibcInternal::g_initial_file_position.data());
	LIB_OBJECT("5PfqUBaQf4g", &LibcInternal::g_cout);               // std::cout
	LIB_OBJECT("TVfbf1sXt0A", &LibcInternal::g_cerr);               // std::cerr
	LIB_OBJECT("jSquWN7i7lc", &LibcInternal::g_clog);               // std::clog
	LIB_FUNC("vU9svJtEnWc", LibcInternal::setw);                    // std::setw(int)
	LIB_FUNC("P8F2oavZXtY", LibcInternal::ios_base_dtor);           // std::ios_base::~ios_base()
	LIB_FUNC("3GPpjQdAMTw", LibcInternal::cxa_guard_acquire);       // __cxa_guard_acquire
	LIB_FUNC("HGPpjQdAMTw", LibcInternal::cxa_guard_acquire);       // __cxa_guard_acquire (alt)
	LIB_FUNC("9rAeANT2tyE", LibcInternal::cxa_guard_release);       // __cxa_guard_release
	LIB_FUNC("NrAeANT2tyE", LibcInternal::cxa_guard_release);       // __cxa_guard_release (alt)
	LIB_FUNC("2emaaluWzUw", LibcInternal::cxa_guard_abort);         // __cxa_guard_abort
	LIB_FUNC("GemaaluWzUw", LibcInternal::cxa_guard_abort);         // __cxa_guard_abort (alt)
	LIB_FUNC("NG1phipELJE", LibcInternal::set_terminate);           // std::set_terminate
	LIB_FUNC("MpxhMh8QFro", LibcInternal::fwrite);                  // fwrite
	LIB_FUNC("QrZZdJ8XsX0", LibcInternal::fputs);                   // fputs
	LIB_FUNC("aZK8lNei-Qw", LibcInternal::fputc);                   // fputc
	LIB_FUNC("fffwELXNVFA", LibcInternal::fprintf);                 // fprintf
	LIB_FUNC("vYWK2Pz8vGE", LibcInternal::Fiopen);                  // std::_Fiopen
	LIB_FUNC("PYWK2Pz8vGE", LibcInternal::Fiopen);                  // std::_Fiopen (libSceLibcInternal)
	LIB_FUNC("vZkmJmvqueY", LibcInternal::Lockfile);
	LIB_FUNC("0x7rx8TKy2Y", LibcInternal::Unlockfile);
	LIB_FUNC("AEuF3F2f8TA", LibcInternal::FileGetc);
	LIB_FUNC("-LFO7jhD5CE", LibcInternal::FileUngetc);
	LIB_FUNC("rQFVBXp-Cxg", LibcInternal::FileSeek);
	LIB_FUNC("SHlt7EhOtqA", LibcInternal::FileGetpos);
	LIB_FUNC("7PkSz+qnTto", LibcInternal::FileSetpos);
	LIB_FUNC("QMFyLoqNxIg", LibcInternal::FileSetbuf);
	LIB_FUNC("uodLYyUip20", LibcInternal::FileClose);
	LIB_FUNC("-hn1tcVHq5Q", LibcInternal::Mspace::Create);          // sceLibcMspaceCreate
	LIB_FUNC("W6SiVSiCDtI", LibcInternal::Mspace::Destroy);         // sceLibcMspaceDestroy
	LIB_FUNC("OJjm-QOIHlI", LibcInternal::Mspace::Malloc);          // sceLibcMspaceMalloc
	LIB_FUNC("Vla-Z+eXlxo", LibcInternal::Mspace::Free);            // sceLibcMspaceFree
	LIB_FUNC("LYo3GhIlB38", LibcInternal::Mspace::Calloc);          // sceLibcMspaceCalloc
	LIB_FUNC("gigoVHZvVPE", LibcInternal::Mspace::Realloc);         // sceLibcMspaceRealloc
	LIB_FUNC("iF1iQHzxBJU", LibcInternal::Mspace::Memalign);        // sceLibcMspaceMemalign
	LIB_FUNC("p6lrRW8-MLY", LibcInternal::Mspace::Reallocalign);    // sceLibcMspaceReallocalign
	LIB_FUNC("qWESlyXMI3E", LibcInternal::Mspace::PosixMemalign);   // sceLibcMspacePosixMemalign
	LIB_FUNC("fEoW6BJsPt4", LibcInternal::Mspace::MallocUsableSize);// sceLibcMspaceMallocUsableSize
	LIB_FUNC("mfHdJTIvhuo", LibcInternal::Mspace::MallocStats);     // sceLibcMspaceMallocStats
	LIB_FUNC("k04jLXu3+Ic", LibcInternal::Mspace::MallocStatsFast); // sceLibcMspaceMallocStatsFast
	LIB_FUNC("pzUa7KEoydw", LibcInternal::Mspace::IsHeapEmpty);     // sceLibcMspaceIsHeapEmpty
	LIB_FUNC("gQX+4GDQjpM", LibcInternal::libc_malloc);             // malloc
	LIB_FUNC("tIhsqj0qsFE", LibcInternal::libc_free);               // free
	LIB_FUNC("Ujf3KzMvRmI", LibcInternal::libc_memalign);           // memalign
	LIB_FUNC("2X5agFjKxMc", LibcInternal::libc_calloc);             // calloc
	LIB_FUNC("Y7aJ1uydPMo", LibcInternal::libc_realloc);            // realloc
	LIB_FUNC("cVSk9y8URbc", LibcInternal::libc_posix_memalign);     // posix_memalign
	LIB_FUNC("cJWGxiQPmDQ", LibcInternal::libc_strsep);             // strsep
	LIB_FUNC("EMutwaQ34Jo", LibcInternal::libc_perror);            // perror
	LIB_FUNC("NDcSfcYZRC8", LibcInternal::libc_malloc_usable_size); // malloc_usable_size
	LIB_FUNC("RIa6GnWp+iU", LibcInternal::libc_strerror);           // strerror
	LIB_FUNC("SfQIZcqvvms", LibcInternal::libc_strlcpy);            // strlcpy
	LIB_FUNC("cpCOXWMgha0", LibcInternal::libc_rand);               // rand
	LIB_FUNC("VPbJwTCgME0", LibcInternal::libc_srand);              // srand
	LIB_FUNC("sPC7XE6hfFY", LibcInternal::libc_srandom);            // srandom
	LIB_FUNC("w1o05aHJT4c", LibcInternal::libc_random);             // random
	LIB_FUNC("lA94ZgT+vMM", LibcInternal::libc_isnanf);             // __isnanf
	LIB_FUNC("rDMyAf1Jhug", LibcInternal::libc_isinff);             // __isinff
	LIB_FUNC("Nmtr628eA3A", LibcInternal::libc_random_device);      // std::random_device
	LIB_FUNC("1Pk0qZQGeWo", LibcInternal::kyty_sscanf_std);         // sscanf
}

} // namespace LibcInternal

namespace LibC {

LIB_DEFINE(InitLibC_1) {
	LibcInternal::InitLibcInternal_1(s);

	LIB_OBJECT("P330P3dFF68", &LibC::g_need_flag);

	LIB_FUNC("uMei1W9uyNo", LibC::exit);
	LIB_FUNC("L1SBTkC+Cvw", LibC::abort);
	LIB_FUNC("9BcDykPmo1I", LibC::libc_error);
	LIB_FUNC("bzQExy189ZI", LibC::init_env);
	LIB_FUNC("8G2LB+A3rzg", LibC::atexit);
	LIB_FUNC("hcuQgD53UxM", LibC::libc_printf);
	LIB_FUNC("YQ0navp+YIc", LibC::puts);
	LIB_FUNC("M4YYbSFfJ8g", LibC::setenv);
	LIB_FUNC("wLlFkwG9UcQ", LibC::libc_time);
	LIB_FUNC("-VVn74ZyhEs", LibC::libc_difftime);
	LIB_FUNC("1mecP7RgI2A", LibC::libc_gmtime);
	LIB_FUNC("efhK-YSUYYQ", LibC::libc_localtime);
	LIB_FUNC("n7AepwR0s34", LibC::libc_mktime);
	LIB_FUNC("Av3zjWi64Kw", LibC::libc_strftime);
	LIB_FUNC("XKRegsFpEpk", LibC::catchReturnFromMain);
	LIB_FUNC("tsvEmnenz48", LibC::cxa_atexit);
	LIB_FUNC("H2e8t5ScQGc", LibC::cxa_finalize);
	LIB_FUNC("DiGVep5yB5w", LibC::std_execute_once);
}

} // namespace LibC

} // namespace Libs
