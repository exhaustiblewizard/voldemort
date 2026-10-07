#include "loader/guestSyscall.h"
#include "loader/runtimeLinker.h"

#include "common/common.h"
#include "common/logging/log.h"

#include <Zydis/Zydis.h>
#include <atomic>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_set>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#include <windows.h> // IWYU pragma: keep
#else
#include <ucontext.h>
#endif

namespace Loader::GuestSyscall {

// Recorded `syscall` site addresses (now holding `ud2`). Written at load time by
// PatchSyscalls, read at fault time by TryEmulate.
static std::mutex                   g_sites_mutex;
static std::unordered_set<uint64_t> g_sites;

static bool IsSyscallSite(uint64_t rip) {
	std::lock_guard<std::mutex> lock(g_sites_mutex);
	return g_sites.find(rip) != g_sites.end();
}

uint64_t PatchSyscalls(uint64_t address, uint64_t size) {
	uint64_t     patched = 0;
	ZydisDecoder decoder {};
	if (!ZYAN_SUCCESS(
	        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
		LOGF("GuestSyscall: ZydisDecoderInit FAILED\n");
		return 0;
	}

	uint64_t decoded = 0;
	std::lock_guard<std::mutex> lock(g_sites_mutex);
	for (uint64_t offset = 0; offset < size;) {
		auto*                   code = reinterpret_cast<uint8_t*>(address + offset);
		ZydisDecodedInstruction instruction {};
		ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT] {};
		if (!ZYAN_SUCCESS(
		        ZydisDecoderDecodeFull(&decoder, code, size - offset, &instruction, operands))) {
			++offset;
			continue;
		}
		++decoded;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_SYSCALL && instruction.length == 2) {
			code[0] = 0x0fu; // ud2 — same 2-byte footprint as `syscall` (0F 05)
			code[1] = 0x0bu;
			g_sites.insert(address + offset);
			++patched;
		}
		offset += instruction.length;
	}

	if (patched != 0) {
		LOGF("GuestSyscall: patched %" PRIu64 " raw syscall site(s) in [0x%016" PRIx64
		     ", 0x%016" PRIx64 ") (scanned %" PRIu64 " insns)\n",
		     patched, address, address + size, decoded);
	}
	return patched;
}

// PS5 syscall number -> name, for readable traces (focused subset; others log as #N).
// Numbers are the PS5 column of the FW 7.00 devkit kernel syscall table.
static const char* SyscallName(uint64_t n) {
	switch (n) {
		case 1: return "exit";
		case 2: return "fork";
		case 3: return "read";
		case 4: return "write";
		case 5: return "open";
		case 6: return "close";
		case 7: return "wait4";
		case 20: return "getpid";
		case 23: return "setuid";
		case 24: return "getuid";
		case 25: return "geteuid";
		case 47: return "getgid";
		case 54: return "ioctl";
		case 59: return "execve";
		case 73: return "munmap";
		case 74: return "mprotect";
		case 97: return "socket";
		case 98: return "connect";
		case 202: return "__sysctl";
		case 232: return "clock_gettime";
		case 324: return "mlockall";
		case 340: return "sigprocmask";
		case 362: return "kqueue";
		case 363: return "kevent";
		case 378: return "nmount";
		case 432: return "thr_self";
		case 455: return "thr_new";
		case 477: return "mmap";
		case 478: return "lseek";
		case 486: return "cpuset_getid";
		case 487: return "cpuset_getaffinity";
		case 488: return "cpuset_setaffinity";
		case 532: return "regmgr_call";
		case 533: return "jitshm_create";
		case 538: return "evf_create";
		case 540: return "evf_open";
		case 542: return "evf_wait";
		case 544: return "evf_set";
		case 545: return "evf_clear";
		case 557: return "namedobj_create";
		case 585: return "is_in_sandbox";
		case 587: return "get_authinfo";
		case 588: return "mname";
		case 591: return "dynlib_dlsym";
		case 594: return "dynlib_load_prx";
		case 606: return "is_development_mode";
		case 622: return "ipmimgr_call";
		default: return nullptr;
	}
}
// Dispatch a guest syscall. Returns the result (goes to RAX); sets *error for the
// carry flag (FreeBSD signals failure via CF, with errno in RAX).
//
// INSTRUMENTATION PHASE: every syscall is traced (bounded) so we can read the exact
// sequence SceSysCore issues, then a handful of trivially-safe calls are serviced and
// everything else returns success(0). TODO phase 2: route open/read/mmap/kqueue/evf_*/
// namedobj/regmgr_call/ipmimgr_call/dynlib_*/thr_*/cpuset/sysctl to the existing Kyty
// kernel HLE, and the process-spawn syscall to the co-elf loader.
static uint64_t Dispatch(uint64_t num, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                         uint64_t a4, uint64_t a5, bool* error) {
	*error = false;
	(void)a3;
	(void)a4;
	(void)a5;

	static std::atomic<uint32_t> trace_count {0};
	if (trace_count.fetch_add(1, std::memory_order_relaxed) < 6000) {
		const char* name = SyscallName(num);
		LOGF("GuestSyscall: sys_%s (#%" PRIu64 ") a0=0x%" PRIx64 " a1=0x%" PRIx64 " a2=0x%" PRIx64
		     " a3=0x%" PRIx64 "\n",
		     name != nullptr ? name : "unknown", num, a0, a1, a2, a3);
	}

	switch (num) {
		case 4: // write(fd, buf, len)
			if ((a0 == 1 || a0 == 2) && a1 != 0 && a2 != 0) {
				Log::WriteToConsoleAndLog(
				    std::string(reinterpret_cast<const char*>(a1), static_cast<size_t>(a2)));
			}
			return a2;
		case 20: return RuntimeLinker::GetCurrentProcessId(); // getpid
		case 24:           // getuid
		case 25:           // geteuid
		case 47: return 0; // getgid
		case 202: return 0; // __sysctl -> success (TODO: honour oldp/oldlenp)
		default:
			return 0; // TODO phase 2: real routing
	}
}

bool TryEmulate(void* native_context) {
	if (native_context == nullptr) {
		return false;
	}
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	auto* ctx = static_cast<PCONTEXT>(native_context);
	if (!IsSyscallSite(ctx->Rip)) {
		return false;
	}
	bool           error = false;
	const uint64_t ret =
	    Dispatch(ctx->Rax, ctx->Rdi, ctx->Rsi, ctx->Rdx, ctx->R10, ctx->R8, ctx->R9, &error);
	ctx->Rax = ret;
	if (error) {
		ctx->EFlags |= 1u;
	} else {
		ctx->EFlags &= ~1u;
	}
	ctx->Rcx = ctx->Rip + 2; // `syscall` leaves return RIP in RCX, RFLAGS in R11
	ctx->R11 = ctx->EFlags;
	ctx->Rip += 2;
	return true;
#else
	auto* uc  = static_cast<ucontext_t*>(native_context);
	auto* r   = uc->uc_mcontext.gregs;
	if (!IsSyscallSite(static_cast<uint64_t>(r[REG_RIP]))) {
		return false;
	}
	bool           error = false;
	const uint64_t ret   = Dispatch(static_cast<uint64_t>(r[REG_RAX]), static_cast<uint64_t>(r[REG_RDI]),
	                                static_cast<uint64_t>(r[REG_RSI]), static_cast<uint64_t>(r[REG_RDX]),
	                                static_cast<uint64_t>(r[REG_R10]), static_cast<uint64_t>(r[REG_R8]),
	                                static_cast<uint64_t>(r[REG_R9]), &error);
	r[REG_RAX] = static_cast<greg_t>(ret);
	if (error) {
		r[REG_EFL] |= 1;
	} else {
		r[REG_EFL] &= ~static_cast<greg_t>(1);
	}
	r[REG_RCX] = r[REG_RIP] + 2;
	r[REG_R11] = r[REG_EFL];
	r[REG_RIP] += 2;
	return true;
#endif
}

} // namespace Loader::GuestSyscall
