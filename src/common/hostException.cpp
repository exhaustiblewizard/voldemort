#include "common/hostException.h"
#include "common/threads.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#include <windows.h> // IWYU pragma: keep
#else
#include <algorithm>
#include <csignal>
#include <cstdlib>
#include <initializer_list>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/ucontext.h>
#else
#include <ucontext.h> // IWYU pragma: keep
#endif
#endif

// IWYU pragma: no_include <errhandlingapi.h>
// IWYU pragma: no_include <excpt.h>
// IWYU pragma: no_include <minwinbase.h>
// IWYU pragma: no_include <minwindef.h>
// IWYU pragma: no_include <wtypes.h>

namespace Common::HostException {

#if !defined(__APPLE__)

static std::atomic<Handler> g_handler {nullptr};
static std::atomic_uint32_t g_install_state {0};

static_assert(decltype(g_handler)::is_always_lock_free);
static_assert(decltype(g_install_state)::is_always_lock_free);
#endif

#if KYTY_PLATFORM == KYTY_PLATFORM_LINUX

// macOS uses the same POSIX platform setting and needs a signal stack too.
class ThreadSignalStack {
public:
	ThreadSignalStack() {
		const auto page_size = static_cast<size_t>(::getpagesize());
		const auto stack_size =
		    (std::max<size_t>(64 * 1024, MINSIGSTKSZ) + page_size - 1) & ~(page_size - 1);
		if (::posix_memalign(&m_memory, page_size, stack_size) != 0) {
			return;
		}

		stack_t stack {};
		stack.ss_sp   = m_memory;
		stack.ss_size = stack_size;
		if (::sigaltstack(&stack, &m_previous) != 0) {
			std::free(m_memory);
			m_memory = nullptr;
		}
	}

	~ThreadSignalStack() {
		if (m_memory != nullptr && ::sigaltstack(&m_previous, nullptr) == 0) {
			std::free(m_memory);
		}
	}

	[[nodiscard]] bool IsInitialized() const { return m_memory != nullptr; }

	KYTY_CLASS_NO_COPY(ThreadSignalStack)

private:
	void*   m_memory = nullptr;
	stack_t m_previous {};
};

bool InitializeThreadSignalStack() {
	// Keep fault handling off guest stacks, which GPU tracking can make read-only.
	thread_local ThreadSignalStack signal_stack;
	return signal_stack.IsInitialized();
}

#endif

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS

static LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS exception) noexcept {
	// The collector must not suspend a guest while the VEH holds CRT logging
	// locks. GPU tracking faults can need those locks before HandleFault's guard.
	Common::HostCriticalScope critical;
	auto* exception_record = exception->ExceptionRecord;
	if ((exception_record->ExceptionCode == 0xC0000374u ||
	     (exception_record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
	      exception->ContextRecord->Rip >= 0x700000000000ull)) &&
	    std::getenv("KYTY_HOST_FAULT_STACK") != nullptr) {
		// Read through the OS rather than dereferencing a damaged stack. Raw
		// candidates remain useful across guest frames without Windows unwind data.
		const auto* ctx = exception->ContextRecord;
		std::fprintf(stderr, "[KYTY][heap fault] tid=%lu rsp=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx\n",
		             GetCurrentThreadId(), ctx->Rsp, ctx->Rbx, ctx->Rcx, ctx->Rdx, ctx->Rsi, ctx->Rdi);
		for (size_t i = 0; i < 512; ++i) {
			uint64_t value = 0;
			SIZE_T read = 0;
			const auto address = ctx->Rsp + i * sizeof(value);
			if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address),
			                       &value, sizeof(value), &read) || read != sizeof(value)) { break; }
			if ((value >= 0x140000000ull && value < 0x141000000ull) ||
			    (value >= 0x900000000ull && value < 0x1000000000ull)) {
				std::fprintf(stderr, "[KYTY][heap fault] stack+%zx=%llx\n", i * sizeof(value), value);
			}
		}
		std::fflush(stderr);
	}

	if (exception_record->ExceptionCode == DBG_PRINTEXCEPTION_C ||
	    exception_record->ExceptionCode == DBG_PRINTEXCEPTION_WIDE_C) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	if (exception_record->ExceptionCode == 0x406D1388) {
		// Set a thread name.
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	// [KYTY-DIAG] Log every first-chance exception (code/address/rip) so a hard exit whose cause
	// is neither an access violation nor ud2 (which the guest-fault handler already reports) can
	// still be identified — e.g. a C++ exception (0xE06D7363) unwinding to death. For MSVC C++
	// throws we also decode the thrown type's mangled name from the throw record. Capped to avoid
	// runaway; remove once the startup crash is diagnosed.
	{
		static std::atomic<int> s_diag_count {0};
		if (s_diag_count.fetch_add(1, std::memory_order_relaxed) < 256) {
			char type_name[256] = "";
			if (exception_record->ExceptionCode == 0xE06D7363u && exception_record->NumberParameters >= 4 &&
			    exception_record->ExceptionInformation[0] == 0x19930520u) {
				const auto base       = exception_record->ExceptionInformation[3];
				const auto throw_info = exception_record->ExceptionInformation[2];
				if (base != 0 && throw_info != 0) {
					const auto* ti  = reinterpret_cast<const int*>(throw_info);
					const auto  cta = base + static_cast<uint64_t>(static_cast<uint32_t>(ti[3]));
					const auto* cta_p = reinterpret_cast<const int*>(cta);
					if (cta_p[0] > 0) {
						const auto  ct   = base + static_cast<uint64_t>(static_cast<uint32_t>(cta_p[1]));
						const auto* ct_p = reinterpret_cast<const int*>(ct);
						const auto  td   = base + static_cast<uint64_t>(static_cast<uint32_t>(ct_p[1]));
						const char* nm   = reinterpret_cast<const char*>(td + 16); // TypeDescriptor::name
						std::snprintf(type_name, sizeof(type_name), " type='%s'", nm);
					}
				}
			}
			std::fprintf(stderr, "[KYTY][VEH] first-chance exc code=0x%08lX addr=%p rip=0x%016llX%s\n",
			             static_cast<unsigned long>(exception_record->ExceptionCode),
			             exception_record->ExceptionAddress,
			             static_cast<unsigned long long>(exception->ContextRecord->Rip), type_name);
			std::fflush(stderr);
			if (exception_record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
				const auto* ctx = exception->ContextRecord;
				std::fprintf(stderr, "[KYTY][VEH] access=%llu target=0x%016llX rax=0x%016llX rdi=0x%016llX rsi=0x%016llX rsp=0x%016llX\n",
				             static_cast<unsigned long long>(exception_record->ExceptionInformation[0]),
				             static_cast<unsigned long long>(exception_record->ExceptionInformation[1]),
				             static_cast<unsigned long long>(ctx->Rax), static_cast<unsigned long long>(ctx->Rdi),
				             static_cast<unsigned long long>(ctx->Rsi), static_cast<unsigned long long>(ctx->Rsp));
				std::fflush(stderr);
			}
		}
	}

	ExceptionInfo info {};
	info.exception_address = reinterpret_cast<uint64_t>(exception_record->ExceptionAddress);
	info.native_code       = exception_record->ExceptionCode;
	info.native_context    = exception->ContextRecord;

	if (exception_record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		info.type = ExceptionType::AccessViolation;
		switch (exception_record->ExceptionInformation[0]) {
			case 0: info.access_violation_type = AccessViolationType::Read; break;
			case 1: info.access_violation_type = AccessViolationType::Write; break;
			case 8: info.access_violation_type = AccessViolationType::Execute; break;
			default: info.access_violation_type = AccessViolationType::Unknown; break;
		}
		info.access_violation_vaddr = exception_record->ExceptionInformation[1];
	} else if (exception_record->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
		info.type = ExceptionType::IllegalInstruction;
	} else {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	info.rax = exception->ContextRecord->Rax;
	info.rbx = exception->ContextRecord->Rbx;
	info.rcx = exception->ContextRecord->Rcx;
	info.rdx = exception->ContextRecord->Rdx;
	info.rsi = exception->ContextRecord->Rsi;
	info.rdi = exception->ContextRecord->Rdi;
	info.rbp = exception->ContextRecord->Rbp;
	info.rsp = exception->ContextRecord->Rsp;
	info.r8  = exception->ContextRecord->R8;
	info.r9  = exception->ContextRecord->R9;
	info.r10 = exception->ContextRecord->R10;
	info.r11 = exception->ContextRecord->R11;
	info.r12 = exception->ContextRecord->R12;
	info.r13 = exception->ContextRecord->R13;
	info.r14 = exception->ContextRecord->R14;
	info.r15 = exception->ContextRecord->R15;

	const auto handler = g_handler.load(std::memory_order_acquire);
	if (handler != nullptr && handler(info)) {
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

#elif defined(__APPLE__)

static std::atomic<Handler> g_handler {nullptr};
static std::atomic_uint32_t g_install_state {0};

static_assert(decltype(g_handler)::is_always_lock_free);
static_assert(decltype(g_install_state)::is_always_lock_free);

// Translate the x86-64 page-fault error code (mcontext __es.__err) into an access type.
// bit 1 (0x2) = write, bit 4 (0x10) = instruction fetch, otherwise a read.
static AccessViolationType DecodeAccess(uint64_t err) {
	if ((err & 0x10u) != 0) {
		return AccessViolationType::Execute;
	}
	if ((err & 0x2u) != 0) {
		return AccessViolationType::Write;
	}
	return AccessViolationType::Read;
}

// POSIX signal handler that mirrors the Windows vectored handler: build an ExceptionInfo
// from the mcontext and dispatch. A resolved fault (handler returns true) simply returns,
// re-executing the faulting instruction against the now-fixed protection. An unresolved
// fault restores the default disposition so the retry terminates the process.
static void SignalHandler(int sig, siginfo_t* si, void* uctx) {
	auto*       uc = static_cast<ucontext_t*>(uctx);
	const auto* mc = uc->uc_mcontext;
	const auto& ss = mc->__ss;

	ExceptionInfo info {};
	info.exception_address = ss.__rip;
	info.native_code       = static_cast<uint32_t>(si->si_code);
	info.native_context    = uctx;

	if (sig == SIGILL) {
		info.type = ExceptionType::IllegalInstruction;
	} else {
		info.type                   = ExceptionType::AccessViolation;
		info.access_violation_type  = DecodeAccess(mc->__es.__err);
		info.access_violation_vaddr = reinterpret_cast<uint64_t>(si->si_addr);
	}

	info.rax = ss.__rax;
	info.rbx = ss.__rbx;
	info.rcx = ss.__rcx;
	info.rdx = ss.__rdx;
	info.rsi = ss.__rsi;
	info.rdi = ss.__rdi;
	info.rbp = ss.__rbp;
	info.rsp = ss.__rsp;
	info.r8  = ss.__r8;
	info.r9  = ss.__r9;
	info.r10 = ss.__r10;
	info.r11 = ss.__r11;
	info.r12 = ss.__r12;
	info.r13 = ss.__r13;
	info.r14 = ss.__r14;
	info.r15 = ss.__r15;

	const auto handler = g_handler.load(std::memory_order_acquire);
	if (handler != nullptr && handler(info)) {
		return; // retry the faulting instruction against the fixed mapping
	}

	// Unresolved: restore the default action so the re-executed instruction terminates.
	struct sigaction dfl {};
	dfl.sa_handler = SIG_DFL;
	sigemptyset(&dfl.sa_mask);
	sigaction(sig, &dfl, nullptr);
}

#else

// x86-64 page-fault error bits.
constexpr uint64_t PAGE_FAULT_ERROR_WRITE       = 0x02;
constexpr uint64_t PAGE_FAULT_ERROR_INSTRUCTION = 0x10;

// Let the kernel handle an unresolved fault on retry.
static void ChainToDefault(int signal_number) noexcept {
	struct sigaction restore {};
	restore.sa_handler = SIG_DFL;
	sigemptyset(&restore.sa_mask);
	restore.sa_flags = 0;
	::sigaction(signal_number, &restore, nullptr);
}

static void SignalHandler(int signal_number, siginfo_t* signal_info, void* native_context) {
	auto* context = static_cast<ucontext_t*>(native_context);
	auto* gregs   = context->uc_mcontext.gregs;

	ExceptionInfo info {};
	info.exception_address = static_cast<uint64_t>(gregs[REG_RIP]);
	info.native_code       = static_cast<uint32_t>(signal_number);
	info.native_context    = context;

	if (signal_number == SIGSEGV || signal_number == SIGBUS) {
		info.type             = ExceptionType::AccessViolation;
		const auto error_code = static_cast<uint64_t>(gregs[REG_ERR]);
		if ((error_code & PAGE_FAULT_ERROR_INSTRUCTION) != 0) {
			info.access_violation_type = AccessViolationType::Execute;
		} else if ((error_code & PAGE_FAULT_ERROR_WRITE) != 0) {
			info.access_violation_type = AccessViolationType::Write;
		} else {
			info.access_violation_type = AccessViolationType::Read;
		}
		info.access_violation_vaddr = reinterpret_cast<uint64_t>(signal_info->si_addr);
	} else if (signal_number == SIGILL) {
		info.type = ExceptionType::IllegalInstruction;
	} else {
		ChainToDefault(signal_number);
		return;
	}

	info.rax = static_cast<uint64_t>(gregs[REG_RAX]);
	info.rbx = static_cast<uint64_t>(gregs[REG_RBX]);
	info.rcx = static_cast<uint64_t>(gregs[REG_RCX]);
	info.rdx = static_cast<uint64_t>(gregs[REG_RDX]);
	info.rsi = static_cast<uint64_t>(gregs[REG_RSI]);
	info.rdi = static_cast<uint64_t>(gregs[REG_RDI]);
	info.rbp = static_cast<uint64_t>(gregs[REG_RBP]);
	info.rsp = static_cast<uint64_t>(gregs[REG_RSP]);
	info.r8  = static_cast<uint64_t>(gregs[REG_R8]);
	info.r9  = static_cast<uint64_t>(gregs[REG_R9]);
	info.r10 = static_cast<uint64_t>(gregs[REG_R10]);
	info.r11 = static_cast<uint64_t>(gregs[REG_R11]);
	info.r12 = static_cast<uint64_t>(gregs[REG_R12]);
	info.r13 = static_cast<uint64_t>(gregs[REG_R13]);
	info.r14 = static_cast<uint64_t>(gregs[REG_R14]);
	info.r15 = static_cast<uint64_t>(gregs[REG_R15]);

	const auto handler = g_handler.load(std::memory_order_acquire);
	if (handler != nullptr && handler(info)) {
		return;
	}

	ChainToDefault(signal_number);
}

#endif

bool InstallHandler(Handler handler) {
	if (handler == nullptr) {
		return false;
	}

	uint32_t expected_state = 0;
	if (!g_install_state.compare_exchange_strong(expected_state, 1, std::memory_order_acq_rel)) {
		return expected_state == 2 && g_handler.load(std::memory_order_acquire) == handler;
	}

	g_handler.store(handler, std::memory_order_release);

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (AddVectoredExceptionHandler(0, ExceptionFilter) == nullptr) {
		g_handler.store(nullptr, std::memory_order_release);
		g_install_state.store(0, std::memory_order_release);
		printf("AddVectoredExceptionHandler() failed\n");
		return false;
	}
#elif defined(__APPLE__)
	struct sigaction sa {};
	sa.sa_sigaction = SignalHandler;
	sa.sa_flags     = SA_SIGINFO | SA_ONSTACK;
	sigemptyset(&sa.sa_mask);
	// The guest signal-dispatch path (KernelRaiseException) interrupts threads with
	// SIGUSR1; block it while a fault is being resolved so a stop-the-world request
	// cannot preempt the handler between the protection fix and the retry.
	sigaddset(&sa.sa_mask, SIGUSR1);

	// macOS raises SIGBUS for protection faults on some paths and SIGSEGV on others;
	// SIGILL covers instructions the host cannot execute (routed to the x64 emulator).
	bool ok = sigaction(SIGSEGV, &sa, nullptr) == 0 && sigaction(SIGBUS, &sa, nullptr) == 0 &&
	          sigaction(SIGILL, &sa, nullptr) == 0;
	if (!ok) {
		g_handler.store(nullptr, std::memory_order_release);
		g_install_state.store(0, std::memory_order_release);
		printf("sigaction() failed to install the host fault handler\n");
		return false;
	}
#else
	struct sigaction action {};
	action.sa_sigaction = SignalHandler;
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;

	for (const int signal_number: {SIGSEGV, SIGBUS, SIGILL}) {
		if (::sigaction(signal_number, &action, nullptr) != 0) {
			g_handler.store(nullptr, std::memory_order_release);
			g_install_state.store(0, std::memory_order_release);
			printf("sigaction(%d) failed\n", signal_number);
			return false;
		}
	}
#endif

	g_install_state.store(2, std::memory_order_release);
	return true;
}

} // namespace Common::HostException
