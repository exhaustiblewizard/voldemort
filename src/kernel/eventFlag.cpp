#include "kernel/eventFlag.h"

#include "common/assert.h"
#include "common/common.h"
#include "common/emulatorConfig.h"
#include "common/logging/log.h"
#include "common/stringUtils.h"
#include "common/threads.h"
#include "common/timer.h"
#include "libs/errno.h"
#include "libs/libs.h"

#include <mutex>
#include <string>
#include <unordered_map>

namespace Libs::LibKernel::EventFlag {

LIB_NAME("libkernel", "libkernel");

// Named event-flag registry. A SHARED (0x100) event flag is created by one process and OPENED by
// name from another (e.g. AgcCompositor opens the UMD sync flag that the graphics driver created).
// Kyty is single-process, so we index named flags here: sceKernelOpenEventFlag hands back the SAME
// object the creator made (so a wait on one side is woken by a set on the other), refcounted so the
// object outlives whichever side deletes first. If the name was never created (offline peer), Open
// creates a fresh process-local flag so the caller still gets a valid handle instead of a null one.
namespace {
std::mutex                                          g_ef_reg_mutex;
std::unordered_map<std::string, KernelEventFlagPrivate*> g_ef_by_name;
std::unordered_map<KernelEventFlagPrivate*, int>         g_ef_refs;

// Boot-status synthesis. On a real PS5 the SceSysCore process drives boot by progressively setting
// bits in the shared "SceBootStatusFlags" event flag; other processes block on them. We co-host
// SceShellCore + AgcCompositor WITHOUT SceSysCore (it spawns the shell via a process syscall we
// don't emulate and faults on its own unresolved imports), so we must synthesize those bits — else
// AgcCompositor's sceGnmCompositorServerInit BLOCKS forever on wait(0x2|0x8) and never becomes a
// live compositor. Bits (reversed from SceSysCore sub_390/35490/3BF50/42A0 + AgcCompositor sub_15CA0
// + SceShellCore BootStatus polls): 0x2 syscore-base, 0x8 (paired with 0x2 = compositor's wait
// mask 0xA), 0x4 compositor-ready (compositor sets it itself; pre-set is harmless), 0x40 mbus,
// 0x80 VSH_READY, 0x200 mdbg. Seed = "system already booted".
constexpr uint64_t kBootStatusSeed = 0x2 | 0x4 | 0x8 | 0x40 | 0x80 | 0x200; // 0xCE
uint64_t InitialPatternForSystemFlag(const char* name) {
	if (name != nullptr && std::string(name) == "SceBootStatusFlags") {
		return kBootStatusSeed;
	}
	return 0;
}
} // namespace

class KernelEventFlagPrivate {
public:
	enum class Result { Ok, AlreadyWaiting, TimedOut, Canceled, Deleted };

	enum class ClearMode { None, All, Bits };

	enum class WaitMode { And, Or };

	KernelEventFlagPrivate(const std::string& name, bool single, bool /*fifo*/, uint64_t bits)
	    : m_name(name), m_single_thread(single), m_bits(bits) {}
	virtual ~KernelEventFlagPrivate();

	KYTY_CLASS_NO_COPY(KernelEventFlagPrivate);

	void   Set(uint64_t bits);
	void   Clear(uint64_t bits);
	void   Cancel(uint64_t bits, int* num_waiting_threads);
	Result Wait(uint64_t bits, WaitMode wait_mode, ClearMode clear_mode, uint64_t* result,
	            uint32_t* ptr_micros);

	Result Poll(uint64_t bits, WaitMode wait_mode, ClearMode clear_mode, uint64_t* result) {
		uint32_t micros = 0;
		return Wait(bits, wait_mode, clear_mode, result, &micros);
	}

private:
	enum class Status { Set, Canceled, Deleted };

	Common::Mutex   m_mutex;
	Common::CondVar m_cond_var;
	Status          m_status          = Status::Set;
	int             m_waiting_threads = 0;
	std::string     m_name;
	bool            m_single_thread = false;
	uint64_t        m_bits          = 0;
	void Trace(const char* operation, uint64_t requested) const;
};

void KernelEventFlagPrivate::Trace(const char* operation, uint64_t requested) const {
	static const bool enabled = [] {
		const auto& environment = Config::GetGuestEnvironment();
		const auto value = environment.find("KYTY_COMPOSITOR_SYNC_TRACE");
		return value != environment.end() && value->second == "1";
	}();
	if (enabled && m_name.starts_with("SceCompositorMultiEVF_")) {
		LOGF("Compositor sync: %s %s requested=0x%" PRIx64 " bits=0x%" PRIx64
		     " waiters=%d thread=%d\n", m_name.c_str(), operation, requested, m_bits,
		     m_waiting_threads, Common::Thread::GetThreadIdUnique());
	}
}

namespace {

struct EventFlagWaitMode {
	KernelEventFlagPrivate::WaitMode  wait  = KernelEventFlagPrivate::WaitMode::And;
	KernelEventFlagPrivate::ClearMode clear = KernelEventFlagPrivate::ClearMode::None;
};

EventFlagWaitMode DecodeEventFlagWaitMode(uint32_t wait_mode) {
	EventFlagWaitMode mode;

	switch (wait_mode & 0xfu) {
		case 0x01: mode.wait = KernelEventFlagPrivate::WaitMode::And; break;
		case 0x02: mode.wait = KernelEventFlagPrivate::WaitMode::Or; break;
		default: EXIT("unknown mode: %u\n", wait_mode);
	}

	switch (wait_mode & 0xf0u) {
		case 0x00: mode.clear = KernelEventFlagPrivate::ClearMode::None; break;
		case 0x10: mode.clear = KernelEventFlagPrivate::ClearMode::All; break;
		case 0x20: mode.clear = KernelEventFlagPrivate::ClearMode::Bits; break;
		default: EXIT("unknown mode: %u\n", wait_mode);
	}

	return mode;
}

} // namespace

KernelEventFlagPrivate::~KernelEventFlagPrivate() {
	Common::LockGuard lock(m_mutex);

	while (m_status != Status::Set) {
		m_mutex.Unlock();
		Common::Thread::SleepMicro(10);
		m_mutex.Lock();
	}

	m_status = Status::Deleted;

	m_cond_var.SignalAll();

	while (m_waiting_threads > 0) {
		m_mutex.Unlock();
		Common::Thread::SleepMicro(10);
		m_mutex.Lock();
	}
}

KernelEventFlagPrivate::Result KernelEventFlagPrivate::Wait(uint64_t bits, WaitMode wait_mode,
                                                            ClearMode clear_mode, uint64_t* result,
                                                            uint32_t* ptr_micros) {
	Common::LockGuard lock(m_mutex);
	Trace("wait", bits);

	uint32_t micros     = 0;
	bool     infinitely = true;
	if (ptr_micros != nullptr) {
		micros     = *ptr_micros;
		infinitely = false;
	}

	uint32_t      elapsed = 0;
	Common::Timer t;
	t.Start();

	auto update_timeout = [&]() {
		if (ptr_micros != nullptr) {
			*ptr_micros = (elapsed >= micros ? 0 : micros - elapsed);
		}
	};

	if (m_single_thread && m_waiting_threads > 0) {
		return Result::AlreadyWaiting;
	}

	while (!((wait_mode == WaitMode::And && (m_bits & bits) == bits) ||
	         (wait_mode == WaitMode::Or && (m_bits & bits) != 0))) {
		if ((elapsed >= micros && !infinitely)) {
			if (result != nullptr) {
				*result = m_bits;
			}
			update_timeout();
			return Result::TimedOut;
		}

		m_waiting_threads++;

		if (infinitely) {
			m_cond_var.Wait(&m_mutex);
		} else {
			m_cond_var.WaitFor(&m_mutex, micros - elapsed);
		}

		m_waiting_threads--;

		elapsed = static_cast<uint32_t>(t.GetTimeS() * 1000000.0);

		switch (m_status) {
			case Status::Canceled:
				if (result != nullptr) {
					*result = m_bits;
				}
				update_timeout();
				return Result::Canceled;
			case Status::Deleted:
				if (result != nullptr) {
					*result = m_bits;
				}
				update_timeout();
				return Result::Deleted;
			case Status::Set: break;
		}
	}

	if (result != nullptr) {
		*result = m_bits;
	}
	update_timeout();

	switch (clear_mode) {
		case ClearMode::All: m_bits = 0; break;
		case ClearMode::Bits: m_bits &= ~bits; break;
		case ClearMode::None: break;
	}
	Trace("received", bits);

	return Result::Ok;
}

void KernelEventFlagPrivate::Set(uint64_t bits) {
	Common::LockGuard lock(m_mutex);

	EXIT_NOT_IMPLEMENTED(m_status == Status::Deleted);

	while (m_status != Status::Set) {
		m_mutex.Unlock();
		Common::Thread::SleepMicro(10);
		m_mutex.Lock();
	}

	m_bits |= bits;
	Trace("set", bits);

	m_cond_var.SignalAll();
}

void KernelEventFlagPrivate::Clear(uint64_t bits) {
	Common::LockGuard lock(m_mutex);

	EXIT_NOT_IMPLEMENTED(m_status == Status::Deleted);

	while (m_status != Status::Set) {
		m_mutex.Unlock();
		Common::Thread::SleepMicro(10);
		m_mutex.Lock();
	}

	m_bits &= bits;
	Trace("clear", bits);
}

void KernelEventFlagPrivate::Cancel(uint64_t bits, int* num_waiting_threads) {
	Common::LockGuard lock(m_mutex);

	EXIT_NOT_IMPLEMENTED(m_status == Status::Deleted);

	while (m_status != Status::Set) {
		m_mutex.Unlock();
		Common::Thread::SleepMicro(10);
		m_mutex.Lock();
	}

	if (num_waiting_threads != nullptr) {
		*num_waiting_threads = m_waiting_threads;
	}

	m_status = Status::Canceled;
	m_bits   = bits;

	m_cond_var.SignalAll();

	while (m_waiting_threads > 0) {
		m_mutex.Unlock();
		Common::Thread::SleepMicro(10);
		m_mutex.Lock();
	}

	m_status = Status::Set;
}

int KYTY_SYSV_ABI KernelCreateEventFlag(KernelEventFlag* ef, const char* name, uint32_t attr,
                                        uint64_t init_pattern, const void* param) {
	PRINT_NAME();

	if (ef == nullptr || name == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	// 0x100 = SCE_KERNEL_EVF_ATTR_SHARED (inter-process event flag, used by the vsh/ShellCore
	// processes e.g. "SceAutoMountUsbMass"). Kyty is single-process, so accept it and treat the
	// flag as process-local (the shared semantics degrade to normal here).
	if (param != nullptr || (attr & ~0x133u) != 0) {
		return KERNEL_ERROR_EINVAL;
	}

	bool single = true;
	bool fifo   = true;

	switch (attr & 0x0fu) {
		case 0x00:
		case 0x01: fifo = true; break;
		case 0x02: fifo = false; break;
		default: return KERNEL_ERROR_EINVAL;
	}

	switch (attr & 0xf0u) {
		case 0x00:
		case 0x10: single = true; break;
		case 0x20: single = false; break;
		default: return KERNEL_ERROR_EINVAL;
	}

	// If a guest creates a known system flag, OR-in the synthesized boot-status bits so consumers
	// that block on them (e.g. AgcCompositor) proceed even though the usual setter (SceSysCore) is
	// not co-hosted.
	*ef = new KernelEventFlagPrivate(std::string(name), single, fifo,
	                                 init_pattern | InitialPatternForSystemFlag(name));

	{
		std::lock_guard<std::mutex> lock(g_ef_reg_mutex);
		g_ef_by_name[std::string(name)] = *ef;
		g_ef_refs[*ef]                  = 1;
	}

	LOGF("\tEventFlag create: %s\n", name);

	return OK;
}

// sceKernelOpenEventFlag(SceKernelEventFlag* ef, const char* name): open an existing named (shared)
// event flag. NID 1vDaenmJtyA. Returns the SAME object the creator made (refcount bumped); if the
// name is unknown offline, create a fresh process-local flag so the handle is valid.
int KYTY_SYSV_ABI KernelOpenEventFlag(KernelEventFlag* ef, const char* name) {
	PRINT_NAME();

	if (ef == nullptr || name == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	std::lock_guard<std::mutex> lock(g_ef_reg_mutex);
	auto                        it = g_ef_by_name.find(std::string(name));
	if (it != g_ef_by_name.end()) {
		*ef = it->second;
		g_ef_refs[*ef]++;
		LOGF("\tEventFlag open (shared): %s\n", name);
		return OK;
	}

	// Unknown name: the creating process does not exist offline. Give the caller a valid flag,
	// seeded with any synthesized boot-status bits so blocked system processes make progress.
	uint64_t seed                   = InitialPatternForSystemFlag(name);
	// No AutoMounter daemon or expansion M.2 device is hosted here. ShellUI's
	// GetM2SystemModalDialogTypeFlags waits for any bit in 0xff on this flag:
	// bit 1 completes the scan without a storage dialog, while bits 2..128
	// request removal/format/fsck/error dialogs. Publish the absent-device
	// result only for an offline open; a real creator keeps its own pattern.
	if (std::string(name) == "SceAutoMounterUIM2Evf") { seed = 1; }
	// Every co-hosted system client can wait on the shared boot-status flag.
	const bool single = std::string(name) != "SceBootStatusFlags";
	*ef                             = new KernelEventFlagPrivate(std::string(name), single, true, seed);
	g_ef_by_name[std::string(name)] = *ef;
	g_ef_refs[*ef]                  = 1;
	LOGF("\tEventFlag open (created offline): %s (seed=0x%" PRIx64 ")\n", name, seed);
	return OK;
}

int KYTY_SYSV_ABI KernelDeleteEventFlag(KernelEventFlag ef) {
	PRINT_NAME();

	if (ef == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	{
		std::lock_guard<std::mutex> lock(g_ef_reg_mutex);
		auto                        r = g_ef_refs.find(ef);
		if (r != g_ef_refs.end()) {
			if (--r->second > 0) {
				return OK; // still opened elsewhere; keep the shared object alive
			}
			g_ef_refs.erase(r);
			for (auto it = g_ef_by_name.begin(); it != g_ef_by_name.end();) {
				it = (it->second == ef) ? g_ef_by_name.erase(it) : std::next(it);
			}
		}
	}

	delete ef;

	return OK;
}

int KYTY_SYSV_ABI KernelWaitEventFlag(KernelEventFlag ef, uint64_t bit_pattern, uint32_t wait_mode,
                                      uint64_t* result_pat, KernelUseconds* timeout) {
	PRINT_NAME();

	if (ef == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	if (bit_pattern == 0) {
		return KERNEL_ERROR_EINVAL;
	}

	const auto mode   = DecodeEventFlagWaitMode(wait_mode);
	auto       result = ef->Wait(bit_pattern, mode.wait, mode.clear, result_pat, timeout);

	int ret = OK;

	switch (result) {
		case KernelEventFlagPrivate::Result::Ok: ret = OK; break;
		case KernelEventFlagPrivate::Result::AlreadyWaiting: ret = KERNEL_ERROR_EPERM; break;
		case KernelEventFlagPrivate::Result::TimedOut: ret = KERNEL_ERROR_ETIMEDOUT; break;
		case KernelEventFlagPrivate::Result::Canceled: ret = KERNEL_ERROR_ECANCELED; break;
		case KernelEventFlagPrivate::Result::Deleted: ret = KERNEL_ERROR_EACCES; break;
	}

	return ret;
}

int KYTY_SYSV_ABI KernelPollEventFlag(KernelEventFlag ef, uint64_t bit_pattern, uint32_t wait_mode,
                                      uint64_t* result_pat) {
	PRINT_NAME();

	if (ef == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	if (bit_pattern == 0) {
		return KERNEL_ERROR_EINVAL;
	}

	const auto mode   = DecodeEventFlagWaitMode(wait_mode);
	auto       result = ef->Poll(bit_pattern, mode.wait, mode.clear, result_pat);

	int ret = OK;

	switch (result) {
		case KernelEventFlagPrivate::Result::Ok: ret = OK; break;
		case KernelEventFlagPrivate::Result::AlreadyWaiting: ret = KERNEL_ERROR_EPERM; break;
		case KernelEventFlagPrivate::Result::TimedOut:
		case KernelEventFlagPrivate::Result::Canceled:
		case KernelEventFlagPrivate::Result::Deleted: ret = KERNEL_ERROR_EBUSY; break;
	}

	return ret;
}

int KYTY_SYSV_ABI KernelSetEventFlag(KernelEventFlag ef, uint64_t bit_pattern) {
	PRINT_NAME();

	if (ef == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	ef->Set(bit_pattern);

	return OK;
}

int KYTY_SYSV_ABI KernelClearEventFlag(KernelEventFlag ef, uint64_t bit_pattern) {
	PRINT_NAME();

	if (ef == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	ef->Clear(bit_pattern);

	return OK;
}

int KYTY_SYSV_ABI KernelCancelEventFlag(KernelEventFlag ef, uint64_t set_pattern,
                                        int* num_wait_threads) {
	PRINT_NAME();

	if (ef == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	ef->Cancel(set_pattern, num_wait_threads);

	return OK;
}

} // namespace Libs::LibKernel::EventFlag
