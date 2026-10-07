#include <SDL3/SDL.h>
#include <SDL3/SDL_main.h>

#include "common/emulatorConfig.h"
#include "common/file.h"
#include "common/hostException.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "common/subsystems.h"
#include "common/threads.h"
#include "common/stringUtils.h"
#include "graphics/presentation/window/windowInternal.h"
#include "graphics/presentation/videoOut.h"
#include "graphics/presentation/flipSelection.h"
#include "kernel/fileSystem.h"
#include "kernel/memory.h"
#include "kernel/eventFlag.h"
#include "kernel/eventQueue.h"
#include "kernel/guestSignal.h"
#include "kernel/pthread.h"
#include "libs/libAvSetting.h"
#include "libs/controller.h"
#include "libs/padData.h"
#include "libs/audio.h"
#include "libs/errno.h"
#include "libs/network.h"
#include "loader/symbolDatabase.h"
#include "loader/runtimeLinker.h"
#include "libs/libLncUtil.h"
#include "libs/libUserService.h"
#include "loader/systemContent.h"
#include "loader/elf.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace Libs::LibKernelApr {
void InitLibKernel_1_Apr(Loader::SymbolDatabase *symbols);
}

namespace Libs {
void InitLibKernel_1(Loader::SymbolDatabase *symbols);
void InitUserService_1(Loader::SymbolDatabase *symbols);
extern "C" __attribute__((returns_twice)) KYTY_SYSV_ABI int kyty_guest_setjmp(void*);
extern "C" __attribute__((noreturn)) KYTY_SYSV_ABI void kyty_guest_longjmp(void*, int);
}

namespace Libs::LibNet {
void InitNet_1_Net(Loader::SymbolDatabase *symbols);
}

namespace Libs::Ipmi { void InitIpmi_1(Loader::SymbolDatabase*); }

namespace Libs::LibC {
void InitLibC_1(Loader::SymbolDatabase *symbols);
}

namespace Libs::LibcInternal {
void InitLibcInternal_1(Loader::SymbolDatabase *symbols);
}

namespace Libs::Posix {
void InitLibKernel_1_Posix(Loader::SymbolDatabase *symbols);
}

namespace Libs::Mbus {
void InitMbus_1(Loader::SymbolDatabase *symbols);
}
namespace Libs::SystemStateMgr { void InitSystemStateMgr_1(Loader::SymbolDatabase*); }
namespace Libs::LoginMgrServer { void InitLoginMgrServer_1(Loader::SymbolDatabase*); }

namespace Libs::LibGen5 {
void InitVideoOut_1(Loader::SymbolDatabase *symbols);
}

namespace Libs::RegMgr { void InitRegMgr_1(Loader::SymbolDatabase*); }
namespace Libs::FsInternalForVsh { void InitFsInternalForVsh_1(Loader::SymbolDatabase*); }
namespace Libs::AvSetting { void InitAvSetting_1(Loader::SymbolDatabase*); }
namespace Libs::RnpsAppMgr { void InitRnpsAppMgr_1(Loader::SymbolDatabase*); }
namespace Libs::UrlConfigResolver { void InitUrlConfigResolver_1(Loader::SymbolDatabase*); }
namespace Libs::LncUtil { void InitLncUtil_1(Loader::SymbolDatabase*); }
namespace Libs::LibJson2 { void InitNet_1_Json2(Loader::SymbolDatabase*); }
namespace Libs::Jsc { void InitJsc_1(Loader::SymbolDatabase*); }
namespace Libs::ShellCoreUtil { void InitShellCoreUtil_1(Loader::SymbolDatabase*); }
namespace Libs { void InitSysmodule_1(Loader::SymbolDatabase*); }

namespace {

struct NetworkCallbackProbe {
  int calls = 0;
  int id = 0;
  uint64_t bits = 0;
  uint64_t retain = 0;
  void* wait_argument = nullptr;
};
uint64_t KYTY_SYSV_ABI ProbeNetworkCallback(int id, uint64_t bits, void* argument, void* wait_argument) {
  auto& probe = *static_cast<NetworkCallbackProbe*>(argument);
  ++probe.calls;
  probe.id = id;
  probe.bits = bits;
  probe.wait_argument = wait_argument;
  return probe.retain;
}

struct AvCallbackProbe {
  int calls = 0;
  uint32_t handle = 0;
  std::array<uint32_t, 3> event {};
  void* wait_argument = nullptr;
};
void KYTY_SYSV_ABI ProbeAvCallback(uint32_t handle, void* argument, void* wait_argument,
                                 uint32_t process, uint32_t ticket, uint32_t reason) {
  auto& probe = *static_cast<AvCallbackProbe*>(argument);
  ++probe.calls;
  probe.handle = handle;
  probe.event = {process, ticket, reason};
  probe.wait_argument = wait_argument;
}

namespace FileSystem = Libs::LibKernel::FileSystem;

void Check(bool value, const char *text) {
  if (!value) {
    std::fprintf(stderr, "KernelFileSystemTests: failed: %s\n", text);
    std::abort();
  }
}

void CheckSymbolLookup() {
  Loader::SymbolDatabase symbols;
  Loader::SymbolResolve request {"sharedNID", "libSceA", 1, "libSceA", 1, 1, Loader::SymbolType::Func};
  symbols.Add(request, 0x1234, "first provider");
  for (int i = 0; i < 10000; ++i) {
    auto unrelated = request;
    unrelated.name = "unrelated" + std::to_string(i);
    symbols.Add(unrelated, 0x80000000 + i);
  }
  auto other = request;
  other.library = "libSceB";
  other.module = "libSceB";
  symbols.Add(other, 0x5678);
  auto object = request;
  object.type = Loader::SymbolType::Object;
  symbols.Add(object, 0xabcd);
  symbols.Add(request, 0x9999, "replacement exact provider");
  Check(symbols.Find(request)->vaddr == 0x9999,
        "an exact symbol registration uses the latest provider");
  Check(symbols.FindByNid("sharedNID", Loader::SymbolType::Func)->vaddr == 0x1234 &&
            symbols.FindByName("sharedNID", Loader::SymbolType::Func)->dbg_name == "first provider",
        "NID fallback retains insertion-order provider precedence after index growth");
  Check(symbols.FindByNid("sharedNID", Loader::SymbolType::Func, 0x5678)->vaddr == 0x5678 &&
            symbols.FindByNid("sharedNID", Loader::SymbolType::Func, 0xdead) == nullptr,
        "unload can still identify the specific exporting address");
  Check(symbols.FindByNid("sharedNID", Loader::SymbolType::Object)->vaddr == 0xabcd &&
            symbols.FindByNid("sharedNID", Loader::SymbolType::NoType) == nullptr &&
            symbols.FindByNid("sharedNI", Loader::SymbolType::Func) == nullptr &&
            symbols.FindByNid("absent", Loader::SymbolType::Func) == nullptr,
        "lookup distinguishes symbol type, full NID and missing imports");
}

void CheckSignalSets() {
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto resolve = [&](const char* nid) {
    const auto* symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "resolve signal set import");
    return symbol->vaddr;
  };
  using SignalSet = int(KYTY_SYSV_ABI *)(void*);
  using SignalBit = int(KYTY_SYSV_ABI *)(void*, int);
  auto empty_set = reinterpret_cast<SignalSet>(resolve("+F7C-hdk7+E"));
  auto fill_set = reinterpret_cast<SignalSet>(resolve("VkTAsrZDcJ0"));
  auto add_signal = reinterpret_cast<SignalBit>(resolve("JUimFtKe0Kc"));
  auto delete_signal = reinterpret_cast<SignalBit>(resolve("Nd-u09VFSCA"));
  auto contains_signal = reinterpret_cast<SignalBit>(resolve("JnNl8Xr-z4Y"));
  std::array<uint32_t, 6> signal_storage;
  signal_storage.fill(0xa5a5a5a5);
  auto* signal_set = signal_storage.data() + 1;
  Check(empty_set(signal_set) == 0 && add_signal(signal_set, 30) == 0 &&
        add_signal(signal_set, 128) == 0 && contains_signal(signal_set, 30) == 1 &&
        contains_signal(signal_set, 127) == 0 && delete_signal(signal_set, 30) == 0 &&
        contains_signal(signal_set, 30) == 0 && signal_storage.front() == 0xa5a5a5a5 &&
        signal_storage.back() == 0xa5a5a5a5,
        "signal set helpers initialize and mutate the full guest mask within its native size");
  Check(fill_set(signal_set) == 0 && contains_signal(signal_set, 128) == 1 &&
        add_signal(signal_set, 129) == -1 &&
        *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "signal set helpers validate signal bounds and report guest errno");
  Check(empty_set(nullptr) == -1 &&
        *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT &&
        contains_signal(signal_set, 0) == -1 &&
        *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "signal set helpers reject null storage and signal zero");
}

#if defined(_WIN32)
static int guest_fault_calls = 0;
static void KYTY_SYSV_ABI GuestFaultProbe(int signal, void* si, void* uc) {
  auto* info = static_cast<const uint64_t*>(si);
  auto* context = static_cast<uint64_t*>(uc);
  Check(signal == 11 && *static_cast<const int*>(si) == 11 && info[3] == 0,
        "SIGSEGV delivers the native signal number and null fault address");
  Check(context[15] == 0 && context[28] >= 0x900000000ull && context[31] != 0,
        "Mono context exposes RAX, RIP and RSP at verified native offsets");
  context[15] = 73;
  context[28] += 3;
  ++guest_fault_calls;
}
#endif

void CheckGuestFaultDelivery() {
#if defined(_WIN32)
  namespace Kernel = Libs::LibKernel;
  Kernel::Initialize();
  Kernel::PthreadInitSelfForMainThread();
  (void)Common::Singleton<Loader::RuntimeLinker>::Instance();
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* symbol = symbols.FindByNid("KiJEPEWRyUY", Loader::SymbolType::Func);
  Check(symbol != nullptr, "resolve native sigaction import");
  struct Action { void* handler; uint32_t flags; uint32_t mask[4]; };
  using Sigaction = int(KYTY_SYSV_ABI *)(int, const Action*, Action*);
  auto sigaction = reinterpret_cast<Sigaction>(symbol->vaddr);
  auto handler = GuestFaultProbe;
  Action action {reinterpret_cast<void*>(handler), 0x40, {}};
  Action old {};
  Check(sigaction(11, &action, &old) == 0, "install a guest SA_SIGINFO handler");
  CONTEXT native {};
  native.Rip = 0x900000100ull;
  native.Rsp = 0x100000;
  native.Rbx = 0x12345678;
  native.FltSave.MxCsr = 0x1f80;
  native.FltSave.XmmRegisters[9].Low = 0x1122334455667788ull;
  Common::HostException::ExceptionInfo fault;
  fault.type = Common::HostException::ExceptionType::AccessViolation;
  fault.exception_address = native.Rip;
  fault.native_context = &native;
  Loader::Program game;
  game.unique_id = 23;
  game.is_application = true;
  auto* owner = Loader::RuntimeLinker::GetCurrentProgram();
  Loader::RuntimeLinker::SetCurrentProgram(&game);
  Action game_previous {};
  Check(sigaction(11, nullptr, &game_previous) == 0 && game_previous.handler == nullptr &&
        !Kernel::KernelDispatchGuestFault(fault),
        "co-hosted game neither inherits nor invokes ShellUI's signal handler");
  Loader::RuntimeLinker::SetCurrentProgram(owner);
  fault.exception_address = reinterpret_cast<uint64_t>(handler);
  Check(!Kernel::KernelDispatchGuestFault(fault), "registered guest handler never receives a host code fault");
  fault.exception_address = native.Rip;
  Check(Kernel::KernelDispatchGuestFault(fault) && native.Rax == 73 &&
        native.Rip == 0x900000103ull && native.Rbx == 0x12345678 &&
        native.FltSave.MxCsr == 0x1f80 && native.FltSave.XmmRegisters[9].Low == 0x1122334455667788ull,
        "guest sigreturn applies handler changes and preserves integer and floating point state");
  Check(Common::HostException::InstallHandler(Kernel::KernelDispatchGuestFault),
        "install synchronous delivery in the real Windows VEH");
  auto* code = static_cast<uint8_t*>(VirtualAlloc(reinterpret_cast<void*>(0x900000000ull),
                                                4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
  Check(code == reinterpret_cast<void*>(0x900000000ull), "allocate guest fault regression code");
  const uint8_t null_read[] = {0x33, 0xc0, 0x48, 0x8b, 0x00, 0xc3}; // XOR EAX,EAX; MOV RAX,[RAX]; RET
  std::memcpy(code, null_read, sizeof(null_read));
  FlushInstructionCache(GetCurrentProcess(), code, sizeof(null_read));
  using Guest = uint64_t(KYTY_SYSV_ABI *)();
  Check(reinterpret_cast<Guest>(code)() == 73 && guest_fault_calls == 2,
        "actual guest access violation reaches its handler and resumes instead of terminating the host");
  VirtualFree(code, 0, MEM_RELEASE);
  Check(sigaction(11, &old, nullptr) == 0 && !Kernel::KernelDispatchGuestFault(fault),
        "restoring default disposition leaves an unhandled fault unhandled");
#endif
}

void* KYTY_SYSV_ABI ReadInheritedProgram(void*) {
  return Loader::RuntimeLinker::GetCurrentProgram();
}

void CheckThreadProgramOwner() {
  namespace Kernel = Libs::LibKernel;
  Kernel::Initialize();
  Kernel::PthreadInitSelfForMainThread();
  (void)Common::Singleton<Loader::RuntimeLinker>::Instance();
  auto* previous = Loader::RuntimeLinker::GetCurrentProgram();
  Loader::Program first, second;
  first.unique_id = 23;
  second.unique_id = 24;
  Kernel::Pthread a = nullptr, b = nullptr;
  Loader::RuntimeLinker::SetCurrentProgram(&first);
  Check(Kernel::PthreadCreate(&a, nullptr, ReadInheritedProgram, nullptr, "OwnerA") == 0,
        "create a worker for the first co-hosted program");
  Loader::RuntimeLinker::SetCurrentProgram(&second);
  Check(Kernel::PthreadCreate(&b, nullptr, ReadInheritedProgram, nullptr, "OwnerB") == 0,
        "create a worker for the second co-hosted program");
  void* a_owner = nullptr;
  void* b_owner = nullptr;
  Check(Kernel::PthreadJoin(a, &a_owner) == 0 && Kernel::PthreadJoin(b, &b_owner) == 0 &&
            a_owner == &first && b_owner == &second &&
            Loader::RuntimeLinker::GetCurrentProgram() == &second,
        "workers inherit their creator's executable without changing the parent or another worker");
  Loader::RuntimeLinker::SetCurrentProgram(previous);
}

void* KYTY_SYSV_ABI WaitForJoinRelease(void* arg) {
  auto* gate = static_cast<std::atomic<bool>*>(arg);
  while (!gate->load()) { std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
  return reinterpret_cast<void*>(uintptr_t{42});
}

void CheckJoinSuspension() {
  namespace Kernel = Libs::LibKernel;
  Kernel::Initialize();
  Kernel::PthreadInitSelfForMainThread();
  (void)Common::Singleton<Loader::RuntimeLinker>::Instance();
  std::atomic<bool> release {false};
  Kernel::Pthread target = nullptr;
  Check(Kernel::PthreadCreate(&target, nullptr, WaitForJoinRelease,
        &release, "JoinTarget") == 0, "create a join target that remains alive");
  std::promise<Kernel::Pthread> started;
  auto ready = started.get_future();
  void* result = nullptr;
  int join_result = -1;
  std::thread joiner([&] {
    Kernel::PthreadInitSelfForCoMainThread("JoinCollectorTest");
    started.set_value(Kernel::PthreadSelf());
    join_result = Kernel::PthreadJoin(target, &result);
  });
  const auto joining_thread = ready.get();
  std::this_thread::sleep_for(std::chrono::milliseconds(30));
  const bool suspendable = !Kernel::PthreadIsHostCritical(joining_thread);
#if defined(_WIN32)
  if (suspendable) {
    Loader::SymbolDatabase symbols;
    Libs::InitLibKernel_1(&symbols);
    using Suspend = int(KYTY_SYSV_ABI *)(Kernel::Pthread);
    auto suspend = reinterpret_cast<Suspend>(symbols.FindByNid("cfjAjVTFG6A", Loader::SymbolType::Func)->vaddr);
    auto resume = reinterpret_cast<Suspend>(symbols.FindByNid("QRdE7dBfNks", Loader::SymbolType::Func)->vaddr);
    Check(suspend(target) == 0 && suspend(joining_thread) == 0,
          "collector can suspend both an unfinished target and the thread joining it");
    Check(resume(joining_thread) == 0 && resume(target) == 0,
          "collector resumes a blocked joiner and its target without a dependency cycle");
  }
#endif
  release = true;
  joiner.join();
  Check(suspendable, "a blocking pthread join does not retain the host suspension barrier");
  Check(join_result == 0 && result == reinterpret_cast<void*>(uintptr_t{42}),
        "join completes with the target's return value after collection");
  Check(Kernel::PthreadJoin(reinterpret_cast<Kernel::Pthread>(uintptr_t{0xbf800000bf800000}), nullptr) ==
            Kernel::KERNEL_ERROR_ESRCH,
        "join still rejects corrupt handles before dereferencing them");
}

void CheckRelativeCondWait() {
  namespace Kernel = Libs::LibKernel;
  Kernel::Initialize();
  Kernel::PthreadInitSelfForMainThread();
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  using RelativeWait = int(KYTY_SYSV_ABI *)(Kernel::PthreadCond*, Kernel::PthreadMutex*, uint32_t);
  auto wait = reinterpret_cast<RelativeWait>(symbols.FindByNid("K953PF5u6Pc", Loader::SymbolType::Func)->vaddr);
  Kernel::PthreadMutex mutex = nullptr;
  Kernel::PthreadCond cond = nullptr;
  Check(Kernel::PthreadMutexInit(&mutex, nullptr, "RelativeWaitTest") == 0 &&
            Kernel::PthreadCondInit(&cond, nullptr, "RelativeWaitTest") == 0 &&
            Kernel::PthreadMutexLock(&mutex) == 0,
        "create and acquire a guest condition mutex");
  auto start = std::chrono::steady_clock::now();
  Check(wait(&cond, &mutex, 20000) == Libs::Posix::POSIX_ETIMEDOUT &&
            std::chrono::steady_clock::now() - start >= std::chrono::milliseconds(15),
        "relative condition wait accepts microseconds and reports a real timeout");
  auto signal = std::async(std::launch::async, [&] {
    Kernel::PthreadInitSelfForCoMainThread("RelativeWaitSignal");
    Check(Kernel::PthreadMutexLock(&mutex) == 0, "wait releases its mutex while blocked");
    const int result = Kernel::PthreadCondSignal(&cond);
    Check(Kernel::PthreadMutexUnlock(&mutex) == 0, "release signaling thread's mutex");
    return result;
  });
  Check(wait(&cond, &mutex, 1000000) == 0 && signal.get() == 0,
        "relative condition wait wakes on a signal and reacquires its mutex");
  Check(wait(&cond, &mutex, 0) == Libs::Posix::POSIX_ETIMEDOUT &&
            Kernel::PthreadMutexUnlock(&mutex) == 0,
        "zero timeout still returns with the mutex held");
  Check(wait(&cond, &mutex, 1) == Libs::Posix::POSIX_EPERM,
        "relative wait rejects an unowned mutex");
  Check(Kernel::PthreadCondDestroy(&cond) == 0 && Kernel::PthreadMutexDestroy(&mutex) == 0,
        "destroy relative condition wait fixture");
}

void CheckUserContext() {
#if defined(_WIN32)
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  using Suspend = int(KYTY_SYSV_ABI *)(Libs::LibKernel::Pthread);
  using ReadContext = int(KYTY_SYSV_ABI *)(Libs::LibKernel::Pthread, void*);
  auto suspend = reinterpret_cast<Suspend>(symbols.FindByNid("cfjAjVTFG6A", Loader::SymbolType::Func)->vaddr);
  auto resume = reinterpret_cast<Suspend>(symbols.FindByNid("QRdE7dBfNks", Loader::SymbolType::Func)->vaddr);
  auto read_context = reinterpret_cast<ReadContext>(symbols.FindByNid("YkGOXpJEtO8", Loader::SymbolType::Func)->vaddr);
  std::promise<Libs::LibKernel::Pthread> started;
  auto ready = started.get_future();
  std::atomic<uint64_t> progress {0};
  std::atomic<bool> stop {false};
  std::thread worker([&] {
    Libs::LibKernel::PthreadInitSelfForCoMainThread("UserContextTest");
    started.set_value(Libs::LibKernel::PthreadSelf());
    while (!stop.load()) { progress.fetch_add(1); }
  });
  auto thread = ready.get();
  while (progress.load() == 0) { std::this_thread::yield(); }
  Check(suspend(thread) == 0, "suspend real target thread");
  std::array<uint64_t, 162> context;
  context.fill(0xa5a5a5a5a5a5a5a5ull);
  Check(read_context(thread, context.data() + 1) == 0 && context[29] != 0 &&
        context[32] != 0 && context.front() == 0xa5a5a5a5a5a5a5a5ull &&
        context.back() == 0xa5a5a5a5a5a5a5a5ull,
        "user context contains actual RIP and RSP within the native output size");
  const auto paused = progress.load();
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  Check(progress.load() == paused && suspend(thread) == Libs::Posix::POSIX_EBUSY,
        "suspended target stops making progress and cannot be suspended twice");
  Check(resume(thread) == 0, "resume suspended target");
  while (progress.load() == paused) { std::this_thread::yield(); }
  stop = true;
  worker.join();
  Check(read_context(thread, context.data()) == Libs::Posix::POSIX_EINVAL &&
        resume(thread) == Libs::Posix::POSIX_EINVAL,
        "resume invalidates the context snapshot and balances host suspend count");

  std::mutex host_lock;
  std::promise<Libs::LibKernel::Pthread> critical_started;
  auto critical_ready = critical_started.get_future();
  stop = false;
  progress = 0;
  std::thread critical_worker([&] {
    Libs::LibKernel::PthreadInitSelfForCoMainThread("CriticalUserContextTest");
    {
      Libs::LibKernel::PthreadHostCriticalScope outer;
      {
        Common::HostCriticalScope inner;
        std::lock_guard lock(host_lock);
        critical_started.set_value(Libs::LibKernel::PthreadSelf());
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
      }
      Check(Libs::LibKernel::PthreadIsHostCritical(Libs::LibKernel::PthreadSelf()),
            "nested host critical scope keeps its outer suspend barrier");
    }
    while (!stop.load()) { progress.fetch_add(1); }
  });
  auto critical_thread = critical_ready.get();
  Check(suspend(critical_thread) == 0, "suspend waits for an active host operation to finish");
  Check(!Libs::LibKernel::PthreadIsHostCritical(critical_thread) && host_lock.try_lock(),
        "suspended target holds no host lock needed by the collector");
  host_lock.unlock();
  const auto critical_paused = progress.load();
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  Check(progress.load() == critical_paused && read_context(critical_thread, context.data() + 1) == 0,
        "deferred suspension still captures and stops the real target");
  Check(resume(critical_thread) == 0, "resume target after host critical operation");
  stop = true;
  critical_worker.join();

  struct FaultProbe {
    std::promise<Libs::LibKernel::Pthread> entered;
    std::atomic<bool> protected_handler {false};
    std::atomic<bool> finished {false};
  } fault_probe;
  static FaultProbe* active_fault_probe = nullptr;
  active_fault_probe = &fault_probe;
  Check(Common::HostException::InstallHandler(+[](const Common::HostException::ExceptionInfo& info) {
    if (info.type != Common::HostException::ExceptionType::IllegalInstruction ||
        active_fault_probe == nullptr) { return false; }
    auto* probe = active_fault_probe;
    auto self = Libs::LibKernel::PthreadSelf();
    probe->protected_handler = Libs::LibKernel::PthreadIsHostCritical(self);
    probe->entered.set_value(self);
    std::this_thread::sleep_for(std::chrono::milliseconds(40));
    probe->finished = true;
    return true;
  }), "install the real Windows exception handler for suspension regression");
  auto fault_ready = fault_probe.entered.get_future();
  stop = false;
  progress = 0;
  std::thread fault_worker([&] {
    Libs::LibKernel::PthreadInitSelfForCoMainThread("FaultUserContextTest");
    // A continuable software exception exercises the VEH without changing RIP.
    RaiseException(EXCEPTION_ILLEGAL_INSTRUCTION, 0, 0, nullptr);
    while (!stop.load()) { progress.fetch_add(1); }
  });
  auto fault_thread = fault_ready.get();
  Check(suspend(fault_thread) == 0, "suspend thread executing a Windows fault handler");
  const bool handler_finished_before_suspend = fault_probe.finished.load();
  const auto fault_paused = progress.load();
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  Check(progress.load() == fault_paused, "fault handler suspension stops the real thread");
  Check(resume(fault_thread) == 0, "resume target after Windows fault handling");
  stop = true;
  fault_worker.join();
  active_fault_probe = nullptr;
  Check(fault_probe.protected_handler && handler_finished_before_suspend,
        "Windows fault logging and dispatch finish before collector suspension");
#endif
}

void CheckPersistentUsers(const std::filesystem::path& root) {
  Config::ConfigOptions options;
  const auto original_environment = Config::GetGuestEnvironment();
  options.guest_environment = original_environment;
  const auto store = root / "profiles/users.json";
  options.guest_environment["KYTY_USER_STORE"] = Common::PathToString(store);
  Config::Load(options);
  Loader::SymbolDatabase symbols;
  Libs::InitUserService_1(&symbols);
  Libs::LoginMgrServer::InitLoginMgrServer_1(&symbols);
  const auto resolve = [&](const char* nid) {
    const auto* symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "resolve persistent user service import");
    return symbol->vaddr;
  };
  using ReadIds = int(KYTY_SYSV_ABI*)(int*);
  using Create = int(KYTY_SYSV_ABI*)(const char*, int, bool, bool, int*);
  using Name = int(KYTY_SYSV_ABI*)(int, char*, size_t);
  using SetName = int(KYTY_SYSV_ABI*)(int, const char*);
  using Flags = int(KYTY_SYSV_ABI*)(int, uint32_t, uint32_t, uint32_t*);
  using ReadFlags = int(KYTY_SYSV_ABI*)(int, uint32_t*);
  using Login = int(KYTY_SYSV_ABI*)(int, uint64_t);
  using User = int(KYTY_SYSV_ABI*)(int);
  const auto registered = reinterpret_cast<ReadIds>(resolve("5EiQCnL2G1Y"));
  const auto logged_in = reinterpret_cast<ReadIds>(resolve("fPhymKNvK-A"));
  const auto foreground = reinterpret_cast<ReadIds>(resolve("eNb53LQJmIM"));
  const auto initial = reinterpret_cast<ReadIds>(resolve("CdWp0oHWGr0"));
  const auto create = reinterpret_cast<Create>(resolve("AT6NySjQ2gY"));
  const auto destroy = reinterpret_cast<User>(resolve("REIRIXzv-H0"));
  const auto name = reinterpret_cast<Name>(resolve("1xxcMiGu2fo"));
  const auto rename = reinterpret_cast<SetName>(resolve("Jqu2XFr5UvA"));
  const auto passcode = reinterpret_cast<Name>(resolve("X5rJZNDZ2Ss"));
  const auto set_passcode = reinterpret_cast<SetName>(resolve("7LCq4lSlmw4"));
  const auto set_status = reinterpret_cast<Flags>(resolve("-+h1C78SdyU"));
  const auto status = reinterpret_cast<ReadFlags>(resolve("RJX7T4sjNgI"));
  const auto login = reinterpret_cast<Login>(resolve("uvVR70ZxFrQ"));
  using Logout = int(KYTY_SYSV_ABI*)(int, uint32_t);
  const auto logout = reinterpret_cast<Logout>(resolve("3T9y5xDcfOk"));
  const auto read_event = reinterpret_cast<ReadIds>(resolve("yH17Q6NWtVg"));
  static std::vector<std::pair<int, std::string>> framework_events;
  framework_events.clear();
  const auto collect_event = +[](int id, const std::string& payload) {
    // Delivery must not hold the user lock: native/managed code may query it.
    (void)Libs::UserService::IsLoggedIn(-1);
    framework_events.emplace_back(id, payload);
    return true;
  };
  using IsLoggedIn = bool(KYTY_SYSV_ABI*)(int);
  const auto is_logged_in = reinterpret_cast<IsLoggedIn>(resolve("MZxH8029+Wg"));
  std::array<int, 16> ids;
  std::array<int, 4> sessions;
  int current = -2;
  Check(registered(ids.data()) == OK && std::all_of(ids.begin(), ids.end(), [](int id) { return id == -1; }) &&
            logged_in(sessions.data()) == OK && sessions[0] == -1 &&
            foreground(&current) == OK && current == -1 &&
            initial(&current) == Libs::UserService::USER_SERVICE_ERROR_NOT_LOGGED_IN,
        "a fresh ShellUI user store has no synthetic registered or logged-in Kyty profile");
  int alice = -1, guest = -1, bob = -1;
  uint32_t old_status = 0, user_status = 0;
  Check(create("Alice", 1, true, true, &alice) == OK &&
            rename(alice, "Alice renamed") == OK && set_status(alice, 1, 0, &old_status) == OK &&
            create("Guest", 3, false, false, &guest) == OK && create("Bob", 1, false, false, &bob) == OK &&
            alice != bob && bob != guest && std::filesystem::is_regular_file(store),
        "local user creation, rename and completion write a persistent profile store");
  std::array<char, 16> pin;
  pin.fill('x');
  Check(passcode(alice, pin.data(), pin.size()) == OK && pin[0] == '\0' &&
            set_passcode(bob, "0123") == OK &&
            passcode(bob, pin.data(), pin.size()) == OK && std::strcmp(pin.data(), "0123") == 0 &&
            passcode(bob, pin.data(), 4) == Libs::UserService::USER_SERVICE_ERROR_BUFFER_TOO_SHORT &&
            pin[0] == '\0' && passcode(bob, nullptr, 16) != OK &&
            set_passcode(bob, "0123456789012345") != OK,
        "passcode queries initialize empty profiles and enforce the native buffer capacity");
  Check(!is_logged_in(bob) && !is_logged_in(-1) && !is_logged_in(255) &&
            login(bob, 0) == OK && is_logged_in(bob) && !is_logged_in(alice) &&
            Libs::Controller::PadOpen(bob, 0, 0, nullptr) == 1,
        "a created logged-in profile can open its controller instead of requiring the configured ID");
  std::array<int, 2> polled_event {};
  Check(read_event(polled_event.data()) == OK && polled_event[0] == 0 && polled_event[1] == bob,
        "native user polling receives login independently of framework subscribers");
  // A transport failure keeps the first event queued, blocking subsequent events.
  Libs::UserService::PumpFrameworkEvents(+[](int, const std::string&) { return false; });
  Check(login(bob, 0) == OK && login(-1, 0) != OK && logout(bob, 0) == OK &&
            logout(bob, 0) != OK && login(bob, 0) == OK && destroy(guest) == OK,
        "repeated and failed user operations do not produce duplicate lifecycle transitions");
  Libs::UserService::PumpFrameworkEvents(collect_event);
  const auto payload = [](int id) { return "{\"userId\":" + std::to_string(id) + "}"; };
  const std::vector<std::pair<int, std::string>> expected_events {
      {42, payload(alice)}, {42, payload(guest)}, {42, payload(bob)},
      {40, payload(bob)}, {41, payload(bob)}, {40, payload(bob)}, {43, payload(guest)}};
  Check(framework_events == expected_events,
        "PSM lifecycle notifications retry in order with the exact lower-case userId payload");
  Libs::UserService::PumpFrameworkEvents(collect_event);
  Check(framework_events == expected_events, "framework delivery consumes each transition once");
  // Leave an event pending and verify service restart discards transient notifications.
  Check(logout(bob, 0) == OK, "queue logout before service restart");
  Libs::InitUserService_1(&symbols); // Simulate a new emulator's service initialization.
  Libs::UserService::PumpFrameworkEvents(collect_event);
  Check(framework_events == expected_events, "restart does not replay a stale session event");
  std::array<char, 64> buffer {};
  Check(registered(ids.data()) == OK && ids[0] == alice && ids[1] == bob && ids[2] == -1 &&
            name(alice, buffer.data(), buffer.size()) == OK && std::strcmp(buffer.data(), "Alice renamed") == 0 &&
            status(alice, &user_status) == OK && user_status == 0,
        "restart reloads the same local IDs, names and completed status while discarding guests");
  Check(passcode(bob, pin.data(), pin.size()) == OK && std::strcmp(pin.data(), "0123") == 0 &&
            passcode(alice, pin.data(), pin.size()) == OK && pin[0] == '\0',
        "restart restores only an explicitly set passcode");
  Check(logged_in(sessions.data()) == OK && sessions[0] == -1 &&
            foreground(&current) == OK && current == -1 && !is_logged_in(bob) &&
            Libs::Controller::PadOpen(bob, 0, 0, nullptr) < 0,
        "restored profiles start logged out for the native user-selection flow");
  int next = -1;
  Check(create("Next", 1, false, false, &next) == OK && next > bob && destroy(alice) == OK,
        "profile allocation does not reuse a saved ID and deletion writes to the same store");
  Libs::InitUserService_1(&symbols);
  Check(registered(ids.data()) == OK && ids[0] == bob && ids[1] == next && ids[2] == -1,
        "deleted profiles remain absent after restart");

  // A write failure must not turn an unsaved create/rename/delete into success.
  const auto saved = root / "profiles/saved.json";
  std::filesystem::rename(store, saved);
  std::filesystem::create_directory(store);
  int failed_id = -1;
  Check(create("Unsaved", 1, false, false, &failed_id) != OK && failed_id == -1 &&
            rename(bob, "Unsaved rename") != OK && destroy(bob) != OK &&
            set_passcode(bob, "4567") != OK &&
            passcode(bob, pin.data(), pin.size()) == OK && std::strcmp(pin.data(), "0123") == 0 &&
            name(bob, buffer.data(), buffer.size()) == OK && std::strcmp(buffer.data(), "Bob") == 0,
        "failed atomic saves retain existing profiles and reject unsaved changes");
  framework_events.clear();
  Libs::UserService::PumpFrameworkEvents(collect_event);
  Check(framework_events.empty(), "failed profile saves do not notify ShellUI of unsaved users");
  std::filesystem::remove(store);
  std::filesystem::rename(saved, store);
  {
    std::ofstream damaged(store, std::ios::binary | std::ios::trunc);
    damaged << "damaged profile store";
  }
  Libs::InitUserService_1(&symbols);
  Check(create("Do not overwrite", 1, false, false, &failed_id) != OK,
        "a damaged store is reported as an error rather than replaced by a fresh profile list");
  std::ifstream damaged(store, std::ios::binary);
  const std::string bytes(std::istreambuf_iterator<char>(damaged), {});
  Check(bytes == "damaged profile store", "damaged user store bytes remain available for recovery");
  options.guest_environment = original_environment;
  Config::Load(options);
  Libs::InitUserService_1(&symbols);
}

void CheckHotServices() {
  Loader::SymbolDatabase symbols;
  Libs::InitSysmodule_1(&symbols);
  Libs::RegMgr::InitRegMgr_1(&symbols);
  Libs::FsInternalForVsh::InitFsInternalForVsh_1(&symbols);
  Libs::AvSetting::InitAvSetting_1(&symbols);
  Libs::LibNet::InitNet_1_Net(&symbols);
  Libs::InitLibKernel_1(&symbols);
  const auto* debug_menu_symbol = symbols.FindByNid("opMiSfTJyJo", Loader::SymbolType::Func);
  Check(debug_menu_symbol != nullptr, "resolve the Debug Settings permission query");
  auto debug_menu = reinterpret_cast<int(KYTY_SYSV_ABI*)()>(debug_menu_symbol->vaddr);
  Check(debug_menu() == 1, "genuine devkit permits the native Debug Settings page");
  Libs::LibcInternal::InitLibcInternal_1(&symbols);
  const auto resolve = [&](const char* nid) {
    const auto* symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "resolve frequently called service import");
    return symbol->vaddr;
  };
  auto module_handle = reinterpret_cast<int(KYTY_SYSV_ABI*)(uint32_t, int*)>(resolve("D8cuU4d72xM"));
  int handle = -123;
  Check(module_handle(0x80000000u, &handle) == 0 && handle == 0,
        "internal HLE sysmodule retains the global dlsym handle without narrowing its ID");
  handle = -123;
  Check(module_handle(149, &handle) < 0 && handle == 0,
        "unloaded native IME cannot report an initialized module handle");
  Check(module_handle(149, nullptr) < 0, "sysmodule handle query rejects a null output");
  using PriorityLimit = int(KYTY_SYSV_ABI *)(int);
  auto priority_min = reinterpret_cast<PriorityLimit>(resolve("m0iS6jNsXds"));
  auto priority_max = reinterpret_cast<PriorityLimit>(resolve("CBNtXOoef-E"));
  Check(priority_min(1) < priority_max(1),
        "PSM accepts the ordered scheduling priority range");
  using SpinInit = int(KYTY_SYSV_ABI *)(uintptr_t*, int);
  using SpinOp = int(KYTY_SYSV_ABI *)(uintptr_t*);
  auto spin_init = reinterpret_cast<SpinInit>(resolve("ZMn3clnAGBA"));
  auto spin_lock = reinterpret_cast<SpinOp>(resolve("pw+70ClLYlY"));
  auto spin_try = reinterpret_cast<SpinOp>(resolve("rCTGkBIHfPY"));
  auto spin_unlock = reinterpret_cast<SpinOp>(resolve("LEfMMCT+SlM"));
  auto spin_destroy = reinterpret_cast<SpinOp>(resolve("IJIggoPZExk"));
  uintptr_t spin = 0;
  Check(spin_init(&spin, 0) == 0 && spin_try(&spin) == 0,
        "spinlock creates a live unlocked handle");
  Check(spin_try(&spin) == Libs::Posix::POSIX_EBUSY &&
        spin_destroy(&spin) == Libs::Posix::POSIX_EBUSY,
        "held spinlock rejects a second acquisition and destruction");
  Check(spin_unlock(&spin) == 0, "spinlock releases held lock");
  int protected_count = 0;
  auto increment = [&] {
    for (int i = 0; i < 2000; ++i) {
      Check(spin_lock(&spin) == 0, "spinlock contention acquisition");
      ++protected_count;
      Check(spin_unlock(&spin) == 0, "spinlock contention release");
    }
  };
  std::thread other(increment);
  increment();
  other.join();
  Check(protected_count == 4000 && spin_destroy(&spin) == 0 &&
        spin_try(&spin) == Libs::Posix::POSIX_EINVAL,
        "spinlock serializes threads and invalidates destroyed handles");

  Libs::Audio::Initialize();
  namespace AO = Libs::Audio::AudioOut;
  Check(AO::AudioOutOpenEx(255, 0, 0, 0, 0, 48000, 1) ==
            Libs::Audio::AUDIO_OUT_ERROR_INVALID_SIZE,
        "extended audio open rejects invalid sample count");
  Check(AO::AudioOutOpenEx(255, 0, 0, 0, 512, 0, 1) ==
            Libs::Audio::AUDIO_OUT_ERROR_INVALID_SAMPLE_FREQ,
        "extended audio open validates frequency");
  const auto audio_handle = AO::AudioOutOpenEx(255, 0, 0, 0, 512, 48000, 1);
  Check(audio_handle > 0, "extended audio open allocates real PCM port");
  std::array<int16_t, 1024> silence {};
  Check(AO::AudioOutOutput(audio_handle, silence.data()) == 512 &&
        AO::AudioOutClose(audio_handle) == 0 &&
        AO::AudioOutClose(audio_handle) == Libs::Audio::AUDIO_OUT_ERROR_INVALID_PORT,
        "extended audio handle supports PCM output and close lifecycle");
  Libs::Audio::Shutdown();
  using SetInt = int(KYTY_SYSV_ABI *)(uint32_t, int);
  using GetInt = int(KYTY_SYSV_ABI *)(uint32_t, int*);
  using IsChange = int(KYTY_SYSV_ABI *)(uint32_t, uint32_t);
  auto set = reinterpret_cast<SetInt>(resolve("khaYelw1Ytc"));
  auto get = reinterpret_cast<GetInt>(resolve("mPYKD12UDQI"));
  auto changed = reinterpret_cast<IsChange>(resolve("xhrI4zhlBuA"));
  constexpr uint32_t key = 0x7802fa03;
  Check(changed(key, 0x0d010020) == 0, "unwritten registry key has no pending change");
  Check(set(key, 17) == 0 && changed(key, 0x0d010020) == 1 &&
            changed(key, 0x0d010020) == 0 && changed(key, 0x0d010001) == 1,
        "registry change is consumed once independently by each consumer");
  int value = 0;
  Check(get(key, &value) == 0 && value == 17 && set(key, 17) == 0 &&
            changed(key, 0x0d010020) == 0 && changed(key, 0xdeadbeef) == 0,
        "registry readback and unchanged writes preserve the notification state");
  Check(set(key, 18) == 0 && changed(key, 0x0d010020) == 1,
        "a subsequent registry write rearms the consumer");
  resolve("zr094EQ39Ww"); // Never invoke a noreturn pure-virtual handler in this process.
  using ThermalQuery = int(KYTY_SYSV_ABI *)(uint16_t*, void*);
  auto thermal = reinterpret_cast<ThermalQuery>(resolve("QkzPx-QbX3A"));
  uint16_t temperature = 0x1234;
  std::array<uint8_t, 14> thresholds;
  thresholds.fill(0xa5);
  Check(thermal(&temperature, thresholds.data()) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENODEV &&
            temperature == 0x1234 && thresholds == std::array<uint8_t, 14>{
              0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5},
        "absent M.2 sensor reports an error without fabricating thermal data");
  using SetName = int(KYTY_SYSV_ABI *)(Libs::LibKernel::PthreadMutex*, const char*);
  auto name = reinterpret_cast<SetName>(resolve("nTxZBp8YNGc"));
  Libs::LibKernel::PthreadMutex mutex = nullptr;
  Check(name(&mutex, "mono mutex") == 0 && mutex == nullptr &&
            name(nullptr, "mutex") == Libs::Posix::POSIX_EINVAL,
        "advisory mutex naming does not create, acquire or alter a mutex");

  using NetCallback = uint64_t(KYTY_SYSV_ABI *)(int, uint64_t, void*, void*);
  using CreateNet = int(KYTY_SYSV_ABI *)(int, NetCallback, void*, uint32_t);
  using DestroyNet = int(KYTY_SYSV_ABI *)(int, uint32_t);
  using WaitNet = int(KYTY_SYSV_ABI *)(uint32_t, void*, uint32_t);
  using ErrorNet = int(KYTY_SYSV_ABI *)(int, int*, uint32_t);
  auto create_net = reinterpret_cast<CreateNet>(resolve("cWGGXoeZUzA"));
  auto destroy_net = reinterpret_cast<DestroyNet>(resolve("jzP0MoZpYnI"));
  auto wait_net = reinterpret_cast<WaitNet>(resolve("5isaotjMWlA"));
  auto error_net = reinterpret_cast<ErrorNet>(resolve("tB3BB8AsrjU"));
  NetworkCallbackProbe probe;
  Check(wait_net(0, nullptr, 0) == Libs::Network::NET_ERROR_ENOENT &&
            create_net(5, ProbeNetworkCallback, &probe, 0) == 0 &&
            create_net(5, ProbeNetworkCallback, &probe, 0) == Libs::Network::NET_ERROR_EEXIST,
        "network callbacks are registered with duplicate and missing-registration errors");
  Check(wait_net(0, nullptr, 0) == static_cast<int>(0x804101a4u),
        "empty nonblocking network poll reports no data");
  auto begin = std::chrono::steady_clock::now();
  Check(wait_net(25000, nullptr, 0) == 0 &&
            std::chrono::steady_clock::now() - begin >= std::chrono::milliseconds(20) && probe.calls == 0,
        "network wait honors its microsecond timeout without inventing an event");
  probe.retain = 0x200;
  Libs::LibNet::PublishInterfaceEvent(5, 0x300, -7);
  Check(wait_net(0, &value, 0) == 0 && probe.bits == 0x300 && probe.calls == 1 &&
            probe.id == 5 && probe.wait_argument == &value,
        "network callback receives interface, mask, registration and wait arguments");
  int error = 0;
  Check(error_net(5, &error, 0) == 0 && error == -7,
        "network event error is available from inside or after callback dispatch");
  probe.retain = 0;
  Check(wait_net(0, nullptr, 0) == 0 && probe.bits == 0x200 && probe.calls == 2 &&
            wait_net(0, nullptr, 0) == static_cast<int>(0x804101a4u),
        "callback acknowledgement retains only its returned bits then drains them");
  auto publisher = std::async(std::launch::async, [&] {
    Check(wait_net(0, nullptr, 0) == Libs::Network::NET_ERROR_ENOENT,
          "a different thread cannot dispatch another thread's callbacks");
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    Libs::LibNet::PublishInterfaceEvent(5, 0x100);
  });
  begin = std::chrono::steady_clock::now();
  Check(wait_net(1000000, nullptr, 0) == 0 && probe.bits == 0x100 && probe.calls == 3 &&
            std::chrono::steady_clock::now() - begin < std::chrono::milliseconds(500),
        "backend event wakes a network wait before its deadline");
  publisher.get();
  Check(destroy_net(5, 0) == 0 && destroy_net(5, 0) == Libs::Network::NET_ERROR_EINVAL,
        "network callback destruction invalidates registration");

  using AvCallback = void(KYTY_SYSV_ABI *)(uint32_t, void*, void*, uint32_t, uint32_t, uint32_t);
  using AddAv = int(KYTY_SYSV_ABI *)(const AvCallback*, void*, const void*);
  using PollAv = int(KYTY_SYSV_ABI *)(uint32_t, void*);
  using RemoveAv = int(KYTY_SYSV_ABI *)(uint32_t);
  auto add_av = reinterpret_cast<AddAv>(resolve("Im9QXnr0QK4"));
  auto poll_av = reinterpret_cast<PollAv>(resolve("s2ODJNcQVkI"));
  auto remove_av = reinterpret_cast<RemoveAv>(resolve("KiCPJyA-prw"));
  AvCallback callback = ProbeAvCallback;
  AvCallbackProbe av;
  std::array<int, 4> handles;
  for (auto& handle : handles) { handle = add_av(&callback, &av, nullptr); Check(handle >= 0, "allocate AvSetting callback handle"); }
  Check(add_av(&callback, &av, nullptr) == static_cast<int>(0x802a0010u) &&
            poll_av(handles[0], nullptr) == 0 && av.calls == 0,
        "AvSetting enforces four slots and an empty poll never suspends an app");
  Libs::AvSetting::PublishUnsupportedOutputEvent(100, 77, 2);
  Check(poll_av(handles[0], &value) == 0 && av.calls == 1 &&
            av.handle == static_cast<uint32_t>(handles[0]) &&
            av.event == std::array<uint32_t, 3>{100, 77, 2} && av.wait_argument == &value &&
            poll_av(handles[0], nullptr) == 0 && av.calls == 1,
        "AvSetting dispatches an actual arbitration event once with the native callback ABI");
  const auto previous = handles[0];
  Check(remove_av(previous) == 0 && poll_av(previous, nullptr) == static_cast<int>(0x802a0011u),
        "AvSetting rejects removed handles");
  handles[0] = add_av(&callback, &av, nullptr);
  Check(handles[0] >= 0 && handles[0] != previous &&
            poll_av(previous, nullptr) == static_cast<int>(0x802a0011u),
        "reused AvSetting slots retain generation checks");
  for (auto handle : handles) { Check(remove_av(handle) == 0, "remove AvSetting callback handle"); }
}

class TempDirectory {
public:
  TempDirectory() {
    const auto unique =
        std::chrono::steady_clock::now().time_since_epoch().count();
    m_path = std::filesystem::temp_directory_path() /
             ("kyty_kernel_file_system_" + std::to_string(unique));
    Check(std::filesystem::create_directories(m_path),
          "create temporary directory");
  }

  ~TempDirectory() {
    std::error_code error;
    std::filesystem::remove_all(m_path, error);
  }

  [[nodiscard]] const std::filesystem::path &Path() const { return m_path; }

  KYTY_CLASS_NO_COPY(TempDirectory);

private:
  std::filesystem::path m_path;
};

void CheckJsonEventTransfer() {
  Loader::SymbolDatabase symbols;
  Libs::LibJson2::InitNet_1_Json2(&symbols);
  struct Value {
    void* parent = nullptr;
    void* root = nullptr;
    uint64_t payload = 0;
    uint32_t padding = 0;
    uint32_t type = 0;
  };
  struct String { void* impl = nullptr; };
  static_assert(sizeof(Value) == 32);
  auto address = [&](const char* nid) {
    const auto* symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "JSON event transfer import is registered");
    return symbol->vaddr;
  };
  auto number = reinterpret_cast<void*(KYTY_SYSV_ABI *)(Value*, uint64_t)>(address("x4AUdbhpRB0"));
  auto copy = reinterpret_cast<void(KYTY_SYSV_ABI *)(Value*, const Value*)>(address("XL8+BUqjB1w"));
  auto swap = reinterpret_cast<void(KYTY_SYSV_ABI *)(Value*, Value*)>(address("9PqrCLfKZZI"));
  auto destroy = reinterpret_cast<void(KYTY_SYSV_ABI *)(Value*)>(address("WTtYf+cNnXI"));
  auto serialize = reinterpret_cast<int(KYTY_SYSV_ABI *)(Value*, String*)>(address("R7FDWtcN6f8"));
  auto cstr = reinterpret_cast<const char*(KYTY_SYSV_ABI *)(const String*)>(address("L1KAkYWml-M"));
  auto destroy_string = reinterpret_cast<void(KYTY_SYSV_ABI *)(String*)>(address("cG1VE2HMl6c"));
  auto parse = reinterpret_cast<int(KYTY_SYSV_ABI *)(Value*, const char*, size_t)>(address("S5JxQnoGF3E"));
  Value queued, delivered, parsed;
  number(&queued, 0x10000001);
  Check(queued.type == 3 && queued.payload == 0x10000001,
        "unsigned JSON constructor stores the foreground user ID");
  swap(&delivered, &queued); // Native PSM removes an event from its queue this way.
  Check(delivered.type == 3 && delivered.payload == 0x10000001 && queued.type == 0,
        "PSM queue swap transfers a numeric event payload instead of null");
  String text;
  Check(serialize(&delivered, &text) == 0 && std::strcmp(cstr(&text), "268435457") == 0,
        "PSM event serialization retains the user ID");
  Check(parse(&parsed, cstr(&text), std::strlen(cstr(&text))) == 0 && parsed.type == 3 &&
            parsed.payload == 0x10000001, "event JSON parses as a non-null scalar");
  destroy_string(&text);
  number(&queued, UINT64_MAX);
  copy(&delivered, &queued);
  Check(delivered.type == 3 && delivered.payload == UINT64_MAX,
        "JSON set preserves unsigned integers without narrowing");
  const char nested[] = R"({"users":[268435457],"label":"offline"})";
  Check(parse(&queued, nested, sizeof(nested) - 1) == 0, "parse owned JSON event data");
  swap(&delivered, &queued);
  destroy(&queued);
  Check(serialize(&delivered, &text) == 0 &&
            std::strstr(cstr(&text), "268435457") != nullptr &&
            std::strstr(cstr(&text), "offline") != nullptr,
        "swapped JSON containers retain independent ownership after source destruction");
  destroy_string(&text);
  destroy(&delivered);
  destroy(&parsed);
  struct Pair { String key; uint64_t reserved; Value value; };
  struct Iterator { void* position = nullptr; };
  static_assert(sizeof(Pair) == 48);
  auto get_uint = reinterpret_cast<const uint64_t*(KYTY_SYSV_ABI*)(const Value*)>(address("sn4HNCtNRzY"));
  auto string_ctor = reinterpret_cast<String*(KYTY_SYSV_ABI*)(String*, const char*)>(address("9KUZFjI1IxA"));
  auto pair_ctor = reinterpret_cast<Pair*(KYTY_SYSV_ABI*)(Pair*, const String*, const Value*)>(address("+hYsagaV-Ug"));
  auto pair_dtor = reinterpret_cast<void(KYTY_SYSV_ABI*)(Pair*)>(address("Q0ng4sWj2E8"));
  auto object_ctor = reinterpret_cast<String*(KYTY_SYSV_ABI*)(String*)>(address("OJPTonqdg0I"));
  auto object_dtor = reinterpret_cast<void(KYTY_SYSV_ABI*)(String*)>(address("5JmzZt8twAo"));
  auto insert = reinterpret_cast<Iterator*(KYTY_SYSV_ABI*)(Iterator*, String*, const Pair*)>(address("ol7KhQl8kfw"));
  auto iterator_dtor = reinterpret_cast<void(KYTY_SYSV_ABI*)(Iterator*)>(address("hoINmSMlYjI"));
  auto index = reinterpret_cast<Value*(KYTY_SYSV_ABI*)(String*, const String*)>(address("ERuf9y0DY84"));
  auto find = reinterpret_cast<Iterator*(KYTY_SYSV_ABI*)(Iterator*, const String*, const String*)>(address("ehN1Biw3tw8"));
  auto end = reinterpret_cast<Iterator*(KYTY_SYSV_ABI*)(Iterator*, const String*)>(address("ivMCitpSQNk"));
  auto equal = reinterpret_cast<bool(KYTY_SYSV_ABI*)(const Iterator*, const Iterator*)>(address("q3YO1c0RqFo"));
  auto copy_iterator = reinterpret_cast<Iterator*(KYTY_SYSV_ABI*)(Iterator*, const Iterator*)>(address("JATlaeBu+lU"));
  auto increment = reinterpret_cast<Iterator*(KYTY_SYSV_ABI*)(Iterator*)>(address("DlWmn2ZQuWY"));
  auto arrow = reinterpret_cast<const Pair*(KYTY_SYSV_ABI*)(const Iterator*)>(address("EnesV4gXDtE"));
  String key, object;
  Value device;
  number(&device, UINT64_MAX);
  Check(*get_uint(&device) == UINT64_MAX, "unsigned getter returns a stable reference without narrowing");
  string_ctor(&key, "deviceId");
  object_ctor(&object);
  Pair pair;
  pair_ctor(&pair, &key, &device);
  Iterator iterator;
  Check(insert(&iterator, &object, &pair) == &iterator && iterator.position != nullptr,
        "object insert returns its non-trivial iterator through the guest result pointer");
  iterator_dtor(&iterator);
  pair_dtor(&pair);
  destroy(&device);
  Check(*get_uint(index(&object, &key)) == UINT64_MAX,
        "inserted device event retains its owned value after pair destruction");
  number(&device, 7);
  pair_ctor(&pair, &key, &device);
  insert(&iterator, &object, &pair);
  iterator_dtor(&iterator);
  pair_dtor(&pair);
  Check(*get_uint(index(&object, &key)) == UINT64_MAX,
        "object insert preserves an existing entry instead of replacing it");
  Iterator found {reinterpret_cast<void*>(0x11111111)}, finish {reinterpret_cast<void*>(0x22222222)}, copied;
  find(&found, &object, &key);
  end(&finish, &object);
  Check(!equal(&found, &finish), "JSON lookup distinguishes an existing device from the end iterator");
  const Pair* entry = arrow(&found);
  Check(entry && std::strcmp(cstr(&entry->key), "deviceId") == 0 &&
            *get_uint(&entry->value) == UINT64_MAX,
        "native iterator arrow exposes the key and value at the guest pair offsets");
  copy_iterator(&copied, &found);
  iterator_dtor(&found);
  entry = arrow(&copied);
  Check(entry && std::strcmp(cstr(&entry->key), "deviceId") == 0 &&
            *get_uint(&entry->value) == UINT64_MAX,
        "copied iterator arrow remains valid after source iterator destruction");
  increment(&copied);
  Check(equal(&copied, &finish), "iterator copy survives source destruction and advances to end");
  Check(arrow(&copied) == nullptr, "end iterator does not expose a JSON entry");
  iterator_dtor(&copied);
  string_ctor(&text, "missing");
  find(&found, &object, &text);
  Check(equal(&found, &finish), "absent JSON configuration key yields an initialized end iterator");
  iterator_dtor(&found);
  iterator_dtor(&finish);
  destroy_string(&text);
  destroy(&device);
  object_dtor(&object);
  destroy_string(&key);
}

void CheckJscHeapLimit() {
  Loader::SymbolDatabase symbols;
  Libs::Jsc::InitJsc_1(&symbols);
  auto address = [&](const char* nid) {
    auto* symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "JSC API registered for heap-limit test");
    return symbol->vaddr;
  };
  auto options = reinterpret_cast<bool(KYTY_SYSV_ABI *)(const char*)>(address("vE61ounVJEI"));
  auto create = reinterpret_cast<void*(KYTY_SYSV_ABI *)(void*, void*)>(address("kQ0tHfaz-R4"));
  auto string = reinterpret_cast<void*(KYTY_SYSV_ABI *)(const char*)>(address("huNf91I8Tjg"));
  auto evaluate = reinterpret_cast<void*(KYTY_SYSV_ABI *)(void*, void*, void*, void*, int, void**)>(
      address("YssF41MWxCU"));
  auto ctx = create(nullptr, nullptr);
  auto script = string("new Array(1000000).fill('allocated')");
  void* exception = nullptr;
  Check(!options(nullptr) && !options("gcMaxHeapSize=garbage") &&
            options("gcMaxHeapSize=131072"), "JSC options validate the requested heap limit");
  Check(evaluate(ctx, script, nullptr, nullptr, 1, &exception) == nullptr && exception != nullptr,
        "JSC heap limit is enforced by the JS engine on an existing context");
  Check(options("gcMaxHeapSize=67108864"), "restore a larger JS heap budget");
  exception = nullptr;
  Check(evaluate(ctx, script, nullptr, nullptr, 1, &exception) != nullptr && exception == nullptr,
        "the same allocation succeeds after raising the engine memory limit");
  options("gcMaxHeapSize=0");
  auto stack_script = string(R"JS((function () {
    var error = new Error('original');
    if (typeof error.stack !== 'string' || error.stack.length === 0)
      throw new Error('initial backtrace missing');
    var values = [null, undefined, 123, ['native frame'], {native: true}, 'replacement'];
    for (var i = 0; i < values.length; ++i) {
      Object.assign(error, {stack: values[i]});
      if (error.stack !== values[i]) throw new Error('stack value changed');
      var descriptor = Object.getOwnPropertyDescriptor(error, 'stack');
      if (!descriptor.writable || !descriptor.configurable || descriptor.enumerable)
        throw new Error('stack property attributes differ');
    }
    var derived = new TypeError('derived');
    derived.stack = null;
    if (derived.stack !== null) throw new Error('derived Error setter differs');
  })())JS");
  exception = nullptr;
  Check(evaluate(ctx, stack_script, nullptr, nullptr, 1, &exception) != nullptr && exception == nullptr,
        "JSC Error.stack retains backtraces and arbitrary native error metadata");
}

void CheckAppConfig(const std::filesystem::path& temporary) {
  Loader::SymbolDatabase symbols;
  Libs::LncUtil::InitLncUtil_1(&symbols);
  using ReceiveLncEvent = int(KYTY_SYSV_ABI *)(void*);
  auto receive_lnc = reinterpret_cast<ReceiveLncEvent>(
      symbols.FindByNid("ZucoOmNsb7w", Loader::SymbolType::Func)->vaddr);
  std::array<uint8_t, 5736> lnc_event;
  lnc_event.fill(0xa5);
  Check(receive_lnc(nullptr) == static_cast<int>(0x80940005u),
        "launch-control receive validates the native event output pointer");
  Check(receive_lnc(lnc_event.data()) == Libs::LibKernel::KERNEL_ERROR_EAGAIN &&
        std::all_of(lnc_event.begin(), lnc_event.end(), [](uint8_t b) { return b == 0xa5; }),
        "empty launch-control receive does not dispatch an invalid zero event");
  Libs::RnpsAppMgr::InitRnpsAppMgr_1(&symbols);
  Libs::UrlConfigResolver::InitUrlConfigResolver_1(&symbols);
  Libs::RegMgr::InitRegMgr_1(&symbols);
  using GetInfo = int (KYTY_SYSV_ABI *)(const char*, void*);
  using GetConfig = int (KYTY_SYSV_ABI *)(const char*, int, void*, uint32_t, uint32_t*, uint64_t);
  using SetStr = int (KYTY_SYSV_ABI *)(uint32_t, const char*, size_t);
  auto info = reinterpret_cast<GetInfo>(symbols.FindByNid("JgBgvkAFMwc", Loader::SymbolType::Func)->vaddr);
  auto config = reinterpret_cast<GetConfig>(symbols.FindByNid("MTEBJdi3YNQ", Loader::SymbolType::Func)->vaddr);
  auto set_str = reinterpret_cast<SetStr>(symbols.FindByNid("ffInidSqRss", Loader::SymbolType::Func)->vaddr);
  using GetInt = int(KYTY_SYSV_ABI *)(uint32_t, int*);
  using SetInt = int(KYTY_SYSV_ABI *)(uint32_t, int);
  using GetIntDefault = int(KYTY_SYSV_ABI *)(uint32_t, int*, uint32_t);
  auto get_int = reinterpret_cast<GetInt>(symbols.FindByNid("mPYKD12UDQI", Loader::SymbolType::Func)->vaddr);
  auto set_int = reinterpret_cast<SetInt>(symbols.FindByNid("khaYelw1Ytc", Loader::SymbolType::Func)->vaddr);
  auto reset_int = reinterpret_cast<SetInt>(symbols.FindByNid("eL7sMZaIdac", Loader::SymbolType::Func)->vaddr);
  auto default_int = reinterpret_cast<GetIntDefault>(symbols.FindByNid("i64ig3BF6f8", Loader::SymbolType::Func)->vaddr);
  int requested_snapshot = 42;
  Check(get_int(0x07410000, &requested_snapshot) == 0 && requested_snapshot == -1,
        "unset user-list restore request does not select snapshot zero");
  Check(set_int(0x07410000, 3) == 0 && get_int(0x07410000, &requested_snapshot) == 0 && requested_snapshot == 3,
        "explicit user-list restore request remains available to ShellCore");
  Check(default_int(0x07410000, &requested_snapshot, 0) == 0 && requested_snapshot == -1,
        "factory restore-request value is independent of an explicit request");
  Check(reset_int(0x07410000, 32) == 0 && get_int(0x07410000, &requested_snapshot) == 0 && requested_snapshot == -1,
        "consuming a restore request resets it to no request");
  const auto rnps = temporary / "rnps";
  const auto cache = temporary / "private" / "cache" / "urlconfig";
  std::filesystem::create_directories(rnps / "apps" / "NPXS40002");
  std::filesystem::create_directories(rnps / "apps" / "NPXS40141");
  std::filesystem::create_directories(rnps / "bgs" / "NPXS40052");
  std::filesystem::create_directories(cache);
  FileSystem::Mount(rnps, "/system_ex/rnps");
  FileSystem::Mount(temporary / "private", "/kyty/priv");
  const auto write = [](const std::filesystem::path& path, const char* data) {
    std::ofstream file(path, std::ios::binary);
    file << data;
    Check(file.good(), "write app catalog fixture");
  };
  using GetAppStatus = int(KYTY_SYSV_ABI *)(void*);
  auto app_status = reinterpret_cast<GetAppStatus>(
      symbols.FindByNid("DxRki7T2E44", Loader::SymbolType::Func)->vaddr);
  const auto current_app = temporary / "shellui";
  std::filesystem::create_directories(current_app / "sce_sys");
  write(current_app / "sce_sys/param.json",
        R"({"titleId":"NPXS40087","applicationCategoryType":16777216,"attribute":7,"masterVersion":"01.00"})");
  Loader::Program program;
  program.file_name = current_app / "eboot.bin";
  program.unique_id = 23;
  const auto previous_program = Loader::RuntimeLinker::GetCurrentProgram();
  Loader::RuntimeLinker::SetCurrentProgram(&program);
  std::array<uint8_t, 57> status; status.fill(0xa5);
  Check(app_status(status.data()) == 0 && status[56] == 0xa5 &&
            *reinterpret_cast<const int32_t*>(status.data()) == 23 &&
            *reinterpret_cast<const int32_t*>(status.data() + 8) == 1 &&
            std::strcmp(reinterpret_cast<const char*>(status.data() + 16), "NPXS40087") == 0 &&
            std::strcmp(reinterpret_cast<const char*>(status.data() + 36), "01.00") == 0,
        "LNC status identifies the running ShellUI from its actual application metadata");
  Check(app_status(nullptr) == static_cast<int>(0x80940005u), "LNC status validates output pointer");
  write(current_app / "sce_sys/param.json",
        R"({"titleId":"NPXS40087","applicationCategoryType":16777216,"kytyLncAppStatusSize":36})");
  status.fill(0xa5);
  Check(app_status(status.data()) == 0 && status[36] == 0xa5 && status[56] == 0xa5 &&
            *reinterpret_cast<const int32_t*>(status.data() + 8) == 1 &&
            std::strcmp(reinterpret_cast<const char*>(status.data() + 16), "NPXS40087") == 0,
        "legacy LNC wire record preserves the bytes beyond its 36-byte output");
  Loader::RuntimeLinker::SetCurrentProgram(previous_program);
  program.is_application = true;
  write(current_app / "sce_sys/param.json",
        R"({"titleId":"PPSA02929","applicationCategoryType":1,"attribute":7})");
  Libs::LncUtil::PostApplicationEvent(1, &program, 0x10000001);
  Libs::LncUtil::PostApplicationEvent(2, &program, 0x10000001);
  struct EventBuffer { Libs::LncUtil::EventWire event; uint64_t canary; } received {};
  received.canary = 0xaabbccddeeff0011ULL;
  Check(receive_lnc(&received.event) == 0 && received.event.event_type == 1 &&
            received.event.app_id == -1 && received.event.app_local_pid == -1 &&
            received.event.app_type == 5 && received.event.user_id == 0x10000001 &&
            std::strcmp(received.event.title_id, "PPSA02929") == 0 &&
            received.event.app_attribute == 7 && received.event.app_category_type == 1 &&
            received.canary == 0xaabbccddeeff0011ULL,
        "LNC launch start opens a pending firmware container and preserves its metadata and buffer bound");
  Check(receive_lnc(&received.event) == 0 && received.event.event_type == 2 &&
            received.event.app_id == 23 && received.event.app_local_pid == 0x10000 + 23 &&
            receive_lnc(&received.event) == Libs::LibKernel::KERNEL_ERROR_EAGAIN,
        "LNC completion assigns the app identity so firmware starts the canvas and releases the launch PS lock");
  using SetAppFocus = int(KYTY_SYSV_ABI *)(int32_t, uint64_t, uint64_t);
  using SetControllerFocus = int(KYTY_SYSV_ABI *)(int32_t);
  auto focus = reinterpret_cast<SetAppFocus>(symbols.FindByNid("v7DYuX0G5TQ", Loader::SymbolType::Func)->vaddr);
  auto controller_focus = reinterpret_cast<SetControllerFocus>(symbols.FindByNid("X8gYbyLG1wk", Loader::SymbolType::Func)->vaddr);
  Check(focus(99999, 0, 0) == static_cast<int>(0x80940005u) &&
            receive_lnc(&received.event) == Libs::LibKernel::KERNEL_ERROR_EAGAIN,
        "unknown application focus cannot publish successful completion");
  Check(focus(23, 0x80, 42) == 0 && receive_lnc(&received.event) == 0 &&
            received.event.event_type == 0x1001 && received.event.app_id == 23 &&
            received.event.context_id == 42 && received.event.check_flags == 0x80 &&
            receive_lnc(&received.event) == 0 && received.event.event_type == 0x1002 &&
            !Libs::LncUtil::IsSystemUiOverlaid(&program),
        "firmware app focus preserves identity and asynchronous completion context");
  Check(controller_focus(23) == 0 && Libs::LncUtil::HasControllerFocus(&program) &&
            receive_lnc(&received.event) == 0 && received.event.event_type == 0x1003 &&
            receive_lnc(&received.event) == 0 && received.event.event_type == 0x1004,
        "firmware controller focus publishes ordered native start and completion events");
  Loader::Program shell;
  shell.unique_id = 24;
  Loader::RuntimeLinker::SetCurrentProgram(&shell);
  shell.file_name = current_app / "eboot.bin";
  write(current_app / "sce_sys/param.json", R"({"titleId":"NPXS40087"})");
  Check(app_status(status.data()) == 0 && focus(24, 0, 0) == 0 && controller_focus(24) == 0 &&
            !Libs::LncUtil::HasControllerFocus(&program) && Libs::LncUtil::HasControllerFocus(&shell) &&
            Libs::LncUtil::IsSystemUiOverlaid(&program),
        "ShellUI focus removes game input while preserving privileged system input");
  while (receive_lnc(&received.event) == 0) {}
  Loader::RuntimeLinker::SetCurrentProgram(previous_program);
  Check(focus(-1, 0, 0) == 0 && controller_focus(-1) == 0,
        "native no-application focus target is accepted");
  while (receive_lnc(&received.event) == 0) {}
  write(rnps / "apps" / "NPXS40002" / "manifest.json",
        R"({"titleId":"NPXS40002","applicationVersion":"7.0.0+16721"})");
  write(rnps / "apps" / "NPXS40141" / "manifest.json",
        R"({"titleId":"NPXS40141","applicationVersion":"0.1.0+2"})");
  using GetMboInfo = int(KYTY_SYSV_ABI *)(void*);
  auto mbo_info = reinterpret_cast<GetMboInfo>(
      symbols.FindByNid("9sYn+PCy608", Loader::SymbolType::Func)->vaddr);
  std::array<char, 129> mbo; mbo.fill('!');
  Check(mbo_info(mbo.data()) == 0 && mbo[128] == '!' &&
            std::strcmp(mbo.data(), "0.1.0+2") == 0 &&
            std::strcmp(mbo.data() + 64, "/system_ex/rnps/apps/NPXS40141") == 0,
        "MBO query supplies the installed RN host's version and directory using the native ABI");
  write(rnps / "bgs" / "NPXS40052" / "manifest.json",
        R"({"titleId":"NPXS40052","applicationVersion":"1.2.3"})");
  std::array<unsigned char, 1163 + 16> record;
  record.fill(0xcc);
  Check(info("NPXS40002", record.data()) == 0, "look up installed RNPS application");
  Check(std::strcmp(reinterpret_cast<char*>(record.data()), "NPXS40002") == 0 &&
            std::strcmp(reinterpret_cast<char*>(record.data() + 10), "7.0.0+16721") == 0 &&
            record[74] == 1 &&
            std::strcmp(reinterpret_cast<char*>(record.data() + 75), "/system_ex/rnps/apps/NPXS40002") == 0,
        "native AppInfo fields select the actual installed manifest");
  Check(std::all_of(record.begin() + 139, record.begin() + 1163, [](auto x) { return x == 0; }) &&
            std::all_of(record.begin() + 1163, record.end(), [](auto x) { return x == 0xcc; }),
        "initialize the entire 1163-byte record without overwriting the caller's next object");
  Check(info("NPXS40052", record.data()) == 0 &&
            std::strcmp(reinterpret_cast<char*>(record.data() + 75), "/system_ex/rnps/bgs/NPXS40052") == 0,
        "background services use their installed bgs directory");
  Check(info("NPXS49999", record.data()) < 0 && info("pstheme:launched", record.data()) < 0 &&
            info("NPXS../..", record.data()) < 0 && info(nullptr, record.data()) < 0 &&
            info("NPXS40002", nullptr) < 0,
        "absent applications and invalid IDs never return a successful empty path");
  std::array<char, 512> output;
  output.fill('x');
  uint32_t required = 999;
  Check(config("pstheme:launched", 0, output.data(), output.size(), &required, 0) < 0 &&
            required == 0 && output[0] == 0,
        "missing URL cache permits ShellUI to fall back to its registered plugin");
  write(cache / "urlconfig_cache.json", R"({"urlconfig":{
    "scheme":{"default":{"pstheme":"app:theme","pshomeui":"app:home",
       "pshomeui:open/detail":"app:detail","default":"app:fallback"},
       "test":{"pstheme":"app:theme"}},
    "app":{"theme":{"default":{"plugin":"Theme"},"test":{"plugin":"TestTheme"}},
       "home":{"default":{"rnps":{"titleId":"NPXS40002"},"component":"Home"}},
       "detail":{"default":{"component":"Detail"}},
       "fallback":{"default":{"component":"Fallback"}}}}})");
  Check(config("pstheme:launched", 0, nullptr, 0, &required, 0) == static_cast<int>(0x80ba8090),
        "probe config size using the native buffer-too-short result");
  Check(required == std::strlen("{\"plugin\":\"Theme\"}") + 1,
        "config required length includes the terminator");
  Check(config("pstheme:launched", 0, output.data(), required - 1, &required, 0) == static_cast<int>(0x80ba8090),
        "a buffer missing the terminator byte is too short");
  Check(config("pstheme:launched", 0, output.data(), output.size(), &required, 0) == 0 &&
            std::strcmp(output.data(), "{\"plugin\":\"Theme\"}") == 0,
        "native theme config is returned without an invented rnps dispatch field");
  Check(config("pshomeui:open/detail/more?q=1", 0, output.data(), output.size(), &required, 0) == 0 &&
            std::strcmp(output.data(), "{\"component\":\"Detail\"}") == 0,
        "longest URI path prefix takes precedence over the generic scheme");
  Check(config("unknown:launch", 0, output.data(), output.size(), &required, 0) == -2135261049 && required == 0,
        "unknown URI cannot silently select an RNPS application");
  Check(config("unknown:launch", 1, output.data(), output.size(), &required, 0) == 0 &&
            std::strcmp(output.data(), "{\"component\":\"Fallback\"}") == 0,
        "default routes apply only when requested");
  Check(set_str(0x19800000, "test", 5) == 0 &&
            config("pstheme:launched", 0, output.data(), output.size(), &required, 0) == 0 &&
            std::strcmp(output.data(), "{\"plugin\":\"TestTheme\"}") == 0,
        "registry selector chooses both route map and app variant");
  Check(set_str(0x19800000, "", 1) == 0, "restore default config selector");
  write(cache / "urlconfig_cache.json", R"({"response":{
      "scheme":{"default":{"pshomeui:main":"app:rnps-homeui"}},
      "app":{"rnps-homeui":{"default":{"rnps":{"component":"Main","titleId":"NPXS40002"}}}}},
      "url":"server-response-cache","hash":"preserved"})");
  Check(config("pshomeui:main?lastFocusTitleId=", 0, output.data(), output.size(), &required, 0) == 0 &&
            std::strcmp(output.data(), "{\"rnps\":{\"component\":\"Main\",\"titleId\":\"NPXS40002\"}}") == 0,
        "installed server response cache resolves the original HomeUI title and component");
  write(cache / "urlconfig_cache.json", R"({"response":{
      "scheme":{"default":{"pshomeui":"app:home","psnotification:main":"app:notification",
          "psvoiceagent:main":"app:agent","pscapture:main":"app:capture",
          "pscheckout:main":"app:checkout","psmediagallery:main":"app:gallery",
          "pstrophy:main":"app:trophy"}},
      "app":{"home":{"default":{"rnps":{"titleId":"NPXS40002"}}},
          "notification":{"default":{"rnps":{"titleId":"NPXS40011"}}},
          "agent":{"default":{"rnps":{"titleId":"NPXS40048"}}},
          "capture":{"default":{"rnps":{"titleId":"NPXS40024"}}},
          "checkout":{"default":{"rnps":{"titleId":"NPXS40062"}}},
          "gallery":{"default":{"rnps":{"titleId":"NPXS40075"}}},
          "trophy":{"default":{"rnps":{"titleId":"NPXS40025"}}}}}})");
  std::filesystem::create_directories(rnps / "apps/NPXS40011");
  std::filesystem::create_directories(rnps / "apps/NPXS40048");
  std::filesystem::create_directories(rnps / "apps/NPXS40024");
  std::filesystem::create_directories(rnps / "apps/NPXS40062");
  write(rnps / "apps/NPXS40011/application.ps.bundle", "RNPSHEDRbinary encrypted payload");
  write(rnps / "apps/NPXS40048/application.ps.bundle", "RNPSHEDRbinary encrypted payload");
  write(rnps / "apps/NPXS40024/application.ps.bundle", "RNPSHEDRbinary encrypted payload");
  write(rnps / "apps/NPXS40062/application.ps.bundle", "RNPSHEDRbinary encrypted payload");
  std::filesystem::create_directories(rnps / "apps/NPXS40025");
  write(rnps / "apps/NPXS40025/application.ps.bundle", "RNPSHEDRbinary encrypted payload");
  std::filesystem::create_directories(rnps / "apps/NPXS40075");
  write(rnps / "apps/NPXS40075/application.ps.bundle", "RNPSHEDRbinary encrypted payload");
  Check(config("psnotification:main", 0, output.data(), output.size(), &required, 0) == 0,
        "default boot retains encrypted overlay routes");
  Config::ConfigOptions diagnostic;
  diagnostic.guest_environment = Config::GetGuestEnvironment();
  const auto original_environment = diagnostic.guest_environment;
  diagnostic.guest_environment["KYTY_SKIP_ENCRYPTED_OVERLAYS"] = "1";
  Config::Load(diagnostic);
  Check(config("psnotification:main", 0, output.data(), output.size(), &required, 0) == -2135261049 &&
            required == 0 && output[0] == 0 &&
            config("psvoiceagent:main", 0, output.data(), output.size(), &required, 0) == -2135261049 &&
            config("pscapture:main", 0, output.data(), output.size(), &required, 0) == -2135261049 &&
            config("pscheckout:main", 0, output.data(), output.size(), &required, 0) == -2135261049 &&
            config("pstrophy:main", 0, output.data(), output.size(), &required, 0) == -2135261049 &&
            config("pshomeui:main", 0, output.data(), output.size(), &required, 0) == 0,
        "diagnostic boot skips unavailable overlays through missing routes while retaining HomeUI");
  Check(config("psmediagallery:main", 0, output.data(), output.size(), &required, 0) == 0,
        "overlay diagnostic option does not disable other application routes");
  diagnostic.guest_environment["KYTY_SKIP_ENCRYPTED_KIT_APPS"] = "1";
  Config::Load(diagnostic);
  Check(config("psmediagallery:main", 0, output.data(), output.size(), &required, 0) == -2135261049 &&
            config("pshomeui:main", 0, output.data(), output.size(), &required, 0) == 0,
        "kit app diagnostic avoids encrypted gallery loading while retaining HomeUI");
  write(rnps / "apps/NPXS40075/application.ps.bundle", "console.log('decoded gallery');");
  Check(config("psmediagallery:main", 0, output.data(), output.size(), &required, 0) == 0,
        "decoded gallery becomes available without changing the signed routing cache");
  write(rnps / "apps/NPXS40011/application.ps.bundle", "console.log('decoded notification');");
  Check(config("psnotification:main", 0, output.data(), output.size(), &required, 0) == 0,
        "diagnostic boot allows supplied decoded optional applications");
  write(rnps / "apps/NPXS40025/application.ps.bundle", "console.log('decoded trophy');");
  Check(config("pstrophy:main", 0, output.data(), output.size(), &required, 0) == 0,
        "decoded trophy restores its original route without an app-specific replacement");
  diagnostic.guest_environment = original_environment;
  Config::Load(diagnostic);
  Check(config("psvoiceagent:main", 0, output.data(), output.size(), &required, 0) == 0,
        "disabling diagnostic mode restores the original encrypted overlay route");
  FileSystem::Umount("/system_ex/rnps");
  FileSystem::Umount("/kyty/priv");
}

void CheckSharedMemory() {
  namespace Memory = Libs::LibKernel::Memory;
  using namespace Libs::LibKernel;
  const char* name = "/kyty-shared-test";
  Check(FileSystem::KernelShmOpen(name, 2, 0600) == KERNEL_ERROR_ENOENT,
        "missing shared memory cannot be opened without create");
  const int first = FileSystem::KernelShmOpen(name, 0x202, 0600);
  Check(first >= 3 && FileSystem::KernelShmOpen(name, 0xa02, 0600) == KERNEL_ERROR_EEXIST,
        "shared memory returns a real descriptor and enforces exclusive create");
  Check(FileSystem::KernelFtruncate(first, 0x8000) == OK, "size shared object");
  FileSystem::FileStat stat {};
  Check(FileSystem::KernelFstat(first, &stat) == OK && stat.st_size == 0x8000,
        "shared memory size is visible through fstat");
  const int second = FileSystem::KernelShmOpen(name, 2, 0600);
  const int readonly = FileSystem::KernelShmOpen(name, 0, 0600);
  void* a = nullptr;
  void* b = nullptr;
  void* denied = nullptr;
  Check(FileSystem::KernelMapSharedMemory(first, &a, 0x8000, 3, 0, 0) == OK &&
            FileSystem::KernelMapSharedMemory(second, &b, 0x8000, 3, 0, 0) == OK && a != b,
        "same named object supports distinct coherent mappings");
  Check(static_cast<uint32_t*>(a)[0] == 0, "new shared object is zero filled");
  static_cast<uint32_t*>(a)[0] = 0x12345678;
  static_cast<uint32_t*>(b)[0x4000 / 4] = 0x87654321;
  Check(static_cast<uint32_t*>(b)[0] == 0x12345678 &&
            static_cast<uint32_t*>(a)[0x4000 / 4] == 0x87654321,
        "both mappings see writes immediately in both directions");
  Check(FileSystem::KernelMapSharedMemory(readonly, &denied, 0x4000, 3, 0, 0) == KERNEL_ERROR_EACCES &&
            FileSystem::KernelFtruncate(readonly, 0x4000) == KERNEL_ERROR_EBADF,
        "read-only descriptors reject writable mappings and truncate");
  Check(FileSystem::KernelFtruncate(first, 0xc000) == OK &&
            static_cast<uint32_t*>(b)[0] == 0x12345678,
        "growing shared backing preserves live aliases");
  void* tail = nullptr;
  Check(FileSystem::KernelMapSharedMemory(first, &tail, 0x4000, 3, 0, 0x8000) == OK &&
            static_cast<uint32_t*>(tail)[0] == 0,
        "newly grown pages are zero filled and support offset mappings");
  Check(FileSystem::KernelShmUnlink(name) == OK &&
            FileSystem::KernelShmOpen(name, 2, 0600) == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelClose(first) == OK && FileSystem::KernelClose(second) == OK &&
            FileSystem::KernelClose(readonly) == OK && static_cast<uint32_t*>(a)[0] == 0x12345678,
        "unlink removes only the name; close leaves mapped content alive");
  const int replacement = FileSystem::KernelShmOpen(name, 0x202, 0600);
  void* fresh = nullptr;
  Check(FileSystem::KernelFtruncate(replacement, 0x4000) == OK &&
            FileSystem::KernelMapSharedMemory(replacement, &fresh, 0x4000, 3, 0, 0) == OK &&
            static_cast<uint32_t*>(fresh)[0] == 0,
        "recreating an unlinked name gives a separate zero-filled object");
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(a), 0x4000) == OK &&
            static_cast<uint32_t*>(a)[0x4000 / 4] == 0x87654321 &&
            Memory::KernelMunmap(reinterpret_cast<uint64_t>(a) + 0x4000, 0x4000) == OK &&
            Memory::KernelMunmap(reinterpret_cast<uint64_t>(b), 0x8000) == OK &&
            Memory::KernelMunmap(reinterpret_cast<uint64_t>(tail), 0x4000) == OK,
        "partial unmap keeps the remaining aliases and backing alive");
  Check(FileSystem::KernelShmUnlink(name) == OK && FileSystem::KernelClose(replacement) == OK &&
            Memory::KernelMunmap(reinterpret_cast<uint64_t>(fresh), 0x4000) == OK,
        "final shared mapping can outlive its name and last descriptor");
}

void CheckFileMapping(const std::filesystem::path& temporary) {
  using namespace Libs::LibKernel;
  const auto directory = temporary / "file-mapping";
  std::filesystem::create_directories(directory);
  std::vector<uint8_t> contents(0x8013);
  for (size_t i = 0; i < contents.size(); ++i) contents[i] = static_cast<uint8_t>(i * 37 + 11);
  { std::ofstream file(directory / "resource.bin", std::ios::binary);
    file.write(reinterpret_cast<const char*>(contents.data()), contents.size()); }
  FileSystem::Mount(directory, "/test-file-mapping");
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  auto* symbol = symbols.FindByNid("PGhQHd-dzv8", Loader::SymbolType::Func);
  Check(symbol != nullptr, "sceKernelMmap is registered");
  auto map = reinterpret_cast<int(KYTY_SYSV_ABI *)(void*, size_t, int, int, int, int64_t, void**)>(symbol->vaddr);
  const int fd = FileSystem::KernelOpen("/test-file-mapping/resource.bin", 0, 0);
  Check(fd >= 3 && FileSystem::KernelLseek(fd, 7, 0) == 7, "open mapping fixture and set file position");
  void* full = nullptr;
  Check(map(nullptr, contents.size(), 1, 0, fd, 0, &full) == OK && full != nullptr &&
            std::memcmp(full, contents.data(), contents.size()) == 0 &&
            static_cast<uint8_t*>(full)[0xbfff] == 0 && FileSystem::KernelLseek(fd, 0, 1) == 7,
        "file mapping reads all pages, zero-fills EOF padding and preserves descriptor position");
  Memory::VirtualQueryInfo info {};
  Check(Memory::KernelVirtualQuery(full, 0, &info, sizeof(info)) == OK && info.protection == 1,
        "file mapping applies the requested read-only protection");
  void* tail = nullptr;
  Check(map(nullptr, 0x4013, 3, 2, fd, 0x4000, &tail) == OK &&
            std::memcmp(tail, contents.data() + 0x4000, 0x4013) == 0,
        "private mapping honors a nonzero page-aligned file offset");
  static_cast<uint8_t*>(tail)[0] ^= 0xff;
  uint8_t original = 0;
  Check(FileSystem::KernelPread(fd, &original, 1, 0x4000) == 1 && original == contents[0x4000] &&
            static_cast<uint8_t*>(full)[0x4000] == contents[0x4000],
        "private writes do not modify the file or other mappings");
  void* unchanged = reinterpret_cast<void*>(0x1234);
  Check(map(nullptr, 0, 1, 0, fd, 0, &unchanged) == KERNEL_ERROR_EINVAL &&
            map(nullptr, 1, 1, 0, fd, 1, &unchanged) == KERNEL_ERROR_EINVAL &&
            map(nullptr, 1, 1, 0, -1, 0, &unchanged) == KERNEL_ERROR_EBADF &&
            map(nullptr, 1, 3, 1, fd, 0, &unchanged) == KERNEL_ERROR_EOPNOTSUPP &&
            unchanged == reinterpret_cast<void*>(0x1234),
        "failed file mappings preserve the output pointer and report unsupported shared writeback");
  Check(FileSystem::KernelClose(fd) == OK && std::memcmp(full, contents.data(), contents.size()) == 0 &&
            Memory::KernelMunmap(reinterpret_cast<uint64_t>(full), 0xc000) == OK &&
            Memory::KernelMunmap(reinterpret_cast<uint64_t>(tail), 0x8000) == OK,
        "file mappings outlive their descriptor and unmap through the guest VM manager");
  FileSystem::Umount("/test-file-mapping");
}

void CheckConsoleDevice() {
  using namespace Libs::LibKernel;
  const int fd = FileSystem::KernelOpen("/dev/console", 1, 0);
  Check(fd >= 3, "ShellUI UART console opens as a descriptor");
  const char message[] = "KernelFileSystemTests: console output bytes\n";
  Check(FileSystem::KernelWrite(fd, message, sizeof(message) - 1) == sizeof(message) - 1,
        "console writes all bytes to the host output stream");
  char byte = 0;
  Check(FileSystem::KernelRead(fd, &byte, 1) == KERNEL_ERROR_EBADF,
        "write-only console cannot be read");
  FileSystem::FileStat stat {};
  Check(FileSystem::KernelFstat(fd, &stat) == OK && (stat.st_mode & 0170000) == 0020000,
        "console descriptor is a character device");
  Check(FileSystem::KernelClose(fd) == OK &&
            FileSystem::KernelWrite(fd, message, 1) == KERNEL_ERROR_EBADF,
        "console close invalidates the guest descriptor");
}

void CheckPipeWakeup() {
  int ends[2] = {};
  Check(FileSystem::KernelCreatePipe(ends) == OK, "create duplex pipe");
  char received = 0;
  auto reader = std::async(std::launch::async, [&] {
    return FileSystem::KernelRead(ends[1], &received, 1);
  });
  Check(reader.wait_for(std::chrono::milliseconds(50)) == std::future_status::timeout,
        "empty blocking pipe waits for data");
  const char payload = 'a';
  Check(FileSystem::KernelWrite(ends[0], &payload, 1) == 1,
        "write through first pipe endpoint");
  Check(reader.wait_for(std::chrono::seconds(2)) == std::future_status::ready &&
            reader.get() == 1 && received == payload,
        "pipe write wakes reverse-end reader");
  Check(FileSystem::KernelWrite(ends[1], &payload, 1) == 1 &&
            FileSystem::KernelRead(ends[0], &received, 1) == 1,
        "pipe transfers bytes in both directions");
  Check(FileSystem::KernelFcntl(ends[0], 4, 4) == 0 &&
            (FileSystem::KernelFcntl(ends[0], 3, 0) & 4) != 0 &&
            FileSystem::KernelRead(ends[0], &received, 1) ==
                Libs::LibKernel::KERNEL_ERROR_EAGAIN,
        "empty nonblocking pipe reports EAGAIN");
  Check(FileSystem::KernelClose(ends[1]) == OK &&
            FileSystem::KernelRead(ends[0], &received, 1) == 0 &&
            FileSystem::KernelWrite(ends[0], &payload, 1) ==
                Libs::LibKernel::KERNEL_ERROR_EPIPE,
        "closed peer produces EOF and broken pipe");
  Check(FileSystem::KernelClose(ends[0]) == OK, "close remaining pipe endpoint");
}

void CheckDevkitActivation(const std::filesystem::path& root) {
  using namespace Libs::LibKernel;
  Config::ConfigOptions config;
  config.guest_environment = Config::GetGuestEnvironment();
  const int fd = FileSystem::KernelOpen("/dev/devact", 2, 0);
  Check(fd >= 3, "native kit activation wrapper can open its device");
  std::array<uint32_t, 6> record;
  for (int days : {30, 2, 1, 0, -1, -365, 49710}) {
    config.devkit_activation_days = days;
    Config::Load(config);
    record.fill(0xdeadbeef);
    Check(FileSystem::KernelIoctl(fd, 0x40144401u, record.data()) == OK &&
          record[4] == 0 && record[5] == 0xdeadbeef,
          "activation reply initializes status and respects the 20-byte ABI");
    const uint32_t remaining = record[1] > record[0] ? record[1] - record[0] : 0;
    Check(days > 0 ? remaining > static_cast<uint32_t>(days - 1) * 86400u &&
                    remaining <= static_cast<uint32_t>(days) * 86400u : remaining == 0,
          "native subtraction produces configured days, including expired negative days");
  }
  Check(FileSystem::KernelIoctl(fd, 0x40144401u, nullptr) == KERNEL_ERROR_EFAULT &&
        FileSystem::KernelIoctl(fd, 0, record.data()) == KERNEL_ERROR_ENOTTY,
        "activation device rejects missing buffers and unsupported requests");
  Check(FileSystem::KernelClose(fd) == OK &&
        FileSystem::KernelIoctl(fd, 0x40144401u, record.data()) == KERNEL_ERROR_EBADF,
        "closed activation descriptors cannot be queried");
  config.devkit_activation_days = 30;
  Config::Load(config);
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  Libs::ShellCoreUtil::InitShellCoreUtil_1(&symbols);
  auto identity = [&](const char* nid, const char* expected) {
    auto fn = reinterpret_cast<int(KYTY_SYSV_ABI*)(char*)>(
        symbols.FindByNid(nid, Loader::SymbolType::Func)->vaddr);
    std::array<char, 128> buffer;
    buffer.fill('!');
    Check(fn(buffer.data()) == OK && std::strcmp(buffer.data(), expected) == 0 &&
          buffer[127] == '!' && fn(nullptr) == KERNEL_ERROR_EFAULT,
          "kit identity queries return terminated virtual identity without overwriting the buffer");
  };
  identity("PgGve9EvhPE", "KYTY0000000001");
  identity("JC7I7J1bllQ", "Kyty DevKit");
  auto space = reinterpret_cast<int(KYTY_SYSV_ABI*)(uint64_t*, uint64_t*)>(
      symbols.FindByNid("ZbY5LxmH6uA", Loader::SymbolType::Func)->vaddr);
  FileSystem::Mount(root, "/system_data");
  uint64_t available = 0, total = 0;
  Check(space(&available, &total) == OK && total > 0 && available <= total &&
        space(nullptr, &total) == KERNEL_ERROR_EFAULT,
        "kit panel storage reports the actual backing volume capacity");
  FileSystem::Umount("/system_data");
}

void CheckScreenshotDevice() {
  namespace Memory = Libs::LibKernel::Memory;
  using namespace Libs::LibKernel;
  constexpr size_t page = 0x4000;
  int64_t physical = -1;
  Check(Memory::KernelAllocateMainDirectMemory(2 * page, page, 11, &physical) == OK,
        "allocate screenshot backing");
  void* buffer = nullptr;
  Check(Memory::KernelMapDirectMemory(&buffer, 2 * page, 3, 0, physical, page) == OK,
        "map screenshot backing");
  std::array<uint8_t, 112> record {};
  const uint64_t address = reinterpret_cast<uint64_t>(buffer);
  const uint32_t length = 2 * page, alignment = page;
  std::memcpy(record.data() + 8, &address, 8);
  std::memcpy(record.data() + 24, &length, 4);
  std::memcpy(record.data() + 28, &alignment, 4);
  const int fd = FileSystem::KernelOpen("/dev/sshot", 2, 0);
  Check(fd >= 3 && FileSystem::KernelIoctl(-1, 0xc0709d01, record.data()) == KERNEL_ERROR_EBADF &&
        FileSystem::KernelIoctl(fd, 0xc0709d01, nullptr) == KERNEL_ERROR_EFAULT,
        "screenshot ioctl validates descriptor and record");
  const auto original = record;
  Check(FileSystem::KernelIoctl(fd, 0xc0709d01, record.data()) == OK && record == original &&
        FileSystem::KernelIoctl(fd, 0xc0709d01, record.data()) == KERNEL_ERROR_EBUSY &&
        FileSystem::KernelIoctl(fd, 0xc4e09d03, record.data()) == KERNEL_ERROR_ENOTTY,
        "screenshot attach tracks ownership and unsupported capture remains an error");
  static_cast<uint32_t*>(buffer)[0] = 0xabc123;
  Check(FileSystem::KernelIoctl(fd, 0xc0709d02, record.data()) == OK &&
        static_cast<uint32_t*>(buffer)[0] == 0xabc123 &&
        FileSystem::KernelIoctl(fd, 0xc0709d01, record.data()) == OK &&
        FileSystem::KernelClose(fd) == OK && static_cast<uint32_t*>(buffer)[0] == 0xabc123 &&
        FileSystem::KernelIoctl(fd, 0xc0709d01, record.data()) == KERNEL_ERROR_EBADF,
        "detach and close never free the caller's screenshot memory");
  const int next = FileSystem::KernelOpen("/dev/sshot", 2, 0);
  Check(Memory::KernelMunmap(address + page, page) == OK &&
        FileSystem::KernelIoctl(next, 0xc0709d01, record.data()) == KERNEL_ERROR_EFAULT &&
        FileSystem::KernelClose(next) == OK && Memory::KernelMunmap(address, page) == OK &&
        Memory::KernelReleaseDirectMemory(physical, 2 * page) == OK,
        "screenshot attach rejects a hole in the backing without taking ownership");
}

void CheckSparseUnmap() {
  namespace Memory = Libs::LibKernel::Memory;
  constexpr uint64_t address = 0x1200000000;
  constexpr size_t page = 0x4000;
  int64_t physical = -1;
  Check(Memory::KernelAllocateMainDirectMemory(2 * page, page, 11, &physical) == OK,
        "allocate sparse unmap backing");
  void* first = reinterpret_cast<void*>(address);
  void* last = reinterpret_cast<void*>(address + 2 * page);
  Check(Memory::KernelMapDirectMemory(&first, page, 3, 0x90, physical, page) == OK &&
        Memory::KernelMapDirectMemory(&last, page, 3, 0x90, physical + page, page) == OK,
        "map pages around a hole");
  Check(Memory::KernelMunmap(address, 3 * page) == OK &&
        Memory::KernelMunmap(address, 3 * page) == OK,
        "sparse and already empty unmap both succeed");
  Memory::VirtualQueryInfo info {};
  Check(Memory::KernelVirtualQuery(first, 0, &info, sizeof(info)) != OK &&
        Memory::KernelVirtualQuery(last, 0, &info, sizeof(info)) != OK &&
        Memory::KernelMunmap(UINT64_MAX - page + 1, 2 * page) == Libs::LibKernel::KERNEL_ERROR_EINVAL &&
        Memory::KernelMunmap(0x1000, page) == Libs::LibKernel::KERNEL_ERROR_EINVAL &&
        Memory::KernelReleaseDirectMemory(physical, 2 * page) == OK,
        "sparse unmap releases both mappings and rejects host addresses and overflow");
}

void CheckCoHostedCompositorViews() {
  namespace Memory = Libs::LibKernel::Memory;
  constexpr size_t page = 0x4000;
  const auto code = Memory::AllocateProgramMemory(0xe000000000ull, page,
      Common::VirtualMemory::Mode::ExecuteReadWrite, "cohost-code-test");
  Check(code != 0, "allocate co-hosted program memory");
  auto* sentinel = reinterpret_cast<uint32_t*>(code);
  *sentinel = 0x15935728;
  void* replacement = reinterpret_cast<void*>(code);
  Check(Memory::KernelReserveVirtualRange(&replacement, page, 0x10, page) ==
            Libs::LibKernel::KERNEL_ERROR_ENOMEM && *sentinel == 0x15935728,
        "guest fixed reservation cannot overwrite another co-hosted program's metadata");
  Check(Memory::FreeGuestMemory(code, page), "release program test mapping through its owner");
  int64_t physical = -1;
  Check(Memory::KernelAllocateMainDirectMemory(3 * page, page, 11, &physical) == OK,
        "allocate compositor shared view backing");
  void* view = nullptr;
  Check(Memory::KernelMapNamedDirectMemory(&view, 2 * page, 0x33, 0, physical, page,
                                           "CompositorShmPermanentMem") == OK,
        "map compositor server permanent memory");
  auto* data = static_cast<uint32_t*>(view);
  data[0] = 0x12345678;
  data[page / sizeof(uint32_t)] = 0xabcdef12;
  Memory::KernelBatchMapEntry entry {view, static_cast<uint64_t>(physical), 2 * page, 3, 11, 0, 0};
  int completed = -1;
  Check(Memory::KernelBatchMap2(&entry, 1, &completed, 0x90) == OK && completed == 1 &&
        data[0] == 0x12345678,
        "co-hosted compositor client leases the identical existing backing");
  entry.offset += page;
  Check(Memory::KernelBatchMap2(&entry, 1, &completed, 0x90) == Libs::LibKernel::KERNEL_ERROR_ENOMEM &&
        completed == 0 && data[0] == 0x12345678,
        "compositor view reuse rejects a different physical mapping");
  entry.offset -= page;
  entry.protection = 1;
  Check(Memory::KernelBatchMap2(&entry, 1, &completed, 0x90) == Libs::LibKernel::KERNEL_ERROR_ENOMEM,
        "compositor view reuse rejects different permissions");
  void* duplicate = view;
  Check(Memory::KernelMapDirectMemory(&duplicate, page, 3, 0x90, physical, page) ==
            Libs::LibKernel::KERNEL_ERROR_ENOMEM,
        "ordinary no-overwrite mapping still rejects an occupied address");
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(view), page) == OK &&
        data[0] == 0x12345678,
        "partial client unmap retains the server's first page");
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(view), 2 * page) == OK &&
        data[page / sizeof(uint32_t)] == 0xabcdef12,
        "server unmap releases its first page and retains the leased second page");
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(view) + page, page) == OK &&
        Memory::KernelReleaseDirectMemory(physical, 3 * page) == OK,
        "final client lease releases the remaining view and physical backing");
}

void CheckLibcRuntime(const std::filesystem::path& root) {
  namespace Flags = Libs::LibKernel::EventFlag;
  Flags::KernelEventFlag boot = nullptr;
  Check(Flags::KernelOpenEventFlag(&boot, "SceBootStatusFlags") == OK,
        "open shared boot status flag");
  std::promise<void> started;
  auto entered = started.get_future();
  auto waiter = std::async(std::launch::async, [&]() {
    uint32_t timeout = 500000;
    started.set_value();
    return Flags::KernelWaitEventFlag(boot, 0x1000, 1, nullptr, &timeout);
  });
  entered.wait();
  Check(waiter.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout,
        "first boot client waits for its missing status bit");
  const int ready = Flags::KernelPollEventFlag(boot, 4, 1, nullptr);
  Flags::KernelSetEventFlag(boot, 0x1000);
  Check(waiter.get() == OK, "pending boot client wakes on its status bit");
  Check(ready == OK, "compositor readiness remains readable while another client waits");
  Check(Flags::KernelDeleteEventFlag(boot) == OK, "close boot status test flag");
  Flags::KernelEventFlag m2 = nullptr;
  uint64_t m2_result = 0;
  uint32_t m2_timeout = 1000;
  Check(Flags::KernelOpenEventFlag(&m2, "SceAutoMounterUIM2Evf") == OK &&
        Flags::KernelWaitEventFlag(m2, 0xff, 2, &m2_result, &m2_timeout) == OK &&
        m2_result == 1 && Flags::KernelDeleteEventFlag(m2) == OK,
        "offline M.2 scan completes without a storage dialog");
  Check(Flags::KernelCreateEventFlag(&m2, "SceAutoMounterUIM2Evf", 0x100, 4, nullptr) == OK &&
        Flags::KernelPollEventFlag(m2, 0xff, 2, &m2_result) == OK && m2_result == 4 &&
        Flags::KernelDeleteEventFlag(m2) == OK,
        "a real M.2 service owns its result without offline synthesis");
  namespace Net = Libs::Network::Net;
  namespace Queues = Libs::LibKernel::EventQueue;
  std::array<uint8_t, 16> listener_address {16, 2, 0, 0, 127, 0, 0, 1};
  const int listener = Net::Socket(2, 1, 0);
  Check(listener >= 0 && Net::Bind(listener, listener_address.data(), listener_address.size()) == 0 &&
            Net::Listen(listener, 1) == 0, "create event queue test listener");
  uint32_t listener_size = listener_address.size();
  Check(Net::Getsockname(listener, listener_address.data(), &listener_size) == 0,
        "get event queue listener port");
  Queues::KernelEqueue queue = Queues::KERNEL_EQUEUE_INVALID;
  Check(Queues::KernelCreateEqueue(&queue, "CompositorReadTest") == OK &&
            Queues::KernelAddReadEvent(queue, listener, 0, &listener_size) == OK,
        "register compositor listener read event");
  auto listening_event = std::async(std::launch::async, [&]() {
    Queues::KernelEvent event {};
    int count = 0;
    uint32_t timeout = 500000;
    const int result = Queues::KernelWaitEqueue(queue, &event, 1, &count, &timeout);
    return result == OK && count == 1 && event.ident == static_cast<uintptr_t>(listener) &&
           event.filter == Queues::KERNEL_EVFILT_READ && event.udata == &listener_size;
  });
  Check(listening_event.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout,
        "read event waits while listener has no pending connection");
  const int client = Net::Socket(2, 1, 0);
  Check(client >= 0 && Net::Connect(client, listener_address.data(), listener_size) == 0,
        "connect compositor event queue client");
  Check(listening_event.get(), "socket readiness wakes a pending compositor event queue wait");
    std::array<uint8_t, 16> peer_address;
    peer_address.fill(0xa5);
    uint32_t peer_size = 0;
    const int accepted = Net::Accept(listener, peer_address.data(), &peer_size);
    Check(accepted >= 0 && peer_size == peer_address.size() && peer_address[0] == 0xa5,
          "accept with zero address capacity preserves the connection and caller buffer");
  Net::SocketClose(accepted);
  Net::SocketClose(client);
  Net::SocketClose(listener);
  Check(Queues::KernelDeleteEqueue(queue) == OK, "delete compositor read test queue");
#if defined(_WIN32)
    FileSystem::Mount(root, "/compositor-test");
    std::array<uint8_t, 106> unix_address {};
    unix_address[0] = unix_address.size();
    unix_address[1] = 1;
    std::strcpy(reinterpret_cast<char*>(unix_address.data() + 2), "/compositor-test/ipc");
    const int unix_listener = Net::Socket(1, 1, 0);
    const int unix_client = Net::Socket(1, 1, 0);
    Check(unix_listener >= 0 && unix_client >= 0 &&
              Net::Bind(unix_listener, unix_address.data(), unix_address.size()) == 0 &&
              Net::Listen(unix_listener, 1) == 0 &&
              Net::Connect(unix_client, unix_address.data(), unix_address.size()) == 0,
          "connect a compositor Unix socket pair");
    peer_size = 0;
    const int unix_accepted = Net::Accept(unix_listener, peer_address.data(), &peer_size);
    Check(unix_accepted >= 0 && peer_size == 2 && peer_address[0] == 0xa5,
          "Unix accept matches the compositor's zero-capacity address request");
    int peer_pid = -1;
    Check(Net::GetUnixPeerProcessId(unix_accepted, &peer_pid) == 0 && peer_pid == 100,
          "compositor peer credentials identify the co-hosted guest process");
    Check(Net::GetUnixPeerProcessId(unix_accepted, nullptr) == -1,
          "peer process query rejects a null destination");
    Loader::Program game;
    game.unique_id = 203;
    game.is_application = true;
    auto* previous_program = Loader::RuntimeLinker::GetCurrentProgram();
    Loader::RuntimeLinker::SetCurrentProgram(&game);
    const int game_pid = Loader::RuntimeLinker::GetCurrentProcessId();
    const int game_client = Net::Socket(1, 1, 0);
    Check(game_pid != 100 && game_client >= 0 &&
              Net::Connect(game_client, unix_address.data(), unix_address.size()) == 0,
          "game connects to the compositor with its own guest process identity");
    Loader::RuntimeLinker::SetCurrentProgram(previous_program);
    const int game_accepted = Net::Accept(unix_listener, nullptr, nullptr);
    Check(game_accepted >= 0 && Net::GetUnixPeerProcessId(game_accepted, &peer_pid) == 0 &&
              peer_pid == game_pid && Loader::RuntimeLinker::GetCurrentProcessId() == 100,
          "compositor sees the game's PID rather than its own accepting-thread PID");
    Net::SocketClose(game_client);
    Check(Net::GetUnixPeerProcessId(game_accepted, &peer_pid) == 0 && peer_pid == game_pid,
          "accepted endpoint preserves guest credentials after the client closes");
    Net::SocketClose(game_accepted);
    const char request = 'q';
    char response = 0;
    Check(Net::Sendto(unix_client, &request, 1, 0, nullptr, 0) == 1 &&
              Net::Recvfrom(unix_accepted, &response, 1, 0, nullptr, nullptr) == 1 && response == request,
          "accepted compositor socket remains usable after address truncation");
    Net::SocketClose(unix_accepted);
    Net::SocketClose(unix_client);
    Net::SocketClose(unix_listener);
  const int ipc_socket = Libs::Network::Net::Socket(1, 1, 0);
  const int no_sigpipe = 1;
  Check(ipc_socket >= 0, "create compositor Unix socket");
  Check(Libs::Network::Net::Setsockopt(ipc_socket, 0xffff, 0x0800,
                                     &no_sigpipe, sizeof(no_sigpipe)) == 0,
        "Unix compositor socket accepts BSD SO_NOSIGPIPE on Windows");
  Check(Libs::Network::Net::Setsockopt(ipc_socket, 0xffff, 0x0800,
                                     &no_sigpipe, 1) == -1,
        "SO_NOSIGPIPE rejects a truncated option value");
  Check(Libs::Network::Net::SocketClose(ipc_socket) == 0, "close compositor test socket");
#endif
  FileSystem::FileStat console {};
  for (int descriptor = 0; descriptor <= 2; ++descriptor) {
    Check(FileSystem::KernelFstat(descriptor, &console) == OK &&
              (console.st_mode & 0170000) == 0020000,
          "standard streams report character devices for managed Console");
    Check(FileSystem::KernelFcntl(descriptor, 3, 0) == (descriptor == 0 ? 0 : 1),
          "standard stream access flags distinguish input from output");
  }
  Check(FileSystem::KernelFstat(-1, &console) == Libs::LibKernel::KERNEL_ERROR_EBADF,
        "invalid standard descriptor reports bad descriptor rather than permission denied");
  Loader::SymbolDatabase symbols;
  Libs::LibC::InitLibC_1(&symbols);
  Libs::LibcInternal::InitLibcInternal_1(&symbols);
  Libs::InitLibKernel_1(&symbols);
  Libs::InitUserService_1(&symbols);
  Libs::Mbus::InitMbus_1(&symbols);
  Libs::LibGen5::InitVideoOut_1(&symbols);
  const auto resolve = [&](const char* nid) {
    const auto* symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "resolve native runtime import");
    return symbol->vaddr;
  };
  const auto app_root = root / "auth-app";
  using GetForegroundUser = int(KYTY_SYSV_ABI*)(int*);
  using SetForegroundUser = int(KYTY_SYSV_ABI*)(int);
  const auto get_foreground = reinterpret_cast<GetForegroundUser>(resolve("eNb53LQJmIM"));
  const auto set_foreground = reinterpret_cast<SetForegroundUser>(resolve("MgBIXUkGtpE"));
  int foreground_user = -2;
  Check(get_foreground(&foreground_user) == OK && foreground_user == Config::GetUserId(),
        "default foreground selection uses the configured logged-in user");
  Check(set_foreground(-1) == OK && get_foreground(&foreground_user) == OK && foreground_user == -1,
        "initial setup can clear foreground ownership without logging out the user");
  Check(set_foreground(Config::GetUserId() + 1) == Libs::UserService::USER_SERVICE_ERROR_NOT_LOGGED_IN &&
            get_foreground(&foreground_user) == OK && foreground_user == -1,
        "an unavailable user cannot replace the current foreground selection");
  Check(set_foreground(Config::GetUserId()) == OK && get_foreground(&foreground_user) == OK &&
            foreground_user == Config::GetUserId(),
        "selecting the logged-in user restores foreground ownership");
  Check(get_foreground(nullptr) == Libs::UserService::USER_SERVICE_ERROR_INVALID_ARGUMENT,
        "foreground query rejects a missing output pointer");
  Libs::LoginMgrServer::InitLoginMgrServer_1(&symbols);
  using CreateUser = int(KYTY_SYSV_ABI*)(const char*, int, bool, bool, int*);
  using UserFlags = int(KYTY_SYSV_ABI*)(int, uint32_t, uint32_t, uint32_t*);
  using ReadUserFlags = int(KYTY_SYSV_ABI*)(int, uint32_t*);
  using RegisteredUsers = int(KYTY_SYSV_ABI*)(int*);
  using UserName = int(KYTY_SYSV_ABI*)(int, char*, size_t);
  using SetUserName = int(KYTY_SYSV_ABI*)(int, const char*);
  const auto create_user = reinterpret_cast<CreateUser>(resolve("AT6NySjQ2gY"));
  const auto destroy_user = reinterpret_cast<SetForegroundUser>(resolve("REIRIXzv-H0"));
  const auto set_status = reinterpret_cast<UserFlags>(resolve("-+h1C78SdyU"));
  const auto set_login_flags = reinterpret_cast<UserFlags>(resolve("Jha8yMoMzrg"));
  const auto get_status = reinterpret_cast<ReadUserFlags>(resolve("RJX7T4sjNgI"));
  const auto get_login_flags = reinterpret_cast<ReadUserFlags>(resolve("QNk7qD4dlD4"));
  const auto registered_users = reinterpret_cast<RegisteredUsers>(resolve("5EiQCnL2G1Y"));
  const auto get_name = reinterpret_cast<UserName>(resolve("1xxcMiGu2fo"));
  const auto set_name = reinterpret_cast<SetUserName>(resolve("Jqu2XFr5UvA"));
  int created_user = -1, second_user = -1;
  Check(create_user("Created user", 0, true, false, &created_user) == OK &&
            create_user("Second user", 0, false, false, &second_user) == OK &&
            created_user >= 0x10000000 && created_user < 0x40000000 &&
            created_user != second_user && created_user != Config::GetUserId(),
        "user creation returns distinct valid IDs without replacing the configured user");
  std::array<int, 18> registered;
  registered.fill(-2);
  Check(registered_users(registered.data() + 1) == OK && registered.front() == -2 &&
            registered.back() == -2 &&
            std::find(registered.begin() + 1, registered.end() - 1, created_user) != registered.end() - 1 &&
            std::count(registered.begin() + 1, registered.end() - 1, -1) == 13,
        "registered-user query exposes created records and bounds its sixteen-ID output");
  std::array<char, 64> user_name;
  Check(get_name(created_user, user_name.data(), user_name.size()) == OK &&
            std::strcmp(user_name.data(), "Created user") == 0 &&
            get_name(created_user, user_name.data(), 2) == Libs::UserService::USER_SERVICE_ERROR_BUFFER_TOO_SHORT &&
            set_name(created_user, "Renamed user") == OK &&
            get_name(created_user, user_name.data(), user_name.size()) == OK &&
            std::strcmp(user_name.data(), "Renamed user") == 0,
        "created users retain mutable names and reject short output buffers");
  uint32_t user_status = 0, old_status = 0;
  Check(get_status(created_user, &user_status) == OK && user_status == 1 &&
            set_status(created_user, 4, 4, &old_status) == OK && old_status == 1 &&
            set_status(created_user, 1, 0, &old_status) == OK && old_status == 5 &&
            get_status(created_user, &user_status) == OK && user_status == 4,
        "finishing user creation clears only the incomplete bit and reports the previous user_status");
  Check(set_login_flags(created_user, 2, 2, &old_status) == OK && old_status == 0 &&
            get_login_flags(created_user, &user_status) == OK && user_status == 2 &&
            get_status(created_user, &user_status) == OK && user_status == 4 &&
            set_foreground(created_user) == Libs::UserService::USER_SERVICE_ERROR_NOT_LOGGED_IN,
        "login preferences and registration do not silently log a new user in");
  using UserLogin = int(KYTY_SYSV_ABI*)(int, uint64_t);
  using UserLogout = int(KYTY_SYSV_ABI*)(int, uint32_t);
  using LoginUsers = int(KYTY_SYSV_ABI*)(int*);
  using ReadUserEvent = int(KYTY_SYSV_ABI*)(int*);
  const auto login_user = reinterpret_cast<UserLogin>(resolve("uvVR70ZxFrQ"));
  const auto logout_user = reinterpret_cast<UserLogout>(resolve("3T9y5xDcfOk"));
  const auto login_users = reinterpret_cast<LoginUsers>(resolve("fPhymKNvK-A"));
  const auto read_user_event = reinterpret_cast<ReadUserEvent>(resolve("yH17Q6NWtVg"));
  std::array<int, 4> logged_in_users;
  std::array<int, 2> user_event;
  while (read_user_event(user_event.data()) == OK) {}
  Check(login_user(created_user, 0) == OK && set_foreground(created_user) == OK &&
            login_users(logged_in_users.data()) == OK &&
            std::find(logged_in_users.begin(), logged_in_users.end(), created_user) != logged_in_users.end() &&
            read_user_event(user_event.data()) == OK && user_event[0] == 0 && user_event[1] == created_user,
        "explicit login exposes the created user and delivers its login event before foreground selection");
  Check(logout_user(created_user, 0) == OK && get_foreground(&foreground_user) == OK &&
            foreground_user == -1 && login_users(logged_in_users.data()) == OK &&
            std::find(logged_in_users.begin(), logged_in_users.end(), created_user) == logged_in_users.end() &&
            read_user_event(user_event.data()) == OK && user_event[0] == 1 && user_event[1] == created_user &&
            read_user_event(user_event.data()) == Libs::UserService::USER_SERVICE_ERROR_NO_EVENT &&
            set_foreground(Config::GetUserId()) == OK,
        "logout removes login ownership, clears foreground and delivers one matching logout event");
  Check(destroy_user(created_user) == OK && get_status(created_user, &user_status) != OK &&
            get_name(created_user, user_name.data(), user_name.size()) != OK &&
            destroy_user(created_user) != OK && destroy_user(second_user) == OK,
        "destroying users invalidates their records while retaining the configured user");
  created_user = -1;
  Check(create_user(nullptr, 0, false, false, &created_user) != OK && created_user == -1 &&
            create_user("User", 7, false, false, &created_user) != OK &&
            registered_users(nullptr) == Libs::UserService::USER_SERVICE_ERROR_INVALID_ARGUMENT,
        "invalid user creation and enumeration return errors without writing bogus IDs");
  using AlignedNew = void*(KYTY_SYSV_ABI*)(size_t, size_t);
  using AlignedDelete = void(KYTY_SYSV_ABI*)(void*, size_t);
  using AlignedDeleteSized = void(KYTY_SYSV_ABI*)(void*, size_t, size_t);
  auto aligned_new = reinterpret_cast<AlignedNew>(resolve("3yxLpdKD0RA"));
  auto aligned_delete = reinterpret_cast<AlignedDelete>(resolve("bZx+FFSlkUM"));
  auto* aligned_block = static_cast<uint8_t*>(aligned_new(2816, 64));
  Check(aligned_block && reinterpret_cast<uintptr_t>(aligned_block) % 64 == 0,
        "aligned C++ new returns real aligned storage for background scene objects");
  std::memset(aligned_block, 0xab, 2816);
  aligned_delete(aligned_block, 64);
  aligned_block = static_cast<uint8_t*>(aligned_new(0, 4096));
  Check(aligned_block && reinterpret_cast<uintptr_t>(aligned_block) % 4096 == 0,
        "zero-size aligned C++ new still returns writable storage");
  *aligned_block = 0xcd;
  reinterpret_cast<AlignedDeleteSized>(resolve("nwujzxOPXzQ"))(aligned_block, 0, 4096);
  aligned_delete(nullptr, 64);
  using Format = int(KYTY_SYSV_ABI *)(char*, const char*, ...);
  const auto guest_sprintf = reinterpret_cast<Format>(resolve("tcVi5SivF7Q"));
  std::array<char, 160> formatted;
  formatted.fill('!');
  const int formatted_length = guest_sprintf(formatted.data(),
      "method_%s_%d/%d/%d/%d/%d/%d/%.2f", "String", 1, 2, 3, 4, 5, 6, 1.25);
  const char* expected_format = "method_String_1/2/3/4/5/6/1.25";
  Check(formatted_length == static_cast<int>(std::strlen(expected_format)) &&
            std::strcmp(formatted.data(), expected_format) == 0 &&
            formatted[formatted_length + 1] == '!',
        "sprintf consumes SysV register, stack and floating arguments and terminates the output");
  using BoundedFormat = int(KYTY_SYSV_ABI *)(char*, size_t, const char*, ...);
  const auto guest_snprintf = reinterpret_cast<BoundedFormat>(resolve("eLdDw6l0-bU"));
  Check(guest_snprintf(nullptr, 0, "%s:%d", "String", 5) == 8,
        "snprintf computes the length with no output buffer");
  std::array<char, 5> truncated {'!', '!', '!', '!', '!'};
  Check(guest_snprintf(truncated.data(), 4, "%s", "String") == 6 &&
            std::strcmp(truncated.data(), "Str") == 0 && truncated.back() == '!',
        "snprintf truncates and leaves the byte beyond the requested capacity untouched");
  using ResolutionStatus = int(KYTY_SYSV_ABI *)(uint32_t, void*);
  const char* expected_scientific = "2.0000000298023223876953125000000000000000e-01";
  Check(guest_snprintf(formatted.data(), formatted.size(), "%.40e", static_cast<double>(0.2f)) ==
            static_cast<int>(std::strlen(expected_scientific)) &&
            std::strcmp(formatted.data(), expected_scientific) == 0,
        "Mono's forty-digit scientific conversion preserves the single-precision animation duration");
  Check(guest_snprintf(formatted.data(), formatted.size(), "%g/%+.2f/%#.0f/%.0f/%.0f",
                       0.2, -0.0, 1.0, 1.5, 2.5) == 16 &&
            std::strcmp(formatted.data(), "0.2/-0.00/1./2/2") == 0,
        "floating formats preserve signed zero, alternate form, significant digits and even rounding");
  Check(guest_snprintf(truncated.data(), 4, "%.40e", static_cast<double>(0.2f)) ==
            static_cast<int>(std::strlen(expected_scientific)) &&
            std::strcmp(truncated.data(), "2.0") == 0 && truncated.back() == '!',
        "high-precision floating conversion reports its full length when the output is truncated");
  const auto resolution_status = reinterpret_cast<ResolutionStatus>(resolve("qLDCAl8ygCw"));
  std::array<uint32_t, 18> scanout_status;
  scanout_status.fill(0xa5a5a5a5);
  Check(resolution_status(0, scanout_status.data() + 1) == OK &&
            scanout_status.front() == 0xa5a5a5a5 && scanout_status.back() == 0xa5a5a5a5 &&
            scanout_status[1] == 1920 && scanout_status[2] == 1080 &&
            scanout_status[5] == 9 && scanout_status[6] == 0,
        "system resolution status fills exactly 64 bytes with 1080p60");
  Check(resolution_status(2, scanout_status.data() + 1) ==
            Libs::VideoOut::VIDEO_OUT_ERROR_INVALID_VALUE &&
            resolution_status(0, nullptr) == Libs::VideoOut::VIDEO_OUT_ERROR_INVALID_ADDRESS,
        "system resolution status validates pipeline and destination");
  using PipelineStatus = int(KYTY_SYSV_ABI *)(uint32_t*, uint64_t);
  const auto pipeline_status = reinterpret_cast<PipelineStatus>(resolve("dFhciCfO31s"));
  std::array<uint32_t, 8> pipeline_record;
  pipeline_record.fill(0xa5a5a5a5);
  Check(pipeline_status(pipeline_record.data(), 0) == OK &&
            std::all_of(pipeline_record.begin(), pipeline_record.end(),
                        [](auto value) { return value == 0; }),
        "normal system display reports no VR modes");
  using SignalMask = int(KYTY_SYSV_ABI *)(int, const void*, void*);
  CheckSignalSets();
  const auto signal_mask = reinterpret_cast<SignalMask>(resolve("6xVpy0Fdq+I"));
  std::array<uint32_t, 4> original_mask {}, blocked_mask {}, restored_mask {};
  blocked_mask[0] = (uint32_t {1} << 29) | (uint32_t {1} << 8) | (uint32_t {1} << 16);
  Check(signal_mask(3, blocked_mask.data(), original_mask.data()) == 0 &&
            signal_mask(0, nullptr, restored_mask.data()) == 0 &&
            restored_mask[0] == (uint32_t {1} << 29),
        "guest signal masks retain blocked signals except unmaskable kill and stop");
  alignas(16) std::array<uint8_t, 96> jump_buffer {};
  volatile int jump_result = Libs::kyty_guest_setjmp(jump_buffer.data());
  if (jump_result == 0) {
    std::array<uint32_t, 4> empty_mask {};
    signal_mask(3, empty_mask.data(), nullptr);
    Libs::kyty_guest_longjmp(jump_buffer.data(), 23);
  }
  Check(jump_result == 23 && signal_mask(0, nullptr, restored_mask.data()) == 0 &&
            restored_mask[0] == (uint32_t {1} << 29),
        "guest longjmp restores execution, return value and the saved signal mask");
  jump_result = Libs::kyty_guest_setjmp(jump_buffer.data());
  if (jump_result == 0) { Libs::kyty_guest_longjmp(jump_buffer.data(), 0); }
  Check(jump_result == 1, "longjmp with zero resumes setjmp with one");
  Check(signal_mask(3, original_mask.data(), nullptr) == 0,
        "restore the runtime fixture's original signal mask");
  using AddSystemVblank = int(KYTY_SYSV_ABI *)(Queues::KernelEqueue, unsigned, void*);
  using DeleteSystemVblank = int(KYTY_SYSV_ABI *)(Queues::KernelEqueue, unsigned);
  const auto add_system_vblank = reinterpret_cast<AddSystemVblank>(resolve("Am8Hlr7tlxA"));
  const auto delete_system_vblank = reinterpret_cast<DeleteSystemVblank>(resolve("2EBuouuYKgM"));
  Queues::KernelEqueue system_queue = Queues::KERNEL_EQUEUE_INVALID;
  Check(Queues::KernelCreateEqueue(&system_queue, "SystemVblankTest") == OK &&
            add_system_vblank(system_queue, 0, &system_queue) == OK,
        "register a system pipeline vblank without a process video-out handle");
  const uintptr_t system_ident = (uint64_t {0x70} << 48) | (uint64_t {1} << 32);
  Queues::KernelEvent system_event {};
  int system_event_count = 0;
  uint32_t poll_timeout = 0;
  Check(Queues::KernelWaitEqueue(system_queue, &system_event, 1, &system_event_count,
                               &poll_timeout) == Libs::LibKernel::KERNEL_ERROR_ETIMEDOUT,
        "registering system vblank does not fabricate a completed frame");
  Check(Queues::KernelTriggerEvent(system_queue, system_ident, Queues::KERNEL_EVFILT_VIDEO_OUT,
                                  reinterpret_cast<void*>(17)) == OK &&
            Queues::KernelWaitEqueue(system_queue, &system_event, 1, &system_event_count,
                                    &poll_timeout) == OK && system_event_count == 1 &&
            system_event.ident == system_ident && system_event.udata == &system_queue &&
            Libs::VideoOut::VideoOutGetEventId(&system_event) == 1,
        "system vblank retains native identifier and caller data");
  int64_t system_frame = 0;
  Check(Libs::VideoOut::VideoOutGetEventData(&system_event, &system_frame) == OK &&
            system_frame == 17 && Libs::VideoOut::VideoOutGetEventCount(&system_event) == 1,
        "system vblank exposes scanout count and occurrence count");
  Check(add_system_vblank(system_queue, 2, nullptr) == Libs::VideoOut::VIDEO_OUT_ERROR_INVALID_VALUE &&
            add_system_vblank(Queues::KERNEL_EQUEUE_INVALID, 0, nullptr) ==
                Libs::VideoOut::VIDEO_OUT_ERROR_INVALID_EVENT_QUEUE,
        "system vblank validates pipeline and queue");
  Check(delete_system_vblank(system_queue, 0) == OK &&
            Queues::KernelTriggerEvent(system_queue, system_ident, Queues::KERNEL_EVFILT_VIDEO_OUT,
                                      nullptr) == Libs::LibKernel::KERNEL_ERROR_ENOENT &&
            add_system_vblank(system_queue, 1, nullptr) == OK &&
            Queues::KernelDeleteEqueue(system_queue) == OK,
        "system vblank unregisters on explicit deletion and queue closure");
  const auto legacy_system_vblank = reinterpret_cast<AddSystemVblank>(resolve("Ek+VR4lcJQI"));
  Check(Queues::KernelCreateEqueue(&system_queue, "LegacySystemVblankTest") == OK &&
            legacy_system_vblank(system_queue, 2, &system_queue) == OK &&
            Queues::KernelTriggerEvent(system_queue, system_ident, Queues::KERNEL_EVFILT_VIDEO_OUT,
                                      nullptr) == OK && Queues::KernelDeleteEqueue(system_queue) == OK,
        "legacy system bus vblank uses pipeline zero rather than a process handle");
  using SignedParse = int64_t(KYTY_SYSV_ABI *)(const char*, char**, int);
  using UnsignedParse = uint64_t(KYTY_SYSV_ABI *)(const char*, char**, int);
  using ExtendedParse = uint64_t(KYTY_SYSV_ABI *)(const char*, char**, int, int*);
  const auto signed_parse = reinterpret_cast<SignedParse>(resolve("VOBg+iNwB-4"));
  const auto unsigned_parse = reinterpret_cast<UnsignedParse>(resolve("5OqszGpy7Mg"));
  const auto stoull = reinterpret_cast<UnsignedParse>(resolve("q+9E0X3aWpU"));
  const auto stoullx = reinterpret_cast<ExtendedParse>(resolve("pSpDCDyxkaY"));
  char* parse_end = nullptr;
  const char* number = "  -4294967297px";
  *Libs::Posix::GetErrorAddr() = Libs::Posix::POSIX_EIO;
  Check(signed_parse(number, &parse_end, 10) == -4294967297LL &&
            std::strcmp(parse_end, "px") == 0 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EIO,
        "signed parsing preserves 64-bit values, end pointer and errno on success");
  const char* no_number = "emoji";
  Check(signed_parse(no_number, &parse_end, 10) == 0 && parse_end == no_number,
        "failed numeric conversion points at the input instead of null");
  Check(unsigned_parse("18446744073709551615!", &parse_end, 10) == UINT64_MAX &&
            *parse_end == '!' && stoull("0x100000001z", &parse_end, 0) == 4294967297ULL &&
            *parse_end == 'z', "unsigned parsers retain the complete guest integer range");
  Check(signed_parse("9223372036854775808x", &parse_end, 10) == INT64_MAX &&
            *parse_end == 'x' && *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ERANGE,
        "signed overflow saturates and reports guest ERANGE");
  Check(signed_parse("-9223372036854775809", nullptr, 10) == INT64_MIN,
        "signed underflow saturates with an optional end pointer");
  int parse_error = -1;
  Check(stoullx("18446744073709551616x", &parse_end, 10, &parse_error) == UINT64_MAX &&
            parse_error == Libs::Posix::POSIX_ERANGE && *parse_end == 'x',
        "extended unsigned conversion reports overflow to its caller");
  *Libs::Posix::GetErrorAddr() = Libs::Posix::POSIX_EIO;
  Check(stoullx(no_number, &parse_end, 1, &parse_error) == 0 && parse_end == no_number &&
            parse_error == Libs::Posix::POSIX_EINVAL &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EIO,
        "Dinkumware invalid base reports EINVAL separately from errno");
  Check(reinterpret_cast<SignedParse>(resolve("mXlxhmLNMPg"))(number, nullptr, 10) == -4294967297LL,
        "guest long retains its LP64 width on Windows");
  using DecimalParse = double(KYTY_SYSV_ABI *)(const char*, char**, int64_t, int*);
  auto stodx = reinterpret_cast<DecimalParse>(resolve("QlcJbyd6jxM"));
  *Libs::Posix::GetErrorAddr() = Libs::Posix::POSIX_EIO;
  Check(stodx("12.5tail", &parse_end, -1, &parse_error) == 1.25 &&
        std::strcmp(parse_end, "tail") == 0 && parse_error == 0 &&
        *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EIO,
        "decimal parser applies signed decimal exponent and preserves end pointer and errno");
  Check(std::isinf(stodx("1e9999!", &parse_end, 0, &parse_error)) &&
        *parse_end == '!' && parse_error == 1 &&
        *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ERANGE,
        "decimal parser reports native range bit separately from guest ERANGE");
  using SplitDouble = double(KYTY_SYSV_ABI *)(double, double*);
  using SplitExponent = double(KYTY_SYSV_ABI *)(double, int*);
  double whole = 0;
  int exponent = 0;
  Check(reinterpret_cast<SplitDouble>(resolve("0WMHDb5Dt94"))(-12.75, &whole) == -0.75 &&
        whole == -12.0 &&
        reinterpret_cast<SplitExponent>(resolve("kA-TdiOCsaY"))(12.0, &exponent) == 0.75 &&
        exponent == 4, "math decomposition writes real integer and exponent outputs");
  using FloatUnary = float(KYTY_SYSV_ABI *)(float);
  using FloatBinary = float(KYTY_SYSV_ABI *)(float, float);
  Check(reinterpret_cast<FloatUnary>(resolve("ZE6RNL+eLbk"))(0) == 0 &&
        reinterpret_cast<FloatBinary>(resolve("1D0H2KNjshE"))(2, 3) == 8 &&
        std::isnan(reinterpret_cast<FloatUnary>(resolve("QI-x0SL8jhw"))(2)) &&
        *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EDOM,
        "math exports compute values and translate domain errors");
  using DoubleUnary = double(KYTY_SYSV_ABI *)(double);
  using DoubleBinary = double(KYTY_SYSV_ABI *)(double, double);
  auto power = reinterpret_cast<DoubleBinary>(resolve("9LCjpWyQ5Zc"));
  auto logarithm = reinterpret_cast<DoubleUnary>(resolve("rtV7-jWC6Yg"));
  Check(power(10.0, -3.0) == 0.001 && power(2.0, 40.0) == 1099511627776.0 &&
            logarithm(1.0) == 0.0 && std::isnan(power(-2.0, 0.5)) &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EDOM,
        "double math uses floating-point arguments and reports guest domain errors");
  Check(std::isinf(logarithm(0.0)) && *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ERANGE,
        "double logarithm reports its pole as a range error");
  using CompareFolded = int(KYTY_SYSV_ABI *)(const char*, const char*, size_t);
  auto compare_folded = reinterpret_cast<CompareFolded>(resolve("pXvbDfchu6k"));
  Check(compare_folded("Content-Type", "content-type", 12) == 0 &&
            compare_folded("prefixA", "PREFIXB", 6) == 0 &&
            compare_folded("prefixA", "PREFIXB", 7) < 0 &&
            compare_folded("ab", "ABC", 4) < 0 &&
            compare_folded("\xff", "\x7f", 1) > 0 &&
            compare_folded(nullptr, nullptr, 0) == 0,
        "case-insensitive comparisons respect length, terminators and unsigned bytes");
  std::filesystem::create_directories(app_root / "sce_sys");
  const auto* codecvt_record = symbols.FindByNid("aK1Ymf-NhAs", Loader::SymbolType::Object);
  Check(codecvt_record != nullptr, "native char codecvt vtable is exported");
  const auto* codecvt_vtable = reinterpret_cast<const uintptr_t*>(codecvt_record->vaddr);
  struct { const uintptr_t* vtable; uint32_t references; uint32_t reserved; } codecvt {codecvt_vtable + 2, 0, 0};
  using CodecvtRetain = void(KYTY_SYSV_ABI *)(void*);
  using CodecvtNoConv = bool(KYTY_SYSV_ABI *)(const void*);
  using CodecvtConvert = int(KYTY_SYSV_ABI *)(const void*, void*, const char*, const char*,
                                           const char**, char*, char*, char**);
  using CodecvtLength = int(KYTY_SYSV_ABI *)(const void*, void*, const char*, const char*, size_t);
  reinterpret_cast<CodecvtRetain>(codecvt_vtable[4])(&codecvt);
  const char codecvt_input[] = "bytes";
  std::array<char, 8> codecvt_output; codecvt_output.fill('!');
  const char* from_next = nullptr; char* to_next = nullptr;
  Check(codecvt.references == 1 && reinterpret_cast<CodecvtNoConv>(codecvt_vtable[6])(&codecvt) &&
            reinterpret_cast<CodecvtConvert>(codecvt_vtable[9])(&codecvt, nullptr, codecvt_input,
                codecvt_input + 5, &from_next, codecvt_output.data(), codecvt_output.data() + 8, &to_next) == 3 &&
            from_next == codecvt_input && to_next == codecvt_output.data() && codecvt_output[0] == '!' &&
            reinterpret_cast<CodecvtLength>(codecvt_vtable[12])(&codecvt, nullptr, codecvt_input,
                codecvt_input + 5, 3) == 3,
        "char codecvt reports identity conversion with unchanged iterators and bounded length");
  using Random = int64_t(KYTY_SYSV_ABI *)();
  using SeedRandom = void(KYTY_SYSV_ABI *)(unsigned);
  using FloatPredicate = int(KYTY_SYSV_ABI *)(float);
  const auto random = reinterpret_cast<Random>(resolve("w1o05aHJT4c"));
  const auto srandom = reinterpret_cast<SeedRandom>(resolve("sPC7XE6hfFY"));
  const auto srand = reinterpret_cast<SeedRandom>(resolve("VPbJwTCgME0"));
  srandom(1);
  Check(random() == 1804289383, "BSD random reproduces the native seed-1 sequence");
  srand(17);
  Check(random() == 846930886 && random() == 1681692777,
        "rand seeding does not reset the separate BSD random state");
  srandom(1);
  Check(random() == 1804289383, "BSD srandom restarts its deterministic sequence");
  srandom(0);
  Check(random() == 577655601 && random() == 1248161417,
        "BSD random preserves the native zero-seed behavior");
  srandom(0xffffffffu);
  Check(random() == 254925627 && random() == 1205188300,
        "BSD random uses native signed arithmetic for high-bit seeds");
  const auto isnanf = reinterpret_cast<FloatPredicate>(resolve("lA94ZgT+vMM"));
  const auto isinff = reinterpret_cast<FloatPredicate>(resolve("rDMyAf1Jhug"));
  const auto positive_inf = std::numeric_limits<float>::infinity();
  const auto signaling_nan = std::bit_cast<float>(uint32_t {0x7f800001});
  Check(isinff(positive_inf) == 1 && isinff(-positive_inf) == 1 &&
            isinff(0.0f) == 0 && isinff(signaling_nan) == 0,
        "__isinff recognizes both infinity signs without classifying NaN as infinity");
  Check(isnanf(signaling_nan) == 1 && isnanf(std::numeric_limits<float>::quiet_NaN()) == 1 &&
            isnanf(positive_inf) == 0 && isnanf(-0.0f) == 0 && isnanf(3.5f) == 0,
        "__isnanf recognizes signaling and quiet NaN without classifying finite values");
  using LocalTime = void*(KYTY_SYSV_ABI *)(const int64_t*);
  using FormatTime = size_t(KYTY_SYSV_ABI *)(char*, size_t, const char*, const void*);
  const int64_t epoch = 0;
  const auto local_time = reinterpret_cast<LocalTime>(resolve("efhK-YSUYYQ"))(&epoch);
  auto format_time = reinterpret_cast<FormatTime>(resolve("Av3zjWi64Kw"));
  std::array<char, 512> formatted_time {};
  Check(local_time && format_time(formatted_time.data(), formatted_time.size(),
                                 "\xd0\xa7\xd0\xb0\xd1\x81\xd1\x8b %Z", local_time) > 0 &&
            std::string_view(formatted_time.data()).starts_with("\xd0\xa7\xd0\xb0\xd1\x81\xd1\x8b "),
        "strftime preserves UTF-8 literals alongside the host timezone name");
  std::array<char, 5> tiny_time {'a', 'b', 'c', 'd', 'e'};
  Check(format_time(tiny_time.data(), 4, "\xd0\xa7\xd0\xb0\xd1\x81\xd1\x8b", local_time) == 0 &&
            tiny_time[4] == 'e', "strftime bounds the encoded byte count without overwriting a canary");
  const auto metadata = app_root / "sce_sys/param.json";
  auto* metadata_file = std::fopen(Common::PathToString(metadata).c_str(), "wb");
  Check(metadata_file != nullptr, "create application metadata fixture");
  std::fputs("{\"titleId\":\"NPXS40087\",\"applicationCategoryType\":16777216}", metadata_file);
  std::fclose(metadata_file);
  Loader::SystemContentLoadParamSfo(metadata);
  using AuthInfo = int(KYTY_SYSV_ABI *)(int, void*);
  const auto auth_info = reinterpret_cast<AuthInfo>(resolve("igMefp4SAv0"));
  std::array<uint8_t, 144> auth;
  auth.fill(0xab);
  Check(auth_info(100, auth.data()) == -1 && auth[0] == 0xab &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOSYS,
        "an ELF without SELF authority does not fabricate an identity");
  Loader::SelfHeader self_header {};
  std::memcpy(self_header.ident, "\x54\x14\xf5\xee", 4);
  self_header.size1 = sizeof(self_header) + sizeof(Loader::Elf64_Ehdr) + sizeof(Loader::Elf64_Phdr) + 8;
  Loader::Elf64_Ehdr elf_header {};
  std::memcpy(elf_header.e_ident, "\x7f" "ELF", 4);
  elf_header.e_phoff = sizeof(elf_header);
  elf_header.e_phentsize = sizeof(Loader::Elf64_Phdr);
  elf_header.e_phnum = 1;
  Loader::Elf64_Phdr program_header {};
  constexpr uint64_t authority = 0x480000000000000f;
  const auto self_path = app_root / "eboot.bin";
  auto* self_file = std::fopen(Common::PathToString(self_path).c_str(), "wb");
  Check(self_file != nullptr, "create SELF authority fixture");
  std::fwrite(&self_header, sizeof(self_header), 1, self_file);
  std::fwrite(&elf_header, sizeof(elf_header), 1, self_file);
  std::fwrite(&program_header, sizeof(program_header), 1, self_file);
  std::fwrite(&authority, sizeof(authority), 1, self_file);
  std::fclose(self_file);
  Loader::SystemContentLoadParamSfo(metadata);
  uint64_t actual_authority = 0;
  Check(auth_info(100, auth.data()) == 0 && auth[136] == 0xab,
        "authinfo writes exactly the native record size");
  std::memcpy(&actual_authority, auth.data(), sizeof(actual_authority));
  uint64_t compositor_caps = 0;
  std::memcpy(&compositor_caps, auth.data() + 8, sizeof(compositor_caps));
  Check(actual_authority == authority && compositor_caps == (uint64_t {1} << 62) &&
            std::all_of(auth.begin() + 16, auth.begin() + 136, [](auto b) { return b == 0; }),
        "ShellUI authinfo exposes only its compositor service capability");
  const uint64_t other_authority = 0x4800000000000001;
  self_file = std::fopen(Common::PathToString(self_path).c_str(), "r+b");
  Check(self_file != nullptr, "update SELF authority fixture");
  std::fseek(self_file, static_cast<long>(self_header.size1 - 8), SEEK_SET);
  std::fwrite(&other_authority, sizeof(other_authority), 1, self_file);
  std::fclose(self_file);
  Loader::SystemContentLoadParamSfo(metadata);
  Check(auth_info(100, auth.data()) == 0 && auth[136] == 0xab &&
            std::all_of(auth.begin() + 8, auth.begin() + 136, [](auto b) { return b == 0; }),
        "a different system authority receives no ShellUI compositor capability");
  Check(auth_info(0, auth.data()) == 0 && auth_info(100, nullptr) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT &&
            auth_info(999, auth.data()) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ESRCH,
        "authinfo handles current PID, missing PID, and null output");
  std::filesystem::resize_file(self_path, sizeof(self_header));
  Loader::SystemContentLoadParamSfo(metadata);
  Check(auth_info(100, auth.data()) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOSYS,
        "truncated SELF clears the previous application's authority");
  using AppCategory = int(KYTY_SYSV_ABI *)(int, uint32_t*);
  using AppInfo = int(KYTY_SYSV_ABI *)(int, void*);
  using Sysctl = int(KYTY_SYSV_ABI *)(int*, uint32_t, void*, size_t*, const void*, size_t);
  const auto app_category = reinterpret_cast<AppCategory>(resolve("+xy9ORMbd8U"));
  const auto app_info = reinterpret_cast<AppInfo>(resolve("G-MYv5erXaU"));
  const auto sysctl = reinterpret_cast<Sysctl>(resolve("DFmMT80xcNI"));
  std::array<uint32_t, 2> category {0, 0xfeed};
  Check(app_category(100, category.data()) == OK && category[0] == 0x01000000 && category[1] == 0xfeed,
        "process category comes from application metadata and writes exactly one word");
  Check(app_category(100, nullptr) == Libs::LibKernel::KERNEL_ERROR_EINVAL &&
            app_category(-1, category.data()) == Libs::LibKernel::KERNEL_ERROR_ESRCH,
        "process category validates destination and process identity");
  std::array<uint8_t, 96> process_info;
  process_info.fill(0xab);
  Check(app_info(100, process_info.data()) == OK && process_info[88] == 0xab,
        "app info writes exactly the native 88-byte record");
  uint32_t record_category = 0;
  std::memcpy(&record_category, process_info.data() + 0x50, sizeof(record_category));
  Check(record_category == category[0], "app info and category query agree");
  int app_mib[] = {1, 14, 35, 100};
  size_t info_length = 0;
  Check(sysctl(app_mib, 4, nullptr, &info_length, nullptr, 0) == 0 && info_length == 88,
        "app-info sysctl supports querying the record size");
  process_info.fill(0xab);
  info_length = 88;
  Check(sysctl(app_mib, 4, process_info.data(), &info_length, nullptr, 0) == 0 &&
            info_length == 88 && process_info[88] == 0xab,
        "native app-info sysctl returns a bounded record");
  std::memcpy(&record_category, process_info.data() + 0x50, sizeof(record_category));
  Check(record_category == category[0], "native sysctl exposes the same application category");
  info_length = 4;
  process_info.fill(0xab);
  Check(sysctl(app_mib, 4, process_info.data(), &info_length, nullptr, 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOMEM && process_info[4] == 0xab,
        "short sysctl buffers report an error without overflowing");
  using MaskStatus = int(KYTY_SYSV_ABI *)(uint64_t*);
  const auto mask_status = reinterpret_cast<MaskStatus>(resolve("pTxsULu4Nh0"));
  std::array<uint64_t, 2> mask {UINT64_MAX, 0xfeed};
  Check(mask_status(mask.data()) == OK && mask[0] == 0 && mask[1] == 0xfeed,
        "privacy mask status writes exactly the available-buffer bitmask");
  Check(mask_status(nullptr) == static_cast<int>(0x80290002u),
        "privacy mask status rejects a null destination");
  using MbusCreate = int(KYTY_SYSV_ABI *)(uint32_t, void*, int, const void*, void*);
  using MbusReceive = int(KYTY_SYSV_ABI *)(uint32_t, void*, int, int);
  using MbusDestroy = int(KYTY_SYSV_ABI *)(uint32_t);
  const auto mbus_create = reinterpret_cast<MbusCreate>(resolve("c08SEHicDNU"));
  const auto mbus_receive = reinterpret_cast<MbusReceive>(resolve("puHrnP8V-dY"));
  const auto mbus_destroy = reinterpret_cast<MbusDestroy>(resolve("AcARz3iay1I"));
  const int event_handle = mbus_create(1, nullptr, 0, nullptr, nullptr);
  Check(event_handle >= 0 && event_handle < 8, "create a native-range Mbus event handle");
  Check(mbus_receive(event_handle, nullptr, 0, 0) == 0,
        "nonblocking empty Mbus receive returns no events");
  auto mbus_waiter = std::async(std::launch::async, [&] {
    return mbus_receive(event_handle, nullptr, 0, 1);
  });
  Check(mbus_waiter.wait_for(std::chrono::milliseconds(30)) == std::future_status::timeout,
        "blocking empty Mbus receive sleeps instead of spinning");
  Check(mbus_destroy(event_handle) == OK &&
            mbus_waiter.wait_for(std::chrono::seconds(2)) == std::future_status::ready &&
            mbus_waiter.get() == static_cast<int>(0x809b0088u),
        "destroying an Mbus event wakes a receiver with the native cancellation result");
  Check(mbus_receive(8, nullptr, 0, 0) == static_cast<int>(0x809b0080u),
        "Mbus receive rejects handles outside the native range");
  using Setenv = int(KYTY_SYSV_ABI *)(const char*, const char*, int);
  using Getenv = char*(KYTY_SYSV_ABI *)(const char*);
  using Compare = int(KYTY_SYSV_ABI *)(const char*, const char*);
  using CompareN = int(KYTY_SYSV_ABI *)(const char*, const char*, size_t);
  using Tokenize = char*(KYTY_SYSV_ABI *)(char*, const char*, char**);
  using OpenDir = void*(KYTY_SYSV_ABI *)(const char*);
  using ReadDir = char*(KYTY_SYSV_ABI *)(void*);
  using CloseDir = int(KYTY_SYSV_ABI *)(void*);
  using Access = int(KYTY_SYSV_ABI *)(const char*, int);
  using Readlink = int64_t(KYTY_SYSV_ABI *)(const char*, char*, size_t);
  using Status = int(KYTY_SYSV_ABI *)(const char*, int*, int*);
  using Copy = char*(KYTY_SYSV_ABI *)(char*, const char*);
  using Duplicate = char*(KYTY_SYSV_ABI *)(const char*);
  const auto duplicate = reinterpret_cast<Duplicate>(resolve("g7zzzLDYGw0"));
  char* duplicated = duplicate("Mono runtime");
  Check(duplicated != nullptr && std::strcmp(duplicated, "Mono runtime") == 0,
        "managed runtime strdup import allocates a terminated copy");
  reinterpret_cast<void(KYTY_SYSV_ABI *)(void*)>(resolve("tIhsqj0qsFE"))(duplicated);
  using Memalign = void*(KYTY_SYSV_ABI *)(size_t, size_t);
  using Free = void(KYTY_SYSV_ABI *)(void*);
  using Realloc = void*(KYTY_SYSV_ABI *)(void*, size_t);
  const auto memalign = reinterpret_cast<Memalign>(resolve("Ujf3KzMvRmI"));
  const auto free_memory = reinterpret_cast<Free>(resolve("tIhsqj0qsFE"));
  const auto realloc_memory = reinterpret_cast<Realloc>(resolve("Y7aJ1uydPMo"));
  using Malloc = void*(KYTY_SYSV_ABI *)(size_t);
  using Calloc = void*(KYTY_SYSV_ABI *)(size_t, size_t);
  using Usable = size_t(KYTY_SYSV_ABI *)(void*);
  const auto malloc_memory = reinterpret_cast<Malloc>(resolve("gQX+4GDQjpM"));
  const auto calloc_memory = reinterpret_cast<Calloc>(resolve("2X5agFjKxMc"));
  const auto usable_memory = reinterpret_cast<Usable>(resolve("NDcSfcYZRC8"));
  void* packed_object = malloc_memory(140400);
  Check(packed_object != nullptr && reinterpret_cast<uintptr_t>(packed_object) < (uint64_t(1) << 40) &&
            usable_memory(packed_object) >= 140400,
        "compositor objects fit the native 40-bit pointer representation");
  std::memset(packed_object, 0x3c, 140400);
  void* resized_object = realloc_memory(packed_object, 300000);
  Check(resized_object != nullptr && static_cast<uint8_t*>(resized_object)[140399] == 0x3c,
        "bounded heap realloc preserves compositor object bytes");
  free_memory(resized_object);
  void* cleared = calloc_memory(257, 17);
  Check(cleared != nullptr && std::all_of(static_cast<uint8_t*>(cleared),
            static_cast<uint8_t*>(cleared) + 257 * 17, [](auto b) { return b == 0; }),
        "reused guest heap blocks are zeroed by calloc");
  free_memory(cleared);
  Check(calloc_memory(SIZE_MAX, 2) == nullptr, "calloc rejects multiplication overflow");
  std::vector<void*> heap_blocks;
  for (int i = 0; i < 80; ++i) {
    auto* block = malloc_memory(70001);
    Check(block != nullptr && reinterpret_cast<uintptr_t>(block) < (uint64_t(1) << 40),
          "bounded heap grows across arenas without truncating addresses");
    std::memset(block, i, 70001);
    heap_blocks.push_back(block);
  }
  for (int i = 79; i >= 0; --i) {
    Check(static_cast<uint8_t*>(heap_blocks[i])[70000] == i, "heap blocks do not overlap");
    free_memory(heap_blocks[i]);
  }
  for (size_t alignment : {size_t(64), size_t(4096)}) {
    void* allocation = memalign(alignment, 137);
    Check(allocation != nullptr && reinterpret_cast<uintptr_t>(allocation) % alignment == 0,
          "CXML resource allocation honors alignment");
    std::memset(allocation, 0x5a, 137);
    void* grown = realloc_memory(allocation, 300);
    Check(grown != nullptr && static_cast<unsigned char*>(grown)[136] == 0x5a,
          "aligned allocation realloc preserves data");
    free_memory(grown);
    free_memory(memalign(alignment, 137));
  }
  Check(memalign(63, 137) == nullptr && memalign(64, SIZE_MAX) == nullptr,
        "aligned allocation rejects invalid alignment and size overflow");
  const auto status = reinterpret_cast<Status>(resolve("8KeeeFcEdls"));
  const auto copy = reinterpret_cast<Copy>(resolve("kiZSXIWd9vg"));
  char copied[32] = {};
  Check(copy(copied, "System.String") == copied && std::strcmp(copied, "System.String") == 0,
        "Mono string copy import fills the destination");
  const auto setenv = reinterpret_cast<Setenv>(resolve("M4YYbSFfJ8g"));
  const auto getenv = reinterpret_cast<Getenv>(resolve("MmbQukfxYJM"));
  const auto compare = reinterpret_cast<Compare>(resolve("Ovb2dSJOAuE"));
  const auto compare_case = reinterpret_cast<Compare>(resolve("AV6ipCNa4Rw"));
  const auto compare_n = reinterpret_cast<CompareN>(resolve("aesyjrHVWy4"));
  const auto tokenize = reinterpret_cast<Tokenize>(resolve("enqPGLfmVNU"));
  const auto open_dir = reinterpret_cast<OpenDir>(resolve("ay3uROQAc5A"));
  const auto read_dir = reinterpret_cast<ReadDir>(resolve("lybyyKtP54c"));
  const auto close_dir = reinterpret_cast<CloseDir>(resolve("XepdqehVYe4"));
  const auto access = reinterpret_cast<Access>(resolve("8vE6Z6VEYyk"));
  const auto readlink = reinterpret_cast<Readlink>(resolve("pd02UI9TbOA"));
  Check(compare("narenas", "tcache") < 0 && compare("equal", "equal") == 0 &&
            compare_n("arena-a", "arena-b", 6) == 0 &&
            compare_n("arena-a", "arena-b", 7) < 0,
        "strcmp and strncmp NIDs use their correct signatures");
  Check(compare_case("MSCorlib", "mscorlib") == 0 &&
            compare_case("app", "mscorlib") < 0 &&
            compare_case("System", "app") > 0,
        "case-insensitive assembly lookup distinguishes different assemblies");
  Loader::Program first, second;
  auto* previous = Loader::RuntimeLinker::GetCurrentProgram();
  Loader::RuntimeLinker::SetCurrentProgram(&first);
  constexpr char variable[] = "KYTY_GUEST_RUNTIME_TEST_ENV";
  Check(getenv("KYTY_RUNTIME_CONFIGURED") != nullptr &&
            std::strcmp(getenv("KYTY_RUNTIME_CONFIGURED"), "configured") == 0 &&
            std::getenv("KYTY_RUNTIME_CONFIGURED") == nullptr,
        "explicit launch environment is visible to the guest without changing host variables");
  Check(getenv(variable) == nullptr && setenv(variable, "one:two", 1) == 0 &&
            std::strcmp(getenv(variable), "one:two") == 0,
        "guest getenv reads guest setenv values");
  Check(setenv(variable, "ignored", 0) == 0 &&
            std::strcmp(getenv(variable), "one:two") == 0 &&
            setenv(variable, "updated", 1) == 0 &&
            std::strcmp(getenv(variable), "updated") == 0,
        "guest environment respects overwrite");
  Loader::RuntimeLinker::SetCurrentProgram(&second);
  Check(getenv(variable) == nullptr && std::getenv(variable) == nullptr,
        "guest environment is isolated by process and from host");
  Check(std::strcmp(getenv("KYTY_RUNTIME_CONFIGURED"), "configured") == 0 &&
            setenv("KYTY_RUNTIME_CONFIGURED", "second", 1) == 0,
        "each co-hosted process receives an independent launch environment");
  Loader::RuntimeLinker::SetCurrentProgram(previous);
  Check(std::strcmp(getenv("KYTY_RUNTIME_CONFIGURED"), "configured") == 0,
        "changing one guest environment preserves the other process value");
  char paths[] = ":first::second:";
  char* cursor = nullptr;
  Check(std::strcmp(tokenize(paths, ":", &cursor), "first") == 0 &&
            std::strcmp(tokenize(nullptr, ":", &cursor), "second") == 0 &&
            tokenize(nullptr, ":", &cursor) == nullptr,
        "reentrant tokenization skips empty path components and reaches EOF");
  Common::File fixture;
  Check(fixture.Create(root / "mscorlib.dll"), "create managed directory fixture");
  fixture.Close();
  FileSystem::Mount(root, "/runtime-test");
  const std::array<uint8_t, 8> binary_bytes {0x52, 0x0d, 0x0a, 0x1a, 0x00, 0xff, 0x0a, 0x0d};
  auto* binary_fixture = std::fopen(Common::PathToString(root / "bundle.bin").c_str(), "wb");
  Check(binary_fixture != nullptr && std::fwrite(binary_bytes.data(), 1, binary_bytes.size(), binary_fixture) == binary_bytes.size(),
        "create a binary bundle containing Windows text-mode control bytes");
  std::fclose(binary_fixture);
  using Fiopen = void*(KYTY_SYSV_ABI *)(const char*, int, int);
  using FileGetpos = int(KYTY_SYSV_ABI *)(void*, void*);
  using FileSetpos = int(KYTY_SYSV_ABI *)(void*, const void*);
  using FileGetc = int(KYTY_SYSV_ABI *)(void*);
  using FileClose = int(KYTY_SYSV_ABI *)(void*);
  auto getpos = reinterpret_cast<FileGetpos>(resolve("SHlt7EhOtqA"));
  auto setpos = reinterpret_cast<FileSetpos>(resolve("7PkSz+qnTto"));
  auto getc = reinterpret_cast<FileGetc>(resolve("AEuF3F2f8TA"));
  auto close_file = reinterpret_cast<FileClose>(resolve("uodLYyUip20"));
  auto fiopen = reinterpret_cast<Fiopen>(resolve("vYWK2Pz8vGE"));
  const auto* bad_offset = symbols.FindByNid("FQ9NFbBHb5Y", Loader::SymbolType::Object);
  const auto* initial_position = symbols.FindByNid("wiR+rIcbnlc", Loader::SymbolType::Object);
  Check(bad_offset && initial_position && *reinterpret_cast<const int64_t*>(bad_offset->vaddr) == -1 &&
            reinterpret_cast<const uint64_t*>(initial_position->vaddr)[0] == 0 &&
            reinterpret_cast<const uint64_t*>(initial_position->vaddr)[1] == 0 &&
            reinterpret_cast<const uint64_t*>(initial_position->vaddr)[2] == 0,
        "filebuf distinguishes a successful seek to zero from the failure sentinel");
  auto* binary_stream = fiopen("/runtime-test/bundle.bin", 0x85, 438);
  std::array<uint64_t, 4> file_position {0, 0, 0, 0xfeed};
  Check(binary_stream != nullptr && getpos(binary_stream, file_position.data()) == 0 &&
            file_position[0] == binary_bytes.size() && file_position[1] == 0 &&
            file_position[2] == 0 && file_position[3] == 0xfeed,
        "native binary and ate flags open the stream at its physical end");
  file_position[0] = 0;
  Check(setpos(binary_stream, file_position.data()) == 0, "guest position restores binary file start");
  std::array<uint8_t, 8> read_bytes {};
  read_bytes[0] = static_cast<uint8_t>(getc(binary_stream));
  // Consume the buffer as native basic_filebuf does, through FILE +24/+32.
  auto** native_get_next = reinterpret_cast<char**>(static_cast<uint8_t*>(binary_stream) + 24);
  auto** native_get_end = reinterpret_cast<char**>(static_cast<uint8_t*>(binary_stream) + 32);
  for (size_t i = 1; i < read_bytes.size(); ++i) {
    Check(*native_get_next < *native_get_end, "guest FILE exposes the actual remaining read buffer");
    read_bytes[i] = static_cast<uint8_t>(*(*native_get_next)++);
  }
  Check(read_bytes == binary_bytes && getpos(binary_stream, file_position.data()) == 0 &&
            file_position[0] == binary_bytes.size() && getc(binary_stream) == EOF,
        "native binary input retains CR/LF, embedded null and DOS EOF bytes");
  file_position[0] = 2;
  Check(setpos(binary_stream, file_position.data()) == 0 && getc(binary_stream) == binary_bytes[2] &&
            getpos(binary_stream, file_position.data()) == 0 && file_position[0] == 3,
        "guest file positions account for host read-ahead and native pointer consumption");
  Check(close_file(binary_stream) == 0, "guest fclose releases its host file and ABI wrapper");
  Check(fiopen("/runtime-test/missing-bundle.bin", 0xc2, 438) == nullptr &&
            !std::filesystem::exists(root / "missing-bundle.bin"),
        "native no-create output fails without creating a missing file");
  int permissions = -1, status_error = -1;
  Check(status("/runtime-test/mscorlib.dll", &permissions, &status_error) == 1 &&
            permissions != -1 && status_error == 0,
        "filesystem status returns regular file type and initializes outputs");
  Check(status("/runtime-test", nullptr, &status_error) == 2 && status_error == 0,
        "filesystem status identifies directories");
  Check(status("/runtime-test/missing.dll", nullptr, &status_error) == -1 &&
            status_error == Libs::Posix::POSIX_ENOENT,
        "filesystem status reports missing files with guest errno");
  void* directory = open_dir("/runtime-test");
  Check(directory != nullptr, "libc opens a mounted directory");
  bool found = false;
  while (char* entry = read_dir(directory)) {
    if (std::strcmp(entry + 8, "mscorlib.dll") == 0) found = true;
  }
  Check(found && close_dir(directory) == 0,
        "libc readdir returns guest dirent names and closes its descriptor");
  Check(access("/runtime-test/mscorlib.dll", 0) == 0 &&
            access("/runtime-test/missing.dll", 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOENT,
        "access distinguishes existing and missing files");
  char target[128] = {};
  Check(readlink("/runtime-test/mscorlib.dll", target, sizeof(target)) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "readlink rejects ordinary files without inventing an empty link target");
  FileSystem::Umount("/runtime-test");
}

void CheckSaveRename(const std::filesystem::path &root,
                     std::string_view payload) {
  constexpr char Source[] = "/savedata0/STEMP000.DAT";
  constexpr char Target[] = "/savedata0/SDATA000.DAT";
  constexpr char Suffix[] = "-after-rename";

  const int fd = FileSystem::KernelOpen(Source, 0x601, 0777);
  Check(fd >= 3, "open temporary save file");
  Check(FileSystem::KernelWrite(fd, payload.data(), payload.size()) ==
            payload.size(),
        "write save payload");
  Check(FileSystem::KernelRename(Source, Target) == OK,
        "rename open save file");
  Check(FileSystem::KernelWrite(fd, Suffix, sizeof(Suffix) - 1) ==
            sizeof(Suffix) - 1,
        "write through renamed descriptor");
  Check(FileSystem::KernelClose(fd) == OK, "close renamed descriptor");

  Common::File result(root / "SDATA000.DAT", Common::File::Mode::Read);
  Check(!result.IsInvalid(), "open renamed save file");
  const auto data = result.ReadWholeBuffer();
  const std::string expected = std::string(payload) + Suffix;
  Check(data.size() == expected.size(), "renamed save size");
  Check(std::memcmp(data.data(), expected.data(), expected.size()) == 0,
        "renamed save contents");
}

void TestSaveOpenVisibility() {
  constexpr char Path[] = "/savedata0/visible-save.dat";
  constexpr char Payload[] = "saved progress";

  const int fd = FileSystem::KernelOpen(Path, 0xa01, 0777);
  Check(fd >= 3, "create save file exclusively");
  FileSystem::FileStat stat {};
  Check(FileSystem::KernelStat(Path, &stat) == OK && stat.st_size == 0,
        "created save file is visible before close");
  Check(FileSystem::KernelOpen(Path, 0xa01, 0777) ==
            Libs::LibKernel::KERNEL_ERROR_EEXIST,
        "exclusive creation detects an open save file");
  Check(FileSystem::KernelWrite(fd, Payload, sizeof(Payload) - 1) ==
            sizeof(Payload) - 1,
        "populate save file before truncation");
  Check(FileSystem::KernelClose(fd) == OK, "close populated save file");
  Check(FileSystem::KernelStat(Path, &stat) == OK &&
            stat.st_size == sizeof(Payload) - 1,
        "save file contains the truncation fixture");

  const int truncated = FileSystem::KernelOpen(Path, 0x401, 0777);
  Check(truncated >= 3, "truncate existing save file");
  Check(FileSystem::KernelStat(Path, &stat) == OK && stat.st_size == 0,
        "save truncation is visible before close");
  Check(FileSystem::KernelClose(truncated) == OK, "close truncated save file");
}

void CheckMountRoot(const std::filesystem::path &root) {
  Loader::Program game, shell;
  game.unique_id = 202;
  shell.unique_id = 203;
  auto* previous = Loader::RuntimeLinker::GetCurrentProgram();
  const auto game_dir = root / "application";
  Check(Common::File::CreateDirectories(game_dir), "create application namespace");
  FileSystem::Mount(root, "/app0");
  FileSystem::Mount(root / "system-child", "/app0/psm");
  FileSystem::MountForProgram(game_dir, "/app0", game.unique_id, true);
  Loader::RuntimeLinker::SetCurrentProgram(&game);
  Check(FileSystem::GetRealFilename("/app0/data") == game_dir / "data", "game app0 is scoped to the executable");
  Check(FileSystem::GetRealFilename("/app0/psm/file") == game_dir / "psm/file", "game namespace hides firmware child mounts");
  Check(FileSystem::KernelOpen("/app0/new-file", 0x201, 0600) == Libs::LibKernel::KERNEL_ERROR_EROFS, "game dump is read only");
  FileSystem::Umount("/app0");
  Check(FileSystem::GetRealFilename("/app0/data") == game_dir / "data", "global unmount preserves active game mount");
  FileSystem::Mount(root, "/app0");
  Loader::RuntimeLinker::SetCurrentProgram(&shell);
  Check(FileSystem::GetRealFilename("/app0/data") == root / "data", "ShellUI app0 is unchanged by game mount");
  Check(FileSystem::GetRealFilename("/app0/psm/file") == root / "system-child/file", "ShellUI retains firmware child mount");
  FileSystem::Umount("/app0/psm");
  Loader::RuntimeLinker::SetCurrentProgram(previous);

  Common::File cache;
  Check(cache.Create(root / "rpf.cache"), "create directory listing fixture");
  cache.Close();
  FileSystem::Mount(root, "/app0");
  Check(FileSystem::GetRealFilename("/app0/rpf.cache") == root / "rpf.cache",
        "resolve mount descendant");
  Check(FileSystem::GetRealFilename("/app01/rpf.cache") == "/app01/rpf.cache",
        "mount prefix must end at a path component");

  const auto child_root = root / "child-host";
  FileSystem::Mount(child_root, "/app0/psm");
  Check(FileSystem::GetRealFilename("/app0/psm/Application") == child_root / "Application",
        "child mount overrides an earlier parent mount");
  Check(FileSystem::GetRealFilename("/app0/psm") == child_root,
        "child mount root resolves without a trailing slash");
  Check(FileSystem::GetRealFilename("/app0/psm-other/file") == root / "psm-other/file",
        "child mount does not match a sibling path prefix");
  FileSystem::Mount(root, "/app0");
  Check(FileSystem::GetRealFilename("/app0/psm/Application") == child_root / "Application",
        "child mount overrides a later parent mount");
  FileSystem::Umount("/app0/psm");

  for (const char *path : {"/app0", "/app0/"}) {
    for (const int flags : {0, 0x00020000}) {
      const int fd = FileSystem::KernelOpen(path, flags, 0);
      Check(fd >= 3, "open mounted root with O_RDONLY or O_DIRECTORY");
      std::array<char, 512> entries {};
      const int size = FileSystem::KernelGetdents(fd, entries.data(), entries.size());
      Check(size > 0 && size <= entries.size(), "enumerate mounted root");
      bool found = false;
      for (int offset = 0; offset < size;) {
        // Directory record: inode, record length, type, name length, name.
        Check(size - offset >= 8, "directory record header fits");
        uint16_t length = 0;
        std::memcpy(&length, entries.data() + offset + 4, sizeof(length));
        const auto name_length = static_cast<uint8_t>(entries[offset + 7]);
        Check(length >= 8 + name_length + 1 && length <= size - offset,
              "directory record and name fit");
        if (std::string_view(entries.data() + offset + 8, name_length) == "rpf.cache") {
          Check(entries[offset + 6] == 8, "cache directory entry is a regular file");
          found = true;
        }
        offset += length;
      }
      Check(found, "mounted root listing contains rpf.cache");
      Check(FileSystem::KernelClose(fd) == OK, "close mounted root");
    }
  }
  FileSystem::Umount("/app0");
  Check(FileSystem::GetRealFilename("/app0/rpf.cache") == "/app0/rpf.cache",
        "unmount by guest path");
  for (const auto &folder : {root, root / ""}) {
    for (const auto &host : {root, root / ""}) {
      FileSystem::Mount(folder, "/app0");
      FileSystem::Umount(Common::PathToGenericString(host));
      Check(FileSystem::GetRealFilename("/app0/rpf.cache") == "/app0/rpf.cache",
            "unmount by host path with or without trailing separator");
    }
  }
}

void CheckUnicodePaths(const std::filesystem::path &root) {
  constexpr std::string_view HostDirectory =
      "Test\xc3\xa9-\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e";
  constexpr std::string_view GuestFilename =
      "asset-\xc3\xa9-\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e.bin";

  const auto unicode_root =
      root / Common::PathFromUtf8(HostDirectory);
  const auto nested_root = unicode_root / "nested";

  Check(Common::File::CreateDirectories(nested_root),
        "create nested Unicode host directory");

  CheckMountRoot(nested_root);

  const auto native_file =
      nested_root / Common::PathFromUtf8(GuestFilename);

  Common::File fixture;
  Check(fixture.Create(native_file), "create Unicode filename");
  fixture.Close();

  const auto entries = Common::File::GetDirEntries(nested_root);
  Check(std::any_of(entries.begin(), entries.end(), [&](const auto &entry) {
          return entry.is_file && entry.name == GuestFilename;
        }), "directory enumeration returns UTF-8 filenames");

  FileSystem::Mount(nested_root, "/app0");

  const auto guest_file =
      std::string("/app0/") + std::string(GuestFilename);

  Check(FileSystem::GetRealFilename(guest_file) == native_file,
        "resolve Unicode guest path");

  const int fd = FileSystem::KernelOpen(guest_file.c_str(), 0, 0);
  Check(fd >= 3, "open Unicode guest path");
  Check(FileSystem::KernelClose(fd) == OK,
        "close Unicode guest path");

  FileSystem::Umount("/app0");
}

void CheckUnicodeLogPath(const std::filesystem::path &root) {
  Config::ConfigOptions options;
  options.printf_direction = Config::LogDirection::File;
  options.printf_output_file = root / u8"logs-\u65e5\u672c\u8a9e-\U0001f600" / u8"log-\u00e9.txt";
  Config::Load(options);
  Log::Initialize();
  constexpr std::string_view Payload = "Unicode log path\n";
  Log::Write(Payload);
  Log::Shutdown();

  Common::File result(options.printf_output_file, Common::File::Mode::Read);
  Check(!result.IsInvalid(), "open Unicode log file");
  const auto data = result.ReadWholeBuffer();
  const std::string logged(reinterpret_cast<const char*>(data.data()), data.size());
  Check(logged.ends_with(Payload),
        "Unicode log file contains output");
  options.printf_direction = Config::LogDirection::Silent;
  Config::Load(options);
  Log::Initialize();
}

void CheckDirectoryStream(const std::filesystem::path &root) {
  const auto directory = root / "directory-stream";
  Check(std::filesystem::create_directory(directory),
        "create seek fixture directory");
  for (int i = 0; i < 48; ++i) {
    Common::File fixture;
    Check(fixture.Create(directory / ("directory-entry-" + std::to_string(i))),
          "create enough entries to cross directory blocks");
    fixture.Close();
  }
  FileSystem::Mount(directory, "/app0");
  const int fd = FileSystem::KernelOpen("/app0/", 0, 0);
  Check(fd >= 3, "open directory as read-only asset");
  const auto end = FileSystem::KernelLseek(fd, 0, 2);
  Check(end > 512 && end % 512 == 0,
        "directory SEEK_END uses padded stream size");
  FileSystem::FileStat stat{};
  Check(FileSystem::KernelFstat(fd, &stat) == OK && stat.st_size == end &&
            stat.st_blksize == 512,
        "directory stat agrees with seek and enumeration");
  Check(FileSystem::KernelStat("/app0/", &stat) == OK && stat.st_size == end &&
            stat.st_blocks == end / 512,
        "path and descriptor directory stat agree");
  Check(FileSystem::KernelLseek(fd, 0, 0) == 0,
        "rewind directory for asset read");
  std::vector<char> raw(static_cast<size_t>(end));
  Check(FileSystem::KernelRead(fd, raw.data(), raw.size()) == end &&
            FileSystem::KernelRead(fd, raw.data(), 1) == 0,
        "raw directory read reaches EOF");
  Check(FileSystem::KernelLseek(fd, -end, 1) == 0,
        "directory SEEK_CUR uses the position advanced by read");

  std::array<char, 512> block{};
  int64_t base = -1;
  for (int64_t offset = 0; offset < end; offset += block.size()) {
    Check(FileSystem::KernelGetdirentries(fd, block.data(), block.size(),
                                          &base) == block.size() &&
              base == offset &&
              std::memcmp(block.data(), raw.data() + offset, block.size()) == 0,
          "directory enumeration shares raw bytes and reports each block "
          "position");
    for (size_t pos = 0; pos < block.size();) {
      Check(block.size() - pos >= 8, "directory record header fits");
      uint16_t length = 0;
      std::memcpy(&length, block.data() + pos + 4, sizeof(length));
      const auto name_length = static_cast<uint8_t>(block[pos + 7]);
      Check(length >= 9 + name_length && length <= block.size() - pos &&
                block[pos + 8 + name_length] == '\0',
            "directory entries remain complete within every block");
      pos += length;
    }
  }
  Check(FileSystem::KernelGetdirentries(fd, block.data(), block.size(),
                                        &base) == 0 &&
            base == end,
        "directory enumeration reports EOF position");
  Check(FileSystem::KernelLseek(fd, 512, 0) == 512 &&
            FileSystem::KernelGetdirentries(fd, block.data(), block.size(),
                                            &base) == block.size() &&
            base == 512 &&
            std::memcmp(block.data(), raw.data() + 512, block.size()) == 0,
        "restore and reread a directory enumeration position");

  const auto position = FileSystem::KernelLseek(fd, 0, 1);
  Check(
      FileSystem::KernelLseek(fd, 0, 9) ==
              Libs::LibKernel::KERNEL_ERROR_EINVAL &&
          FileSystem::KernelLseek(fd, -1, 0) ==
              Libs::LibKernel::KERNEL_ERROR_EINVAL &&
          FileSystem::KernelLseek(fd, std::numeric_limits<int64_t>::min(), 1) ==
              Libs::LibKernel::KERNEL_ERROR_EINVAL &&
          FileSystem::KernelLseek(fd, std::numeric_limits<int64_t>::max(), 1) ==
              Libs::LibKernel::KERNEL_ERROR_EOVERFLOW &&
          FileSystem::KernelLseek(fd, 0, 1) == position,
      "invalid and overflowing directory seeks preserve the position");
  Check(FileSystem::KernelLseek(fd, -19, 2) == end - 19 &&
            FileSystem::KernelRead(fd, block.data(), block.size()) == 19 &&
            std::memcmp(block.data(), raw.data() + end - 19, 19) == 0,
        "raw directory reads support byte positions and stop at EOF");
  Check(FileSystem::KernelLseek(fd, 1, 0) == 1 &&
            FileSystem::KernelGetdents(fd, block.data(), block.size()) ==
                Libs::LibKernel::KERNEL_ERROR_EINVAL &&
            FileSystem::KernelLseek(fd, 0, 1) == 1,
        "directory enumeration rejects an incomplete record position");
  Check(FileSystem::KernelLseek(fd, 512, 2) == end + 512 &&
            FileSystem::KernelGetdirentries(fd, block.data(), block.size(),
                                            &base) ==
                Libs::LibKernel::KERNEL_ERROR_EINVAL &&
            FileSystem::KernelLseek(fd, 0, 1) == end + 512,
        "directory enumeration rejects a position beyond EOF");
  Check(FileSystem::KernelRead(
            fd, block.data(),
            static_cast<size_t>(std::numeric_limits<int>::max()) + 1) ==
                Libs::LibKernel::KERNEL_ERROR_EINVAL &&
            FileSystem::KernelLseek(fd, 0, 1) == end + 512,
        "oversized read fails without changing the directory position");
  Check(FileSystem::KernelClose(fd) == OK, "close directory stream");
  Check(FileSystem::KernelLseek(fd, 0, 0) ==
            Libs::LibKernel::KERNEL_ERROR_EBADF,
        "seek rejects a closed descriptor");
  FileSystem::Umount("/app0");
}

void CheckAprPaths(const std::filesystem::path &root) {
  Loader::SymbolDatabase symbols;
  Libs::LibKernelApr::InitLibKernel_1_Apr(&symbols);
  const auto *resolve_symbol = symbols.FindByNid("w5fcCG+t31g", Loader::SymbolType::Func);
  const auto *each_symbol = symbols.FindByNid("C+Khtbbx2g8", Loader::SymbolType::Func);
  Check(resolve_symbol && each_symbol, "APR path exports are registered");
  using Resolve = int (KYTY_SYSV_ABI *)(const char *, const char *const *, uint32_t,
                                      uint32_t *, uint64_t *, uint32_t *);
  using ResolveEach = int (KYTY_SYSV_ABI *)(const char *, const char *const *, uint32_t,
                                          uint32_t *, uint64_t *, int *);
  const auto resolve = reinterpret_cast<Resolve>(resolve_symbol->vaddr);
  const auto resolve_each = reinterpret_cast<ResolveEach>(each_symbol->vaddr);
  Common::File fixture;
  Check(fixture.Create(root / "apr.dat"), "create APR fixture");
  fixture.Write("APR", 3);
  fixture.Close();
  FileSystem::Mount(root, "/app0");

  uint32_t expected_id = 0xffffffffu;
  for (const auto &parts : {std::array{"", "/app0/apr.dat"},
                           std::array{"/app0/", "apr.dat"},
                           std::array{"/", "app0/apr.dat"},
                           std::array{"/app", "0/apr.dat"}}) {
    uint32_t id = 0xffffffffu, error_index = 0xffffffffu;
    uint64_t size = 0;
    Check(resolve(parts[0], &parts[1], 1, &id, &size, &error_index) == OK &&
              id != 0xffffffffu && size == 3,
          "APR concatenates empty, one-character and partial-component prefixes");
    if (expected_id == 0xffffffffu) {
      expected_id = id;
    }
    Check(id == expected_id, "equivalent APR paths return the same ID");
  }

  const char *paths[] = {"/app0/missing.dat", "/app0/apr.dat"};
  uint32_t ids[2] = {}, error_index = 0xffffffffu;
  uint64_t sizes[2] = {1, 1};
  int results[2] = {};
  Check(resolve_each("", paths, 2, ids, sizes, results) == 1 &&
            results[0] == Libs::LibKernel::KERNEL_ERROR_ENOENT && results[1] == OK &&
            ids[0] == 0xffffffffu && ids[1] == expected_id && sizes[0] == 0 && sizes[1] == 3,
        "APR foreach reports a missing path and continues to the valid file");

  // PATH_MAX includes NUL; all components remain below NAME_MAX (255).
  std::string longest = "/app0/";
  for (int i = 0; i < 3; ++i) {
    longest += std::string(254, 'a') + '/';
  }
  longest += std::string(1023 - longest.size(), 'b');
  paths[0] = longest.c_str();
  Check(resolve("", paths, 1, ids, sizes, &error_index) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOENT && error_index == 0,
        "APR accepts a pathname whose final NUL is at PATH_MAX minus one");
  Check(resolve("/", paths, 1, ids, sizes, &error_index) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENAMETOOLONG,
        "APR rejects concatenated paths exceeding PATH_MAX");
  std::array<char, 1024> unterminated;
  unterminated.fill('/');
  paths[0] = unterminated.data();
  Check(resolve("", paths, 1, ids, sizes, &error_index) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENAMETOOLONG,
        "APR rejects an unterminated pathname");
  paths[0] = "apr.dat";
  Check(resolve(unterminated.data(), paths, 1, ids, sizes, &error_index) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENAMETOOLONG,
        "APR rejects an unterminated prefix");
  FileSystem::Umount("/app0");
}

void CheckSocketWakeup() {
  namespace Net = Libs::Network::Net;
  Loader::SymbolDatabase symbols;
  Libs::LibNet::InitNet_1_Net(&symbols);
  const auto *send_symbol = symbols.Find(
      {"beRjXBn-z+o", "Net", 1, "Net", 1, 1, Loader::SymbolType::Func});
  const auto *recv_symbol = symbols.Find(
      {"9wO9XrMsNhc", "Net", 1, "Net", 1, 1, Loader::SymbolType::Func});
  const auto *errno_symbol = symbols.Find(
      {"HQOwnfMGipQ", "Net", 1, "Net", 1, 1, Loader::SymbolType::Func});
  Check(send_symbol && recv_symbol && errno_symbol,
        "Net send, receive and errno exports resolve with the guest ABI versions");
  using Send = int (KYTY_SYSV_ABI *)(int, const void *, size_t, int);
  using Recv = int (KYTY_SYSV_ABI *)(int, void *, size_t, int);
  using Errno = int *(KYTY_SYSV_ABI *)();
  const auto net_send = reinterpret_cast<Send>(send_symbol->vaddr);
  const auto net_recv = reinterpret_cast<Recv>(recv_symbol->vaddr);
  auto *net_errno = reinterpret_cast<Errno>(errno_symbol->vaddr)();
  // Guest sockaddr_in: length, family, network-order port/address, padding.
  std::array<uint8_t, 16> address {16, 2, 0, 0, 127, 0, 0, 1};
  const int listener = Net::Socket(2, 1, 0);
  Check(listener >= 0, "create loopback listener");
  Check(Net::Bind(listener, address.data(), address.size()) == 0, "bind loopback");
  Check(Net::Listen(listener, 1) == 0, "listen on loopback");
  uint32_t address_size = address.size();
  Check(Net::Getsockname(listener, address.data(), &address_size) == 0,
        "get assigned loopback port");
  const int writer = Net::Socket(2, 1, 0);
  Check(writer >= 0 && Net::Connect(writer, address.data(), address_size) == 0,
        "connect wake socket");
  const int reader = Net::Accept(listener, nullptr, nullptr);
  Check(reader >= 0, "accept wake socket");
  Check(Net::SocketClose(listener) == 0, "close listener");
  const int enabled = 1;
  Check(Net::Setsockopt(writer, 6, 1, &enabled, sizeof(enabled)) == 0,
        "enable TCP_NODELAY");
  int socket_error = -1;
  uint32_t error_size = sizeof(socket_error);
  *Libs::Posix::GetErrorAddr() = Libs::Posix::POSIX_EINVAL;
  Check(Net::Getsockopt(writer, 0xffff, 0x1007, &socket_error, &error_size) == 0 &&
            socket_error == 0 && error_size == sizeof(socket_error) &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "SO_ERROR reports socket status without changing guest errno");

  std::array<uint64_t, 16> readable {};
  const auto bit = uint64_t {1} << (reader % 64);
  readable[reader / 64] = bit;
  const std::array<int64_t, 2> immediate {0, 0};
  Check(Net::Select(reader + 1, readable.data(), nullptr, nullptr,
                    immediate.data()) == 0 && readable[reader / 64] == 0,
        "empty socket is not readable");
  const char payload[] = "wake";
  *net_errno = Libs::Posix::POSIX_EINVAL;
  Check(net_send(writer, payload, sizeof(payload), 0) == sizeof(payload) &&
            *net_errno == Libs::Posix::POSIX_EINVAL,
        "Net send forwards bytes and preserves errno on success");
  readable[reader / 64] = bit;
  const std::array<int64_t, 2> deadline {1, 0};
  Check(Net::Select(reader + 1, readable.data(), nullptr, nullptr,
                    deadline.data()) == 1 && readable[reader / 64] == bit,
        "select reports the guest descriptor after wake");
  std::array<char, sizeof(payload)> received {};
  Check(net_recv(reader, received.data(), received.size(), 0x42) == sizeof(payload) &&
            std::memcmp(received.data(), payload, sizeof(payload)) == 0 &&
            *net_errno == Libs::Posix::POSIX_EINVAL,
        "Net receive forwards PEEK and WAITALL without consuming bytes");
  received.fill(0);
  Check(net_recv(reader, received.data(), received.size(), 0x40) == sizeof(payload) &&
            std::memcmp(received.data(), payload, sizeof(payload)) == 0,
        "Net receive consumes the same bytes after peeking");
#if !defined(_WIN32)
  Check(Net::Recv(reader, received.data(), received.size(), 0x80) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EWOULDBLOCK,
        "empty nonblocking receive translates guest errno");
  Check(net_recv(reader, received.data(), received.size(), 0x80) ==
            Libs::Network::NET_ERROR_EWOULDBLOCK &&
            *net_errno == Libs::Posix::POSIX_EWOULDBLOCK,
        "Net nonblocking receive translates POSIX failure and Net errno");
#endif
  Check(net_send(-1, payload, sizeof(payload), 0) == Libs::Network::NET_ERROR_EBADF &&
            *net_errno == Libs::Posix::POSIX_EBADF,
        "Net send translates an invalid socket instead of returning POSIX minus one");
  Check(net_recv(reader, nullptr, received.size(), 0) == Libs::Network::NET_ERROR_EFAULT &&
            *net_errno == Libs::Posix::POSIX_EFAULT,
        "Net receive translates an invalid output buffer");
  Check(net_send(writer, payload, sizeof(payload), 0x100000) ==
            Libs::Network::NET_ERROR_EOPNOTSUPP &&
            *net_errno == Libs::Posix::POSIX_EOPNOTSUPP,
        "Net send preserves the backend's unsupported crypto flag error");
#if defined(__linux__)
  const int disconnected = Net::Socket(2, 1, 0);
  Check(disconnected >= 0, "create unconnected socket for broken pipe check");
  const auto previous_sigpipe = std::signal(SIGPIPE, SIG_DFL);
  Check(previous_sigpipe != SIG_ERR, "set default SIGPIPE disposition for Net send");
  const auto broken_send = net_send(disconnected, payload, sizeof(payload), 0);
  std::signal(SIGPIPE, previous_sigpipe);
  Check(broken_send == Libs::Network::NET_ERROR_EPIPE &&
            *net_errno == Libs::Posix::POSIX_EPIPE,
        "Net send reports a broken pipe without raising host SIGPIPE");
  Check(Net::SocketClose(disconnected) == 0, "close unconnected socket");
#endif
  Check(Net::SocketClose(writer) == 0, "close wake writer");
  *net_errno = Libs::Posix::POSIX_EINVAL;
  Check(net_recv(reader, received.data(), received.size(), 0) == 0 &&
            *net_errno == Libs::Posix::POSIX_EINVAL,
        "Net receive returns EOF without replacing errno");
  Check(Net::SocketClose(reader) == 0, "close wake reader");
  readable[reader / 64] = bit;
  Check(Net::Select(reader + 1, readable.data(), nullptr, nullptr,
                    immediate.data()) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EBADF &&
            readable[reader / 64] == bit,
        "closed descriptor fails without clearing input fd_set");
}

} // namespace

void CheckPsmSharedDmem() {
  Loader::SymbolDatabase symbols;
  Libs::Ipmi::InitIpmi_1(&symbols);
  using Create = int(KYTY_SYSV_ABI*)(void**, const void*, void*, void*);
  auto create = reinterpret_cast<Create>(symbols.FindByNid("0zsTiDhM0nU", Loader::SymbolType::Func)->vaddr);
  struct Input { const void* data; uint64_t size; };
  struct Output { void* data; uint64_t capacity; uint64_t written; };
  using Invoke = int(KYTY_SYSV_ABI*)(void*, uint32_t, const Input*, uint32_t, int*, Output*, uint32_t);
  using Destroy = int64_t(KYTY_SYSV_ABI*)(void*);
  void* client = nullptr;
  std::array<uint8_t, 0x1010> client_storage;
  client_storage.fill(0xa5);
  Check(create(&client, "ScePsmSharedDmem", nullptr, client_storage.data()) == 0 &&
            client == client_storage.data() && client_storage[0x1000] == 0xa5,
        "IPMI client uses caller-owned estimated-size storage without overflow");
  auto vtable = *reinterpret_cast<void***>(client);
  auto invoke = reinterpret_cast<Invoke>(vtable[11]);
  std::array<uint32_t, 3> request {0, 0, 0};
  std::array<uint8_t, 40> reply;
  reply.fill(0xa5);
  Input input {request.data(), 4};
  Output output {reply.data(), 32, 0};
  int result = 0;
  auto call = [&](uint32_t method, bool has_output) {
    result = 0;
    Check(invoke(client, method, &input, 1, &result, has_output ? &output : nullptr,
                 has_output ? 1 : 0) == 0, "PSM IPMI transport result");
    return static_cast<uint32_t>(result);
  };
  Check(call(0x34560002, true) == 0x81668204, "missing metadata returns not-created");
  input.size = 12;
  Check(call(0x34560000, true) == 0 && output.written == 32 && reply[32] == 0xa5,
        "create real bookkeeping mapping with bounded reply");
  int fd = FileSystem::KernelShmOpen("/ScePsmSharedDmem_00000000", 2, 0);
  Check(fd >= 0, "PSM client can open published shared memory name");
  void* view = nullptr;
  Check(FileSystem::KernelMapSharedMemory(fd, &view, 0x100000, 3, 1, 0) == 0,
        "PSM metadata has real shared backing");
  FileSystem::KernelClose(fd);
  static_cast<uint64_t*>(view)[3] = 0x12345678;
  input.size = 4;
  Check(call(0x34560003, false) == 0 && call(0x34560003, false) == 0x81668201,
        "PSM lock detects competing acquisition");
  reinterpret_cast<Destroy>(vtable[0])(client);
  Check(create(&client, "ScePsmSharedDmem", nullptr, client_storage.data()) == 0,
        "new IPC session retains process-owned PSM lock");
  Check(call(0x34560002, true) == 0 && static_cast<uint64_t*>(view)[3] == 0x12345678,
        "query preserves published metadata across sessions");
  Check(call(0x34560004, false) == 0 && call(0x34560004, false) == 0x81668201,
        "PSM unlock requires an acquired lock");
  Input deletion[2] {{request.data(), 4}, {reply.data(), 32}};
  Check(invoke(client, 0x34560001, deletion, 2, &result, nullptr, 0) == 0 && result == 0,
        "PSM metadata deletion releases service mapping");
  Check(FileSystem::KernelShmOpen("/ScePsmSharedDmem_00000000", 2, 0) ==
            Libs::LibKernel::KERNEL_ERROR_ENOENT &&
            static_cast<uint64_t*>(view)[3] == 0x12345678,
        "unlink removes name while existing client mapping survives");
  Libs::LibKernel::Memory::KernelMunmap(reinterpret_cast<uint64_t>(view), 0x100000);
  reinterpret_cast<Destroy>(vtable[0])(client);
  Check(create(&client, "SceMediaEventListnerIpc", nullptr, client_storage.data()) == 0,
        "create missing legacy media-event client");
  uint32_t capacity = 1024, required = 0xa5a5a5a5;
  std::array<char, 1024> json {};
  Input disc_input {&capacity, 4};
  Output disc_output[2] {{json.data(), json.size(), 123}, {&required, 4, 123}};
  result = 0;
  Check(invoke(client, 0x150002, &disc_input, 1, &result, disc_output, 2) == 0 &&
            result < 0 && disc_output[0].written == 0 && disc_output[1].written == 0 && json[0] == 0,
        "missing disc service reports an error instead of successful empty JSON");
  reinterpret_cast<Destroy>(vtable[0])(client);
}

struct ControllerCallbackProbe {
  std::mutex mutex;
  std::condition_variable changed;
  std::vector<uint32_t> types;
  uint64_t device = 0;
  Loader::Program* owner = nullptr;
  Libs::LibKernel::Pthread thread = nullptr;
};
static void KYTY_SYSV_ABI ObserveControllerCallback(uint32_t, void* user, const void* event) {
  auto* probe = static_cast<ControllerCallbackProbe*>(user);
  std::lock_guard lock(probe->mutex);
  uint32_t type = 0;
  std::memcpy(&type, event, 4);
  std::memcpy(&probe->device, static_cast<const uint8_t*>(event) + 8, 8);
  probe->types.push_back(type);
  probe->owner = Loader::RuntimeLinker::GetCurrentProgram();
  probe->thread = Libs::LibKernel::PthreadSelfOrNull();
  probe->changed.notify_all();
}
static void CheckSystemControllerDiscovery() {
  namespace Pad = Libs::Controller;
  Pad::Initialize();
  Loader::SymbolDatabase symbols;
  Libs::Mbus::InitMbus_1(&symbols);
  const auto resolve = [&](const char* nid) {
    const auto* entry = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(entry != nullptr, "resolve native Mbus discovery export");
    return entry->vaddr;
  };
  using InitInfo = void(KYTY_SYSV_ABI*)(void*, uint32_t);
  using Query = int(KYTY_SYSV_ABI*)(const void*, int, void*, int, int*, int*, int);
  auto init = reinterpret_cast<InitInfo>(resolve("edYHYROxzx4"));
  auto query = reinterpret_cast<Query>(resolve("KRL-S9qBqXw"));
  using GetInfo = int(KYTY_SYSV_ABI*)(uint64_t, void*, uint32_t);
  using Bind = int(KYTY_SYSV_ABI*)(uint64_t, int32_t);
  auto get_info = reinterpret_cast<GetInfo>(resolve("RsKVKhSWt28"));
  auto bind = reinterpret_cast<Bind>(resolve("Cpo6sQmnZgU"));
  using EventCreate = int(KYTY_SYSV_ABI*)(uint32_t, void*, int, const void*, void*);
  using EventReceive = int(KYTY_SYSV_ABI*)(uint32_t, void*, int, int);
  using EventDestroy = int(KYTY_SYSV_ABI*)(uint32_t);
  auto create_event = reinterpret_cast<EventCreate>(resolve("c08SEHicDNU"));
  auto receive_event = reinterpret_cast<EventReceive>(resolve("puHrnP8V-dY"));
  auto destroy_event = reinterpret_cast<EventDestroy>(resolve("AcARz3iay1I"));
  Libs::LibKernel::Initialize();
  Libs::LibKernel::PthreadInitSelfForMainThread();
  (void)Common::Singleton<Loader::RuntimeLinker>::Instance();
  namespace Flags = Libs::LibKernel::EventFlag;
  Flags::KernelEventFlag system_state = nullptr;
  Check(Flags::KernelCreateEventFlag(&system_state, "SceSystemStateMgrInfo", 0x20, 0, nullptr) == 0,
        "create shared system-state publication");
  Libs::SystemStateMgr::InitSystemStateMgr_1(&symbols);
  auto current_state = reinterpret_cast<int(KYTY_SYSV_ABI*)()>(resolve("ze0ky5Q1yE8"));
  auto state_waiter = std::async(std::launch::async, [=] { return current_state(); });
  Check(state_waiter.wait_for(std::chrono::milliseconds(25)) == std::future_status::timeout,
        "system-state query waits for SysCore publication");
  Flags::KernelSetEventFlag(system_state, (uint64_t{7} << 32) | 1000);
  Check(state_waiter.wait_for(std::chrono::seconds(2)) == std::future_status::ready &&
            state_waiter.get() == 1000, "system-state query extracts running state independently of trigger code");
  Flags::KernelClearEventFlag(system_state, ~uint64_t{0xffff});
  Flags::KernelSetEventFlag(system_state, 500);
  Check(current_state() == 500, "system-state query follows standby transition without caching the value");
  Flags::KernelClearEventFlag(system_state, ~uint64_t{0xffff});
  Flags::KernelSetEventFlag(system_state, 1000);
  Check(current_state() == 1000, "system-state query follows resume transition");
  Loader::Program callback_owner;
  Loader::RuntimeLinker::SetCurrentProgram(&callback_owner);
  ControllerCallbackProbe callback_probe;
  std::array<uint64_t, 2> callbacks {0, reinterpret_cast<uint64_t>(&ObserveControllerCallback)};
  const int callback_queue = create_event(3, nullptr, 0, callbacks.data(), &callback_probe);
  Check(callback_queue >= 0, "subscribe through native callback ABI");
  const int connection_queue = create_event(3, nullptr, 0, nullptr, nullptr);
  const int removal_queue = create_event(2, nullptr, 0, nullptr, nullptr);
  Check(connection_queue >= 0 && removal_queue >= 0, "subscribe to controller bus hotplug");
  std::array<uint8_t, 81> hotplug {};
  hotplug.back() = 0x5a;
  auto waiter = std::async(std::launch::async, [&] {
    return receive_event(connection_queue, hotplug.data(), 1, 1);
  });
  Check(waiter.wait_for(std::chrono::milliseconds(25)) == std::future_status::timeout,
        "PSM bus scanner sleeps until a real host connection change");
  std::array<uint8_t, 256> condition {}, record {};
  init(condition.data(), condition.size());
  int total = -1, generation = -1;
  Check(query(condition.data(), 0, record.data(), 1, &total, &generation, 256) == 0 && total == 0,
        "keyboard fallback does not invent a physical controller on the system bus");
  Pad::Connect(4); // Exercise host instance IDs independent of guest handles.
  Check(waiter.wait_for(std::chrono::seconds(2)) == std::future_status::ready && waiter.get() == 1,
        "connecting a pad after boot wakes the blocked PSM bus scanner");
  uint32_t event_type = 0;
  uint64_t event_device = 0;
  std::memcpy(&event_type, hotplug.data(), 4);
  std::memcpy(&event_device, hotplug.data() + 8, 8);
  Check(event_type == 1 && event_device == 4 && hotplug.back() == 0x5a,
        "hotplug event reports the connected device in the native 80-byte ABI");
  {
    std::unique_lock lock(callback_probe.mutex);
    Check(callback_probe.changed.wait_for(lock, std::chrono::seconds(2), [&] {
      return callback_probe.types.size() == 1;
    }) && callback_probe.types[0] == 1 && callback_probe.device == 4 &&
          callback_probe.owner == &callback_owner && callback_probe.thread != nullptr &&
          callback_probe.thread != Libs::LibKernel::PthreadSelfOrNull(),
          "hotplug callback runs with guest stack, thread state and subscriber ownership");
  }
  Check(receive_event(callback_queue, hotplug.data(), 1, 0) == 0,
        "callback subscriptions bypass the native receive ring");
  Check(receive_event(removal_queue, hotplug.data(), 1, 0) == 0,
        "removal-only subscribers do not receive connect events");
  Check(query(condition.data(), 0, record.data(), 1, &total, &generation, 256) == 1 && total == 1,
        "host controller connection becomes visible to native PSM discovery");
  uint64_t device_id = 0;
  int32_t type = 0, user = 0, transport = -1;
  std::memcpy(&device_id, record.data(), 8);
  std::memcpy(&type, record.data() + 12, 4);
  std::memcpy(&transport, record.data() + 8, 4);
  std::memcpy(&user, record.data() + 200, 4);
  Check(device_id == 4 && type == 2 && user == 0 && transport == 0,
        "new controller starts unassigned so native onboarding can discover it");
  std::array<uint8_t, 256> queried_record {};
  Check(get_info(4, queried_record.data(), 256) == 0 && queried_record == record &&
            get_info(99, queried_record.data(), 256) < 0,
        "lookup by physical ID returns the same complete device record");
  uint32_t function_count = 0;
  std::memcpy(&function_count, record.data() + 20, 4);
  Check(function_count == 1 && record[24] == 0 && record[32] == 0,
        "native peripheral conversion receives an enabled controller function");
  // LoginMgr sums separate queries for controller, Move, VR and special
  // controller functions. One physical pad must not count in all five groups.
  int controller_total = 0;
  for (int32_t requested_function: {0, 6, 19, 20, 11}) {
    init(condition.data(), condition.size());
    int32_t requested_count = 1;
    std::memcpy(condition.data() + 20, &requested_count, 4);
    std::memcpy(condition.data() + 24, &requested_function, 4);
    const int copied = query(condition.data(), 0, record.data(), 1, &total, &generation, 256);
    Check(copied == (requested_function == 0 ? 1 : 0) && total == copied,
          "Mbus filters native function types during controller-limit checks");
    controller_total += total;
  }
  Check(controller_total == 1, "LoginMgr counts one controller instead of five function categories");
  init(condition.data(), condition.size());
  using ConvertLocal = int(KYTY_SYSV_ABI*)(uint64_t, uint32_t, uint64_t*);
  auto convert_local = reinterpret_cast<ConvertLocal>(resolve("wxmyc+71ijI"));
  uint64_t local_id = UINT64_MAX;
  Check(convert_local(4, 0, &local_id) == 0 && local_id == 4 &&
            convert_local(4, 1, &local_id) < 0 && convert_local(99, 0, &local_id) < 0,
        "local controller conversion preserves real IDs and rejects unrelated buses/devices");
  Check(Pad::PadSetUserNumber(4, 1) == 0 && Pad::PadSetUserNumber(99, 1) < 0 &&
            Pad::PadSetUserNumber(4, 0) < 0,
        "initial setup can set a physical controller player number with native argument validation");
  const int owner_queue = create_event(0x10, nullptr, 0, nullptr, nullptr);
  const int old_generation = generation;
  Check(bind(4, Config::GetUserId()) == 0 &&
            query(condition.data(), 0, record.data(), 1, &total, &generation, 256) == 1,
        "LoginMgr can bind a real physical controller");
  std::memcpy(&user, record.data() + 200, 4);
  Check(user == Config::GetUserId() && generation > old_generation &&
            receive_event(owner_queue, hotplug.data(), 1, 0) == 1 && hotplug[0] == 0x10 &&
            bind(999, Config::GetUserId()) < 0,
        "assignment persists, advances generation and wakes owner-change subscribers");
  int32_t event_owner = 0;
  std::memcpy(&event_owner, hotplug.data() + 28, sizeof(event_owner));
  Check(event_owner == user && hotplug[16] == 0 && hotplug[20] == 2,
        "owner-change event uses the native bus, class and user offsets");
  Check(destroy_event(owner_queue) == 0, "destroy assignment subscription");
  int32_t other_type = 22;
  std::memcpy(condition.data() + 12, &other_type, 4);
  Check(query(condition.data(), 0, record.data(), 1, &total, &generation, 256) == 0 && total == 0,
        "controller enumeration excludes unrelated device classes");
  init(condition.data(), condition.size());
  Check(query(condition.data(), 1, record.data(), 1, &total, &generation, 256) == 0 && total == 1,
        "system device pagination reports total independently of copied records");
  Check(query(condition.data(), 0, record.data(), 1, &total, &generation, 255) < 0,
        "system device enumeration rejects the wrong native record stride");
  const int handle = Pad::PadDeviceOpen(device_id, 0, 0);
  uint32_t capabilities = 0;
  Check(Pad::PadGetCapability(device_id, &capabilities) == 0 && capabilities != 0 &&
            Pad::PadGetCapability(999, &capabilities) < 0,
        "privileged capabilities are queried by bus device ID rather than a pad handle");
  Check(handle == 1 && Pad::PadDeviceOpen(999, 0, 0) < 0,
        "native device open maps the real host ID and rejects absent devices");
  Pad::SetButton(4, Pad::PAD_BUTTON_PS | Pad::PAD_BUTTON_CROSS, true);
  Pad::SetAxis(4, Pad::Axis::LeftX, 211);
  std::array<uint8_t, 113> ui {};
  ui.back() = 0xa5;
  Check(Pad::PadUiReadState(handle, ui.data()) == 0 && ui[76] == 1 && ui[77] != 0 && ui.back() == 0xa5,
        "privileged UI pad read supplies connection state within its 112-byte ABI");
  uint32_t buttons = 0;
  std::memcpy(&buttons, ui.data(), 4);
  Check(buttons == (Pad::PAD_BUTTON_PS | Pad::PAD_BUTTON_CROSS) && ui[4] == 211,
        "real button and axis state reaches the system UI, including the PS button");
  Pad::SetButton(4, Pad::PAD_BUTTON_PS | Pad::PAD_BUTTON_CROSS, false);
  Check(Pad::PadUiReadState(handle, ui.data()) == 0 && ui[0] == 0 && ui[2] == 0,
        "button release reaches the system UI without sticking");
  Pad::Disconnect(4);
  {
    std::unique_lock lock(callback_probe.mutex);
    Check(callback_probe.changed.wait_for(lock, std::chrono::seconds(2), [&] {
      return callback_probe.types.size() == 2;
    }) && callback_probe.types[1] == 2, "callback receives disconnect in order");
  }
  Check(receive_event(connection_queue, hotplug.data(), 1, 0) == 1 && hotplug[0] == 2 &&
            receive_event(removal_queue, hotplug.data(), 1, 0) == 1 && hotplug[0] == 2,
        "disconnect reaches each matching bus subscriber independently");
  Check(query(condition.data(), 0, record.data(), 1, &total, &generation, 256) == 0 && total == 0,
        "host disconnect removes the physical controller from system discovery");
  Pad::Shutdown();
  Check(destroy_event(connection_queue) == 0 && destroy_event(removal_queue) == 0,
        "release controller bus subscriptions");
  Check(destroy_event(callback_queue) == 0, "destroy joins guest callback worker");
  Loader::RuntimeLinker::SetCurrentProgram(nullptr);
}

static void CheckFlipPlaneScheduling() {
  using namespace Libs::VideoOutInternal;
  int game, system, overlay;
  std::vector<QueuedFlip> queue {{1, 1, &system, true}, {2, 2, &game, true},
                                 {3, 3, &system, true}, {4, 4, &game, true}};
  Check(SelectFlipGroups(queue) == std::vector<uint64_t>({1, 2}),
        "game and system heads advance together without draining either FIFO");
  queue[0].ready = false;
  Check(SelectFlipGroups(queue) == std::vector<uint64_t>({2}),
        "unfinished system frame cannot stall game or let a later system frame overtake");
  queue = {{1, 3, &overlay, true}, {2, 2, &game, true}, {3, 3, &system, false}};
  Check(SelectFlipGroups(queue) == std::vector<uint64_t>({2}),
        "master and slave remain atomic while an independent game advances");
  queue[2].ready = true;
  Check(SelectFlipGroups(queue) == std::vector<uint64_t>({2, 3}),
        "ready master and captured slave advance alongside game");
  queue.insert(queue.begin(), {0, 0, &overlay, false});
  Check(SelectFlipGroups(queue) == std::vector<uint64_t>({2}),
        "older CPU request blocks its port across CPU and GPU queues");
  queue = {{1, 0, &overlay, true}, {2, 2, &game, true}};
  Check(SelectFlipGroups(queue) == std::vector<uint64_t>({2}),
        "uncaptured slave is held until its master arrives");
}

int main(int argc, char **argv) {
  if (argc > 1 && std::strcmp(argv[1], "--flip-planes-only") == 0) {
    CheckFlipPlaneScheduling();
    std::printf("KernelFileSystemTests: display plane scheduling cases passed\n");
    return 0;
  }
  Common::InitializeThreads();
  Common::Subsystems subsystems;
  subsystems.Initialize<Config::Lifecycle>();
  Config::ConfigOptions options;
  options.guest_environment["KYTY_RUNTIME_CONFIGURED"] = "configured";
  options.printf_direction = Config::LogDirection::Silent;
  Config::Load(options);
  subsystems.Initialize<Log::Lifecycle>();

  if (argc > 1 && std::strcmp(argv[1], "--guest-fault-only") == 0) {
    CheckGuestFaultDelivery();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: guest fault delivery cases passed\n");
    return 0;
  }

  Check(SDL_InitSubSystem(SDL_INIT_VIDEO), "initialize Vulkan test video");
  auto graphics = std::make_unique<Libs::Graphics::WindowContext>();
  graphics->graphic_ctx.screen_width = 64;
  graphics->graphic_ctx.screen_height = 64;
  graphics->window = SDL_CreateWindow("KernelFileSystemTests", 64, 64,
                                      SDL_WINDOW_VULKAN | SDL_WINDOW_HIDDEN);
  Check(graphics->window != nullptr, "create hidden Vulkan test window");
  graphics->CreateVulkan();

  TempDirectory temporary;
  const bool shared_test = argc > 1 && std::strcmp(argv[1], "--shm-only") == 0;
  const bool runtime_test = argc > 1 && std::strcmp(argv[1], "--runtime-only") == 0;
  const bool thread_owner_test = argc > 1 && std::strcmp(argv[1], "--thread-owner-only") == 0;
  const bool join_suspension_test = argc > 1 && std::strcmp(argv[1], "--join-suspension-only") == 0;
  const bool controller_test = argc > 1 && std::strcmp(argv[1], "--controller-only") == 0;
  if (shared_test || runtime_test || thread_owner_test || controller_test || join_suspension_test) { Libs::LibKernel::Memory::Initialize(); }
  FileSystem::Initialize();
  CheckSymbolLookup();
  CheckPipeWakeup();
  if (argc > 1 && std::strcmp(argv[1], "--users-only") == 0) {
    CheckPersistentUsers(temporary.Path());
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: persistent user cases passed\n");
    return 0;
  }
  if (argc > 1 && std::strcmp(argv[1], "--controller-only") == 0) {
    CheckSystemControllerDiscovery();
    FileSystem::Shutdown();
    Libs::LibKernel::Memory::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: system controller cases passed\n");
    return 0;
  }
  if (join_suspension_test) {
    CheckJoinSuspension();
    FileSystem::Shutdown();
    Libs::LibKernel::Memory::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: join suspension cases passed\n");
    return 0;
  }
  if (thread_owner_test) {
    CheckThreadProgramOwner();
    FileSystem::Shutdown();
    Libs::LibKernel::Memory::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: thread program owner cases passed\n");
    return 0;
  }
  if (argc > 1 && std::strcmp(argv[1], "--sigset-only") == 0) {
    CheckSignalSets();
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: signal set cases passed\n");
    return 0;
  }
  if (argc > 1 && std::strcmp(argv[1], "--usercontext-only") == 0) {
    CheckUserContext();
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: user context cases passed\n");
    return 0;
  }
  if (shared_test) {
    CheckSharedMemory();
    CheckPsmSharedDmem();
    FileSystem::Shutdown();
    Libs::LibKernel::Memory::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: shared memory cases passed\n");
    return 0;
  }
  if (argc > 1 && std::strcmp(argv[1], "--runtime-only") == 0) {
    CheckFlipPlaneScheduling();
    CheckFileMapping(temporary.Path());
    CheckConsoleDevice();
    CheckDevkitActivation(temporary.Path());
    CheckScreenshotDevice();
    CheckSparseUnmap();
    CheckCoHostedCompositorViews();
    CheckLibcRuntime(temporary.Path());
    CheckHotServices();
    CheckAppConfig(temporary.Path());
    FileSystem::Shutdown();
    Libs::LibKernel::Memory::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: native runtime cases passed\n");
    return 0;
  }
  if (argc > 1 && std::strcmp(argv[1], "--appconfig-only") == 0) {
    CheckJsonEventTransfer();
    CheckJscHeapLimit();
    CheckAppConfig(temporary.Path());
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: app config cases passed\n");
    return 0;
  }
  if (argc > 1 && std::strcmp(argv[1], "--relative-cond-only") == 0) {
    CheckRelativeCondWait();
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: relative condition wait cases passed\n");
    return 0;
  }
  if (argc > 1 && std::strcmp(argv[1], "--libc-only") == 0) {
    CheckLibcRuntime(temporary.Path());
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: libc runtime cases passed\n");
    return 0;
  }
  if (argc > 1 && std::strcmp(argv[1], "--mount-only") == 0) {
    CheckMountRoot(temporary.Path());
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: mount cases passed\n");
    return 0;
  }
  if (argc > 1 && std::strcmp(argv[1], "--pipe-only") == 0) {
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: pipe cases passed\n");
    return 0;
  }
  CheckMountRoot(temporary.Path());
  CheckLibcRuntime(temporary.Path());
  CheckUnicodePaths(temporary.Path());
  CheckUnicodeLogPath(temporary.Path());
  CheckDirectoryStream(temporary.Path());
  CheckAprPaths(temporary.Path());
  FileSystem::Mount(temporary.Path(), "/savedata0");
  TestSaveOpenVisibility();
  CheckSaveRename(temporary.Path(), "first-save");
  CheckSaveRename(temporary.Path(), "replacement-save");
  FileSystem::Shutdown();
  CheckSocketWakeup();
  graphics.reset();
  subsystems.Destroy();

  std::printf("KernelFileSystemTests: all cases passed\n");
  return 0;
}
