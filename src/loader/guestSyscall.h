#pragma once

#include <cstdint>

// Guest raw-syscall emulation.
//
// Statically-linked PS5 system processes (SceSysCore, and the privileged system
// binaries in general) do NOT go through dynamically-imported libkernel wrappers —
// they talk to the kernel directly through a table of `mov eax, N; syscall` thunks.
// Kyty's HLE is import-level (it patches PLT stubs), so these raw `syscall` (0F 05)
// instructions would otherwise execute as host Windows/Linux syscalls and crash.
//
// Approach (mirrors the existing rsqrt handling in X64InstructionEmulator):
//   1. PatchSyscalls() scans each loaded executable segment with Zydis and overwrites
//      every `syscall` (0F 05) with `ud2` (0F 0B) — same 2-byte footprint, so all
//      following code offsets stay valid — recording each site address.
//   2. A `ud2` raises EXCEPTION_ILLEGAL_INSTRUCTION, which Kyty already routes to
//      KytyExceptionHandler -> TryEmulate. TryEmulate() below recognises a recorded
//      syscall site, reads the FreeBSD syscall ABI (number in RAX; args in RDI, RSI,
//      RDX, R10, R8, R9), dispatches, writes the result back (RAX + carry flag for
//      error), and advances RIP past the 2-byte instruction.
//
// This reuses the illegal-instruction plumbing with no change to hostException.cpp.

namespace Loader::GuestSyscall {

// Scan [address, address+size) for `syscall` instructions, patch each to `ud2`, and
// record the site. Returns the number of sites patched. Call once per executable
// segment after it is mapped (before FlushInstructionCache).
uint64_t PatchSyscalls(uint64_t address, uint64_t size);

// If the faulting RIP in native_context is a recorded syscall site, emulate the
// syscall against native_context and return true (RIP advanced, result in RAX).
// Returns false for any other illegal instruction so the next emulator can try it.
[[nodiscard]] bool TryEmulate(void* native_context);

} // namespace Loader::GuestSyscall
