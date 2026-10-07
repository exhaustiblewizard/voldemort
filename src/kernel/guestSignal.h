#ifndef KYTY_KERNEL_GUEST_SIGNAL_H_
#define KYTY_KERNEL_GUEST_SIGNAL_H_

#include "common/hostException.h"

namespace Libs::LibKernel {
// Deliver a synchronous guest fault after instruction emulation and GPU tracking.
// The registered handler may change native_context to resume exception dispatch.
bool KernelDispatchGuestFault(const Common::HostException::ExceptionInfo& info);
}

#endif
