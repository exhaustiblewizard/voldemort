#include "common/abi.h"
#include "libs/errno.h"
#include "libs/libs.h"
#include "loader/symbolDatabase.h"

namespace Libs::FsInternalForVsh {
LIB_VERSION("FsInternalForVsh", 1, "FsInternalForVsh", 1, 1);

// QkzPx-QbX3A: native 42730 opens /dev/m2.ctl and reads thermal data
// with ioctl 0x40103207. The emulator has no expansion M.2 controller.
// Native open failure returns -1 (with POSIX errno), without touching either
// output. ShellCore 79F9E0 disables thermal alarms on this error path.
static int KYTY_SYSV_ABI GetM2ThermalInformation(uint16_t* temperature, void* thresholds) {
	(void)temperature;
	(void)thresholds;
	*Posix::GetErrorAddr() = Posix::POSIX_ENODEV;
	return -1;
}

LIB_DEFINE(InitFsInternalForVsh_1) {
	LIB_FUNC("QkzPx-QbX3A", GetM2ThermalInformation);
}
} // namespace Libs::FsInternalForVsh
