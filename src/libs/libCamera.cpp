#include "common/common.h"
#include "common/logging/log.h"
#include "libs/errno.h"
#include "libs/libs.h"
#include "loader/symbolDatabase.h"

#include <cstdint>

// libSceCamera: the PS5 front camera. AgcCompositor spawns a CompositorCameraThr that opens the
// camera (for e.g. HMD/PS-Camera passthrough overlays). Standalone there is no camera hardware and
// it is NOT needed to composite the ShellUI, so every entry point reports "no camera": open/start
// fail, IsConnected = 0, GetFrameData fails, stop/close succeed. The compositor's camera thread then
// cleanly gives up instead of using a garbage handle (which was deref'd -> host crash).

namespace Libs {
namespace Camera {

LIB_VERSION("Camera", 1, "Camera", 1, 1);

// Generic "no camera device" error; callers only check for a negative/non-zero result.
constexpr int CAMERA_ERROR_NOT_CONNECTED = static_cast<int>(0x80E90002u);

static int KYTY_SYSV_ABI CameraOpenByModuleId(int user_id, int module_id, const void* param) {
	PRINT_NAME();
	(void)user_id; (void)module_id; (void)param;
	return CAMERA_ERROR_NOT_CONNECTED;
}
static int KYTY_SYSV_ABI CameraStartByHandle(int handle, const void* param) {
	PRINT_NAME();
	(void)handle; (void)param;
	return CAMERA_ERROR_NOT_CONNECTED;
}
static int KYTY_SYSV_ABI CameraIsConnectedForSystem(int arg) {
	PRINT_NAME();
	(void)arg;
	return 0; // not connected
}
static int KYTY_SYSV_ABI CameraGetFrameData(int handle, void* frame_data) {
	PRINT_NAME();
	(void)handle; (void)frame_data;
	return CAMERA_ERROR_NOT_CONNECTED;
}
static int KYTY_SYSV_ABI CameraStopByHandle(int handle) {
	PRINT_NAME();
	(void)handle;
	return OK;
}
static int KYTY_SYSV_ABI CameraCloseByHandle(int handle) {
	PRINT_NAME();
	(void)handle;
	return OK;
}

LIB_DEFINE(InitCamera_1) {
	LIB_FUNC("eTywOSWsEiI", Camera::CameraOpenByModuleId);       // sceCameraOpenByModuleId
	LIB_FUNC("cLxF1QtHch0", Camera::CameraStartByHandle);        // sceCameraStartByHandle
	LIB_FUNC("68S3GKWhY6o", Camera::CameraIsConnectedForSystem); // sceCameraIsConnectedForSystem
	LIB_FUNC("mxgMmR+1Kr0", Camera::CameraGetFrameData);         // sceCameraGetFrameData
	LIB_FUNC("+X1Kgnn3bzg", Camera::CameraStopByHandle);         // sceCameraStopByHandle
	LIB_FUNC("ztqH5qNTpTk", Camera::CameraCloseByHandle);        // sceCameraCloseByHandle
}

} // namespace Camera
} // namespace Libs
