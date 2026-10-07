#include "common/abi.h"
#include "graphics/presentation/videoOut.h"
#include "libs/errno.h"
#include "libs/libs.h"
#include "loader/symbolDatabase.h"

#include <cstring>

namespace Libs {

namespace LibGen5 {

LIB_VERSION("VideoOut", 1, "VideoOut", 1, 1);

// AgcCompositor-only VideoOut functions (hardware cursor, set-mode event, blank-after-resume, VR
// native). Not needed to produce the main scanout; stub as benign success so compositor display
// setup proceeds. SysOpenVrNative reports no VR device.
static KYTY_SYSV_ABI int VideoOutAddSetModeEvent(void* eq, int handle, void* udata) {
	PRINT_NAME();
	(void)eq; (void)handle; (void)udata;
	return OK;
}
static KYTY_SYSV_ABI int VideoOutSetBlankAfterResume(int handle, int blank) {
	PRINT_NAME();
	(void)handle; (void)blank;
	return OK;
}
static KYTY_SYSV_ABI int VideoOutSysCursorSetSize(int handle, int index, uint32_t w, uint32_t h) {
	PRINT_NAME();
	(void)handle; (void)index; (void)w; (void)h;
	return OK;
}
static KYTY_SYSV_ABI int VideoOutCursorSetPosition(int handle, int index, int x, int y) {
	PRINT_NAME();
	(void)handle; (void)index; (void)x; (void)y;
	return OK;
}
static KYTY_SYSV_ABI int VideoOutCursorSet2xMagnify(int handle, int index, int enable) {
	PRINT_NAME();
	(void)handle; (void)index; (void)enable;
	return OK;
}
static KYTY_SYSV_ABI int VideoOutSysOpenVrNative() {
	PRINT_NAME();
	return VideoOut::VIDEO_OUT_ERROR_NO_DEVICE;
}
// sceVideoOutSysAddSetModeEvent2 (fYWVVDKZOCk): register a display set-mode event on an equeue.
// Benign success — the system scanout mode never changes under Kyty.
static KYTY_SYSV_ABI int VideoOutSysAddSetModeEvent2(void* eq, int handle, void* udata) {
	PRINT_NAME();
	(void)eq; (void)handle; (void)udata;
	return OK;
}
// sceVideoOutSysGetPipelineStatus (dFhciCfO31s): SceSysCore queries the display pipeline state.
// Real fn ioctls the VideoOut device and fills a 32-byte status block. Offline we report a present,
// ready pipeline: zero the block and mark it active. Returns SCE_VIDEO_OUT_ERROR_INVALID_* on bad
// args (a1 == null or a2 != 0), else 0.
static KYTY_SYSV_ABI int VideoOutSysGetPipelineStatus(uint32_t* status, uint64_t reserved) {
	PRINT_NAME();
	if (status == nullptr || reserved != 0) {
		return static_cast<int>(0x80290002u); // SCE_VIDEO_OUT_ERROR_INVALID_VALUE
	}
	for (int i = 0; i < 8; i++) {
		status[i] = 0;
	}
	// These are VR mode flags, not readiness flags. Both are clear for normal scanout.
	return OK;
}

static KYTY_SYSV_ABI int VideoOutSysGetResolutionStatus2(uint32_t pipeline, void* status) {
	if (pipeline >= 2) { return VideoOut::VIDEO_OUT_ERROR_INVALID_VALUE; }
	if (status == nullptr) { return VideoOut::VIDEO_OUT_ERROR_INVALID_ADDRESS; }
	// Native SysGetResolutionStatus2 writes a 64-byte record. The fixed system
	// scanout is 1080p60; the host window may scale it independently.
	uint32_t record[16] {};
	record[0] = record[2] = 1920;
	record[1] = record[3] = 1080;
	record[4] = 9; // Native PSM refresh-rate enum: 60 Hz (3 is 59.94 Hz).
	record[7] = 6; // Fixed output supports both required scanout capabilities.
	std::memcpy(status, record, sizeof(record));
	return OK;
}

static int ValidateSystemStatusQuery(int user, uint32_t pipeline, int reserved,
                                    uint64_t reserved2) {
	if (user != 255 || pipeline >= 2 || reserved2 != 0) {
		return VideoOut::VIDEO_OUT_ERROR_INVALID_VALUE;
	}
	if (reserved != 0) { return static_cast<int>(0x8029001au); }
	return OK;
}

static KYTY_SYSV_ABI int VideoOutSysIsUserStatusSystemDefault(int user, uint32_t pipeline,
    uint64_t unused, int reserved, uint64_t reserved2) {
	const auto result = ValidateSystemStatusQuery(user, pipeline, reserved, reserved2);
	return result == OK ? 1 : result;
}

static KYTY_SYSV_ABI int VideoOutSysIsUserStatusVr(int user, uint32_t pipeline,
    uint64_t unused, int reserved, uint64_t reserved2) {
	return ValidateSystemStatusQuery(user, pipeline, reserved, reserved2);
}

// pTxsULu4Nh0 queries the occupied privacy-mask buffer IDs (ioctl 0x80208218).
// AgcCompositor getPrivacyMaskAvailableId reads this bitmask after success.
// Kyty currently allocates no privacy-mask buffers, so all bits are clear.
static KYTY_SYSV_ABI int VideoOutSysGetPrivacyMaskStatus(uint64_t* occupied_ids) {
	if (occupied_ids == nullptr) {
		return VideoOut::VIDEO_OUT_ERROR_INVALID_ADDRESS;
	}
	*occupied_ids = 0;
	return OK;
}

LIB_DEFINE(InitVideoOut_1) {
	PRINT_NAME_ENABLE(true);

	LIB_FUNC("Up36PTk687E", VideoOut::VideoOutOpen);
	LIB_FUNC("uquVH4-Du78", VideoOut::VideoOutClose);
	LIB_FUNC("WkYtyOg30do", VideoOut::VideoOutSetFlipMaster);
	LIB_FUNC("MBlv8YWoyOk", VideoOut::VideoOutAddBufferAttributeOption);
	LIB_FUNC("PjS5uASwcV8", VideoOut::VideoOutSetBufferAttribute2);
	LIB_FUNC("i6-sR91Wt-4", VideoOut::VideoOutSetBufferAttribute);
	LIB_FUNC("w3BY+tAEiQY", VideoOut::VideoOutRegisterBuffers);
	LIB_FUNC("6kPnj51T62Y", VideoOut::VideoOutGetResolutionStatus);
	LIB_FUNC("rKBUtgRrtbk", VideoOut::VideoOutRegisterBuffers2);
	LIB_FUNC("HuViW4HnrOw", VideoOut::VideoOutSubmitChangeBufferAttribute2);
	LIB_FUNC("N5KDtkIjjJ4", VideoOut::VideoOutUnregisterBuffers);
	LIB_FUNC("CBiu4mCE1DA", VideoOut::VideoOutSetFlipRate);
	LIB_FUNC("HXzjK9yI30k", VideoOut::VideoOutAddFlipEvent);
	LIB_FUNC("Xru92wHJRmg", VideoOut::VideoOutAddVblankEvent);
	LIB_FUNC("Am8Hlr7tlxA", VideoOut::VideoOutSysAddVblankEvent2);
	LIB_FUNC("Ek+VR4lcJQI", VideoOut::VideoOutSysAddVblankEvent);
	LIB_FUNC("iwsJdAZCg34", VideoOut::VideoOutSysDeleteVblankEvent);
	LIB_FUNC("2EBuouuYKgM", VideoOut::VideoOutSysDeleteVblankEvent2);
	LIB_FUNC("keipklF0pMY", VideoOut::VideoOutAddPreVblankStartEvent);
	LIB_FUNC("-Ozn0F1AFRg", VideoOut::VideoOutDeleteFlipEvent);
	LIB_FUNC("oNOQn3knW6s", VideoOut::VideoOutDeleteVblankEvent);
	LIB_FUNC("elWQ9vERF-Q", VideoOut::VideoOutDeletePreVblankStartEvent);
	LIB_FUNC("U46NwOiJpys", VideoOut::VideoOutSubmitFlip);
	LIB_FUNC("SbU3dwp80lQ", VideoOut::VideoOutGetFlipStatus);
	LIB_FUNC("zgXifHT9ErY", VideoOut::VideoOutIsFlipPending);
	LIB_FUNC("1FZBKy8HeNU", VideoOut::VideoOutGetVblankStatus);
	LIB_FUNC("MTxxrOCeSig", VideoOut::VideoOutSetWindowModeMargins);
	LIB_FUNC("kmSe30JTs+E", VideoOut::VideoOutAddOutputModeEvent);
	LIB_FUNC("U2JJtSqNKZI", VideoOut::VideoOutGetEventId);
	LIB_FUNC("rWUTcKdkUzQ", VideoOut::VideoOutGetEventData);
	LIB_FUNC("Mt4QHHkxkOc", VideoOut::VideoOutGetEventCount);
	LIB_FUNC("j6RaAUlaLv0", VideoOut::VideoOutWaitVblank);
	LIB_FUNC("utPrVdxio-8", VideoOut::VideoOutGetOutputStatus);
	LIB_FUNC("+I4K03i3EL0", VideoOut::VideoOutInitializeOutputOptions);
	LIB_FUNC("Nv8c-Kb+DUM", VideoOut::VideoOutIsOutputSupported);
	LIB_FUNC("w0hLuNarQxY", VideoOut::VideoOutConfigureOutput);
	LIB_FUNC("eb-gvTYQcoY", VideoOut::VideoOutLatencyControlWaitBeforeInput);
	LIB_FUNC("MCJ8SkzsQxY", VideoOut::VideoOutLatencyMeasureSetStartPoint);
	LIB_FUNC("DYhhWbJSeRg", VideoOut::VideoOutColorSettingsSetGamma);
	LIB_FUNC("pv9CI5VC+R0", VideoOut::VideoOutAdjustColor);
	// AgcCompositor-only (cursor / set-mode event / blank-after-resume / VR native)
	LIB_FUNC("AjtlFa2HRws", VideoOutAddSetModeEvent);      // sceVideoOutAddSetModeEvent
	LIB_FUNC("zILy8t+5bPo", VideoOutSetBlankAfterResume);  // sceVideoOutSetBlankAfterResume
	LIB_FUNC("I7ms8YxoZio", VideoOutSysCursorSetSize);     // sceVideoOutSysCursorSetSize
	LIB_FUNC("N17AK88NdD0", VideoOutCursorSetPosition);    // sceVideoOutCursorSetPosition
	LIB_FUNC("Se-Zs6koGzk", VideoOutCursorSet2xMagnify);   // sceVideoOutCursorSet2xMagnify
	LIB_FUNC("WUU+ufqgLJg", VideoOutSysOpenVrNative);      // sceVideoOutSysOpenVrNative
	LIB_FUNC("fYWVVDKZOCk", VideoOutSysAddSetModeEvent2);  // sceVideoOutSysAddSetModeEvent2
	LIB_FUNC("dFhciCfO31s", VideoOutSysGetPipelineStatus); // sceVideoOutSysGetPipelineStatus
	LIB_FUNC("qLDCAl8ygCw", VideoOutSysGetResolutionStatus2);
	LIB_FUNC("O57F5ikhGxo", VideoOutSysIsUserStatusSystemDefault);
	LIB_FUNC("4XsQdhiOaAc", VideoOutSysIsUserStatusVr);
	LIB_FUNC("pTxsULu4Nh0", VideoOutSysGetPrivacyMaskStatus);
}

} // namespace LibGen5

namespace LibGen5::VrrStatus {

LIB_VERSION("VideoOutVrrStatus", 1, "VideoOut", 1, 1);

static KYTY_SYSV_ABI int VideoOutVrrStatus_kP2L8t3j_aM() {
	// The observed guest call passes no arguments.
	// Return success for Kyty's fixed-refresh path.
	return OK;
}

LIB_DEFINE(InitVideoOutVrrStatus_1) {
	LIB_FUNC("kP2L8t3j-aM", VideoOutVrrStatus_kP2L8t3j_aM);
}

} // namespace LibGen5::VrrStatus

namespace AvSetting {

LIB_VERSION("AvSetting", 1, "AvSetting", 1, 1);
LIB_DEFINE(InitAvSettingCallbacks_1);

// sceAvSettingInit (EIZdWTT7Zdw): one-time init of the AV-settings (display/audio capability)
// service. The real fn returns 0 on success / already-initialised. Offline there is no AV hardware
// to probe; report success so SceSysCore's display setup proceeds.
static KYTY_SYSV_ABI int AvSettingInit() {
	PRINT_NAME();
	return OK;
}

LIB_DEFINE(InitAvSetting_1) {
	LIB_FUNC("EIZdWTT7Zdw", AvSettingInit); // sceAvSettingInit
	InitAvSettingCallbacks_1(s);
}

} // namespace AvSetting

} // namespace Libs
