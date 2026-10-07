#include "libs/agc.h"
#include "libs/libs.h"
#include "libs/errno.h"
#include "graphics/guest_gpu/graphicsRun.h"
#include "graphics/presentation/videoOut.h"
#include "loader/symbolDatabase.h"
#include <array>
#include <cstring>

namespace Libs {
namespace Gnm {
LIB_VERSION("GnmDriver", 1, "GnmDriver", 1, 1);

// Fixed packet sizes and register offsets verified against the 4.03 GNM exports.
static void Pad(uint32_t* cmd, uint32_t used, uint32_t total) {
	std::memset(cmd + used, 0, (total - used) * sizeof(uint32_t));
	cmd[used] = 0xc0001000u | ((total - used - 2) << 16u);
}

int KYTY_SYSV_ABI SetPsShader(uint32_t* cmd, uint32_t size, const uint32_t* regs) {
	if (!cmd || size < 40 || (regs && regs[1] != 0)) { return -1; }
	if (!regs) { Pad(cmd, 0, 40); return 0; }
	const uint32_t packets[] = {
		0xc0027600, 0x8, regs[0], 0, 0xc0027600, 0xa, regs[2], regs[3],
		0xc0026900, 0x1c4, regs[4], regs[5], 0xc0026900, 0x1b3, regs[6], regs[6],
		0xc0016900, 0x1b6, regs[8], 0xc0016900, 0x1b8, regs[9],
		0xc0016900, 0x203, regs[10], 0xc0016900, 0x8f, regs[11]
	};
	std::memcpy(cmd, packets, sizeof(packets));
	Pad(cmd, 28, 40);
	return 0;
}

int KYTY_SYSV_ABI SetVsShader(uint32_t* cmd, uint32_t size, const uint32_t* regs, uint32_t modifier) {
	if (!cmd || size < 29 || !regs || regs[1] != 0 || (modifier & 0xfcfffc3f) != 0) { return -1; }
	const auto rsrc1 = modifier ? modifier | (regs[2] & 0xfcfffc3f) : regs[2];
	const uint32_t packets[] = {
		0xc0027600, 0x48, regs[0], 0, 0xc0027600, 0x4a, rsrc1, regs[3],
		0xc0016900, 0x207, regs[6], 0xc0016900, 0x1b1, regs[4],
		0xc0016900, 0x1c3, regs[5]
	};
	std::memcpy(cmd, packets, sizeof(packets));
	Pad(cmd, 17, 29);
	return 0;
}

int KYTY_SYSV_ABI SetCsShader(uint32_t* cmd, uint32_t size, const uint32_t* regs) {
	if (!cmd || size < 25 || !regs || regs[1] != 0) { return -1; }
	const uint32_t packets[] = {
		0xc0027602, 0x20c, regs[0], 0,
		0xc0027602, 0x212, regs[2], regs[3],
		0xc0037602, 0x207, regs[4], regs[5], regs[6]
	};
	std::memcpy(cmd, packets, sizeof(packets));
	Pad(cmd, 13, 25);
	LOGF("GNM compute shader: cmd=%p address=%08x threads=%u/%u/%u\n",
	     static_cast<void*>(cmd), regs[0], regs[4], regs[5], regs[6]);
	return 0;
}

int KYTY_SYSV_ABI InsertPushMarker(uint32_t* cmd, uint32_t size, const char* label) {
	if (!cmd || !label) { return -1; }
	const auto length = std::strlen(label);
	// The native GNM ABI reserves both the text and its aligned trace payload.
	const auto payload = ((length + 8) >> 2) + 2 * ((length + 12) >> 3);
	if (payload > 0x3fff || size != payload + 2) { return -1; }
	std::memset(cmd, 0, size * sizeof(uint32_t));
	cmd[0] = 0xc0001000u | (static_cast<uint32_t>(payload) << 16);
	cmd[1] = 0x68750001;
	std::memcpy(cmd + 2, label, length + 1);
	LOGF("GNM push marker: cmd=%p dwords=%u label=%s\n", static_cast<void*>(cmd), size, label);
	return 0;
}

int KYTY_SYSV_ABI InsertPopMarker(uint32_t* cmd, uint32_t size) {
	if (!cmd || size != 6) { return -1; }
	const uint32_t packet[] = {0xc0041000, 0x68750002, 0, 0, 0, 0};
	std::memcpy(cmd, packet, sizeof(packet));
	return 0;
}

uint32_t KYTY_SYSV_ABI DrawInit200(uint32_t* cmd, uint32_t size) {
	if (!cmd || size < 256) { return 0; }
	static constexpr uint32_t defaults[] = {
#include "libs/gnmDefaultState.inc"
	};
	std::memcpy(cmd, defaults, sizeof(defaults));
	cmd[128] = 0x200;
	cmd[129] = 0xe0000000;
	Pad(cmd, 130, 256);
	return 256;
}

int KYTY_SYSV_ABI InsertWaitFlipDone(uint32_t* cmd, uint32_t size, int handle, int index) {
	if (!cmd || size != 7 || index < 0) { return -1; }
	// Same wait operation as the native label packet, using the VideoOut queue directly.
	const uint32_t packet[] = {0xc0051018, static_cast<uint32_t>(handle), static_cast<uint32_t>(index), 0, 0, 0, 0};
	std::memcpy(cmd, packet, sizeof(packet));
	return 0;
}

static int Submit(uint32_t count, uint32_t* const* dcbs, const uint32_t* dcb_sizes,
                  uint32_t* const* ccbs, const uint32_t* ccb_sizes,
                  Graphics::CommandProcessor::FlipInfo flip) {
	PRINT_NAME();
	if (!count || !dcbs || !dcb_sizes || (ccbs && !ccb_sizes)) { return LibKernel::KERNEL_ERROR_EINVAL; }
	for (uint32_t i = 0; i < count; ++i) {
		if (!dcbs[i] || !dcb_sizes[i] || dcb_sizes[i] % 4 || (ccbs && ccb_sizes[i] % 4)) { return LibKernel::KERNEL_ERROR_EINVAL; }
	}
	for (uint32_t i = 0; i < count; ++i) {
		LOGF("GNM submit dcb=%p bytes=%u ccb-bytes=%u\n", static_cast<void*>(dcbs[i]), dcb_sizes[i], ccbs ? ccb_sizes[i] : 0);
		Graphics::GraphicsDbgDumpDcb("gnm", dcb_sizes[i] / 4, dcbs[i]);
		Graphics::GetGuestGpu().Submit({dcbs[i], dcb_sizes[i] / 4},
		                             ccbs ? std::span<const uint32_t>{ccbs[i], ccb_sizes[i] / 4} : std::span<const uint32_t>{},
		                             0x40, true, i == count - 1 ? flip : Graphics::CommandProcessor::FlipInfo{});
	}
	return 0;
}

int KYTY_SYSV_ABI SubmitCommandBuffers(uint32_t count, uint32_t* const* dcbs, const uint32_t* dcb_sizes,
                                      uint32_t* const* ccbs, const uint32_t* ccb_sizes) {
	return Submit(count, dcbs, dcb_sizes, ccbs, ccb_sizes, {});
}

int KYTY_SYSV_ABI SubmitAndFlip(uint32_t count, uint32_t* const* dcbs, const uint32_t* dcb_sizes,
                               uint32_t* const* ccbs, const uint32_t* ccb_sizes,
                               int handle, int index, int mode, int64_t arg) {
	return Submit(count, dcbs, dcb_sizes, ccbs, ccb_sizes, {handle, index, mode, arg});
}

int KYTY_SYSV_ABI SubmitDone() { Graphics::GetGuestGpu().Done(); return 0; }
int KYTY_SYSV_ABI AreSubmitsAllowed() { return 1; }
int KYTY_SYSV_ABI IsUserPaEnabled() { return 0; }
uint64_t KYTY_SYSV_ABI TessellationRing() { return 0xff0000000ull; }

LIB_DEFINE(InitGnmDriver_1) {
	PRINT_NAME_ENABLE(true);
	LIB_FUNC("0H2vBYbTLHI", DrawInit200);
	LIB_FUNC("gAhCn6UiU4Y", SetVsShader);
	LIB_FUNC("bQVd5YzCal0", SetPsShader);
	LIB_FUNC("KXltnCwEJHQ", SetCsShader);
	LIB_FUNC("W1Etj-jlW7Y", InsertPushMarker);
	LIB_FUNC("7qZVNgEu+SY", InsertPopMarker);
	LIB_FUNC("1qXLHIpROPE", InsertWaitFlipDone);
	LIB_FUNC("xbxNatawohc", SubmitAndFlip);
	LIB_FUNC("yvZ73uQUqrk", SubmitDone);
	LIB_FUNC("jg33rEKLfVs", IsUserPaEnabled);
	LIB_FUNC("ln33zjBrfjk", TessellationRing);
	LIB_FUNC("b0xyllnVY-I", Graphics::Gen5Driver::AgcDriverAddEqEvent);
}
} // namespace Gnm
LIB_DEFINE(InitGnmDriver_1) { Gnm::InitGnmDriver_1(s); }
} // namespace Libs
