#include "common/assert.h"
#include "common/common.h"
#include "common/logging/log.h"
#include "libs/libs.h"
#include "libs/kitProfile.h"
#include "libs/libRegMgr.h"
#include "libs/localNetwork.h"
#include "loader/symbolDatabase.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <vector>

// Minimal HLE for the system-configuration and PSN/online-service modules the ShellUI JSCd
// daemon pulls in. The emulator runs forced-offline, so online-service init succeeds while
// queries report no data.

namespace Libs {

// ---- RegMgr (system registry) ----
namespace RegMgr {

LIB_VERSION("RegMgr", 1, "RegMgr", 1, 1);

// In-memory system registry. On real hardware every sceRegMgrGet*/Set* forwards to the kernel
// via __sys_regmgr_call(cmd, reg_id, &result, data, size) and the actual key/value store lives
// in the kernel registry service (persisted to disk). Verified in IDA (libSceRegMgr.sprx): the
// command byte selects the operation — 1=SetInt, 2=GetInt, 3=SetStr, 4=GetStr, 5=SetBin,
// 6=GetBin, 11=ResetVal — reg_id is the entry key, and each call returns the per-call result
// code (0 = success).
//
// SceShellCore writes ~1600 registry entries during boot (SetStr x962, SetBin x674) and reads
// some of them back to drive its own configuration. A no-op that always returned "empty" would
// desync those read-after-write pairs, so we keep a real process-local store keyed by reg_id:
// Set records the bytes, Get returns exactly what was last written (or a zero/empty default for
// an unwritten key, matching a factory-fresh registry). This is process-local only — offline
// there is no cross-process kernel registry to share it with, which is fine for the ShellUI.
namespace {
std::mutex                                          g_reg_mutex;
std::unordered_map<uint32_t, std::vector<uint8_t>>  g_reg;
std::unordered_map<uint32_t, uint8_t> g_changed;

int DefaultInt(uint32_t id) {
	// NetworkModule accepts current-profile numbers 1..10. The local
	// backend supplies a virtual access point in the first profile slot.
	if (id == 0x14190b00u && LocalNetwork::Enabled()) { return 1; }
	// FW7 SceShellCore sub_8A7080 reads the requested user-list snapshot
	// index. Nonnegative values request restoration; sub_8A70C0 resets
	// this key after consuming the request. An unset request is -1.
	return id == 0x07410000u ? -1 : 0;
}

void Store(uint32_t id, std::vector<uint8_t> bytes) {
	auto it = g_reg.find(id);
	if (it == g_reg.end() || it->second != bytes) {
		g_changed[id] = 0xff;
		g_reg[id] = std::move(bytes);
	}
}
} // namespace

// FW7 kernel sub_E932E0: the second argument identifies a consumer, not a
// version or a value. Its low byte selects dirty bits; a successful query
// consumes only that consumer's bits, leaving other consumers notified.
static int KYTY_SYSV_ABI IsChange(uint32_t reg_id, uint32_t consumer) {
	const uint32_t index = consumer - 0x0d010001u;
	if (!(index < 32 && ((0x8000808bu >> index) & 1u)) && consumer != 0x0d890080u) {
		return 0;
	}
	std::lock_guard lock(g_reg_mutex);
	auto it = g_changed.find(reg_id);
	if (it == g_changed.end()) {
		return 0;
	}
	const auto mask = static_cast<uint8_t>(consumer);
	const bool changed = (it->second & mask) != 0;
	it->second &= static_cast<uint8_t>(~mask);
	return changed ? 1 : 0;
}

static int KYTY_SYSV_ABI GetInt(uint32_t reg_id, int* value) {
	PRINT_NAME();
	LOGF("\t reg_id = 0x%08" PRIx32 "\n", reg_id);
	if (value != nullptr) {
		*value = DefaultInt(reg_id);
		std::lock_guard<std::mutex> lock(g_reg_mutex);
		auto it = g_reg.find(reg_id);
		if (it != g_reg.end() && it->second.size() >= sizeof(int)) {
			std::memcpy(value, it->second.data(), sizeof(int));
		}
	}
	return 0;
}

int KYTY_SYSV_ABI GetStr(uint32_t reg_id, char* buf, size_t size) {
	PRINT_NAME();
	LOGF("\t reg_id = 0x%08" PRIx32 ", size = %zu\n", reg_id, size);
	if (buf != nullptr && size != 0) {
		buf[0] = '\0';
		if (reg_id == 2013331712u) {
			const auto count = std::min(sizeof(KitProfile::SystemName) - 1, size - 1);
			std::memcpy(buf, KitProfile::SystemName, count);
			buf[count] = '\0';
			return 0;
		}
		std::lock_guard<std::mutex> lock(g_reg_mutex);
		auto it = g_reg.find(reg_id);
		if (it != g_reg.end() && !it->second.empty()) {
			const size_t n = std::min(it->second.size(), size);
			std::memcpy(buf, it->second.data(), n);
			buf[(n < size) ? n : size - 1] = '\0'; // always NUL-terminate within the buffer
		}
	}
	return 0;
}

static int KYTY_SYSV_ABI GetBin(uint32_t reg_id, void* buf, size_t size) {
	PRINT_NAME();
	LOGF("\t reg_id = 0x%08" PRIx32 ", size = %zu\n", reg_id, size);
	if (buf != nullptr && size != 0) {
		std::memset(buf, 0, size);
		std::lock_guard<std::mutex> lock(g_reg_mutex);
		auto it = g_reg.find(reg_id);
		if (it != g_reg.end() && !it->second.empty()) {
			std::memcpy(buf, it->second.data(), std::min(it->second.size(), size));
		}
	}
	return 0;
}

// *InitVal variants return the registry entry's factory/default value. SceShellCore calls these
// heavily during boot. Signatures verified in IDA (SceShellCore sub_8A0EB0): GetIntInitVal(reg_id
// /*edi*/, int* out /*rsi*/, ...); GetStrInitVal(reg_id /*edi*/, char* buf /*rsi*/, size /*edx*/).
// Same shape as GetInt/GetStr/GetBin — report "use default" with a zero/empty value, success.
static int KYTY_SYSV_ABI GetIntInitVal(uint32_t reg_id, int* value, uint32_t a3) {
	PRINT_NAME();
	LOGF("\t reg_id = 0x%08" PRIx32 "\n", reg_id);
	(void)a3;
	if (value != nullptr) {
		*value = DefaultInt(reg_id);
	}
	return 0;
}
static int KYTY_SYSV_ABI GetStrInitVal(uint32_t reg_id, char* buf, size_t size, uint32_t a4) {
	PRINT_NAME();
	LOGF("\t reg_id = 0x%08" PRIx32 ", size = %zu\n", reg_id, size);
	(void)a4;
	if (buf != nullptr && size != 0) {
		buf[0] = '\0';
	}
	return 0;
}
static int KYTY_SYSV_ABI GetBinInitVal(uint32_t reg_id, void* buf, size_t size, uint32_t a4) {
	PRINT_NAME();
	LOGF("\t reg_id = 0x%08" PRIx32 ", size = %zu\n", reg_id, size);
	(void)a4;
	if (buf != nullptr && size != 0) {
		std::memset(buf, 0, size);
	}
	return 0;
}

// sceRegMgrSetInt(reg_id, value): record the value so a later GetInt returns it.
static int KYTY_SYSV_ABI SetInt(uint32_t reg_id, int value) {
	PRINT_NAME();
	LOGF("\t reg_id = 0x%08" PRIx32 ", value = %d\n", reg_id, value);
	std::lock_guard<std::mutex> lock(g_reg_mutex);
	std::vector<uint8_t> v(sizeof(int));
	std::memcpy(v.data(), &value, sizeof(int));
	Store(reg_id, std::move(v));
	return 0;
}

// sceRegMgrSetStr(reg_id, str, size): record `size` bytes of the string. Verified in IDA:
// __sys_regmgr_call(cmd=3, reg_id, &result, str, size) — `size` is the caller-supplied buffer
// length, stored verbatim (a later GetStr copies it back, NUL-terminated within the reader's
// buffer). NID ffInidSqRss.
static int KYTY_SYSV_ABI SetStr(uint32_t reg_id, const char* str, size_t size) {
	PRINT_NAME();
	LOGF("\t reg_id = 0x%08" PRIx32 ", size = %zu, str = %.64s\n", reg_id, size,
	     (str != nullptr) ? str : "(null)");
	std::lock_guard<std::mutex> lock(g_reg_mutex);
	std::vector<uint8_t> v;
	if (str != nullptr && size != 0) {
		v.assign(reinterpret_cast<const uint8_t*>(str), reinterpret_cast<const uint8_t*>(str) + size);
	} else {
		v.clear();
	}
	Store(reg_id, std::move(v));
	return 0;
}

// sceRegMgrSetBin(reg_id, buf, size): record `size` raw bytes. Verified in IDA:
// __sys_regmgr_call(cmd=5, reg_id, &result, buf, size). NID eXxrXkrLXa4.
static int KYTY_SYSV_ABI SetBin(uint32_t reg_id, const void* buf, size_t size) {
	PRINT_NAME();
	LOGF("\t reg_id = 0x%08" PRIx32 ", size = %zu\n", reg_id, size);
	std::lock_guard<std::mutex> lock(g_reg_mutex);
	std::vector<uint8_t> v;
	if (buf != nullptr && size != 0) {
		v.assign(reinterpret_cast<const uint8_t*>(buf), reinterpret_cast<const uint8_t*>(buf) + size);
	} else {
		v.clear();
	}
	Store(reg_id, std::move(v));
	return 0;
}

// sceRegMgrGetVersion(): registry format version. Verified in IDA: __sys_regmgr_call(cmd=0,
// arg=1, &result, 0, 0). The one SceShellCore caller (sub_550860, in NetCtl init) discards the
// result, so any success value is fine; report 0. NID q+lPgqZniW4.
static int KYTY_SYSV_ABI GetVersion() {
	PRINT_NAME();
	return 0;
}

// sceRegMgrResetVal(reg_id, a2): reset an entry to its factory default. Verified in IDA:
// __sys_regmgr_call(cmd=11, reg_id, &result, &a2, 0). Drop the process-local override so a later
// Get falls back to the zero/empty default. NID eL7sMZaIdac.
static int KYTY_SYSV_ABI ResetVal(uint32_t reg_id, int a2) {
	PRINT_NAME();
	LOGF("\t reg_id = 0x%08" PRIx32 ", a2 = %d\n", reg_id, a2);
	(void)a2;
	std::lock_guard<std::mutex> lock(g_reg_mutex);
	if (g_reg.erase(reg_id) != 0) {
		g_changed[reg_id] = 0xff;
	}
	return 0;
}

// sceRegMgrSrvGetRegion(): console region code. Verified in IDA: __sys_regmgr_call(cmd=18,...)
// returns the region reg value; SceShellCore's app_content.cpp treats any non-negative value as a
// valid region (only < 0 is an error). Report region 0 (a valid, unrestricted default). NID
// sywg-RnhZMA.
static int KYTY_SYSV_ABI SrvGetRegion() {
	PRINT_NAME();
	return 0;
}

// sceRegMgrSrvGetQAFforReg(): QA-flag (quality-assurance/debug feature gate) for the region.
// Report 0 (no special QA bits) — a retail-like default. NID wQlp94zzrWg.
static int KYTY_SYSV_ABI SrvGetQAFforReg() {
	PRINT_NAME();
	return 0;
}

LIB_DEFINE(InitRegMgr_1) {
	LIB_FUNC("xhrI4zhlBuA", RegMgr::IsChange);
	LIB_FUNC("mPYKD12UDQI", RegMgr::GetInt);        // sceRegMgrGetInt
	LIB_FUNC("CTplLrrndUg", RegMgr::GetStr);        // sceRegMgrGetStr
	LIB_FUNC("NqxMleeTiLs", RegMgr::GetBin);        // sceRegMgrGetBin
	LIB_FUNC("i64ig3BF6f8", RegMgr::GetIntInitVal); // sceRegMgrGetIntInitVal
	LIB_FUNC("jqyhb1oMgHw", RegMgr::GetStrInitVal); // sceRegMgrGetStrInitVal
	LIB_FUNC("dhuH8HjNhUY", RegMgr::GetBinInitVal); // sceRegMgrGetBinInitVal
	LIB_FUNC("khaYelw1Ytc", RegMgr::SetInt);        // sceRegMgrSetInt
	LIB_FUNC("ffInidSqRss", RegMgr::SetStr);        // sceRegMgrSetStr
	LIB_FUNC("eXxrXkrLXa4", RegMgr::SetBin);        // sceRegMgrSetBin
	LIB_FUNC("q+lPgqZniW4", RegMgr::GetVersion);    // sceRegMgrGetVersion
	LIB_FUNC("eL7sMZaIdac", RegMgr::ResetVal);      // sceRegMgrResetVal
	LIB_FUNC("sywg-RnhZMA", RegMgr::SrvGetRegion);  // sceRegMgrSrvGetRegion
	LIB_FUNC("wQlp94zzrWg", RegMgr::SrvGetQAFforReg); // sceRegMgrSrvGetQAFforReg
}

} // namespace RegMgr

} // namespace Libs
