#include "common/assert.h"
#include "common/common.h"
#include "common/logging/log.h"
#include "libs/libs.h"
#include "loader/symbolDatabase.h"

#include <cstdint>
#include <cstdlib>

// libSceNpCommon: the NP memory-heap family the JSCd daemon uses to back its IPMI/RifManager
// clients (EntitlementCSI init calls sceNpMemoryHeapInit + _sceNpHeapMalloc; a NULL malloc there
// left the RifManager uninitialised -> sceRifManagerRegisterGlobalEventCallback returned 0x80E90001
// -> guest abort()). We back these with the host heap; the guest's "heap" handle is opaque to us.

namespace Libs {
namespace NpCommon {

LIB_VERSION("NpCommon", 1, "NpCommon", 1, 1);

// sceNpMemoryHeapInit(heap, size, name) / ...variants: accept and report success.
static int KYTY_SYSV_ABI MemoryHeapInit(void* heap, uint64_t a, const char* name) {
	PRINT_NAME();
	(void)heap; (void)a;
	LOGF("\t name = %s\n", (name != nullptr) ? name : "(null)");
	return 0;
}
static int KYTY_SYSV_ABI MemoryHeapDestroy(void* heap) {
	PRINT_NAME();
	(void)heap;
	return 0;
}
// _sceNpHeapMalloc(heap, size): back with host malloc (never NULL for a 0-size request).
static void* KYTY_SYSV_ABI HeapMalloc(void* heap, size_t size) {
	(void)heap;
	return std::malloc(size != 0 ? size : 1);
}
static void KYTY_SYSV_ABI HeapFree(void* heap, void* ptr) {
	(void)heap;
	std::free(ptr);
}
static void* KYTY_SYSV_ABI HeapCalloc(void* heap, size_t n, size_t size) {
	(void)heap;
	return std::calloc(n != 0 ? n : 1, size != 0 ? size : 1);
}
static void* KYTY_SYSV_ABI HeapRealloc(void* heap, void* ptr, size_t size) {
	(void)heap;
	return std::realloc(ptr, size);
}
static int KYTY_SYSV_ABI HeapGetStat(void* heap, void* stat) {
	PRINT_NAME();
	(void)heap; (void)stat;
	return 0;
}

// sceNpUserGetUserIdList(SceUserServiceUserId* list /*rdi*/, int max /*esi*/, int* count /*rdx*/):
// reversed from JSCd RifManager init sub_801F0 — `if (sceNpUserGetUserIdList(v31,20,&v21) >= 0 &&
// v21 > 0)` then it enumerates each user's entitlements over the (faked) IPMI RifManager. Offline
// there are no NP-signed-in users, so report an empty list (count 0, success): the RifManager skips
// per-user entitlement enumeration cleanly instead of hitting the fake IPMI path. NID Gh74vNl06sg.
static int KYTY_SYSV_ABI UserGetUserIdList(int* list, int max, int* count) {
	PRINT_NAME();
	(void)list; (void)max;
	if (count != nullptr) {
		*count = 0;
	}
	return 0;
}

LIB_DEFINE(InitNpCommon_1) {
	LIB_FUNC("kZizwrFvWZY", NpCommon::MemoryHeapInit);    // sceNpMemoryHeapInit (PS5)
	LIB_FUNC("EZizwrFvWZY", NpCommon::MemoryHeapInit);    // sceNpMemoryHeapInit (PS4)
	LIB_FUNC("dfXSH2Tsjkw", NpCommon::MemoryHeapDestroy); // sceNpMemoryHeapDestroy (PS5)
	LIB_FUNC("NfXSH2Tsjkw", NpCommon::MemoryHeapDestroy); // sceNpMemoryHeapDestroy (PS4)
	LIB_FUNC("kwW5qddf+Lo", NpCommon::HeapMalloc);        // _sceNpHeapMalloc (PS5)
	LIB_FUNC("EwW5qddf+Lo", NpCommon::HeapMalloc);        // _sceNpHeapMalloc (PS4)
	LIB_FUNC("p1vvpKGRXe4", NpCommon::HeapFree);          // _sceNpHeapFree (PS5)
	LIB_FUNC("J1vvpKGRXe4", NpCommon::HeapFree);          // _sceNpHeapFree (PS4)
	LIB_FUNC("wsfyvM+VbUk", NpCommon::HeapRealloc);       // _sceNpHeapRealloc (PS5)
	LIB_FUNC("AsfyvM+VbUk", NpCommon::HeapRealloc);       // _sceNpHeapRealloc (PS4)
	LIB_FUNC("GjdHoPpS+W0", NpCommon::HeapGetStat);       // sceNpHeapGetStat (PS5)
	LIB_FUNC("2jdHoPpS+W0", NpCommon::HeapGetStat);       // sceNpHeapGetStat (PS4)
	LIB_FUNC("Gh74vNl06sg", NpCommon::UserGetUserIdList); // sceNpUserGetUserIdList
}

} // namespace NpCommon
} // namespace Libs
