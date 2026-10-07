#ifndef KYTY_LIBS_LIB_APP_DB_SHIM_H_
#define KYTY_LIBS_LIB_APP_DB_SHIM_H_
#include <cstdint>
#include "common/abi.h"
namespace Libs::AppDbShellCoreClient {
struct PInvokeEntry { const char* name; uint64_t address; };
struct PInvokeLibrary { const char* name; const PInvokeEntry* functions; };
const PInvokeLibrary* AdaptManagedReadTable(const PInvokeLibrary* table);
int KYTY_SYSV_ABI RegisterManagedReadTable(const PInvokeLibrary* table);
// Adapt legacy AppDb P/Invokes for virtual discs; other titles keep the native reader.
uint64_t ResolveManagedReadShim(const char* symbol, uint64_t native);
}
#endif
