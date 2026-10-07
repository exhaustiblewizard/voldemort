#ifndef EMULATOR_INCLUDE_EMULATOR_LOADER_SYSTEMCONTENT_H_
#define EMULATOR_INCLUDE_EMULATOR_LOADER_SYSTEMCONTENT_H_

#include "common/abi.h"
#include "common/common.h"
#include "common/stringUtils.h"

#include <cstdint>
#include <filesystem>
#include <map>
#include <variant>

namespace Loader {

using SfoFields = std::map<std::string, std::variant<std::string, int32_t>>;
// Read PS4 binary PSF metadata without modifying the source dump.
SfoFields ReadParamSfo(const std::filesystem::path& file_name);
std::filesystem::path FindApplicationMetadata(const std::filesystem::path& folder);

void     SystemContentLoadForProgram(int32_t program_id, const std::filesystem::path& file_name);
void     SystemContentLoadParamSfo(const std::filesystem::path& file_name);
bool     SystemContentParamSfoGetInt(const char* name, int32_t* value);
bool     SystemContentParamSfoGetString(const char* name, std::string* value);
bool     SystemContentParamSfoGetString(const char* name, char* value, size_t value_size);
uint64_t SystemContentGetFlexibleMemorySize();
bool     SystemContentGetProgramAuthorityId(uint64_t* value);
bool     SystemContentGetProcessAuthorityId(int32_t pid, uint64_t* value);
bool     SystemContentGetProcessCategory(int32_t pid, uint32_t* value);
bool     SystemContentGetIconPath(std::filesystem::path* path);
bool     SystemContentGetChunksNum(uint32_t* num);

} // namespace Loader

#endif /* EMULATOR_INCLUDE_EMULATOR_LOADER_SYSTEMCONTENT_H_ */
