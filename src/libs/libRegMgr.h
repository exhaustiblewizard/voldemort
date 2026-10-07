#pragma once

#include "common/abi.h"
#include <cstddef>
#include <cstdint>

namespace Libs::RegMgr {
int KYTY_SYSV_ABI GetStr(uint32_t reg_id, char* buf, size_t size);
}
