#pragma once
#include <cstdint>

namespace Libs::AvSetting {
// Called by output-mode arbitration when an application's requested mode
// cannot be supported. Polling alone never generates a suspension event.
void PublishUnsupportedOutputEvent(uint32_t process, uint32_t ticket, uint32_t reason);
}
