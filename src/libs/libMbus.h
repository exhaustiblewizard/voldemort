#ifndef KYTY_LIBS_MBUS_H_
#define KYTY_LIBS_MBUS_H_

#include <cstdint>

namespace Libs::Mbus {
// Called after the host controller registry changes, outside its mutex.
void ControllerConnectionChanged(uint64_t device_id, bool connected);
}

#endif
