#ifndef KYTY_LIBS_USER_SERVICE_H_
#define KYTY_LIBS_USER_SERVICE_H_

#include <string>

namespace Libs::UserService {
bool IsLoggedIn(int user_id);
// Deliver lifecycle notifications through the native PSM queue on a guest thread.
void PumpFrameworkEvents(bool (*post)(int, const std::string&) = nullptr);
}

#endif
