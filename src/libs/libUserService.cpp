#include "common/abi.h"
#include "common/assert.h"
#include "common/emulatorConfig.h"
#include "common/stringUtils.h"
#include "libs/libUserService.h"
#include "libs/virtualDisc.h"
#include "libs/errno.h"
#include "libs/libs.h"
#include "loader/symbolDatabase.h"

#include <cstdio>
#include <cstring>
#include <atomic>
#include <algorithm>
#include <deque>
#include <map>
#include <mutex>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#undef GetUserName
#endif

namespace Libs {

LIB_VERSION("UserService", 1, "UserService", 1, 1);

namespace UserService {

static std::atomic<int> g_foreground_user {-1};

struct UserServiceLoginUserIdList {
	int user_id[4];
};

enum UserServiceEventType { UserServiceEventTypeLogin, UserServiceEventTypeLogout };

struct SceUserServiceEvent {
	UserServiceEventType event_type;
	int                  user_id;
};

struct UserRecord {
	std::string name;
	uint32_t status = 0;
	uint32_t login_flags = 0;
	int type = 0;
	bool logged_in = false;
	bool shown_eula = false;
	std::string passcode;
};
static std::mutex g_users_mutex;
static std::map<int, UserRecord> g_users;
static std::deque<SceUserServiceEvent> g_user_events;
static std::deque<std::pair<int, std::string>> g_framework_events;
static std::mutex g_framework_dispatch_mutex;

// Lx.UserService keeps its own cached lists. Native polling events do not update
// them: it listens to PSM 40/41 (login/logout) and 42/43 (create/destroy), each
// carrying a lower-case userId. Keep this queue independent of sceUserServiceGetEvent.
static void QueueFrameworkEventLocked(int event_id, int user_id) {
	g_framework_events.emplace_back(event_id, "{\"userId\":" + std::to_string(user_id) + "}");
}

void PumpFrameworkEvents(bool (*post)(int, const std::string&)) {
	Common::HostCriticalScope critical;
	std::unique_lock dispatch(g_framework_dispatch_mutex, std::try_to_lock);
	if (!dispatch.owns_lock()) { return; }
	for (;;) {
		std::pair<int, std::string> event;
		{
			std::lock_guard lock(g_users_mutex);
			if (g_framework_events.empty()) { return; }
			event = g_framework_events.front();
		}
		// Native Post copies into its queue; managed callbacks run during the
		// firmware's update, outside the service lock. Retry until PSM is ready.
		if (!(post ? post : LibJson2::PostFrameworkEvent)(event.first, event.second)) { return; }
		std::lock_guard lock(g_users_mutex);
		g_framework_events.pop_front();
	}
}
static uint32_t g_next_user_number = 1;
static std::filesystem::path g_user_store;
static bool g_user_store_readable = true;

// Login sessions and foreground ownership are transient. Only real local
// profiles (the managed PersistentUser / PersistentUserbyUIOperation types)
// survive restart; guests and remote-play users remain session-local.
static bool SaveUsersLocked() {
	if (g_user_store.empty()) { return true; }
	if (!g_user_store_readable) { return false; }
	try {
		nlohmann::json records = nlohmann::json::array();
		for (const auto& [id, user]: g_users) {
			if (user.type > 1) { continue; }
			records.push_back({{"id", id}, {"name", user.name}, {"type", user.type},
			                  {"status", user.status}, {"login_flags", user.login_flags},
			                  {"shown_eula", user.shown_eula}, {"passcode", user.passcode}});
		}
		const nlohmann::json data {{"version", 1}, {"next_user_number", g_next_user_number},
		                           {"users", std::move(records)}};
		std::error_code error;
		std::filesystem::create_directories(g_user_store.parent_path(), error);
		if (error) { return false; }
		auto temporary = g_user_store;
		temporary += ".tmp";
		std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
		stream << data.dump(2) << '\n';
		stream.flush();
		if (!stream) { return false; }
		stream.close();
		if (!stream) { return false; }
#if defined(_WIN32)
		if (!MoveFileExW(temporary.c_str(), g_user_store.c_str(),
		                 MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) { return false; }
#else
		std::filesystem::rename(temporary, g_user_store, error);
		if (error) { return false; }
#endif
		return true;
	} catch (const std::exception& error) {
		LOGF("UserService: could not save local profiles: %s\n", error.what());
		return false;
	}
}

static bool LoadUsersLocked() {
	try {
		std::error_code error;
		if (!std::filesystem::exists(g_user_store, error)) { return !error; }
		std::ifstream stream(g_user_store, std::ios::binary);
		if (!stream) { return false; }
		const auto data = nlohmann::json::parse(stream);
		if (data.at("version") != 1 || !data.at("users").is_array() ||
		    data.at("users").size() > 16) { return false; }
		std::map<int, UserRecord> users;
		uint32_t next = data.at("next_user_number").get<uint32_t>();
		if (next == 0 || next > 0x0fffffffu) { return false; }
		for (const auto& record: data.at("users")) {
			const int id = record.at("id").get<int>();
			UserRecord user {record.at("name").get<std::string>(),
			                 record.at("status").get<uint32_t>(),
			                 record.at("login_flags").get<uint32_t>(),
			                 record.at("type").get<int>(), false,
			                 record.at("shown_eula").get<bool>()};
			user.passcode = record.value("passcode", std::string {});
			if (id <= 0x10000000 || id >= 0x20000000 || user.name.empty() ||
			    user.name.size() > 64 || user.passcode.size() >= 16 ||
			    user.passcode.find('\0') != std::string::npos || user.type < 0 || user.type > 1 ||
			    !users.emplace(id, std::move(user)).second) { return false; }
			next = std::max(next, (static_cast<uint32_t>(id) & 0x0fffffffu) + 1);
		}
		g_users = std::move(users);
		g_next_user_number = next;
		return true;
	} catch (const std::exception& error) {
		LOGF("UserService: could not load local profiles: %s\n", error.what());
		return false;
	}
}

bool IsLoggedIn(int user_id) {
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_users_mutex);
	auto user = g_users.find(user_id);
	return user != g_users.end() && user->second.logged_in;
}

static bool HasUser(int user_id) {
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_users_mutex);
	return g_users.contains(user_id);
}

static KYTY_SYSV_ABI int UserServiceGetRegisteredUserIdList(int* user_ids) {
	if (!user_ids) { return USER_SERVICE_ERROR_INVALID_ARGUMENT; }
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_users_mutex);
	std::fill_n(user_ids, 16, -1);
	size_t index = 0;
	for (const auto& [id, user]: g_users) { user_ids[index++] = id; }
	return OK;
}

static KYTY_SYSV_ABI int UserServiceGetUserStatus(int user_id, uint32_t* status) {
	if (!status) { return USER_SERVICE_ERROR_INVALID_ARGUMENT; }
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_users_mutex);
	auto user = g_users.find(user_id);
	if (user == g_users.end()) { return USER_SERVICE_ERROR_NOT_LOGGED_IN; }
	*status = user->second.status;
	return OK;
}

static KYTY_SYSV_ABI int UserServiceGetLoginFlag(int user_id, uint32_t* flags) {
	if (!flags) { return USER_SERVICE_ERROR_INVALID_ARGUMENT; }
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_users_mutex);
	auto user = g_users.find(user_id);
	if (user == g_users.end()) { return USER_SERVICE_ERROR_NOT_LOGGED_IN; }
	*flags = user->second.login_flags;
	return OK;
}

static KYTY_SYSV_ABI int UserServiceSetUserName(int user_id, const char* name) {
	if (!name || !*name || std::strlen(name) > 64) { return USER_SERVICE_ERROR_INVALID_ARGUMENT; }
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_users_mutex);
	auto user = g_users.find(user_id);
	if (user == g_users.end()) { return USER_SERVICE_ERROR_NOT_LOGGED_IN; }
	auto old_name = user->second.name;
	user->second.name = name;
	if (!SaveUsersLocked()) {
		user->second.name = std::move(old_name);
		return USER_SERVICE_ERROR_INTERNAL;
	}
	return OK;
}

// ShellUI's native _GetPasscode allocates an uninitialized 16-byte buffer.
// Success must write a terminated string, including for a profile without a
// passcode; leaving it untouched makes IsLoginPasscodeSet see heap garbage.
static KYTY_SYSV_ABI int UserServiceGetPasscode(int user_id, char* buffer, size_t size) {
	if (!buffer || !size) { return USER_SERVICE_ERROR_INVALID_ARGUMENT; }
	buffer[0] = '\0';
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_users_mutex);
	auto user = g_users.find(user_id);
	if (user == g_users.end()) { return USER_SERVICE_ERROR_NOT_LOGGED_IN; }
	if (size <= user->second.passcode.size()) { return USER_SERVICE_ERROR_BUFFER_TOO_SHORT; }
	std::memcpy(buffer, user->second.passcode.c_str(), user->second.passcode.size() + 1);
	return OK;
}

static KYTY_SYSV_ABI int UserServiceSetPasscode(int user_id, const char* passcode) {
	if (!passcode || std::strlen(passcode) >= 16) { return USER_SERVICE_ERROR_INVALID_ARGUMENT; }
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_users_mutex);
	auto user = g_users.find(user_id);
	if (user == g_users.end()) { return USER_SERVICE_ERROR_NOT_LOGGED_IN; }
	auto previous = user->second.passcode;
	user->second.passcode = passcode;
	if (!SaveUsersLocked()) {
		user->second.passcode = std::move(previous);
		return USER_SERVICE_ERROR_INTERNAL;
	}
	return OK;
}

struct UserServiceGamePresets {
	size_t   this_size;
	uint32_t difficulty;
	uint32_t priority;
	uint32_t invert_vertical_view_for_1st_person_view;
	uint32_t invert_horizontal_view_for_1st_person_view;
	uint32_t invert_vertical_view_for_3rd_person_view;
	uint32_t invert_horizontal_view_for_3rd_person_view;
	uint32_t display_sub_titles;
	uint32_t audio_language;
};

static_assert(sizeof(UserServiceGamePresets) == 40);

static KYTY_SYSV_ABI int UserServiceInitialize(const void* /*params*/) {
	PRINT_NAME();

	return OK;
}

static KYTY_SYSV_ABI int UserServiceInitialize2() {
	PRINT_NAME();

	return OK;
}

static KYTY_SYSV_ABI int UserServiceGetInitialUser(int* user_id) {
	PRINT_NAME();

	if (!user_id) { return USER_SERVICE_ERROR_INVALID_ARGUMENT; }
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_users_mutex);
	*user_id = -1;
	for (const auto& [id, user]: g_users) {
		if (user.logged_in) { *user_id = id; return OK; }
	}
	return USER_SERVICE_ERROR_NOT_LOGGED_IN;
}

// Foreground selection is independent of the configured/logged-in user.
// Initial setup can receive input from unassigned devices before selecting a user.
static KYTY_SYSV_ABI int UserServiceGetForegroundUser(int* user_id) {
	PRINT_NAME();

	if (user_id == nullptr) { return USER_SERVICE_ERROR_INVALID_ARGUMENT; }

	*user_id = g_foreground_user.load(std::memory_order_relaxed);

	return OK;
}

static KYTY_SYSV_ABI int UserServiceSetForegroundUser(int user_id) {
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_users_mutex);
	if (user_id != -1 && (!g_users.contains(user_id) || !g_users.at(user_id).logged_in)) {
		return USER_SERVICE_ERROR_NOT_LOGGED_IN;
	}
	g_foreground_user.store(user_id, std::memory_order_relaxed);
	LOGF("UserService foreground user: 0x%x\n", user_id);
	return OK;
}

static KYTY_SYSV_ABI int UserServiceGetEvent(SceUserServiceEvent* event) {
	PRINT_NAME();

	if (!event) { return USER_SERVICE_ERROR_INVALID_ARGUMENT; }
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_users_mutex);
	if (g_user_events.empty()) { return USER_SERVICE_ERROR_NO_EVENT; }
	*event = g_user_events.front();
	g_user_events.pop_front();
	return OK;
}

static KYTY_SYSV_ABI int UserServiceGetLoginUserIdList(UserServiceLoginUserIdList* user_id_list) {
	PRINT_NAME();

	if (!user_id_list) { return USER_SERVICE_ERROR_INVALID_ARGUMENT; }
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_users_mutex);
	std::fill_n(user_id_list->user_id, 4, -1);
	size_t index = 0;
	for (const auto& [id, user]: g_users) {
		if (user.logged_in && index < 4) { user_id_list->user_id[index++] = id; }
	}

	return OK;
}

// The original API synchronously waits for its login/logout job. Offline the
// operation completes locally, but the user list and event queue still change.
static KYTY_SYSV_ABI bool UserServiceIsLoggedIn(int user_id) {
	return IsLoggedIn(user_id);
}

static KYTY_SYSV_ABI int UserServiceLogin(int user_id, uint64_t /*options*/) {
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_users_mutex);
	auto user = g_users.find(user_id);
	if (user == g_users.end()) { return USER_SERVICE_ERROR_NOT_LOGGED_IN; }
	if (user->second.logged_in) { return OK; }
	if (std::count_if(g_users.begin(), g_users.end(), [](const auto& item) {
		return item.second.logged_in;
	}) >= 4) { return USER_SERVICE_ERROR_NO_MEMORY; }
	user->second.logged_in = true;
	g_user_events.push_back({UserServiceEventTypeLogin, user_id});
	QueueFrameworkEventLocked(40, user_id);
	LOGF("UserService login: id=0x%x\n", user_id);
	return OK;
}

static KYTY_SYSV_ABI int UserServiceLogout(int user_id, uint32_t /*options*/) {
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_users_mutex);
	auto user = g_users.find(user_id);
	if (user == g_users.end() || !user->second.logged_in) { return USER_SERVICE_ERROR_NOT_LOGGED_IN; }
	user->second.logged_in = false;
	g_user_events.push_back({UserServiceEventTypeLogout, user_id});
	QueueFrameworkEventLocked(41, user_id);
	if (g_foreground_user.load() == user_id) { g_foreground_user.store(-1); }
	LOGF("UserService logout: id=0x%x\n", user_id);
	return OK;
}

static KYTY_SYSV_ABI int UserServiceGetUserName(int user_id, char* name, size_t size) {
	if (!name || size == 0) { return USER_SERVICE_ERROR_INVALID_ARGUMENT; }
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_users_mutex);
	auto user = g_users.find(user_id);
	if (user == g_users.end()) {
		return USER_SERVICE_ERROR_NOT_LOGGED_IN;
	}
	const auto& user_name = user->second.name;
	if (size <= user_name.size()) { return USER_SERVICE_ERROR_BUFFER_TOO_SHORT; }
	std::memcpy(name, user_name.c_str(), user_name.size() + 1);

	return OK;
}

static KYTY_SYSV_ABI int UserServiceGetUserNumber(int user_id, int32_t* number) {
	PRINT_NAME();

	if (number == nullptr) {
		return USER_SERVICE_ERROR_INVALID_ARGUMENT;
	}
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_users_mutex);
	int index = 0;
	for (const auto& [id, user]: g_users) {
		if (user.logged_in) {
			++index;
			if (id == user_id) { *number = index; return OK; }
		}
	}
	return USER_SERVICE_ERROR_NOT_LOGGED_IN;
}

static KYTY_SYSV_ABI int UserServiceGetGamePresets(int user_id, UserServiceGamePresets* presets) {
	PRINT_NAME();

	if (presets == nullptr) {
		return USER_SERVICE_ERROR_INVALID_ARGUMENT;
	}
	if (!HasUser(user_id)) {
		return USER_SERVICE_ERROR_NOT_LOGGED_IN;
	}

	auto this_size = presets->this_size;
	if (this_size == 0 || this_size > sizeof(UserServiceGamePresets)) {
		this_size = sizeof(UserServiceGamePresets);
	}

	std::memset(presets, 0, this_size);
	presets->this_size = sizeof(UserServiceGamePresets);

	return OK;
}

static KYTY_SYSV_ABI int UserServiceGetAccessibilityVibration(int user_id, int32_t* vibration) {
	PRINT_NAME();

	if (vibration == nullptr) {
		return USER_SERVICE_ERROR_INVALID_ARGUMENT;
	}
	if (!HasUser(user_id)) {
		return USER_SERVICE_ERROR_NOT_LOGGED_IN;
	}

	*vibration = 1;

	return OK;
}

static KYTY_SYSV_ABI int UserServiceGetAccessibilityTriggerEffect(int      user_id,
                                                                  int32_t* trigger_effect) {
	PRINT_NAME();

	if (trigger_effect == nullptr) {
		return USER_SERVICE_ERROR_INVALID_ARGUMENT;
	}
	if (!HasUser(user_id)) {
		return USER_SERVICE_ERROR_NOT_LOGGED_IN;
	}

	*trigger_effect = 1;

	return OK;
}

static KYTY_SYSV_ABI int UserServiceGetAgeLevel(int user_id, uint32_t* age_level) {
	PRINT_NAME();

	if (age_level == nullptr) {
		return USER_SERVICE_ERROR_INVALID_ARGUMENT;
	}
	if (!HasUser(user_id)) {
		return USER_SERVICE_ERROR_NOT_LOGGED_IN;
	}

	*age_level = 9;

	return OK;
}

static KYTY_SYSV_ABI int UserServiceGetAccessibilityChatTranscription(int      user_id,
                                                                      int32_t* chat_transcription) {
	PRINT_NAME();

	if (chat_transcription == nullptr) {
		return USER_SERVICE_ERROR_INVALID_ARGUMENT;
	}
	if (!HasUser(user_id)) {
		return USER_SERVICE_ERROR_NOT_LOGGED_IN;
	}

	*chat_transcription = 0;

	return OK;
}

static KYTY_SYSV_ABI int
UserServiceGetAccessibilityPressAndHoldDelay(int user_id, int32_t* press_and_hold_delay) {
	PRINT_NAME();

	if (press_and_hold_delay == nullptr) {
		return USER_SERVICE_ERROR_INVALID_ARGUMENT;
	}
	if (!HasUser(user_id)) {
		return USER_SERVICE_ERROR_NOT_LOGGED_IN;
	}

	*press_and_hold_delay = 0;

	return OK;
}

static KYTY_SYSV_ABI int UserServiceGetAccessibilityZoomEnabled(int      user_id,
                                                                int32_t* zoom_enabled) {
	PRINT_NAME();

	if (zoom_enabled == nullptr) {
		return USER_SERVICE_ERROR_INVALID_ARGUMENT;
	}
	if (!HasUser(user_id)) {
		return USER_SERVICE_ERROR_NOT_LOGGED_IN;
	}

	*zoom_enabled = 0;

	return OK;
}

static KYTY_SYSV_ABI int UserServiceGetAccessibilityZoomFollowFocus(int      user_id,
                                                                    int32_t* zoom_follow_focus) {
	PRINT_NAME();

	if (zoom_follow_focus == nullptr) {
		return USER_SERVICE_ERROR_INVALID_ARGUMENT;
	}
	if (!HasUser(user_id)) {
		return USER_SERVICE_ERROR_NOT_LOGGED_IN;
	}

	*zoom_follow_focus = 0;

	return OK;
}

static KYTY_SYSV_ABI int UserServicePlatformPrivacyWs1Stub(uint64_t, uint64_t, uint64_t, uint64_t,
                                                           uint64_t, uint64_t) {
	return OK;
}

// sceUserServiceRegisterEventCallback(callback, arg): the JSCd daemon registers for user
// login/logout events. Callback delivery is still unimplemented; polling via
// UserServiceGetEvent observes the actual login/logout queue. NID wuI7c7UNk0A.
static KYTY_SYSV_ABI int UserServiceRegisterEventCallback(void* callback, void* arg) {
	PRINT_NAME();
	(void)callback; (void)arg;
	return OK;
}

} // namespace UserService

LIB_DEFINE(InitUserService_1) {
	const auto& environment = Config::GetGuestEnvironment();
	{
		Common::HostCriticalScope critical;
		std::lock_guard dispatch(UserService::g_framework_dispatch_mutex);
		std::lock_guard lock(UserService::g_users_mutex);
		UserService::g_users.clear();
		UserService::g_user_events.clear();
		UserService::g_framework_events.clear();
		UserService::g_next_user_number = 1;
		UserService::g_user_store.clear();
		UserService::g_user_store_readable = true;
		const auto store = environment.find("KYTY_USER_STORE");
		if (store != environment.end() && !store->second.empty()) {
			UserService::g_user_store = Common::PathFromUtf8(store->second);
			UserService::g_user_store_readable = UserService::LoadUsersLocked();
			LOGF("UserService: loaded %zu local profiles, automatic login disabled%s\n",
			     UserService::g_users.size(), UserService::g_user_store_readable ? "" : " (store read failed)");
		} else {
			UserService::g_users.emplace(Config::GetUserId(),
			    UserService::UserRecord {Config::GetUserName(), 0, 0, 0, true});
			UserService::g_user_events.push_back({UserService::UserServiceEventTypeLogin, Config::GetUserId()});
		}
	}
	const auto foreground = environment.find("KYTY_INITIAL_FOREGROUND_USER");
	UserService::g_foreground_user.store(
	    !UserService::g_user_store.empty() || (foreground != environment.end() && foreground->second == "none")
	        ? -1 : Config::GetUserId(),
	    std::memory_order_relaxed);
	LIB_FUNC("j3YMu1MVNNo", UserService::UserServiceInitialize);
	LIB_FUNC("az-0R6eviZ0", UserService::UserServiceInitialize2);
	LIB_FUNC("CdWp0oHWGr0", UserService::UserServiceGetInitialUser);
	LIB_FUNC("eNb53LQJmIM", UserService::UserServiceGetForegroundUser);
	LIB_FUNC("MgBIXUkGtpE", UserService::UserServiceSetForegroundUser);
	LIB_FUNC("yH17Q6NWtVg", UserService::UserServiceGetEvent);
	LIB_FUNC("fPhymKNvK-A", UserService::UserServiceGetLoginUserIdList);
	LIB_FUNC("uvVR70ZxFrQ", UserService::UserServiceLogin);
	LIB_FUNC("MZxH8029+Wg", UserService::UserServiceIsLoggedIn);
	LIB_FUNC("3T9y5xDcfOk", UserService::UserServiceLogout);
	LIB_FUNC("5EiQCnL2G1Y", UserService::UserServiceGetRegisteredUserIdList);
	LIB_FUNC("1xxcMiGu2fo", UserService::UserServiceGetUserName);
	LIB_FUNC("Jqu2XFr5UvA", UserService::UserServiceSetUserName);
	LIB_FUNC("X5rJZNDZ2Ss", UserService::UserServiceGetPasscode);
	LIB_FUNC("7LCq4lSlmw4", UserService::UserServiceSetPasscode);
	LIB_FUNC("RJX7T4sjNgI", UserService::UserServiceGetUserStatus);
	LIB_FUNC("QNk7qD4dlD4", UserService::UserServiceGetLoginFlag);
	LIB_FUNC("bwFjS+bX9mA", UserService::UserServiceGetUserNumber);
	LIB_FUNC("qbwy0Ub8b3M", UserService::UserServiceGetUserNumber);
	LIB_FUNC("-sD02mFDBh4", UserService::UserServiceGetGamePresets);
	LIB_FUNC("woNpu+45RLk", UserService::UserServiceGetAgeLevel);
	LIB_FUNC("rnEhHqG-4xo", UserService::UserServiceGetAccessibilityChatTranscription);
	LIB_FUNC("ZKJtxdgvzwg", UserService::UserServiceGetAccessibilityPressAndHoldDelay);
	LIB_FUNC("qWYHOFwqCxY", UserService::UserServiceGetAccessibilityVibration);
	LIB_FUNC("-3Y5GO+-i78", UserService::UserServiceGetAccessibilityTriggerEffect);
	LIB_FUNC("hD-H81EN9Vg", UserService::UserServiceGetAccessibilityZoomEnabled);
	LIB_FUNC("O6IW1-Dwm-w", UserService::UserServiceGetAccessibilityZoomFollowFocus);
	LIB_FUNC("D-CzAxQL0XI", UserService::UserServicePlatformPrivacyWs1Stub);
	LIB_FUNC("wuI7c7UNk0A", UserService::UserServiceRegisterEventCallback);
}

namespace LoginMgrServer {
LIB_VERSION("LoginMgrServer", 1, "LoginMgrServer", 1, 1);
static constexpr int kInvalidArgument = static_cast<int>(0x813e0002u);
static constexpr int kInvalidUser = static_cast<int>(0x813e0006u);

// ABI verified in the original libSceLoginMgrServer: createUser sends
// type + two byte flags and returns one four-byte ID; status setters return
// the previous value in a four-byte output, not a success flag.
static int KYTY_SYSV_ABI CreateUser(const char* name, int type, bool incomplete,
                                   bool shown_eula, int* user_id) {
	if (!name || !*name || std::strlen(name) > 64 || !user_id || type < 0 || type > 6) {
		return kInvalidArgument;
	}
	Common::HostCriticalScope critical;
	std::lock_guard lock(UserService::g_users_mutex);
	if (UserService::g_users.size() >= 16) { return UserService::USER_SERVICE_ERROR_NO_MEMORY; }
	int id;
	do {
		if (UserService::g_next_user_number >= 0x0fffffffu) { return UserService::USER_SERVICE_ERROR_NO_MEMORY; }
		id = static_cast<int>(0x10000000u | UserService::g_next_user_number++);
	} while (UserService::g_users.contains(id));
	// Bit zero is the incomplete flag: the managed completion path clears mask 1.
	const uint32_t status = incomplete ? 1u : 0u;
	UserService::g_users.emplace(id, UserService::UserRecord {name, status, 0, type, false, shown_eula});
	if (!UserService::SaveUsersLocked()) {
		UserService::g_users.erase(id);
		return UserService::USER_SERVICE_ERROR_INTERNAL;
	}
	*user_id = id;
	UserService::QueueFrameworkEventLocked(42, id);
	LOGF("LoginMgr created user: id=0x%x type=%d status=0x%x\n", id, type, status);
	return OK;
}

static int KYTY_SYSV_ABI DestroyUser(int user_id) {
	Common::HostCriticalScope critical;
	std::lock_guard lock(UserService::g_users_mutex);
	auto user = UserService::g_users.find(user_id);
	if (user == UserService::g_users.end()) { return kInvalidUser; }
	auto removed = UserService::g_users.extract(user);
	if (!UserService::SaveUsersLocked()) {
		UserService::g_users.insert(std::move(removed));
		return UserService::USER_SERVICE_ERROR_INTERNAL;
	}
	if (removed.mapped().logged_in) {
		UserService::g_user_events.push_back({UserService::UserServiceEventTypeLogout, user_id});
		UserService::QueueFrameworkEventLocked(41, user_id);
	}
	UserService::QueueFrameworkEventLocked(43, user_id);
	if (UserService::g_foreground_user.load() == user_id) {
		UserService::g_foreground_user.store(-1);
	}
	return OK;
}

static int SetFlags(int user_id, uint32_t mask, uint32_t value, uint32_t* old_value,
                    bool login_flags) {
	if (!old_value) { return kInvalidArgument; }
	Common::HostCriticalScope critical;
	std::lock_guard lock(UserService::g_users_mutex);
	auto user = UserService::g_users.find(user_id);
	if (user == UserService::g_users.end()) { return kInvalidUser; }
	auto& flags = login_flags ? user->second.login_flags : user->second.status;
	*old_value = flags;
	flags = (flags & ~mask) | (value & mask);
	if (!UserService::SaveUsersLocked()) {
		flags = *old_value;
		return UserService::USER_SERVICE_ERROR_INTERNAL;
	}
	return OK;
}

static int KYTY_SYSV_ABI SetUserStatus(int user_id, uint32_t mask, uint32_t value, uint32_t* old_value) {
	return SetFlags(user_id, mask, value, old_value, false);
}
static int KYTY_SYSV_ABI SetLoginFlag(int user_id, uint32_t mask, uint32_t value, uint32_t* old_value) {
	return SetFlags(user_id, mask, value, old_value, true);
}

LIB_DEFINE(InitLoginMgrServer_1) {
	LIB_FUNC("AT6NySjQ2gY", CreateUser);
	LIB_FUNC("REIRIXzv-H0", DestroyUser);
	LIB_FUNC("-+h1C78SdyU", SetUserStatus);
	LIB_FUNC("Jha8yMoMzrg", SetLoginFlag);
}
} // namespace LoginMgrServer

} // namespace Libs
