#include "common/abi.h"
#include "libs/libs.h"
#include "libs/libAvSetting.h"
#include "loader/symbolDatabase.h"

#include <array>
#include <memory>
#include <mutex>
#include <vector>

namespace Libs::AvSetting {
LIB_VERSION("AvSetting", 1, "AvSetting", 1, 1);

namespace {
constexpr int Invalid = static_cast<int>(0x802a0001u);
constexpr int Full = static_cast<int>(0x802a0010u);
constexpr int BadHandle = static_cast<int>(0x802a0011u);
using LncCallback = void(KYTY_SYSV_ABI *)(uint32_t, void*, void*, uint32_t, uint32_t, uint32_t);
struct Subscription {
	uint32_t handle;
	LncCallback callback;
	void* argument;
	std::recursive_mutex mutex;
	bool removed = false;
	bool pending = false;
	std::array<uint32_t, 3> event {};
};
std::mutex g_mutex;
std::array<std::shared_ptr<Subscription>, 4> g_callbacks;
uint8_t g_generation = 0;

std::shared_ptr<Subscription> Find(uint32_t handle) {
	const auto index = static_cast<uint8_t>(handle - 1) ^ 0xcdu;
	if (index >= g_callbacks.size()) { return {}; }
	std::lock_guard lock(g_mutex);
	auto slot = g_callbacks[index];
	return slot && slot->handle == handle ? slot : nullptr;
}
} // namespace

// The LNC callback struct is one pointer (native init at D210 clears 8 bytes).
static void KYTY_SYSV_ABI InitLncCallbacks(LncCallback* callback) {
	if (callback) { *callback = nullptr; }
}

// Native D280 -> EEB0 -> EB50 allocates one of four generational handles.
static int KYTY_SYSV_ABI AddLncCallbacks(const LncCallback* callback, void* argument,
                                       const void* option) {
	if (!callback || !*callback || option) { return Invalid; }
	std::lock_guard lock(g_mutex);
	for (uint32_t i = 0; i < g_callbacks.size(); ++i) {
		if (!g_callbacks[i]) {
			auto slot = std::make_shared<Subscription>();
			slot->handle = ((i | (uint32_t{g_generation++} << 8)) ^ 0x91cdu) + 1;
			slot->callback = *callback;
			slot->argument = argument;
			g_callbacks[i] = slot;
			return static_cast<int>(slot->handle);
		}
	}
	return Full;
}

static int KYTY_SYSV_ABI RemoveCallbacks(uint32_t handle) {
	auto slot = Find(handle);
	if (!slot) { return BadHandle; }
	// Synchronize with dispatch without holding the global registry lock;
	// callbacks may unregister themselves or create another subscription.
	std::lock_guard slot_lock(slot->mutex);
	std::lock_guard lock(g_mutex);
	const auto index = static_cast<uint8_t>(handle - 1) ^ 0xcdu;
	if (g_callbacks[index] != slot) { return BadHandle; }
	slot->removed = true;
	g_callbacks[index].reset();
	return 0;
}

// s2ODJNcQVkI / native D380 -> F2F0 uses nonblocking event intake and
// dispatches each accumulated change once. There is no sleep in this API.
static int KYTY_SYSV_ABI PollCallbacks(uint32_t handle, void* argument) {
	auto slot = Find(handle);
	if (!slot) { return BadHandle; }
	std::lock_guard lock(slot->mutex);
	if (slot->removed) { return BadHandle; }
	if (slot->pending) {
		const auto event = slot->event;
		slot->pending = false;
		slot->callback(handle, slot->argument, argument, event[0], event[1], event[2]);
	}
	return 0;
}

void PublishUnsupportedOutputEvent(uint32_t process, uint32_t ticket, uint32_t reason) {
	std::array<std::shared_ptr<Subscription>, 4> slots;
	{
		std::lock_guard lock(g_mutex);
		slots = g_callbacks;
	}
	for (const auto& slot : slots) {
		if (!slot) { continue; }
		std::lock_guard lock(slot->mutex);
		if (!slot->removed) {
			slot->event = {process, ticket, reason};
			slot->pending = true;
		}
	}
}

LIB_DEFINE(InitAvSettingCallbacks_1) {
	LIB_FUNC("A143jTEYkNw", InitLncCallbacks);
	LIB_FUNC("Im9QXnr0QK4", AddLncCallbacks);
	LIB_FUNC("KiCPJyA-prw", RemoveCallbacks);
	LIB_FUNC("s2ODJNcQVkI", PollCallbacks);
}
} // namespace Libs::AvSetting
