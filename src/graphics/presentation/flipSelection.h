#pragma once

#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>

namespace Libs::VideoOutInternal {
struct QueuedFlip {
	uint64_t id;
	uint64_t group;
	const void* port;
	bool ready;
};

// One head flip per port and one atomic master/slave group per Vblank.
// An unfinished port must not stall independent display planes.
inline std::vector<uint64_t> SelectFlipGroups(std::span<const QueuedFlip> queue) {
	std::vector<uint64_t> groups;
	for (const auto& owner: queue) {
		if (owner.group != owner.id) continue;
		const bool blocked = std::any_of(queue.begin(), queue.end(), [&](const auto& member) {
			if (member.group != owner.group) return false;
			return !member.ready || std::any_of(queue.begin(), queue.end(), [&](const auto& older) {
				return older.port == member.port && older.id < member.id;
			});
		});
		if (!blocked) groups.push_back(owner.group);
	}
	return groups;
}
}
