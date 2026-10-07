#pragma once

#include "common/abi.h"
#include "common/emulatorConfig.h"
#include "common/logging/log.h"
#include "libs/errno.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace Libs::KitProfile {
inline constexpr char Model[] = "DFI-1000AA";
inline constexpr char SerialNumber[] = "AJ049281734";
inline constexpr char SystemName[] = "SONY-PS5-DEV-01";
inline constexpr char Version[] = "04.030.041";
inline constexpr char IpAddress[] = "10.28.4.162";
inline constexpr uint8_t MacAddress[] = {0x70, 0x9e, 0x29, 0xe5, 0xa4, 0x7b};

struct GenuineSystemSwVersion {
	uint64_t size;
	char info[28];
	uint64_t value;
};
static_assert(sizeof(GenuineSystemSwVersion) == 48);
static_assert(offsetof(GenuineSystemSwVersion, value) == 40);

inline int KYTY_SYSV_ABI GetGenuineSystemSwVersion(GenuineSystemSwVersion* version) {
	if (!version) { return LibKernel::KERNEL_ERROR_EFAULT; }
	*version = {};
	version->size = sizeof(*version);
	std::memcpy(version->info, Version, sizeof(Version));
	// Major at bits 40..47, revision at 8..15; low beta/release flags are zero.
	version->value = (uint64_t{4} << 40) | (uint64_t{30} << 24) | (uint64_t{41} << 8);
	LOGF("Virtual kit firmware: %s\n", Version);
	return 0;
}

inline int KYTY_SYSV_ABI GetPrefixVersion(char* prefix, uint64_t capacity) {
	if (!prefix || !capacity) { return LibKernel::KERNEL_ERROR_EFAULT; }
	prefix[0] = '\0';
	return 0;
}

inline int KYTY_SYSV_ABI PupExpirationGetStatus(uint32_t* status, uint32_t* time) {
	if (!status || !time) { return LibKernel::KERNEL_ERROR_EFAULT; }
	*time = Config::GetPupExpirationRemainingSeconds();
	*status = *time ? 2 : 1; // trial firmware, or expired trial firmware
	LOGF("Virtual kit PUP expiration: status=%u remaining=%u seconds\n", *status, *time);
	return 0;
}

#pragma pack(push, 4)
struct IfAddress { uint32_t address, destination, broadcast, netmask; };
struct PacketStatistics { uint64_t counters[8]; };
struct IfStatistics { PacketStatistics tx, rx; };
// SysBridge's SceNetIfList has Pack=4, including its nested 64-bit statistics.
struct IfList {
	char name[16], destination_name[16];
	int32_t index, destination_index;
	IfAddress addresses[2];
	uint32_t flags, type;
	uint8_t mac[6];
	int32_t mtu, max_mtu;
	IfStatistics driver_statistics, emulator_statistics;
	int32_t link_status, reserved1, total_use_timer, tx_bps, rx_bps, max_tx_bps, max_rx_bps;
	uint8_t ipv6_addresses[2][16];
	uint32_t ipv6_prefix_lengths[2], ipv6_flags[2];
	uint8_t reserved[52];
};
#pragma pack(pop)
static_assert(sizeof(IfList) == 480);
static_assert(offsetof(IfList, mac) == 80);
static_assert(offsetof(IfList, mtu) == 88);
static_assert(offsetof(IfList, link_status) == 352);

inline int KYTY_SYSV_ABI GetIfList(int id, IfList* list, int capacity) {
	if (capacity < 0 || (capacity > 0 && !list)) { return Network::NET_ERROR_EINVAL; }
	// The virtual kit exposes one physical Ethernet interface.
	if (id != 1 && id != -1) { return 0; }
	if (!capacity) { return 1; }
	*list = {};
	std::memcpy(list->name, "eth0", 5);
	list->index = 1;
	list->addresses[0] = {0xa2041c0a, 0, 0xff041c0a, 0x00ffffff};
	list->flags = 0x01008043; // UP, BROADCAST, RUNNING, MULTICAST, INTERNET
	list->type = 1;
	std::memcpy(list->mac, MacAddress, sizeof(MacAddress));
	list->mtu = list->max_mtu = 1500;
	list->link_status = 0x43; // 1G full duplex
	list->max_tx_bps = list->max_rx_bps = 1000000000;
	return 1;
}
} // namespace Libs::KitProfile
