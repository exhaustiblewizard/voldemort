#ifndef EMULATOR_INCLUDE_EMULATOR_EMULATOR_H_
#define EMULATOR_INCLUDE_EMULATOR_EMULATOR_H_

#include "common/emulatorConfig.h"
#include "common/stringUtils.h"

#include <filesystem>
#include <vector>

namespace Emulator {

struct RunOptions {
	Config::ConfigOptions config;
	std::filesystem::path app0_dir;
	std::filesystem::path elf;
	std::filesystem::path game_patch;
	std::filesystem::path virtual_disc;
	std::filesystem::path param_json; // Optional metadata for a co-hosted application.
	// Additional guest executables to co-host in the same process (fake multi-process). Each is a
	// host filesystem path to an ELF; loaded + relocated alongside --game and run on its own main.
	std::vector<std::filesystem::path> co_elfs;
	// Extra guest mount points: {guest_point, host_dir}. Lets us expose the devkit firmware tree
	// (/system, /system_ex, /preinst, ...) so SceShellCore can enumerate /system_ex/app etc.
	std::vector<std::pair<std::string, std::filesystem::path>> extra_mounts;
};

void Run(const RunOptions& options);

} // namespace Emulator

#endif /* EMULATOR_INCLUDE_EMULATOR_EMULATOR_H_ */
