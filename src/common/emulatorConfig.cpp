#include "common/emulatorConfig.h"

#include "common/assert.h"

#include <algorithm>
#include <chrono>
#include <memory>

namespace Config {

static std::unique_ptr<ConfigOptions> g_config;
static std::chrono::steady_clock::time_point g_session_start;

void Initialize() {
	EXIT_IF(g_config != nullptr);

	g_config = std::make_unique<ConfigOptions>();
}

void Shutdown() {
	g_config.reset();
}

void Load(const ConfigOptions& cfg) {
	EXIT_IF(g_config == nullptr);
	EXIT_IF(cfg.user_name.empty() || cfg.user_name.size() > MAX_USER_NAME_LENGTH);
	EXIT_IF(!IsConfiguredUserIdValid(cfg.user_id));

	*g_config = cfg;
	g_session_start = std::chrono::steady_clock::now();
}

uint32_t GetScreenWidth() {
	return g_config->screen_width;
}

const std::map<std::string, std::string>& GetGuestEnvironment() {
	return g_config->guest_environment;
}

uint32_t GetScreenHeight() {
	return g_config->screen_height;
}

const std::string& GetUserName() {
	return g_config->user_name;
}

int32_t GetUserId() {
	return g_config->user_id;
}

int32_t GetDevkitActivationDays() {
	return g_config->devkit_activation_days;
}

uint32_t GetPupExpirationRemainingSeconds() {
	const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
	    std::chrono::steady_clock::now() - g_session_start).count();
	const auto lifetime = std::max<int64_t>(0, g_config->pup_expiration_days) * 86400;
	return static_cast<uint32_t>(std::clamp<int64_t>(lifetime - elapsed, 0, UINT32_MAX));
}

uint16_t GetLocalNetworkPort() {
	return g_config->local_network_port;
}

const std::string& GetAudioInputDevice() {
	return g_config->audio_input_device;
}

PresentMode GetPresentMode() {
	return g_config->present_mode;
}

int32_t GetGpuIndex() {
	return g_config->gpu_index;
}

bool FullscreenEnabled() {
	return g_config->fullscreen_enabled;
}

bool VrEnabled() {
	return g_config->vr_enabled;
}

bool AmdCpuEnabled() {
	return g_config->amd_cpu_enabled;
}

uint32_t GetVblankFrequency() {
	return std::clamp(g_config->vblank_frequency, 30u, 360u);
}

uint32_t GetConsoleLanguage() {
	return g_config->console_language;
}

bool VulkanValidationEnabled() {
	return g_config->vulkan_validation_enabled;
}

bool ShaderValidationEnabled() {
	return g_config->shader_validation_enabled;
}

ShaderOptimizationType GetShaderOptimizationType() {
	return g_config->shader_optimization_type;
}

LogDirection GetShaderLogDirection() {
	return g_config->shader_log_direction;
}

std::filesystem::path GetShaderLogFolder() {
	return g_config->shader_log_folder;
}

bool CommandBufferDumpEnabled() {
	return g_config->command_buffer_dump_enabled;
}

std::filesystem::path GetCommandBufferDumpFolder() {
	return g_config->command_buffer_dump_folder;
}

bool GraphicsDebugDumpEnabled() {
	return g_config->graphics_debug_dump_enabled;
}

LogDirection GetPrintfDirection() {
	return g_config->printf_direction;
}

std::filesystem::path GetPrintfOutputFile() {
	return g_config->printf_output_file;
}

bool ProfilerEnabled() {
	return g_config->profiler_enabled;
}

bool SpirvDebugPrintfEnabled() {
	return g_config->spirv_debug_printf_enabled;
}

bool GpuAssistedValidationEnabled() {
	return g_config->gpu_assisted_validation_enabled && g_config->vulkan_validation_enabled;
}

bool RenderDocEnabled() {
	return g_config->renderdoc_enabled;
}

bool ReadbackLinearImagesEnabled() {
	return g_config->readback_linear_images;
}

bool TessellationEnabled() {
	return g_config->tessellation_enabled;
}

bool PlayGoHackEnabled() {
	return g_config->playgo_hack_enabled;
}

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
bool RedZoneProtectionEnabled() {
	return g_config->red_zone_protection_enabled;
}
#endif

const Keymap& GetKeymap() {
	return g_config->keymap;
}

} // namespace Config
