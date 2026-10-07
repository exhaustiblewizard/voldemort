#pragma once

#include <cstdint>

namespace Loader { struct Program; }

namespace Libs::LncUtil {
// Native LNC event ABI, verified against Event's field order and MarshalAs
// lengths in Sce.Vsh.LncUtilWrapper.dll. Read by LncProxy and EventMonitor.
struct alignas(8) EventWire {
	int32_t event_type;
	char title_id[16];
	int32_t app_id;
	int32_t app_type;
	uint32_t app_attribute;
	int32_t launch_request_app_id;
	int32_t user_id;
	uint8_t arguments[4096];
	int32_t argument_size;
	int32_t error_code;
	int32_t error_data;
	int32_t app_local_pid;
	char path[1024];
	char sce_sys_dir[256];
	int32_t cause_code;
	int32_t existing_app_id;
	uint64_t check_flags;
	uint64_t context_id;
	int32_t coredump_reason;
	char corefile_name[256];
	uint32_t exception_code;
	char category[4];
	uint32_t app_category_type;
	int32_t is_crashed;
};
static_assert(sizeof(EventWire) == 5736);

void PostApplicationEvent(int32_t type, const Loader::Program* program, int32_t user_id);
bool HasControllerFocus(const Loader::Program* program);
bool IsSystemUiOverlaid(const Loader::Program* program);
}
