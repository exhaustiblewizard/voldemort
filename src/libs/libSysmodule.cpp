#include "common/abi.h"
#include "common/assert.h"
#include "common/common.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "common/stringUtils.h"
#include "kernel/fileSystem.h"
#include "libs/libs.h"
#include "loader/runtimeLinker.h"
#include "loader/symbolDatabase.h"

namespace Libs {

LIB_VERSION("Sysmodule", 1, "Sysmodule", 1, 1);

namespace LibKernel {
struct ModuleInfoForUnwind;
int KYTY_SYSV_ABI KernelGetModuleInfoForUnwind(uint64_t addr, int flags, ModuleInfoForUnwind* info);
} // namespace LibKernel

namespace Sysmodule {

static Loader::Program* FindNativeModule(uint32_t id) {
	// PSM initializes the public IME and IME dialog modules (0x95/0x96).
	const char* filename = nullptr;
	if (id == 149) { filename = "/system/common/lib/libSceIme.sprx"; }
	if (id == 150) { filename = "/system/common/lib/libSceImeDialog.sprx"; }
	if (!filename) { return nullptr; }
	auto* rt = Common::Singleton<Loader::RuntimeLinker>::Instance();
	return rt->FindProgramByFileName(LibKernel::FileSystem::GetRealFilename(filename));
}

static KYTY_SYSV_ABI int SysmoduleGetModuleHandleInternal(uint32_t id, int* handle) {
	if (!handle) { return -1; }
	*handle = 0;
	if (auto* program = FindNativeModule(id)) {
		*handle = program->unique_id;
		LOGF("Sysmodule: module %u native handle %d\n", id, *handle);
		return 0;
	}
	// KernelDlsym reserves handle zero for HLE modules, including JSC.
	return (id == 149 || id == 150) ? -1 : 0;
}

static KYTY_SYSV_ABI int SysmoduleGetModuleInfoForUnwind(uint64_t addr, int flags,
                                                         LibKernel::ModuleInfoForUnwind* info) {
	return LibKernel::KernelGetModuleInfoForUnwind(addr, flags, info);
}

static KYTY_SYSV_ABI int SysmoduleLoadModule(uint16_t id) {
	PRINT_NAME();

	LOGF("\t id = %d\n", static_cast<int>(id));

	return 0;
}

static KYTY_SYSV_ABI int SysmoduleLoadModuleInternal(uint16_t id) {
	PRINT_NAME();

	LOGF("\t id = %d\n", static_cast<int>(id));

	return 0;
}

static KYTY_SYSV_ABI int SysmoduleUnloadModule(uint16_t id) {
	PRINT_NAME();

	LOGF("\t id = %d\n", static_cast<int>(id));

	return 0;
}

static KYTY_SYSV_ABI int SysmoduleLoadModuleInternalWithArg(uint16_t id, int arg1, int arg2,
                                                            int arg3, int* ret) {
	PRINT_NAME();

	LOGF("\t id = %d, arg1 = %d, arg2 = %d, arg3 = %d\n", static_cast<int>(id), arg1, arg2, arg3);

	// SceShellCore's module loader calls this with non-zero args (module-load parameters). We
	// HLE the modules rather than really loading them, so ignore the args and report success.
	if (ret != nullptr) {
		*ret = 0;
	}

	return 0;
}

// sceSysmoduleLoadModuleByNameInternal(const char* name /*rdi*/, uint64_t a2 /*rsi*/,
//     uint64_t a3 /*rdx*/, uint64_t a4 /*rcx*/, int* modres /*r8*/): loads a system module by
// name (not numeric id). Reversed from JSCd sub_5EAC0: the caller does `(ret | *modres) < 0` and
// abort()s on either being negative, so BOTH the return value AND *modres must be set to >=0. The
// unresolved-import stub returned 0 but left *modres uninitialised (0xdeadbeef → negative) → abort.
// Offline the modules are HLE'd, not really loaded; report success with a 0 module result.
static KYTY_SYSV_ABI int SysmoduleLoadModuleByNameInternal(const char* name, uint64_t a2,
                                                           uint64_t a3, uint64_t a4, int* modres) {
	PRINT_NAME();

	LOGF("\t name = %s\n", (name != nullptr) ? name : "(null)");
	(void)a4;

	if (modres != nullptr) {
		*modres = 0;
	}

	// A co-loaded native module must retain its real handle for subsequent dlsym calls.
	if (name != nullptr) {
		auto* rt = Common::Singleton<Loader::RuntimeLinker>::Instance();
		std::string filename(name);
		if (!filename.ends_with(".sprx")) {
			filename += ".sprx";
		}
		for (const char* directory: {"/system_ex/common_ex/lib/", "/system/common/lib/", "/system/priv/lib/"}) {
			const auto path = LibKernel::FileSystem::GetRealFilename(std::string(directory) + filename);
			auto* program = rt->FindProgramByFileName(path);
			if (program != nullptr) {
				++program->load_count;
				return program->unique_id;
			}
			// ShellUI passes an eight-byte callback output to SysBridge's native
			// module_start. It returns the routine registering all P/Invoke tables
			// with PSM; reporting success without executing it leaves Mono unable
			// to resolve libSysBridgeKernel, even though the SPRX exists.
			if (filename == "libSceSysBridge.sprx" && std::filesystem::is_regular_file(path)) {
				program = rt->LoadProgram(path, true);
				if (program == nullptr) { continue; }
				rt->RelocateProgram(program);
				program->load_count = 1;
				const int result = rt->StartModule(program, static_cast<size_t>(a2),
				                                  reinterpret_cast<const void*>(a3), nullptr);
				if (modres != nullptr) { *modres = result; }
				return program->unique_id;
			}
		}
	}
	return 0;
}

static KYTY_SYSV_ABI int SysmoduleIsLoaded(uint16_t id) {
	PRINT_NAME();

	LOGF("\t id = %d\n", static_cast<int>(id));

	return 0;
}

} // namespace Sysmodule

LIB_DEFINE(InitSysmodule_1) {
	LIB_FUNC("4fU5yvOkVG4", Sysmodule::SysmoduleGetModuleInfoForUnwind);
	LIB_FUNC("eR2bZFAAU0Q", Sysmodule::SysmoduleUnloadModule);
	LIB_FUNC("hHrGoGoNf+s", Sysmodule::SysmoduleLoadModuleInternalWithArg);
	LIB_FUNC("39iV5E1HoCk", Sysmodule::SysmoduleLoadModuleInternal);
	LIB_FUNC("g8cM39EUZ6o", Sysmodule::SysmoduleLoadModule);
	LIB_FUNC("fMP5NHUOaMk", Sysmodule::SysmoduleIsLoaded);
	LIB_FUNC("ynFKQ5bfGks", Sysmodule::SysmoduleIsLoaded); // sceSysmoduleIsLoadedInternal
	LIB_FUNC("CU8m+Qs+HN4", Sysmodule::SysmoduleLoadModuleByNameInternal);
	LIB_FUNC("D8cuU4d72xM", Sysmodule::SysmoduleGetModuleHandleInternal);
}

} // namespace Libs
