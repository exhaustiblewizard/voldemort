#include "libs/libs.h"

#include "common/logging/log.h"
#include "libs/errno.h"
#include "loader/symbolDatabase.h"

namespace Libs {

namespace LibContentDelete {
LIB_DEFINE(InitContentDelete_1);
} // namespace LibContentDelete

namespace LibContentExport {
LIB_DEFINE(InitContentExport_1);
} // namespace LibContentExport

namespace LibContentSearch {
LIB_DEFINE(InitContentSearch_1);
} // namespace LibContentSearch

namespace VideoDec2 {
LIB_DEFINE(InitVideoDec2_1);
} // namespace VideoDec2

namespace LibMouse {
LIB_DEFINE(InitMouse_1);
} // namespace LibMouse

namespace LibKeyboard {
LIB_DEFINE(InitKeyboard_1);
} // namespace LibKeyboard

namespace Ime {
LIB_DEFINE(InitPlatform_1_Ime);
} // namespace Ime

namespace LibUlt {
LIB_DEFINE(InitUlt_1);
} // namespace LibUlt

namespace LibPsml {
LIB_DEFINE(InitPsml_1);
} // namespace LibPsml

namespace LibCes {
LIB_DEFINE(InitCes_1);
} // namespace LibCes

namespace LibC {
LIB_DEFINE(InitLibC_1);
} // namespace LibC

namespace LibAmpr {
LIB_DEFINE(InitAmpr_1);
} // namespace LibAmpr

namespace Coredump {
LIB_DEFINE(InitCoredump_1);
} // namespace Coredump

namespace LibRazorCpu {
LIB_DEFINE(InitRazorCpu_1);
} // namespace LibRazorCpu

namespace Fiber {
LIB_DEFINE(InitFiber_1);
} // namespace Fiber

namespace LibRtc {
LIB_DEFINE(InitRtc_1);
} // namespace LibRtc

namespace LibreSsl {
LIB_DEFINE(InitLibreSsl_1);
} // namespace LibreSsl

namespace Curl {
LIB_DEFINE(InitCurl_1);
} // namespace Curl

namespace RegMgr {
LIB_DEFINE(InitRegMgr_1);
} // namespace RegMgr

namespace FsInternalForVsh {
LIB_DEFINE(InitFsInternalForVsh_1);
} // namespace FsInternalForVsh

namespace SystemServiceTelemetry2 {
LIB_DEFINE(InitSystemServiceTelemetry2_1);
} // namespace SystemServiceTelemetry2
namespace RnpsAppMgr {
LIB_DEFINE(InitRnpsAppMgr_1);
} // namespace RnpsAppMgr
namespace NpManagerInt {
LIB_DEFINE(InitNpManagerInt_1);
} // namespace NpManagerInt
namespace LncUtil {
LIB_DEFINE(InitLncUtil_1);
} // namespace LncUtil
namespace UrlConfigResolver {
LIB_DEFINE(InitUrlConfigResolver_1);
} // namespace UrlConfigResolver
namespace Jsc {
LIB_DEFINE(InitJsc_1);
} // namespace Jsc
namespace CxxAbi {
LIB_DEFINE(InitCxxAbi_1);
} // namespace CxxAbi
namespace ShellCoreUtil {
LIB_DEFINE(InitShellCoreUtil_1);
} // namespace ShellCoreUtil
namespace AppInstUtil {
LIB_DEFINE(InitAppInstUtil_1);
} // namespace AppInstUtil
namespace SystemLogger2 {
LIB_DEFINE(InitSystemLogger2_1);
} // namespace SystemLogger2
namespace SystemLogger2Main {
LIB_DEFINE(InitSystemLogger2Main_1);
} // namespace SystemLogger2Main
namespace AppDbShellCoreClient {
LIB_DEFINE(InitAppDbShellCoreClient_1);
} // namespace AppDbShellCoreClient
namespace UsbStorageForShellUI {
LIB_DEFINE(InitUsbStorageForShellUI_1);
} // namespace UsbStorageForShellUI
namespace NpCommon {
LIB_DEFINE(InitNpCommon_1);
} // namespace NpCommon
namespace Ipmi {
LIB_DEFINE(InitIpmi_1);
} // namespace Ipmi
namespace Camera {
LIB_DEFINE(InitCamera_1);
} // namespace Camera
namespace NpManagerIpc {
LIB_DEFINE(InitNpManagerIpc_1);
} // namespace NpManagerIpc
namespace AppMessaging {
LIB_DEFINE(InitAppMessaging_1);
} // namespace AppMessaging
namespace BgsStorage {
LIB_DEFINE(InitBgsStorage_1);
} // namespace BgsStorage
namespace HttpCache {
LIB_DEFINE(InitHttpCache_1);
} // namespace HttpCache
namespace RnpsBundle {
LIB_DEFINE(InitRnpsBundle_1);
} // namespace RnpsBundle
namespace NpWebApi2 {
LIB_DEFINE(InitNpWebApi2_1);
} // namespace NpWebApi2

namespace Mbus {
LIB_DEFINE(InitMbus_1);
} // namespace Mbus

namespace SysCore {
LIB_DEFINE(InitSysCore_1);
} // namespace SysCore
namespace Remoteplay {
LIB_DEFINE(InitRemoteplay_1);
} // namespace Remoteplay
namespace Icu {
LIB_DEFINE(InitIcu_1);
} // namespace Icu

namespace LibGen5 {
LIB_DEFINE(InitVideoOut_1);
namespace VrrStatus {
LIB_DEFINE(InitVideoOutVrrStatus_1);
} // namespace VrrStatus
} // namespace LibGen5

namespace AvSetting {
LIB_DEFINE(InitAvSetting_1);
} // namespace AvSetting

LIB_DEFINE(InitAppContent_1);
LIB_DEFINE(InitAudio_1);
LIB_DEFINE(InitConvertKeycode_1);
LIB_DEFINE(InitDbgAddressSanitizer_1);
LIB_DEFINE(InitDialog_1);
LIB_DEFINE(InitFont_1);
LIB_DEFINE(InitFontFt_1);
LIB_DEFINE(InitAgcDriver_1);
LIB_DEFINE(InitGnmDriver_1);
LIB_DEFINE(InitHmd2_1);
LIB_DEFINE(InitLibKernel_1);
LIB_DEFINE(InitNet_1);
LIB_DEFINE(InitPad_1);
LIB_DEFINE(InitPlayGo_1);
LIB_DEFINE(InitPngDec_1);
LIB_DEFINE(InitPlatform_1);
LIB_DEFINE(InitRudp_1);
LIB_DEFINE(InitSaveData_1);
LIB_DEFINE(InitShare_1);
LIB_DEFINE(InitSysmodule_1);
LIB_DEFINE(InitSystemService_1);
LIB_DEFINE(InitTextToSpeech2_1);
LIB_DEFINE(InitUserService_1);
namespace LoginMgrServer { LIB_DEFINE(InitLoginMgrServer_1); }
LIB_DEFINE(InitWebBrowserDialog_1);

void InitAll(Loader::SymbolDatabase* s) {
	InitAudio_1(s);
	InitConvertKeycode_1(s);
	LibAmpr::InitAmpr_1(s);
	InitAppContent_1(s);
	Coredump::InitCoredump_1(s);
	LibContentDelete::InitContentDelete_1(s);
	LibContentExport::InitContentExport_1(s);
	LibContentSearch::InitContentSearch_1(s);
	LibC::InitLibC_1(s);
	LibCes::InitCes_1(s);
	InitDbgAddressSanitizer_1(s);
	LibRazorCpu::InitRazorCpu_1(s);
	InitDialog_1(s);
	Fiber::InitFiber_1(s);
	InitFont_1(s);
	InitFontFt_1(s);
	InitAgcDriver_1(s);
	InitGnmDriver_1(s);
	InitHmd2_1(s);
	InitLibKernel_1(s);
	LibMouse::InitMouse_1(s);
	LibKeyboard::InitKeyboard_1(s);
	Ime::InitPlatform_1_Ime(s);
	InitNet_1(s);
	InitPad_1(s);
	InitPlayGo_1(s);
	LibPsml::InitPsml_1(s);
	InitPngDec_1(s);
	InitPlatform_1(s);
	InitRudp_1(s);
	LibRtc::InitRtc_1(s);
	LibreSsl::InitLibreSsl_1(s);
	Curl::InitCurl_1(s);
	RegMgr::InitRegMgr_1(s);
	FsInternalForVsh::InitFsInternalForVsh_1(s);
	SystemServiceTelemetry2::InitSystemServiceTelemetry2_1(s);
	RnpsAppMgr::InitRnpsAppMgr_1(s);
	NpManagerInt::InitNpManagerInt_1(s);
	LncUtil::InitLncUtil_1(s);
	UrlConfigResolver::InitUrlConfigResolver_1(s);
	Jsc::InitJsc_1(s);
	CxxAbi::InitCxxAbi_1(s);
	ShellCoreUtil::InitShellCoreUtil_1(s);
	AppInstUtil::InitAppInstUtil_1(s);
	SystemLogger2::InitSystemLogger2_1(s);
	SystemLogger2Main::InitSystemLogger2Main_1(s);
	AppDbShellCoreClient::InitAppDbShellCoreClient_1(s);
	UsbStorageForShellUI::InitUsbStorageForShellUI_1(s);
	NpCommon::InitNpCommon_1(s);
	Ipmi::InitIpmi_1(s);
	Camera::InitCamera_1(s);
	NpManagerIpc::InitNpManagerIpc_1(s);
	AppMessaging::InitAppMessaging_1(s);
	BgsStorage::InitBgsStorage_1(s);
	HttpCache::InitHttpCache_1(s);
	RnpsBundle::InitRnpsBundle_1(s);
	NpWebApi2::InitNpWebApi2_1(s);
	Mbus::InitMbus_1(s);
	SysCore::InitSysCore_1(s);
	Remoteplay::InitRemoteplay_1(s);
	Icu::InitIcu_1(s);
	InitSaveData_1(s);
	InitShare_1(s);
	InitSysmodule_1(s);
	InitSystemService_1(s);
	InitTextToSpeech2_1(s);
	LibUlt::InitUlt_1(s);
	InitUserService_1(s);
	LoginMgrServer::InitLoginMgrServer_1(s);
	VideoDec2::InitVideoDec2_1(s);
	LibGen5::InitVideoOut_1(s);
	LibGen5::VrrStatus::InitVideoOutVrrStatus_1(s);
	AvSetting::InitAvSetting_1(s);
	InitWebBrowserDialog_1(s);
}

namespace LibContentExport {

LIB_VERSION("ContentExport", 1, "ContentExport", 1, 1);

namespace ContentExport {

constexpr int CONTENT_EXPORT_ERROR_INVALID_PARAM = -2137182186; /* 0x809D3016 */

struct ContentExportInitParam2 {
	void*   malloc_func;
	void*   free_func;
	void*   user_data;
	size_t  buffer_size;
	int64_t reserved0;
	int64_t reserved1;
};

static bool g_initialized = false;

static int KYTY_SYSV_ABI ContentExportInit2(const ContentExportInitParam2* init_param) {
	PRINT_NAME();

	LOGF("\t init_param  = 0x%016" PRIx64 "\n", reinterpret_cast<uint64_t>(init_param));

	if (init_param == nullptr) {
		return CONTENT_EXPORT_ERROR_INVALID_PARAM;
	}

	LOGF("\t malloc_func = 0x%016" PRIx64 "\n"
	     "\t free_func   = 0x%016" PRIx64 "\n"
	     "\t user_data   = 0x%016" PRIx64 "\n"
	     "\t buffer_size = %" PRIu64 "\n",
	     reinterpret_cast<uint64_t>(init_param->malloc_func),
	     reinterpret_cast<uint64_t>(init_param->free_func),
	     reinterpret_cast<uint64_t>(init_param->user_data),
	     static_cast<uint64_t>(init_param->buffer_size));

	g_initialized = true;

	return OK;
}

} // namespace ContentExport

LIB_DEFINE(InitContentExport_1) {
	LIB_FUNC("0GnN4QCgIfs", ContentExport::ContentExportInit2);
}

} // namespace LibContentExport

namespace LibContentSearch {

LIB_VERSION("ContentSearch", 1, "ContentSearch", 1, 0);

namespace ContentSearch {

constexpr int CONTENT_SEARCH_ERROR_INVALID_PARAM = -2137190397; /* 0x809D1003 */

struct ContentSearchInitParam {
	size_t memory_size;
};

static bool g_initialized = false;

static int KYTY_SYSV_ABI ContentSearchInit(const ContentSearchInitParam* init_param) {
	PRINT_NAME();

	LOGF("\t init_param  = 0x%016" PRIx64 "\n", reinterpret_cast<uint64_t>(init_param));

	if (init_param == nullptr) {
		return CONTENT_SEARCH_ERROR_INVALID_PARAM;
	}

	LOGF("\t memory_size = %" PRIu64 "\n", static_cast<uint64_t>(init_param->memory_size));

	g_initialized = true;

	return OK;
}

} // namespace ContentSearch

LIB_DEFINE(InitContentSearch_1) {
	LIB_FUNC("dPj4ZtRcIWk", ContentSearch::ContentSearchInit);
}

} // namespace LibContentSearch

namespace LibContentDelete {

LIB_VERSION("ContentDelete", 1, "ContentDelete", 1, 1);

namespace ContentDelete {

constexpr int CONTENT_DELETE_ERROR_INVALID_PARAM = -2137174015; /* 0x809D5001 */

struct ContentDeleteInitParam {
	char   reserved1[4];
	size_t heap_size;
	char   reserved2[32];
};

static bool g_initialized = false;

static int KYTY_SYSV_ABI ContentDeleteInitialize(const ContentDeleteInitParam* init_param) {
	PRINT_NAME();

	LOGF("\t init_param = 0x%016" PRIx64 "\n", reinterpret_cast<uint64_t>(init_param));

	if (init_param == nullptr) {
		return CONTENT_DELETE_ERROR_INVALID_PARAM;
	}

	LOGF("\t heap_size  = %" PRIu64 "\n", static_cast<uint64_t>(init_param->heap_size));

	g_initialized = true;

	return OK;
}

} // namespace ContentDelete

LIB_DEFINE(InitContentDelete_1) {
	LIB_FUNC("zoxb0wEChEM", ContentDelete::ContentDeleteInitialize);
}

} // namespace LibContentDelete

} // namespace Libs
