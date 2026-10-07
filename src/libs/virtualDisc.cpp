#include "libs/virtualDisc.h"
#include "common/common.h"
#include "common/stringUtils.h"
#include "common/threads.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "loader/runtimeLinker.h"
#include "loader/systemContent.h"
#include "kernel/fileSystem.h"
#include "libs/errno.h"

#include <nlohmann/json.hpp>
#include <deque>
#include <fstream>
#include <limits>
#include <map>
#include <mutex>
#include <regex>
#include <stdexcept>
#include <vector>
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#include <windows.h>
#undef GetUserName
#endif

namespace Libs::VirtualDisc {
namespace {
using Json = nlohmann::json;
std::mutex mutex;
std::string title_id;
std::filesystem::path disc_folder;
std::map<std::string, std::string> metadata_snapshots;
std::deque<std::pair<int, std::string>> events;
constexpr const char* concept_prefix = "cid:virtualdisc:";
// HomeUI requests the experience switcher (128) and game space (2).
// Library (8) keeps the disc available in the collection browser too.
constexpr int disc_display_location = 128 | 8 | 2;

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
// Windows supplies SQLite with the OS; no external process or extra runtime is needed.
struct Sqlite {
	void* db = nullptr;
	HMODULE library = nullptr;
	int (*open)(const char*, void**, int, const char*) = nullptr;
	int (*close)(void*) = nullptr;
	int (*exec)(void*, const char*, int(*)(void*,int,char**,char**), void*, char**) = nullptr;
	int (*prepare)(void*,const char*,int,void**,const char**) = nullptr;
	int (*bind_text)(void*,int,const char*,int,void(*)(void*)) = nullptr;
	int (*bind_int64)(void*,int,int64_t) = nullptr;
	int (*step)(void*) = nullptr;
	int64_t (*column_int64)(void*,int) = nullptr;
	int (*finalize)(void*) = nullptr;
	const char* (*errmsg)(void*) = nullptr;
	int (*busy_timeout)(void*,int) = nullptr;

	Sqlite(const std::filesystem::path& path) {
		library = LoadLibraryW(L"winsqlite3.dll");
		if (!library) throw std::runtime_error("Windows SQLite is unavailable");
#define LOAD(name, symbol) name = reinterpret_cast<decltype(name)>(GetProcAddress(library, "sqlite3_" symbol)); if (!name) { FreeLibrary(library); throw std::runtime_error("Missing SQLite function: " symbol); }
		LOAD(open, "open_v2"); LOAD(close, "close"); LOAD(exec, "exec");
		LOAD(prepare, "prepare_v2"); LOAD(bind_text, "bind_text"); LOAD(bind_int64, "bind_int64");
		LOAD(step, "step"); LOAD(column_int64, "column_int64"); LOAD(finalize, "finalize"); LOAD(errmsg, "errmsg"); LOAD(busy_timeout, "busy_timeout");
#undef LOAD
		const int result = open(Common::PathToGenericString(path).c_str(), &db, 2 /* READWRITE */, nullptr);
		if (result != 0) {
			const std::string message = db ? errmsg(db) : "Cannot open app.db";
			if (db) close(db); db = nullptr; FreeLibrary(library); library = nullptr;
			throw std::runtime_error(message);
		}
		busy_timeout(db, 2000);
	}
	~Sqlite() { if (db) close(db); if (library) FreeLibrary(library); }
	void Execute(const std::string& sql) {
		if (exec(db, sql.c_str(), nullptr, nullptr, nullptr) != 0) throw std::runtime_error(errmsg(db));
	}
	std::vector<std::string> Tables() {
		std::vector<std::string> tables;
		auto callback = [](void* user, int count, char** values, char**) -> int {
			if (count && values[0]) static_cast<std::vector<std::string>*>(user)->emplace_back(values[0]);
			return 0;
		};
		if (exec(db, "SELECT name FROM sqlite_master WHERE type='table'", callback, &tables, nullptr) != 0) throw std::runtime_error(errmsg(db));
		return tables;
	}
	void Insert(const std::string& table, const std::map<std::string,Json>& values) {
		std::string names, placeholders;
		for (const auto& [name, value] : values) {
			if (!names.empty()) { names += ','; placeholders += ','; }
			names += '"' + name + '"'; placeholders += '?';
		}
		const auto sql = "INSERT INTO \"" + table + "\" (" + names + ") VALUES (" + placeholders + ')';
		void* stmt = nullptr;
		if (prepare(db, sql.c_str(), -1, &stmt, nullptr) != 0) throw std::runtime_error(errmsg(db));
		int index = 1, result = 0;
		for (const auto& [name, value] : values) {
			if (value.is_string()) {
				const auto& text = value.get_ref<const std::string&>();
				result = bind_text(stmt, index++, text.c_str(), static_cast<int>(text.size()), nullptr);
			} else { result = bind_int64(stmt, index++, value.get<int64_t>()); }
			if (result != 0) break;
		}
		if (!result) result = step(stmt);
		const std::string error = result == 101 /* DONE */ ? "" : errmsg(db);
		finalize(stmt);
		if (!error.empty()) throw std::runtime_error(error);
	}
	int64_t NextAccessIndex(const std::string& table) {
		const auto sql = "SELECT COALESCE(MAX(lastAccessIndex),-1) FROM \"" + table + "\"";
		void* stmt = nullptr;
		if (prepare(db,sql.c_str(),-1,&stmt,nullptr) != 0) throw std::runtime_error(errmsg(db));
		const auto result = step(stmt);
		const auto maximum = result == 100 ? column_int64(stmt,0) : 0;
		const std::string error = result == 100 ? "" : errmsg(db);
		finalize(stmt);
		if (!error.empty()) throw std::runtime_error(error);
		if (maximum == (std::numeric_limits<int64_t>::max)()) throw std::runtime_error("App catalog access index overflow");
		return maximum + 1;
	}
};
#endif

std::vector<std::string> Catalog(const Json* param) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	const auto path = LibKernel::FileSystem::GetRealFilename("/system_data/priv/mms/app.db");
	if (!std::filesystem::is_regular_file(path)) {
		if (param) throw std::runtime_error("ShellUI app.db is not available; start with -OfflineDatabases");
		return {};
	}
	Sqlite db(path);
	const auto tables = db.Tables();
	db.Execute("BEGIN IMMEDIATE");
	try {
		for (const auto& table : tables) {
			if (table == "tbl_contentinfo") {
				db.Execute("DELETE FROM tbl_contentinfo WHERE metaDataPath='/mnt/disc/sce_sys'");
			} else if (table == "tbl_conceptmetadata" ||
			           std::regex_match(table, std::regex("tbl_(concept)?iconinfo_[0-9]{10}"))) {
				db.Execute("DELETE FROM \"" + table + "\" WHERE localConceptId LIKE 'cid:virtualdisc:%'");
			}
		}
		if (param) {
			const auto title = param->at("titleId").get<std::string>();
			const int platform = title.starts_with("CUSA") ? 1 : 0;
			const auto local_concept = std::string(concept_prefix) + title;
			// ShellCore's AppDb metadata builder supplies these defaults for games
			// without explicit links (sub_D7ECD0 in the FW7 ShellCore dump).
			const auto deeplink = param->value("deeplinkUri", std::string());
			const auto launch_uri = deeplink.empty() ? "psgm:play?id=" + title : deeplink;
			const auto hub = param->value("hubAppUri", std::string());
			const auto hub_uri = hub.empty() ? "pshome:gamehub?titleId=" + title : hub;
			const auto& locales = param->at("localizedParameters");
			const auto language = locales.value("defaultLanguage", "en-US");
			const auto label = locales.at(language).at("titleName").get<std::string>();
			const std::string metadata = "/mnt/disc/sce_sys", icon = metadata + "/icon0.png";
			// A pre-existing installed copy owns its content row; do not overwrite it.
			void* stmt = nullptr;
			db.prepare(db.db, "SELECT 1 FROM tbl_contentinfo WHERE titleId=?", -1, &stmt, nullptr);
			if (!stmt) throw std::runtime_error(db.errmsg(db.db));
			db.bind_text(stmt, 1, title.c_str(), -1, nullptr);
			const bool installed = db.step(stmt) == 100;
			db.finalize(stmt);
			if (installed) throw std::runtime_error("This title already has a content record; keeping the installed copy intact");
			db.Insert("tbl_contentinfo", {{"titleId",title},{"titleName",label},{"metaDataPath",metadata},
				{"icon0Info",icon},{"pprDeeplinkUri",launch_uri},{"contentStatus",0},{"contentLocation",1},{"installStatus",0},
				{"appinfoContentType",1},{"categoryType",param->value("applicationCategoryType",0)},
				{"hddLocation",0},{"externalHddAppStatus",0},{"uninstallable",0},{"sortPriority",100},
				{"pathInfo",0},{"pathInfo2",0},{"size",0}});
			db.Insert("tbl_conceptmetadata", {{"localConceptId",local_concept},{"pathInfo",0},{"pathInfo2",0},
				{"totalSize",0},{"sortPriority",100},{"hddLocation",0},{"externalHddAppStatus",0},
				{"mergedContentsStatus",0},{"mergedOperationCapability",0}});
			for (const auto& table : tables) {
				if (std::regex_match(table, std::regex("tbl_iconinfo_[0-9]{10}"))) {
					db.Insert(table, {{"localConceptId",local_concept},{"titleId",title},{"titleName",label},
						{"conceptId",local_concept},{"contentId",param->value("contentId", "")},{"visible",1},
						{"dispLocation",disc_display_location},{"discStatus",1},{"platform",platform},{"installStatus",0},{"entEntitlement",0},
						{"entFilTypeEnt",0},{"entHidden",0},{"lastAccessIndex",db.NextAccessIndex(table)},{"primaryTitleSort",0},
						{"hubAppUri",hub_uri},{"psNowFlag",0}});
				} else if (std::regex_match(table, std::regex("tbl_concepticoninfo_[0-9]{10}"))) {
					db.Insert(table, {{"localConceptId",local_concept},{"primaryTitleId",title},{"primaryTitleName",label},
						{"conceptName",label},{"primaryTitlePlatform",platform},{"dispLocation",disc_display_location},{"platform",platform},
						{"validFlag",1},{"installedStatus",0},{"entitlementStatus",0},{"metadataPath",metadata},
						{"icon0Info",icon},{"pic0Info",metadata+"/pic0.png"},{"lastAccessIndex",db.NextAccessIndex(table)},
						{"totalPlayedTime",0},{"totalEstimatedSize",0},{"genreFlags",0},{"deeplinkUri",launch_uri},
						{"hubAppUri",hub_uri},{"psNowFlag",0}});
				}
			}
		}
		db.Execute("COMMIT");
	} catch (...) { db.Execute("ROLLBACK"); throw; }
	std::vector<std::string> changed;
	for (const auto& table : tables) {
		if (table == "tbl_contentinfo" || table == "tbl_conceptmetadata" ||
		    std::regex_match(table, std::regex("tbl_(concept)?iconinfo_[0-9]{10}"))) {
			changed.push_back(table);
		}
	}
	return changed;
#else
	if (param) throw std::runtime_error("Virtual-disc catalog currently requires Windows SQLite");
	return {};
#endif
}

void NotifyCatalog(const std::vector<std::string>& tables) {
	const std::string path = std::string("/") + LibKernel::FileSystem::KernelGetFsSandboxRandomWord() + "/priv/mms/app.db";
	// DbNotify's event 45 invalidates each accessor's cached query. DiscInserted
	// updates drive state, but does not notify readers of changes to app.db.
	for (const auto& table : tables) {
		events.emplace_back(45, Json{{"DbPath",path},{"TableName",table}}.dump());
	}
}
}

bool Insert(const std::filesystem::path& folder, std::string* error) {
	Common::HostCriticalScope host;
	try {
		const auto path = std::filesystem::canonical(folder);
		if (!std::filesystem::is_regular_file(path/"eboot.bin") ||
		    !std::filesystem::is_regular_file(path/"sce_sys/icon0.png"))
			throw std::runtime_error("Select a game dump containing eboot.bin and sce_sys/icon0.png");
		const auto metadata_path = Loader::FindApplicationMetadata(path);
		Json param;
		Loader::SfoFields sfo;
		const bool ps4 = metadata_path.extension() == ".sfo";
		if (ps4) {
			sfo = Loader::ReadParamSfo(metadata_path);
			auto text = [&](const char* key) { return std::get<std::string>(sfo.at(key)); };
			param = {{"titleId",text("TITLE_ID")},{"contentId",text("CONTENT_ID")},
			         {"contentVersion",text("APP_VER")},
			         {"localizedParameters",{{"defaultLanguage","en-US"},{"en-US",{{"titleName",text("TITLE")}}}}}};
		} else {
			std::ifstream input(metadata_path);
			if (!input) throw std::runtime_error("Cannot open sce_sys/param.json");
			param = Json::parse(input);
		}
		const auto title = param.at("titleId").get<std::string>();
		if (!std::regex_match(title, std::regex(ps4 ? "CUSA[0-9]{5}" : "PPSA[0-9]{5}")))
			throw std::runtime_error("Invalid title ID for the selected metadata format");
		std::lock_guard lock(mutex);
		// MetadataReaderWriter uses a typed field list, unlike param.json. Keep
		// the constructor's unknown parser/mime IDs until those parsers exist.
		Json fields = Json::array();
		auto field = [&](const char* key, const Json& value) {
			fields.push_back({{"key",key},{"type",value.is_string()?2:0},
			                 {"size",value.is_string()?value.get<std::string>().size()+1:8},{"data",value}});
		};
		if (ps4) {
			for (const auto& [key,value] : sfo) {
				if (const auto* text = std::get_if<std::string>(&value)) field(key.c_str(),*text);
				else field(key.c_str(),std::get<int32_t>(value));
			}
		} else {
			for (auto [source,target] : {std::pair{"titleId","TITLE_ID"}, {"contentId","CONTENT_ID"},
			                             {"contentVersion","APP_VER"}, {"attribute3","ATTRIBUTE3"},
			                             {"attribute","ATTRIBUTE"}, {"applicationCategoryType","APPLICATION_CATEGORY_TYPE"}}) {
				if (param.contains(source) && (param[source].is_string() || param[source].is_number_integer()))
					field(target,param[source]);
			}
			const auto& locales = param.at("localizedParameters");
			const auto language = locales.value("defaultLanguage", "en-US");
			field("TITLE",locales.at(language).at("titleName"));
		}
		field("_metadata_path","/mnt/disc/sce_sys");
		const auto metadata = Json{{"parserId",UINT32_MAX},{"mimeType",UINT32_MAX},
		    {"mimeTypeFormatVersion",0},{"promoterFormatVersion",0},{"field_list",fields}}.dump();
		const auto changed = Catalog(&param); // Commit before notifying readers.
		if (metadata_snapshots.size() >= 16 && !metadata_snapshots.contains(title)) metadata_snapshots.erase(metadata_snapshots.begin());
		metadata_snapshots[title] = metadata;
		LibKernel::FileSystem::Mount(path, "/mnt/disc", true);
		LibKernel::FileSystem::Mount(path, "/mnt/bd", true);
		if (!title_id.empty()) events.emplace_back(87, "{}");
		title_id = title;
		disc_folder = path;
		events.emplace_back(86, Json{{"titleId",title}}.dump());
		NotifyCatalog(changed);
		LOGF("VirtualDisc: mounted %s as %s at /mnt/disc (read-only)\n", Common::PathToGenericString(path).c_str(), title.c_str());
		return true;
	} catch (const std::exception& ex) { if (error) *error = ex.what(); return false; }
}

bool Eject(std::string* error) {
	Common::HostCriticalScope host;
	try {
		std::lock_guard lock(mutex);
		const auto changed = Catalog(nullptr);
		LibKernel::FileSystem::Umount("/mnt/disc"); LibKernel::FileSystem::Umount("/mnt/bd");
		if (!title_id.empty()) events.emplace_back(87, "{}");
		title_id.clear();
		disc_folder.clear();
		NotifyCatalog(changed);
		LOGF("VirtualDisc: ejected\n");
		return true;
	} catch (const std::exception& ex) { if (error) *error = ex.what(); return false; }
}

int Launch(const char* title, int user_id) {
	Common::HostCriticalScope host;
	try {
		if (!title || !std::regex_match(title, std::regex("(PPSA|CUSA)[0-9]{5}"))) return static_cast<int>(0x80940005u);
		std::filesystem::path folder;
		{
			std::lock_guard lock(mutex);
			if (title_id != title || disc_folder.empty()) return LibKernel::KERNEL_ERROR_ENOENT;
			folder = disc_folder;
		}
		auto* rt = Common::Singleton<Loader::RuntimeLinker>::Instance();
		const int result = rt->LaunchApplication(folder, user_id);
		LOGF("VirtualDisc: in-process launch %s user=0x%x result=0x%08x\n", title, user_id, result);
		return result;
	} catch (const std::exception& ex) {
		LOGF("VirtualDisc: launch failed: %s\n", ex.what());
		return LibKernel::KERNEL_ERROR_EIO;
	}
}

std::string MetadataJson(const std::string& title) {
	Common::HostCriticalScope host;
	std::lock_guard lock(mutex);
	const auto found = metadata_snapshots.find(title);
	return found == metadata_snapshots.end() ? std::string() : found->second;
}

std::string InfoJson() {
	Common::HostCriticalScope host;
	std::lock_guard lock(mutex);
	return Json{{"titleId",title_id}}.dump();
}

void ResetCatalog() {
	Common::HostCriticalScope host;
	try { Catalog(nullptr); }
	catch (const std::exception& ex) { LOGF("VirtualDisc: startup cleanup failed: %s\n", ex.what()); }
}

void PumpEvents(bool (*post)(int, const std::string&)) {
	Common::HostCriticalScope host;
	// Called from guest pad polling, so native queue operations run on a guest thread.
	// The native framework subsequently delivers callbacks on its own update thread.
	static std::mutex dispatch_mutex;
	std::unique_lock dispatch(dispatch_mutex, std::try_to_lock);
	if (!dispatch.owns_lock()) return;
	for (;;) {
		std::pair<int,std::string> event;
		{
			std::lock_guard lock(mutex);
			if (events.empty()) return;
			event = events.front();
		}
		if (!(post ? post : LibJson2::PostFrameworkEvent)(event.first,event.second)) return;
		std::lock_guard lock(mutex); events.pop_front();
	}
}
}
