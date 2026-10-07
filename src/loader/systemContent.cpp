#include "loader/systemContent.h"
#include "loader/elf.h"
#include "loader/runtimeLinker.h"
#include <map>
#include <mutex>
#include <memory>

#include "common/assert.h"
#include "common/common.h"
#include "common/file.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "common/threads.h"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

namespace Loader {

std::filesystem::path FindApplicationMetadata(const std::filesystem::path& folder) {
	const auto json = folder / "sce_sys/param.json";
	return std::filesystem::is_regular_file(json) ? json : folder / "sce_sys/param.sfo";
}

SfoFields ReadParamSfo(const std::filesystem::path& file_name) {
	std::ifstream input(file_name, std::ios::binary | std::ios::ate);
	if (!input) throw std::runtime_error("Cannot open sce_sys/param.sfo");
	const auto length = input.tellg();
	if (length < 20 || length > 16 * 1024 * 1024)
		throw std::runtime_error("Invalid param.sfo size");
	std::vector<uint8_t> bytes(static_cast<size_t>(length));
	input.seekg(0);
	if (!input.read(reinterpret_cast<char*>(bytes.data()), bytes.size()))
		throw std::runtime_error("Cannot read param.sfo");
	auto word = [&](size_t offset, size_t width) {
		if (offset > bytes.size() || width > bytes.size() - offset)
			throw std::runtime_error("Truncated param.sfo");
		uint32_t value = 0;
		for (size_t i = 0; i < width; ++i) value |= uint32_t(bytes[offset+i]) << (8*i);
		return value;
	};
	if (word(0,4) != 0x46535000 || word(4,4) != 0x101)
		throw std::runtime_error("Invalid param.sfo signature or version");
	const size_t keys = word(8,4), data = word(12,4), count = word(16,4);
	if (count > (bytes.size()-20)/16 || keys < 20 + count*16 || data < keys || data > bytes.size())
		throw std::runtime_error("Invalid param.sfo tables");
	SfoFields fields;
	for (size_t i = 0; i < count; ++i) {
		const size_t entry = 20 + i*16;
		const size_t key_offset = word(entry,2), format = word(entry+2,2);
		const size_t used = word(entry+4,4), capacity = word(entry+8,4), value_offset = word(entry+12,4);
		if (key_offset >= data-keys || used > capacity || value_offset > bytes.size()-data ||
		    capacity > bytes.size()-data-value_offset)
			throw std::runtime_error("Invalid param.sfo entry bounds");
		const auto key_begin = bytes.begin() + keys + key_offset;
		const auto key_end = std::find(key_begin, bytes.begin()+data, uint8_t(0));
		if (key_end == bytes.begin()+data || key_end == key_begin)
			throw std::runtime_error("Invalid param.sfo key");
		const std::string key(key_begin,key_end);
		if (fields.contains(key)) throw std::runtime_error("Duplicate param.sfo key");
		const size_t offset = data + value_offset;
		if (format == 0x204) {
			if (!used || bytes[offset+used-1] != 0)
				throw std::runtime_error("Unterminated param.sfo string");
			const auto begin = bytes.begin()+offset;
			fields.emplace(key,std::string(begin,std::find(begin,begin+used,uint8_t(0))));
		} else if (format == 0x404) {
			if (used != 4) throw std::runtime_error("Invalid param.sfo integer size");
			fields.emplace(key,static_cast<int32_t>(word(offset,4)));
		} else if (format != 0x004) {
			throw std::runtime_error("Unsupported param.sfo value format");
		}
	}
	return fields;
}

class Psf {
public:
	Psf() = default;
	virtual ~Psf();

	KYTY_CLASS_NO_COPY(Psf);

	void Open(const std::filesystem::path& file_name);
	void OpenChunkDefs(const std::filesystem::path& file_name);
	void Close();

	bool IsValid();

	bool     GetParamInt(const char* name, int32_t* value);
	bool     GetParamString(const char* name, std::string* value);
	bool     GetParamString(const char* name, char* value, size_t value_size);
	uint64_t GetFlexibleMemorySize();

	void DbgPrint();

private:
	enum class ParamType {
		Text,
		Int,
	};

	struct Param {
		std::string name;
		ParamType   type = ParamType::Text;
		std::string string_value;
		std::string string_utf8;
		int32_t     int_value = 0;
	};

	void   OpenJson(const std::filesystem::path& file_name);
	void   AddParamString(const std::string& name, const std::string& value);
	void   AddParamInt(const std::string& name, int32_t value);
	Param* FindParam(const char* name);

	Common::Mutex      m_mutex;
	bool               m_opened = false;
	std::vector<Param> m_params;
	uint64_t           m_flexible_memory_size = 0;
};

class PlayGo {
public:
	PlayGo() = default;
	virtual ~PlayGo();

	KYTY_CLASS_NO_COPY(PlayGo);

	void Open(const std::filesystem::path& file_name);
	void OpenChunkDefs(const std::filesystem::path& file_name);
	void OpenChunkManifest(const std::filesystem::path& file_name);
	void Close();

	bool IsValid();

	bool GetChunksNum(uint32_t* num);

	void DbgPrint();

private:
	Common::File  m_f;
	Common::Mutex m_mutex;
	bool          m_opened     = false;
	uint16_t      m_chunks_num = 0;
};

struct SystemContent {
	uint64_t program_authority_id = 0;
	bool has_program_authority_id = false;
	std::filesystem::path psf_path;
	Psf                   psf;
	std::filesystem::path playgo_path;
	PlayGo                playgo;
	std::filesystem::path icon_path;
};

static std::mutex g_content_mutex;
static std::map<int32_t, std::unique_ptr<SystemContent>> g_application_content;
static SystemContent* CurrentContent() {
	const auto* program = RuntimeLinker::GetCurrentProgram();
	if (program && program->is_application) {
		std::lock_guard lock(g_content_mutex);
		if (auto it = g_application_content.find(program->unique_id); it != g_application_content.end()) return it->second.get();
	}
	return Common::Singleton<SystemContent>::Instance();
}

static SystemContent* ContentForProcess(int32_t pid) {
	if (pid == 0) return CurrentContent();
	if (pid == 100) return Common::Singleton<SystemContent>::Instance();
	std::lock_guard lock(g_content_mutex);
	auto it = g_application_content.find(pid - 0x10000);
	return pid > 0x10000 && it != g_application_content.end() ? it->second.get() : nullptr;
}

bool SystemContentGetProcessAuthorityId(int32_t pid, uint64_t* value) {
	auto* sc = ContentForProcess(pid);
	if (!sc || !value || !sc->has_program_authority_id) return false;
	*value = sc->program_authority_id;
	return true;
}

bool SystemContentGetProcessCategory(int32_t pid, uint32_t* value) {
	auto* sc = ContentForProcess(pid);
	if (!sc || !value) return false;
	int32_t category = 0;
	if (!sc->psf.GetParamInt("APPLICATION_CATEGORY_TYPE", &category)) return false;
	*value = static_cast<uint32_t>(category);
	return true;
}

Psf::~Psf() {
	Close();
}

void Psf::Open(const std::filesystem::path& file_name) {
	Common::LockGuard lock(m_mutex);

	Close();

	if (file_name.extension() == ".sfo") {
		try {
			for (const auto& [key,value] : ReadParamSfo(file_name)) {
				if (const auto* text = std::get_if<std::string>(&value)) AddParamString(key,*text);
				else AddParamInt(key,std::get<int32_t>(value));
			}
			m_opened = true;
		} catch (const std::exception& ex) {
			m_params.clear();
			LOGF("Invalid SFO %s: %s\n", Common::PathToString(file_name).c_str(), ex.what());
		}
	} else OpenJson(file_name);
}

void Psf::OpenJson(const std::filesystem::path& file_name) {
	Common::File f;

	f.Open(file_name, Common::File::Mode::Read);

	if (f.IsInvalid()) {
		LOGF("Can't open %s\n", Common::PathToString(file_name).c_str());
		return;
	}

	auto buf = f.ReadWholeBuffer();
	if (buf.empty()) {
		LOGF("invalid json file: %s\n", Common::PathToString(file_name).c_str());
		f.Close();
		return;
	}

	std::string              default_language;
	std::vector<std::string> localized_languages;
	std::vector<std::string> localized_titles;

	const auto* json_begin = reinterpret_cast<const char*>(buf.data());
	const auto* json_end   = json_begin + buf.size();
	auto        param_json = nlohmann::ordered_json::parse(json_begin, json_end, nullptr, false);
	if (param_json.is_discarded() || !param_json.is_object()) {
		LOGF("invalid json file: %s\n", Common::PathToString(file_name).c_str());
		f.Close();
		return;
	}

	auto add_string_param = [&](const char* json_key, const char* param_key) {
		auto it = param_json.find(json_key);
		if (it != param_json.end() && it->is_string()) {
			AddParamString(param_key, it->get_ref<const std::string&>());
		}
	};

	auto add_int_param = [&](const char* json_key, const char* param_key) {
		auto it = param_json.find(json_key);
		if (it == param_json.end() || !it->is_number_integer()) {
			return;
		}
		int64_t value = 0;
		if (it->is_number_unsigned()) {
			value = static_cast<int64_t>(it->get<uint64_t>());
		} else {
			value = it->get<int64_t>();
		}
		AddParamInt(param_key, static_cast<int32_t>(value));
	};

	add_string_param("titleId", "TITLE_ID");
	add_string_param("contentId", "CONTENT_ID");
	add_string_param("contentVersion", "APP_VER");
	add_string_param("appVersion", "APP_VER");
	add_int_param("attribute3", "ATTRIBUTE3");
	add_int_param("applicationCategoryType", "APPLICATION_CATEGORY_TYPE");
	add_int_param("userDefinedParam1", "USER_DEFINED_PARAM_1");
	add_int_param("userDefinedParam2", "USER_DEFINED_PARAM_2");
	add_int_param("userDefinedParam3", "USER_DEFINED_PARAM_3");
	add_int_param("userDefinedParam4", "USER_DEFINED_PARAM_4");

	if (auto kernel = param_json.find("kernel");
	    kernel != param_json.end() && kernel->is_object()) {
		if (auto it = kernel->find("flexibleMemorySize"); it != kernel->end()) {
			m_flexible_memory_size = it->get<uint64_t>();
		}
	}

	auto localized = param_json.find("localizedParameters");
	if (localized != param_json.end() && localized->is_object()) {
		auto default_it = localized->find("defaultLanguage");
		if (default_it != localized->end() && default_it->is_string()) {
			default_language = default_it->get_ref<const std::string&>();
		}
		for (auto it = localized->begin(); it != localized->end(); ++it) {
			if (!it->is_object()) {
				continue;
			}
			auto title_it = it->find("titleName");
			if (title_it != it->end() && title_it->is_string()) {
				localized_languages.push_back(it.key());
				localized_titles.push_back(title_it->get_ref<const std::string&>());
			}
		}
	}

	std::string title;
	for (size_t i = 0; i < localized_titles.size(); i++) {
		if (!default_language.empty() && localized_languages[i] == default_language) {
			title = localized_titles[i];
			break;
		}
	}
	if (title.empty()) {
		for (size_t i = 0; i < localized_titles.size(); i++) {
			if (localized_languages[i] == "en-US") {
				title = localized_titles[i];
				break;
			}
		}
	}
	if (title.empty() && !localized_titles.empty()) {
		title = localized_titles[0];
	}
	if (!title.empty()) {
		AddParamString("TITLE", title);
	}

	f.Close();
	m_opened = true;
}

void Psf::Close() {
	Common::LockGuard lock(m_mutex);

	m_params.clear();
	m_flexible_memory_size = 0;
	m_opened               = false;
}

bool Psf::IsValid() {
	Common::LockGuard lock(m_mutex);

	return m_opened;
}

void Psf::DbgPrint() {
	Common::LockGuard lock(m_mutex);

	if (!m_opened) {
		return;
	}

	for (const auto& param: m_params) {
		LOGF("%s, ", param.name.c_str());

		switch (param.type) {
			case ParamType::Text: {
				auto str = Common::ReplaceChar(param.string_value, '\n', ',');
				LOGF("string = %s\n", str.c_str());
				break;
			}
			case ParamType::Int:
				LOGF("int = 0x%08" PRIx32 "\n", static_cast<uint32_t>(param.int_value));
				break;
			default: EXIT("unknown type\n");
		}
	}
}

Psf::Param* Psf::FindParam(const char* name) {
	for (auto& param: m_params) {
		if (param.name == name) {
			return &param;
		}
	}

	return nullptr;
}

void Psf::AddParamString(const std::string& name, const std::string& value) {
	auto* param = FindParam(name.c_str());
	if (param == nullptr) {
		m_params.push_back({});
		param       = &m_params.back();
		param->name = name;
	}

	param->type         = ParamType::Text;
	param->string_utf8  = value;
	param->string_value = value;
}

void Psf::AddParamInt(const std::string& name, int32_t value) {
	auto* param = FindParam(name.c_str());
	if (param == nullptr) {
		m_params.push_back({});
		param       = &m_params.back();
		param->name = name;
	}

	param->type      = ParamType::Int;
	param->int_value = value;
}

bool Psf::GetParamInt(const char* name, int32_t* value) {
	Common::LockGuard lock(m_mutex);

	if (!m_opened) {
		return false;
	}
	if (auto* param = FindParam(name); param != nullptr && param->type == ParamType::Int) {
		*value = param->int_value;
		return true;
	}

	return false;
}

bool Psf::GetParamString(const char* name, std::string* value) {
	Common::LockGuard lock(m_mutex);

	if (!m_opened) {
		return false;
	}
	if (auto* param = FindParam(name); param != nullptr && param->type == ParamType::Text) {
		*value = param->string_value;
		return true;
	}

	return false;
}

bool Psf::GetParamString(const char* name, char* value, size_t value_size) {
	Common::LockGuard lock(m_mutex);

	if (!m_opened) {
		return false;
	}
	if (auto* param = FindParam(name); param != nullptr && param->type == ParamType::Text &&
	                                   param->string_utf8.size() + 1 <= value_size) {
		std::memcpy(value, param->string_utf8.c_str(), param->string_utf8.size() + 1);
		return true;
	}

	return false;
}

uint64_t Psf::GetFlexibleMemorySize() {
	Common::LockGuard lock(m_mutex);

	return m_flexible_memory_size;
}

PlayGo::~PlayGo() {
	Close();
}

void PlayGo::Open(const std::filesystem::path& file_name) {
	Common::LockGuard lock(m_mutex);

	Close();

	m_f.Open(file_name, Common::File::Mode::Read);

	if (m_f.IsInvalid()) {
		LOGF("Can't open %s\n", Common::PathToString(file_name).c_str());
		return;
	}

	uint32_t magic1 = 0;

	m_f.Read(&magic1, 4);

	if (magic1 != 0x6f676c70) {
		LOGF("invalid file: magic1 = %08" PRIx32 "\n", magic1);
		return;
	}

	m_f.Seek(10);
	m_f.Read(&m_chunks_num, 2);

	m_opened = true;
}

static bool ParseXmlUintAttr(std::string_view tag, std::string_view attr, uint32_t& value) {
	const auto attr_pos = tag.find(attr);
	if (attr_pos == std::string_view::npos) {
		return false;
	}

	auto pos = attr_pos + attr.size();
	while (pos < tag.size() && (tag[pos] == ' ' || tag[pos] == '\t')) {
		pos++;
	}
	if (pos >= tag.size() || tag[pos] != '=') {
		return false;
	}
	pos++;
	while (pos < tag.size() && (tag[pos] == ' ' || tag[pos] == '\t')) {
		pos++;
	}
	if (pos >= tag.size() || (tag[pos] != '"' && tag[pos] != '\'')) {
		return false;
	}

	const char quote = tag[pos++];
	const auto start = pos;
	while (pos < tag.size() && tag[pos] >= '0' && tag[pos] <= '9') {
		pos++;
	}
	if (start == pos || pos >= tag.size() || tag[pos] != quote) {
		return false;
	}

	uint32_t parsed      = 0;
	const auto [ptr, ec] = std::from_chars(tag.data() + start, tag.data() + pos, parsed);
	if (ec != std::errc {} || ptr != tag.data() + pos) {
		return false;
	}

	value = parsed;
	return true;
}

void PlayGo::OpenChunkDefs(const std::filesystem::path& file_name) {
	Common::LockGuard lock(m_mutex);

	if (m_opened) {
		return;
	}

	Common::File f;
	f.Open(file_name, Common::File::Mode::Read);

	if (f.IsInvalid()) {
		LOGF("Can't open %s\n", Common::PathToString(file_name).c_str());
		return;
	}

	auto buf = f.ReadWholeBuffer();
	f.Close();

	if (buf.empty()) {
		LOGF("invalid file: %s\n", Common::PathToString(file_name).c_str());
		return;
	}

	const std::string_view xml(reinterpret_cast<const char*>(buf.data()), buf.size());

	uint32_t max_chunk_id = 0;
	bool     found        = false;

	if (const auto chunks_pos = xml.find("<chunks"); chunks_pos != std::string_view::npos) {
		const auto tag_end = xml.find('>', chunks_pos);
		if (tag_end != std::string_view::npos) {
			uint32_t default_chunk = 0;
			if (ParseXmlUintAttr(xml.substr(chunks_pos, tag_end - chunks_pos), "default_chunk",
			                     default_chunk)) {
				max_chunk_id = std::max(max_chunk_id, default_chunk);
				found        = true;
			}
		}
	}

	size_t pos = 0;
	while ((pos = xml.find("<chunk", pos)) != std::string_view::npos) {
		const auto name_end = pos + 6;
		if (name_end >= xml.size() || !(xml[name_end] == ' ' || xml[name_end] == '\t' ||
		                                xml[name_end] == '\r' || xml[name_end] == '\n')) {
			pos = name_end;
			continue;
		}

		const auto tag_end = xml.find('>', name_end);
		if (tag_end == std::string_view::npos) {
			break;
		}

		uint32_t chunk_id = 0;
		if (ParseXmlUintAttr(xml.substr(pos, tag_end - pos), "id", chunk_id)) {
			max_chunk_id = std::max(max_chunk_id, chunk_id);
			found        = true;
		}

		pos = tag_end + 1;
	}

	if (!found || max_chunk_id >= 1000) {
		LOGF("invalid playgo chunk definitions: max_chunk_id=%" PRIu32 ", path=%s\n", max_chunk_id,
		     Common::PathToString(file_name).c_str());
		return;
	}

	m_chunks_num = static_cast<uint16_t>(max_chunk_id + 1);
	m_opened     = true;
}

void PlayGo::OpenChunkManifest(const std::filesystem::path& file_name) {
	Common::LockGuard lock(m_mutex);

	if (m_opened) {
		return;
	}

	Common::File f;
	f.Open(file_name, Common::File::Mode::Read);

	if (f.IsInvalid()) {
		LOGF("Can't open %s\n", Common::PathToString(file_name).c_str());
		return;
	}

	auto buf = f.ReadWholeBuffer();
	f.Close();

	constexpr uint8_t id_field[] = {0x08, 'i', 'd', 0x00};
	bool              chunks[1000] {};
	uint32_t          max_chunk_id = 0;
	bool              found        = false;
	const auto*       data         = buf.data();

	for (size_t pos = 0; pos + sizeof(id_field) + sizeof(uint32_t) <= buf.size(); pos++) {
		if (std::memcmp(data + pos, id_field, sizeof(id_field)) != 0) {
			continue;
		}

		const auto* value = data + pos + sizeof(id_field);
		const auto  chunk_id =
		    static_cast<uint32_t>(value[0]) | (static_cast<uint32_t>(value[1]) << 8u) |
		    (static_cast<uint32_t>(value[2]) << 16u) | (static_cast<uint32_t>(value[3]) << 24u);
		if (chunk_id < 1000) {
			chunks[chunk_id] = true;
			max_chunk_id     = std::max(max_chunk_id, chunk_id);
			found            = true;
		}
	}

	if (!found ||
	    !std::all_of(chunks, chunks + max_chunk_id + 1, [](bool chunk) { return chunk; })) {
		LOGF("invalid chunk manifest: path=%s\n", Common::PathToString(file_name).c_str());
		return;
	}

	m_chunks_num = static_cast<uint16_t>(max_chunk_id + 1);
	m_opened     = true;
	LOGF("PlayGo: chunks num = %" PRIu16 " (from %s)\n", m_chunks_num,
	     Common::PathToString(file_name).c_str());
}

void PlayGo::Close() {
	Common::LockGuard lock(m_mutex);

	if (!m_f.IsInvalid()) {
		m_f.Close();
	}
	m_opened     = false;
	m_chunks_num = 0;
}

bool PlayGo::IsValid() {
	Common::LockGuard lock(m_mutex);

	return m_opened;
}

bool PlayGo::GetChunksNum(uint32_t* num) {
	Common::LockGuard lock(m_mutex);

	if (m_opened) {
		*num = m_chunks_num;
		return true;
	}
	return false;
}

void PlayGo::DbgPrint() {
	Common::LockGuard lock(m_mutex);

	if (!m_opened) {
		return;
	}
	LOGF("PlayGo: chunks num = %" PRIu16 "\n", m_chunks_num);
}

static void LoadContent(SystemContent* sc, const std::filesystem::path& file_name) {
	sc->has_program_authority_id = false;
	sc->program_authority_id = 0;

	if (!Common::File::IsFileExisting(file_name)) {
		EXIT("Can't find file: %s\n", Common::PathToString(file_name).c_str());
	}

	sc->psf.Open(file_name);

	if (!sc->psf.IsValid()) {
		EXIT("invalid file: %s\n", Common::PathToString(file_name).c_str());
	}

	sc->psf_path = file_name;
	sc->psf.DbgPrint();

	// A decrypted ELF no longer carries its SELF identity. Read the public
	// extended header of the original eboot alongside sce_sys/param.json.
	// This does not decrypt or load the encrypted executable's segments.
	Common::File self_file;
	self_file.Open(file_name.parent_path().parent_path() / "eboot.bin", Common::File::Mode::Read);
	if (!self_file.IsInvalid() && self_file.Size() >= sizeof(SelfHeader)) {
		SelfHeader self {};
		self_file.Read(&self, sizeof(self));
		const bool magic = std::memcmp(self.ident, "\x54\x14\xf5\xee", 4) == 0 ||
		                   std::memcmp(self.ident, "\x4f\x15\x3d\x1d", 4) == 0;
		const uint64_t elf_offset = sizeof(SelfHeader) + uint64_t(self.segments_num) * sizeof(SelfSegment);
		if (magic && elf_offset + sizeof(Elf64_Ehdr) <= self_file.Size()) {
			Elf64_Ehdr elf {};
			self_file.Seek(elf_offset);
			self_file.Read(&elf, sizeof(elf));
			const uint64_t extended = elf_offset + elf.e_phoff + uint64_t(elf.e_phnum) * sizeof(Elf64_Phdr);
			if (std::memcmp(elf.e_ident, "\x7f" "ELF", 4) == 0 && elf.e_phoff == sizeof(Elf64_Ehdr) &&
			    elf.e_phentsize == sizeof(Elf64_Phdr) && extended + 8 <= self_file.Size() &&
			    extended + 8 <= self.size1) {
				self_file.Seek(extended);
				self_file.Read(&sc->program_authority_id, sizeof(sc->program_authority_id));
				sc->has_program_authority_id = true;
				LOGF("SELF program authority id: 0x%016" PRIx64 "\n", sc->program_authority_id);
			}
		}
	}

	sc->icon_path = file_name.parent_path() / "icon0.png";

	if (!Common::File::IsFileExisting(sc->icon_path)) {
		sc->icon_path.clear();
	}

	sc->playgo_path = file_name.parent_path() / "playgo-chunk.dat";
	sc->playgo.Open(sc->playgo_path);
	if (!sc->playgo.IsValid()) {
		sc->playgo_path = file_name.parent_path().parent_path() / "playgo-chunkdefs.xml";
		sc->playgo.OpenChunkDefs(sc->playgo_path);
	}
	if (!sc->playgo.IsValid()) {
		sc->playgo_path = file_name.parent_path().parent_path() / "Data" / "chunkmanifest";
		sc->playgo.OpenChunkManifest(sc->playgo_path);
	}

	if (sc->playgo.IsValid()) {
		sc->playgo.DbgPrint();
	}
}

void SystemContentLoadParamSfo(const std::filesystem::path& file_name) {
	LoadContent(Common::Singleton<SystemContent>::Instance(), file_name);
}
void SystemContentLoadForProgram(int32_t program_id, const std::filesystem::path& file_name) {
	auto content = std::make_unique<SystemContent>();
	LoadContent(content.get(), file_name);
	std::lock_guard lock(g_content_mutex);
	g_application_content.emplace(program_id, std::move(content));
}

bool SystemContentParamSfoGetInt(const char* name, int32_t* value) {
	if (name == nullptr || value == nullptr) {
		return false;
	}

	auto* sc = CurrentContent();

	return sc->psf.GetParamInt(name, value);
}

bool SystemContentGetProgramAuthorityId(uint64_t* value) {
	auto* sc = CurrentContent();
	if (value == nullptr || !sc->has_program_authority_id) { return false; }
	*value = sc->program_authority_id;
	return true;
}

bool SystemContentParamSfoGetString(const char* name, std::string* value) {
	if (name == nullptr || value == nullptr) {
		return false;
	}

	auto* sc = CurrentContent();

	return sc->psf.GetParamString(name, value);
}

bool SystemContentParamSfoGetString(const char* name, char* value, size_t value_size) {
	if (name == nullptr || value == nullptr) {
		return false;
	}

	auto* sc = CurrentContent();

	return sc->psf.GetParamString(name, value, value_size);
}

uint64_t SystemContentGetFlexibleMemorySize() {
	auto* sc = CurrentContent();

	return sc->psf.GetFlexibleMemorySize();
}

bool SystemContentGetIconPath(std::filesystem::path* path) {
    if (path == nullptr) {
        return false;
    }

    auto* sc = CurrentContent();

    if (sc->icon_path.empty()) {
        return false;
    }

    *path = sc->icon_path;

    return true;
}

bool SystemContentGetChunksNum(uint32_t* num) {
	if (num == nullptr) {
		return false;
	}

	auto* sc = CurrentContent();

	return sc->playgo.GetChunksNum(num);
}

} // namespace Loader
