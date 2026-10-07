#include "loader/symbolDatabase.h"

#include "common/file.h"

#include <fmt/format.h>
#include <magic_enum.hpp>

namespace Loader {

constexpr char LIB_PREFIX[] = "libSce";

static std::string UpdateName(const std::string& str) {
	return str.starts_with(LIB_PREFIX) ? Common::RemoveFirst(str, 6) : str;
}

static std::string NidKey(const std::string& name, SymbolType type) {
	std::string key(name);
	key.push_back('\0');
	key.push_back(static_cast<char>(type));
	return key;
}

std::string SymbolDatabase::GenerateName(const SymbolResolve& s) {
	auto library = UpdateName(s.library);
	auto module  = UpdateName(s.module);
	return fmt::format("{}[{}_v{}][{}_v{}.{}][{}]", s.name.c_str(), library.c_str(),
	                   s.library_version, module.c_str(), s.module_version_major,
	                   s.module_version_minor, magic_enum::enum_name(s.type));
}

void SymbolDatabase::Add(const SymbolResolve& s, uint64_t vaddr) {
	Add(s, vaddr, "");
}

void SymbolDatabase::Add(const SymbolResolve& s, uint64_t vaddr, const std::string& dbg_name) {
	SymbolRecord r {};
	r.name     = GenerateName(s);
	r.vaddr    = vaddr;
	r.dbg_name = dbg_name;
	r.library  = UpdateName(s.library);
	r.module   = UpdateName(s.module);
	m_map.insert_or_assign(r.name, m_symbols.size());
	m_nid_map[NidKey(s.name, s.type)].push_back(m_symbols.size());
	m_symbols.push_back(r);
}

void SymbolDatabase::DbgDump(const std::string& folder, const std::string& file_name) {
	auto folder_str = Common::FixDirectorySlash(folder);

	Common::File::CreateDirectories(folder_str);

	Common::File f;
	f.Create(folder_str + file_name);

	for (const auto& sym: m_symbols) {
		f.Printf("%" PRIx64 " %s\n", sym.vaddr, sym.name.c_str());
	}

	f.Close();
}

const SymbolRecord* SymbolDatabase::Find(const SymbolResolve& s) const {
	auto it = m_map.find(GenerateName(s));
	if (it == m_map.end()) {
		return nullptr;
	}
	auto index = it->second;
	if (index >= m_symbols.size()) {
		return nullptr;
	}
	return &m_symbols[index];
}

const SymbolRecord* SymbolDatabase::FindByNid(const std::string& nid, SymbolType type,
                                                uint64_t vaddr) const {
	const auto it = m_nid_map.find(NidKey(nid, type));
	if (it == m_nid_map.end()) { return nullptr; }
	for (const auto index: it->second) {
		const auto& symbol = m_symbols[index];
		if (vaddr == 0 || symbol.vaddr == vaddr) {
			return &symbol;
		}
	}

	return nullptr;
}

const SymbolRecord* SymbolDatabase::FindByNid(const SymbolResolve& s) const {
	const auto it = m_nid_map.find(NidKey(s.name, s.type));
	if (it == m_nid_map.end()) { return nullptr; }
	const auto library = UpdateName(s.library);
	const auto module = UpdateName(s.module);
	for (const auto index: it->second) {
		const auto& symbol = m_symbols[index];
		if (symbol.library == library && symbol.module == module) { return &symbol; }
	}
	return nullptr;
}

const SymbolRecord* SymbolDatabase::FindByName(const std::string& name, SymbolType type) const {
	return FindByNid(name, type);
}

} // namespace Loader
