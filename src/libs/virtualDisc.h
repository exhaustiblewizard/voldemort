#ifndef KYTY_LIBS_VIRTUAL_DISC_H_
#define KYTY_LIBS_VIRTUAL_DISC_H_

#include <filesystem>
#include <string>

namespace Libs::VirtualDisc {
// The selected dump supplies an optical volume; ShellUI's /app0 stays mounted.
bool Insert(const std::filesystem::path& folder, std::string* error);
bool Eject(std::string* error);
// Launch the mounted title alongside ShellUI, with an application-specific /app0.
int Launch(const char* title, int user_id);
// Retain the last inserted title metadata for in-flight reads during eject.
std::string MetadataJson(const std::string& title);
std::string InfoJson();
void ResetCatalog();
// A transport can defer delivery until the native event receiver is ready.
void PumpEvents(bool (*post)(int, const std::string&) = nullptr);
}

namespace Libs::LibJson2 {
bool PostFrameworkEvent(int id, const std::string& json);
}
#endif
