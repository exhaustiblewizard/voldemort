
#include "common/logging/log.h"

#include "common/assert.h"
#include "common/emulatorConfig.h"
#include "common/threads.h"

#include <cstdio>
#include <filesystem>
#include <fmt/format.h>
#include <memory>
#include <mutex>
#include <spdlog/formatter.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/sinks/stdout_sinks.h>
#include <string_view>

namespace {

class RawFormatter final: public spdlog::formatter {
public:
	void format(const spdlog::details::log_msg& msg, spdlog::memory_buf_t& dest) override {
		const std::string_view payload(msg.payload.data(), msg.payload.size());
		dest.append(payload.data(), payload.data() + payload.size());
	}

	std::unique_ptr<spdlog::formatter> clone() const override {
		return std::make_unique<RawFormatter>();
	}
};

std::shared_ptr<spdlog::logger> MakeLogger(std::string name, spdlog::sink_ptr sink) {
	sink->set_formatter(std::make_unique<RawFormatter>());

	auto logger = std::make_shared<spdlog::logger>(std::move(name), std::move(sink));
	logger->set_level(spdlog::level::trace);
	logger->flush_on(spdlog::level::trace);
	return logger;
}

std::shared_ptr<spdlog::logger> MakeFileLogger(std::string                  name,
                                               const std::filesystem::path& path) {
	const auto parent = path.parent_path();
	if (!parent.empty()) {
		std::filesystem::create_directories(parent);
	}

	auto sink =
	    std::make_shared<spdlog::sinks::basic_file_sink_mt>(path.native(), true);
	return MakeLogger(std::move(name), std::move(sink));
}

static bool HasStyle(fmt::text_style style) {
	return style != fmt::text_style {};
}

void WriteStdout(std::string_view text, fmt::text_style style = {}) {
	Common::HostCriticalScope critical;
	if (HasStyle(style)) {
		fmt::print(stdout, style, "{}", text);
	} else {
		std::fwrite(text.data(), 1, text.size(), stdout);
	}
	std::fflush(stdout);
}

} // namespace

namespace Log {

static bool                            g_initialized = false;
static Direction                       g_direction   = Direction::Console;
static std::filesystem::path           g_output_file;
static std::mutex                      g_logger_mutex;
static std::shared_ptr<spdlog::logger> g_logger;

void Flush() {
	Common::HostCriticalScope critical;
	if (g_logger != nullptr) {
		g_logger->flush();
	}
}

static void SetupLogger() {
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_logger_mutex);
	Flush();
	g_logger.reset();

	switch (g_direction) {
		case Direction::Silent:
			g_logger = MakeLogger("kyty", std::make_shared<spdlog::sinks::null_sink_mt>());
			break;
		case Direction::Console:
			g_logger = MakeLogger("kyty", std::make_shared<spdlog::sinks::stdout_sink_mt>());
			break;
		case Direction::File:
			if (!g_output_file.empty()) {
				g_logger = MakeFileLogger("kyty", g_output_file);
			}
			break;
	}
}

static std::shared_ptr<spdlog::logger> GetLogger() {
	Common::HostCriticalScope critical;
	std::lock_guard lock(g_logger_mutex);
	return g_logger;
}

static void WriteImpl(std::string_view text, fmt::text_style style = {}) {
	Common::HostCriticalScope critical;
	if (text.empty()) {
		return;
	}

	if (!g_initialized) {
		WriteStdout(text, style);
		return;
	}

	if (g_direction == Direction::Silent) {
		return;
	}

	auto logger = GetLogger();
	if (!logger) {
		return;
	}

	// Per-thread line assembly. The guest runs many threads that all log through here; because
	// each LOGF/PRINT_NAME is a separate write, their output used to interleave mid-line and
	// become unreadable. We accumulate this thread's text in a thread_local buffer and only emit
	// on a complete line ('\n'), tagging every physical line with the writer's unique thread id.
	// A single logger->log() call is atomic in spdlog's _mt sinks, so no two threads can ever
	// share a physical line, and any interleaving that remains is line-granular and attributable.
	// Newline-less fragments are held until the line is finished (they belong on one line anyway).
	static thread_local std::string line_buffer;
	line_buffer.append(text.data(), text.size());

	const auto tid    = Common::Thread::GetThreadIdUnique();
	const bool styled = (g_direction == Direction::Console && HasStyle(style));

	std::size_t start = 0;
	std::size_t nl    = 0;
	while ((nl = line_buffer.find('\n', start)) != std::string::npos) {
		const std::string_view line(line_buffer.data() + start, nl - start + 1); // incl. '\n'
		std::string            out = fmt::format("[{:>3}] ", tid);
		out.append(line.data(), line.size());
		if (styled) {
			const auto colored = fmt::format(style, "{}", out);
			logger->log(spdlog::level::info, spdlog::string_view_t(colored.data(), colored.size()));
		} else {
			logger->log(spdlog::level::info, spdlog::string_view_t(out.data(), out.size()));
		}
		start = nl + 1;
	}
	line_buffer.erase(0, start); // keep only the unfinished tail for the next write
}

void WriteToConsoleAndLog(std::string_view text) {
	WriteImpl(text);
	if (g_initialized && g_direction != Direction::Console) {
		WriteStdout(text);
	}
	Flush();
}

void WriteFatal(std::string_view text) {
	if (g_direction == Direction::Silent || !g_initialized) {
		WriteStdout(text);
	} else {
		WriteStdout(text);
		WriteImpl(text);
	}
	Flush();
}

void WriteFatal(fmt::text_style style, std::string_view text) {
	if (g_direction == Direction::Silent || !g_initialized) {
		WriteStdout(text, style);
	} else {
		WriteStdout(text, style);
		WriteImpl(text, style);
	}
	Flush();
}

void Initialize() {
	g_initialized = true;
	switch (Config::GetPrintfDirection()) {
		case Config::LogDirection::Silent: g_direction = Direction::Silent; break;
		case Config::LogDirection::Console: g_direction = Direction::Console; break;
		case Config::LogDirection::File: g_direction = Direction::File; break;
	}
	g_output_file =
	    (g_direction == Direction::File ? Config::GetPrintfOutputFile() : std::filesystem::path {});
	SetupLogger();
}

void Shutdown() {
	Common::HostCriticalScope critical;
	Flush();
	std::lock_guard lock(g_logger_mutex);
	g_logger.reset();
}

Direction GetDirection() {
	EXIT_IF(!g_initialized);
	return g_direction;
}

bool IsSilent() {
	// Before init LOGF must keep writing to stdout, so report non-silent.
	return g_initialized && g_direction == Direction::Silent;
}

void Write(std::string_view text) {
	WriteImpl(text);
}

void Write(fmt::text_style style, std::string_view text) {
	WriteImpl(text, style);
}

} // namespace Log
