#pragma once

#include "OSTPlatform/include/DynamicLibrary.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// Local, offline replacement for the remote pattern / IPC TOML downloads.
//
// Signatures are IDA-style ("48 8B ?? 05"), scanned against the module's
// in-memory .text section.  Results are cached per DLL build in
//   <Steam>\opensteamtool\<channel>\<component>\<sha256>.local.toml
// so the scan only runs the first time a new steamclient / steamui is seen.
namespace SigScan {

    struct Pattern {
        std::vector<uint8_t> bytes;
        std::vector<uint8_t> mask;   // 1 = must match, 0 = wildcard
    };

    std::optional<Pattern> Parse(std::string_view sig);

    // The module's .text section as mapped in memory (rva = offset from the
    // module base).  Empty span if the section can't be located.
    struct CodeRange {
        const uint8_t* base = nullptr;   // module base
        uint32_t       rva  = 0;         // .text start
        uint32_t       size = 0;
        std::span<const uint8_t> Bytes() const { return {base + rva, size}; }
        bool Contains(uint32_t r, size_t len) const {
            return size && r >= rva && r + len <= static_cast<uint64_t>(rva) + size;
        }
        explicit operator bool() const { return base && size; }
    };

    CodeRange GetCodeRange(OSTPlatform::DynamicLibrary::ModuleHandle module,
                           const std::string& dllPath);

    // RVAs of up to `limit` matches inside the code range.
    std::vector<uint32_t> FindAll(const CodeRange& code, const Pattern& pat, size_t limit = 2);

    // Exactly one match, or nullopt (none, or ambiguous).
    std::optional<uint32_t> FindUnique(const CodeRange& code, const Pattern& pat);

    // True if `pat` matches at `rva`.
    bool MatchesAt(const CodeRange& code, uint32_t rva, const Pattern& pat);

    // <Steam>\opensteamtool\<channel>\<component>\<sha256>.local.toml
    std::filesystem::path LocalCachePath(const std::string& dllPath,
                                         std::string_view channel,
                                         std::string_view component,
                                         std::string_view sha256);

    std::optional<std::string> ReadFile(const std::filesystem::path& path);

    // Write via a temp file + rename so a crash never leaves a half file.
    bool WriteFile(const std::filesystem::path& path, std::string_view body);

} // namespace SigScan
