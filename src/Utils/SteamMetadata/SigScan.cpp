#include "SigScan.h"

#include "OSTPlatform/include/PE.h"
#include "Utils/Logging/Log.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <functional>
#include <sstream>
#include <system_error>

namespace SigScan {

namespace {
    int Nibble(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    // Longest run of non-wildcard bytes: used as the search anchor.
    void LongestLiteralRun(const Pattern& pat, size_t& outStart, size_t& outLen)
    {
        outStart = 0; outLen = 0;
        size_t i = 0;
        while (i < pat.mask.size()) {
            if (!pat.mask[i]) { ++i; continue; }
            size_t j = i;
            while (j < pat.mask.size() && pat.mask[j]) ++j;
            if (j - i > outLen) { outStart = i; outLen = j - i; }
            i = j;
        }
    }

    bool MatchAtPtr(const uint8_t* p, const Pattern& pat)
    {
        for (size_t k = 0; k < pat.bytes.size(); ++k)
            if (pat.mask[k] && p[k] != pat.bytes[k]) return false;
        return true;
    }
} // namespace

std::optional<Pattern> Parse(std::string_view sig)
{
    Pattern pat;
    for (size_t i = 0; i < sig.size(); ) {
        const char c = sig[i];
        if (c == ' ' || c == '\t' || c == ',') { ++i; continue; }
        if (c == '?') {
            pat.bytes.push_back(0);
            pat.mask.push_back(0);
            i += (i + 1 < sig.size() && sig[i + 1] == '?') ? 2 : 1;
            continue;
        }
        if (i + 1 >= sig.size()) return std::nullopt;
        const int h = Nibble(sig[i]), l = Nibble(sig[i + 1]);
        if (h < 0 || l < 0) return std::nullopt;
        pat.bytes.push_back(static_cast<uint8_t>((h << 4) | l));
        pat.mask.push_back(1);
        i += 2;
    }
    // Require at least one literal byte, or every position would match.
    if (pat.bytes.empty() || std::find(pat.mask.begin(), pat.mask.end(), 1) == pat.mask.end())
        return std::nullopt;
    return pat;
}

CodeRange GetCodeRange(OSTPlatform::DynamicLibrary::ModuleHandle module,
                       const std::string& dllPath)
{
    CodeRange out;
    if (!module) return out;

    const OSTPlatform::PE::Image image{std::filesystem::path(dllPath)};
    if (!image) {
        LOG_WARN("SigScan: could not parse PE headers of {}", dllPath);
        return out;
    }
    for (const auto& s : image.Sections()) {
        if (s.name == ".text") {
            out.base = reinterpret_cast<const uint8_t*>(module);
            out.rva  = s.virtualAddress;
            out.size = s.virtualSize;
            return out;
        }
    }
    LOG_WARN("SigScan: no .text section in {}", dllPath);
    return out;
}

std::vector<uint32_t> FindAll(const CodeRange& code, const Pattern& pat, size_t limit)
{
    std::vector<uint32_t> hits;
    if (!code || pat.bytes.size() > code.size) return hits;

    size_t anchorOff = 0, anchorLen = 0;
    LongestLiteralRun(pat, anchorOff, anchorLen);

    const uint8_t* const first = code.base + code.rva;
    const uint8_t* const last  = first + code.size;
    const std::boyer_moore_horspool_searcher searcher(
        pat.bytes.begin() + anchorOff, pat.bytes.begin() + anchorOff + anchorLen);

    // Candidates are anchor hits; the full pattern must fit around them.
    const uint8_t* it = first + anchorOff;
    while (it < last) {
        const auto found = searcher(it, last);
        const uint8_t* a = found.first;
        if (a == last) break;
        const uint8_t* start = a - anchorOff;
        if (start + pat.bytes.size() <= last && MatchAtPtr(start, pat)) {
            hits.push_back(static_cast<uint32_t>(start - code.base));
            if (hits.size() >= limit) break;
        }
        it = a + 1;
    }
    return hits;
}

std::optional<uint32_t> FindUnique(const CodeRange& code, const Pattern& pat)
{
    const auto hits = FindAll(code, pat, 2);
    if (hits.size() != 1) return std::nullopt;
    return hits.front();
}

bool MatchesAt(const CodeRange& code, uint32_t rva, const Pattern& pat)
{
    if (!code.Contains(rva, pat.bytes.size())) return false;
    return MatchAtPtr(code.base + rva, pat);
}

std::filesystem::path LocalCachePath(const std::string& dllPath,
                                     std::string_view channel,
                                     std::string_view component,
                                     std::string_view sha256)
{
    namespace fs = std::filesystem;
    return fs::path(dllPath).parent_path() / "opensteamtool" / std::string(channel)
         / std::string(component) / (std::string(sha256) + ".local.toml");
}

std::optional<std::string> ReadFile(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

bool WriteFile(const std::filesystem::path& path, std::string_view body)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    if (ec) {
        LOG_WARN("SigScan: could not create {} ({})", path.parent_path().string(), ec.message());
        return false;
    }
    fs::path tmp = path;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            LOG_WARN("SigScan: could not open {} for writing", tmp.string());
            return false;
        }
        out.write(body.data(), static_cast<std::streamsize>(body.size()));
        if (!out) {
            LOG_WARN("SigScan: write failed for {}", tmp.string());
            return false;
        }
    }
    fs::rename(tmp, path, ec);
    if (ec) {
        // rename onto an existing file can fail on some setups; fall back.
        fs::remove(path, ec);
        fs::rename(tmp, path, ec);
        if (ec) {
            LOG_WARN("SigScan: could not move {} into place ({})", path.string(), ec.message());
            return false;
        }
    }
    return true;
}

} // namespace SigScan
