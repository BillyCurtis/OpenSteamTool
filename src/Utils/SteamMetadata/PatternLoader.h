#pragma once

#include "OSTPlatform/include/DynamicLibrary.h"

#include <string>

namespace PatternLoader {

    // Resolve every built-in signature for `component` in `module` before
    // installing its hooks.  Reuses the cache file
    // <Steam>\opensteamtool\pattern\<component>\<sha256>.local.toml when it
    // matches this DLL, otherwise scans once and writes it.  Returns false if any signature failed to resolve.
    bool Load(OSTPlatform::DynamicLibrary::ModuleHandle module, const std::string& dllPath, const std::string& component);

    // Address of a function resolved by Load(), or nullptr (and queued for
    // ReportMissingFunctions) if its signature didn't match.
    void* FindPattern(OSTPlatform::DynamicLibrary::ModuleHandle module, const char* funcName);

    // Report unresolved functions after all hooks have been installed.
    void ReportMissingFunctions();

} // namespace PatternLoader
