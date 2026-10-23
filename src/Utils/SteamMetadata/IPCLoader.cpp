#include "IPCLoader.h"
#include "IPCMessages.gen.h"
#include "OSTPlatform/include/Numbers.h"
#include "Utils/Logging/Log.h"
#include "Utils/Support/FnvHash.h"
#include "Utils/SteamMetadata/BuiltinPatterns.h"
#include "Utils/SteamMetadata/SigScan.h"
#include "Utils/SteamMetadata/SteamDiagnostics.h"

#include <cstdio>
#include <filesystem>
#include <cstring>
#include <iterator>
#include <map>
#include <unordered_map>
#include <utility>

#include <toml++/toml.hpp>

namespace IPCLoader {

namespace {

    struct Registry {
        std::vector<Interface> interfaces;
        std::unordered_map<EIPCInterface, size_t> byID;
        std::unordered_map<std::string, size_t> byName;

        void Clear()
        {
            interfaces.clear();
            byID.clear();
            byName.clear();
        }

        void Add(Interface iface)
        {
            const size_t index = interfaces.size();
            byID[iface.id] = index;
            byName[iface.name] = index;
            interfaces.push_back(std::move(iface));
        }

        const Method* Find(EIPCInterface interfaceID, uint32_t funcHash) const
        {
            const auto it = byID.find(interfaceID);
            if (it == byID.end()) return nullptr;

            for (const auto& method : interfaces[it->second].methods) {
                if (method.funcHash == funcHash) return &method;
            }
            return nullptr;
        }

        const Method* Find(std::string_view interfaceName,
                           std::string_view methodName) const
        {
            const auto it = byName.find(std::string(interfaceName));
            if (it == byName.end()) return nullptr;

            for (const auto& method : interfaces[it->second].methods) {
                if (method.name == methodName) return &method;
            }
            return nullptr;
        }

        size_t MethodCount() const
        {
            size_t count = 0;
            for (const auto& iface : interfaces)
                count += iface.methods.size();
            return count;
        }
    };

    Registry g_registry;

    // ---- TOML helpers ----

    static bool ParseHexU32(std::string_view s, uint32_t& out)
    {
        const auto parsed = OSTPlatform::Numbers::ParseHexUInt32(s);
        if (!parsed) return false;
        out = *parsed;
        return true;
    }

    static bool ParseInterfaceTable(std::string_view name,
                                    const toml::table& tbl,
                                    Interface& out)
    {
        out.name = std::string(name);

        const auto expected = EIPCInterfaceFromName(name);
        if (!expected) {
            LOG_WARN("IPCLoader: [{}] is not declared in EIPCInterface", name);
            return false;
        }
        out.id = *expected;

        // Backward-compatible metadata: EIPCInterface is authoritative.
        if (auto v = tbl["interface_id"].value<int64_t>()) {
            if (*v < 0 || *v > 0xFF) {
                LOG_WARN("IPCLoader: [{}] interface_id out of range ({})", name, *v);
                return false;
            }
            if (static_cast<EIPCInterface>(*v) != out.id) {
                LOG_WARN("IPCLoader: [{}] interface_id {} disagrees with generated EIPCInterface value {}",
                         name, *v, static_cast<uint8_t>(out.id));
                return false;
            }
        }

        if (auto v = tbl["vtable_rva"].value<std::string>())
            ParseHexU32(*v, out.vtableRva);

        // Walk dotted sub-tables — each is a method.
        for (auto& [methodKey, methodVal] : tbl) {
            if (!methodVal.is_table()) continue;
            const auto& mtbl = *methodVal.as_table();

            Method m;
            m.interfaceID = out.id;
            m.name = std::string(methodKey.str());

            if (auto v = mtbl["funcHash"].value<std::string>()) {
                if (!ParseHexU32(*v, m.funcHash)) {
                    LOG_WARN("IPCLoader: [{}.{}] bad funcHash '{}'",
                             name, m.name, *v);
                    continue;
                }
            } else {
                LOG_WARN("IPCLoader: [{}.{}] missing funcHash", name, m.name);
                continue;
            }

            if (auto v = mtbl["fencepost"].value<std::string>())
                ParseHexU32(*v, m.fencepost);
            if (auto v = mtbl["argc"].value<int64_t>())
                m.argc = static_cast<uint32_t>(*v);
            out.methods.push_back(std::move(m));
        }
        return true;
    }

    static std::string Hex32(uint32_t v)
    {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "0x%08X", v);
        return buf;
    }

    // Bump when the cache file layout or verification rule changes.
    constexpr uint32_t kCacheFormat = 1;

    static uint32_t TableVersion()
    {
        std::string blob = "ipc-format=" + std::to_string(kCacheFormat) + ";";
        for (const auto& m : BuiltinPatterns::kIpcMethods) {
            blob += m.interfaceName; blob += '.'; blob += m.methodName; blob += '=';
            blob += Hex32(m.funcHash) + "/" + Hex32(m.fencepost) + "/" + std::to_string(m.argc) + ";";
        }
        return Fnv1aHash(blob.c_str());
    }

    // funcHash and fencepost are both immediates in the method's client-side
    // IPC wrapper.  Require them within a few hundred bytes of each other, so
    // a method Valve renumbered is dropped instead of mis-decoding messages.
    static bool VerifyAgainstDll(const SigScan::CodeRange& code, const BuiltinPatterns::IpcMethod& m)
    {
        constexpr uint32_t kWindow = 0x400;
        SigScan::Pattern hashPat;
        hashPat.bytes.resize(4);
        std::memcpy(hashPat.bytes.data(), &m.funcHash, 4);
        hashPat.mask.assign(4, 1);

        uint8_t fence[4];
        std::memcpy(fence, &m.fencepost, 4);

        const auto hits = SigScan::FindAll(code, hashPat, 32);
        const uint32_t codeEnd = code.rva + code.size;
        for (const uint32_t hit : hits) {
            const uint32_t lo = hit > code.rva + kWindow ? hit - kWindow : code.rva;
            const uint32_t hi = hit + kWindow + 4 < codeEnd ? hit + kWindow + 4 : codeEnd;
            for (uint32_t r = lo; r + 4 <= hi; ++r)
                if (std::memcmp(code.base + r, fence, 4) == 0) return true;
        }
        return false;
    }

    // Same layout the remote files used, so the parser below is unchanged.
    static std::string BuildCacheToml(const std::string& sha256, uint32_t version,
                                      const std::vector<const BuiltinPatterns::IpcMethod*>& verified)
    {
        std::map<std::string, std::vector<const BuiltinPatterns::IpcMethod*>> byIface;
        for (const auto* m : verified) byIface[m->interfaceName].push_back(m);

        std::string out;
        out += "# Generated by OpenSteamTool from its built-in IPC metadata, verified\n";
        out += "# against this steamclient build. Safe to delete: rebuilt on next start.\n";
        out += "generator_version = \"" + Hex32(version) + "\"\n";
        out += "sha256 = \"" + sha256 + "\"\n";
        for (const auto& [iface, methods] : byIface) {
            const auto id = EIPCInterfaceFromName(iface);
            out += "\n[" + iface + "]\n";
            if (id) out += "interface_id = " + std::to_string(static_cast<int>(*id)) + "\n";
            for (const auto* m : methods) {
                out += "\n[" + iface + "." + m->methodName + "]\n";
                out += "funcHash = \"" + Hex32(m->funcHash) + "\"\n";
                out += "fencepost = \"" + Hex32(m->fencepost) + "\"\n";
                out += "argc = " + std::to_string(m->argc) + "\n";
            }
        }
        return out;
    }

    static bool ParseRegistry(const std::string& body)
    {
        toml::table root;
        try {
            root = toml::parse(body);
        } catch (const toml::parse_error& e) {
            LOG_WARN("IPCLoader: TOML parse error: {}", e.description());
            return false;
        }
        for (auto& [key, val] : root) {
            if (!val.is_table()) continue;
            Interface iface;
            if (!ParseInterfaceTable(key.str(), *val.as_table(), iface)) continue;
            g_registry.Add(std::move(iface));
        }
        return true;
    }

} // namespace

constexpr const char* kIPCChannel = "ipc";

bool Load(OSTPlatform::DynamicLibrary::ModuleHandle module, const std::string& steamclientPath)
{
    g_registry.Clear();

    const uint32_t version = TableVersion();
    const std::string sha256 = SteamDiagnostics::Sha256Of(steamclientPath);
    const auto cachePath = sha256.empty()
        ? std::filesystem::path{}
        : SigScan::LocalCachePath(steamclientPath, kIPCChannel, "steamclient", sha256);

    // 1. Cached result for this exact steamclient build.
    if (!cachePath.empty()) {
        if (const auto body = SigScan::ReadFile(cachePath)) {
            bool current = false;
            try {
                current = toml::parse(*body)["generator_version"].value<std::string>()
                              .value_or("") == Hex32(version);
            } catch (const toml::parse_error&) {}
            if (current && ParseRegistry(*body)) {
                LOG_INFO("IPCLoader: loaded {} methods across {} interfaces (local cache)",
                         MethodCount(), InterfaceCount());
                return MethodCount() != 0;
            }
            g_registry.Clear();
        }
    }

    // 2. Verify the built-in table against the DLL, then cache it.
    const SigScan::CodeRange code = SigScan::GetCodeRange(module, steamclientPath);
    if (!code) {
        LOG_ERROR("IPCLoader: could not locate steamclient code section; IPC handlers disabled");
        return false;
    }

    std::vector<const BuiltinPatterns::IpcMethod*> verified;
    for (const auto& m : BuiltinPatterns::kIpcMethods) {
        if (VerifyAgainstDll(code, m)) {
            verified.push_back(&m);
        } else {
            LOG_WARN("IPCLoader: {}::{} funcHash {} / fencepost {} not found in this steamclient; "
                     "handler disabled", m.interfaceName, m.methodName, Hex32(m.funcHash), Hex32(m.fencepost));
        }
    }

    const std::string body = BuildCacheToml(sha256, version, verified);
    if (!ParseRegistry(body)) return false;

    if (!cachePath.empty() && !verified.empty() && SigScan::WriteFile(cachePath, body))
        LOG_INFO("IPCLoader: wrote {}", cachePath.string());

    LOG_INFO("IPCLoader: loaded {} methods across {} interfaces ({} of {} verified)",
             MethodCount(), InterfaceCount(), verified.size(), std::size(BuiltinPatterns::kIpcMethods));
    return MethodCount() != 0;
}

const Method* Find(EIPCInterface interfaceID, uint32_t funcHash)
{
    return g_registry.Find(interfaceID, funcHash);
}

const Method* Find(std::string_view ifaceName, std::string_view methodName)
{
    return g_registry.Find(ifaceName, methodName);
}

size_t InterfaceCount() 
{ 
    return g_registry.interfaces.size();
}

size_t MethodCount() {
    return g_registry.MethodCount();
}

} // namespace IPCLoader
