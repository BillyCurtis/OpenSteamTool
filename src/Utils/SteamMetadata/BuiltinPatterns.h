#pragma once

// Built-in signatures for every function OpenSteamTool resolves, and the IPC
// method metadata.  Replaces the remote pattern / IPC TOML downloads.
//
// Each signature must match exactly once in the module's .text section; an
// ambiguous or missing match disables just that hook.  RIP-relative
// displacements and branch targets are wildcarded so the signatures survive
// code moving between Steam builds.
//
// Verified against steamclient64.dll sha256 253e0a11a4415b38c78a42f7bdd6ecc426455f06c1ba6453a48090df3142dbbc
// and steamui.dll sha256 cd9226db4e6c28942df70c22c0475d91fdd62cba5f100baae2d65af57cabb610
// (RVAs in comments are for those builds).

#include <cstdint>

namespace BuiltinPatterns {

    struct Entry {
        const char* component;   // "steamclient" or "steamui"
        const char* name;        // FindPattern() name
        const char* sig;
    };

    inline constexpr Entry kPatterns[] = {
        // ── steamclient ─────────────────────────────────────────────────
        // 0xD44F70
        { "steamclient", "BBuildAndAsyncSendFrame",
          "48 8B C4 55 48 8D 68 A1 48 81 EC C0 00 00 00 48 89 70 18" },
        // 0x5BCA50
        { "steamclient", "RecvPkt",
          "48 8B C4 55 48 8D A8 E8 FB FF FF 48 81 EC 10 05" },
        // 0xD25640
        { "steamclient", "PchMsgNameFromEMsg",
          "48 89 5C 24 08 57 48 83 EC 20 8B D9 E8 ?? ?? ?? ??" },
        // 0x4D75D0
        { "steamclient", "BuildDepotDependency",
          "48 8B C4 4C 89 48 20 89 50 10 48 89 48 08 55 48 8D A8" },
        // 0x9DE600
        { "steamclient", "CheckAppOwnership",
          "48 8B C4 89 50 10 48 89 48 08 55 53 48 8D 68 D8 48 81 EC 18 01 00 00" },
        // 0x5049C0
        { "steamclient", "DispatchCallbackByAppId",
          "4C 89 4C 24 20 44 89 44 24 18 41 54 41 55 41 56 48 83 EC 50" },
        // 0x993F90  engine per-pipe callback post (pipes.cpp); not 0x8E3DC0
        { "steamclient", "SendCallbackToPipe",
          "48 89 5C 24 08 57 48 83 EC 30 41 8B D9 41 8B F8" },
        // 0xE93A0  4-byte element copy (mov r9d,4); 0x4E0AA0 is the 32-byte one
        { "steamclient", "CUtlMemoryGrow",
          "48 89 5C 24 10 57 48 83 EC 30 8B FA 48 8B D9 8B 51 08 8B 49 10 8D 04 39 "
          "3B C2 0F 8E ?? ?? ?? ?? 2B CA 48 89 74 24 40 8D 34 39 85 F6 7F ?? 4C 8D "
          "05 ?? ?? ?? ?? BA ?? ?? 00 00 48 8D 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 84 "
          "C0 75 ?? FF 15 ?? ?? ?? ?? 84 C0 74 ?? CC 8B 53 0C 8B C2 C1 E8 1F 84 C0 "
          "74 ?? 4C 8D 05 ?? ?? ?? ?? BA ?? ?? 00 00 48 8D 0D ?? ?? ?? ?? FF 15 ?? "
          "?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 84 C0 74 ?? CC 48 8B "
          "74 24 40 01 7B 10 48 8B 5C 24 48 48 83 C4 30 5F C3 8B 4B 08 41 B9 04 00 "
          "00 00" },
        // 0x9EB150
        { "steamclient", "MarkLicenseAsChanged",
          "48 89 5C 24 20 89 54 24 10 55 56 57 48 83 EC 20" },
        // 0x9D53C0
        { "steamclient", "ProcessPendingLicenseUpdates",
          "41 56 41 57 48 83 EC 38 83 B9 C8 24 00 00 00 B8 E0 23 00 00" },
        // 0x4CA430
        { "steamclient", "GetPackageInfo",
          "48 89 5C 24 18 89 54 24 10 55 56 57 48 83 EC 20 44 8B 49 20" },
        // 0x5D95E0
        { "steamclient", "ConfigStoreGetBinary",
          "40 53 55 56 57 48 83 EC 38 48 63 FA 49 8B E9 8B D7 49 8B D8" },
        // 0x8A06C0
        { "steamclient", "IPCProcessMessage",
          "48 89 5C 24 18 48 89 6C 24 20 57 41 54 41 55 41 56 41 57 48 83 EC 30" },
        // 0x8A10B0
        { "steamclient", "GetPipeClient",
          "85 D2 74 ?? 44 0F B7 CA 44 3B 49 60 73 ?? 48 8B 41 40 45 8B C1" },
        // 0x98EE80
        { "steamclient", "GetAppIDForCurrentPipe",
          "8B 81 D0 10 00 00 83 F8 FF 74 49 44 8B 89 D8 00" },
        // 0x9F7470  refs SteamOverlayGameId/SteamGameId, called by SpawnProcess; not 0xA82340
        { "steamclient", "BuildSpawnEnvBlock",
          "4C 89 4C 24 20 4C 89 44 24 18 48 89 54 24 10 48 89 4C 24 08 55 53 56 57 "
          "41 54 41 55 41 56 41 57 48 8D AC 24 B8 FE FF FF" },
        // 0x6048B0
        { "steamclient", "OptedInMask",
          "89 54 24 10 55 53 56 57 41 55 41 56 48 8D AC 24 38 FF FF FF" },
        // 0xCF4760
        { "steamclient", "CUtlBufferEnsureCapacity",
          "48 89 5C 24 08 57 48 83 EC 30 48 8B D9 8D 7A 01" },
        // 0x4C8E50
        { "steamclient", "GetAppDataFromAppInfo",
          "40 53 55 56 57 41 56 41 57 48 81 EC 78 01 00 00" },
        // 0x9F8C60
        { "steamclient", "SpawnProcess",
          "48 89 5C 24 18 4C 89 4C 24 20 48 89 54 24 10 55 56 57 41 54 41 55 41 56 "
          "41 57 48 8D" },
        // 0xD2A860  KeyValues::ReadAsBinary (hook currently disabled)
        { "steamclient", "ReadAsBinary",
          "48 8B C4 44 88 48 20 55 48 8D 68 A9 48 81 EC C0 00 00 00 48 89 70 F0" },
        // 0xD27B70  KeyValues::FindOrCreateKey (hook currently disabled)
        { "steamclient", "FindOrCreateKey",
          "48 8B C4 4C 89 48 20 57 48 81 EC 60 04 00 00 48 89 70 E8 48 8B FA" },
        // 0x4CA190  CAppInfoCache::GetOrAddAppData (hook currently disabled)
        { "steamclient", "GetOrAddAppData",
          "48 83 EC 58 48 8B 05 ?? ?? ?? ?? 48 89 5C 24 68 48 89 6C 24 70" },
        // ── steamui ─────────────────────────────────────────────────────
        // 0x61B230
        { "steamui", "GetAppByID",
          "89 54 24 10 53 48 83 EC 40 48 8B 05 ?? ?? ?? ??" },
        // 0x6A9BA0
        { "steamui", "MarkAppChange",
          "48 83 EC 78 48 8B 05 ?? ?? ?? ?? 48 89 74 24 70" },
        // 0x7054B0
        { "steamui", "RepeatedFieldUint32_Add",
          "48 89 74 24 10 48 89 7C 24 18 41 56 48 83 EC 20 8B 31 48 8B F9 8B 49 04 "
          "4C 8D 34 B5" },
        // 0x6189E0
        { "steamui", "FillInAppOverview",
          "48 89 54 24 10 48 89 4C 24 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D "
          "6C 24 E1 48 81 EC B8 00 00 00" },
        // 0x611CF0
        { "steamui", "BuildCompleteAppOverviewChange",
          "4C 89 44 24 18 48 89 54 24 10 48 89 4C 24 08 55 53 56 57 41 54 41 55 41 "
          "56 41 57 48 8D 6C 24 E1" },
        // 0x6289D0
        { "steamui", "CSteamUIAppControllerRunFrame",
          "48 89 5C 24 10 48 89 6C 24 18 56 57 41 54 41 56 41 57 48 83 EC 40 0F 29 "
          "74 24 30" },
    };

    // IPC method metadata.  funcHash / fencepost are constants compiled into
    // steamclient (both appear in the method's client-side IPC wrapper); they
    // were identical across builds e9045710... and 253e0a11....  Each is
    // re-verified against the DLL before use.
    struct IpcMethod {
        const char* interfaceName;   // must match EIPCInterface
        const char* methodName;
        uint32_t    funcHash;
        uint32_t    fencepost;
        uint32_t    argc;
    };

    inline constexpr IpcMethod kIpcMethods[] = {
        { "IClientUser", "GetSteamID", 0xD6FC3200u, 0xD7058CA5u, 0 },
        { "IClientUser", "GetAppOwnershipTicketExtendedData", 0xC7E71245u, 0xC8449840u, 2 },
        { "IClientUser", "RequestEncryptedAppTicket", 0x25D6BB1Du, 0x2646B663u, 2 },
        { "IClientUser", "GetEncryptedAppTicket", 0xE0468CB4u, 0xE0B80200u, 1 },
        { "IClientUtils", "GetAppID", 0x09607EC4u, 0x0AFE7552u, 0 },
        { "IClientUtils", "GetAPICallResult", 0x2D3D3947u, 0x2EDF5EE6u, 3 },
    };

} // namespace BuiltinPatterns
