#pragma once

#include "dllmain.h"

// Catch-all for lightweight info-capture int3 traps and launch-time rewrites
// that don't fit a dedicated category — currently:
//   * GetAppIDForCurrentPipe  -> captures the SteamEngine pointer
//   * SpawnProcess            -> OnlineFix detection + 480 rewrite
//   * GetAppDataFromAppInfo   -> captures the CAppInfoCache pointer
namespace Hooks_Misc {
    void Install();
    void Uninstall();

    // Returns the AppId for the current Steam pipe via the captured engine
    // pointer, or 0 if we haven't yet observed the host calling
    // GetAppIDForCurrentPipe.
    AppId_t GetAppIDForCurrentPipeWrap();

    // True while a -onlinefix game is the active spawn.
    bool IsOnlineFixActive();

    // Call when the game uses SteamNetworkingSockets (IPC interface 46).
    void NotifyNetworkingSocketsUsed();

    // True once P2P started — GetAppID reports 480; before, the real appid.
    bool ShouldReportOnlineFixAppId();

    // Grow a CUtlBuffer to at least 'newCapacity' bytes and set m_Put = newCapacity.
    // Uses CUtlBuffer::EnsureCapacity from steamclient, resolved on first call.
    bool EnsureBufferCapacity(CUtlBuffer* pWrite, uint32 newCapacity,bool updatePut = false);

    // Resolve the real appid: if OnlineFix is active return real appid,
    // otherwise fall back to GetAppIDForCurrentPipe().
    AppId_t ResolveAppId();

    // Select real app identity while forwarding OnlineFix user-stats calls.
    void SetUserStatsContext(HSteamPipe hSteamPipe, bool active);

    // Called on every pipe handshake with the process's raw SteamAppId /
    // SteamGameId env values.  Remembers the -onlinefix game's own pipe: a
    // non-Steam process launched with SteamAppId / SteamGameId 480.  (Not the
    // resolved appid: BuildSpawnEnvBlock sets SteamOverlayGameId to the real
    // app, and ProcessInspector prefers that.)
    void NotifyPipeHandshake(HSteamPipe hSteamPipe, AppId_t envSteamAppId,
                             AppId_t envSteamGameId, bool steamClientProcess);

    // True if IClientUserStats calls on this pipe should get the OnlineFix
    // real-appid treatment: only the game's own pipe, never the overlay or
    // other Steam processes.  False when no -onlinefix game is active.
    bool IsOnlineFixStatsPipe(HSteamPipe hSteamPipe);

    // Same rule, for anything else that should only be spoofed for the game
    // itself (e.g. IClientUtils::GetAppID).
    bool IsOnlineFixGamePipe(HSteamPipe hSteamPipe);

    // Called for every outgoing GamesPlayed with whether it lists 480.  Ends
    // the OnlineFix session once the game has been listed and then isn't.
    void NotifyOnlineFixGamesPlayed(bool lists480);

    // Present real-app stats callbacks through the OnlineFix game identity.
    bool RewriteOnlineFixUserStatsCallback(HSteamPipe hSteamPipe, uint64& gameId);
    bool ShouldRouteOnlineFixUserStatsCallback(AppId_t routeAppId);

    // Get localized game name via GetAppDataFromAppInfo (cached).
    std::string GetGameNameByAppID(AppId_t appId);

}
