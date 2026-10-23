#include "Hooks_Misc.h"
#include "HookMacros.h"
#include "Utils/HookSupport/VehCommon.h"
#include "dllmain.h"

namespace {
    // ── Resolve-only functions ─────────────────────────────────────
    RESOLVE_FUNC(CUtlBufferEnsureCapacity, void*, CUtlBuffer* pCUtlBuffer, uint32 newCapacity);

    // ── VEH-captured functions (one-shot int3) ───────────────────────────────
    // On int3 hit, ctx->Rcx is stored to the named output variable.
    //CAPTURE_THIS_FUNC(GetAppIDForCurrentPipe, AppId_t,      g_steamEngine,    void*);
    CAPTURE_THIS_FUNC(GetAppDataFromAppInfo,  int64,        g_pCAppInfoCache, void*, AppId_t, const char*, uint8*, int32);

    // Assumes one game at a time.  Set by SpawnProcess VEH when -onlinefix
    // is detected; cleared when a non-onlinefix game launches.
    AppId_t   g_OnlineFixRealAppId;
    void*     g_steamEngine = nullptr;
    HSteamPipe g_OnlineFixUserStatsPipe = 0;
    // The -onlinefix game's own pipe, from its handshake (SteamAppId=480).
    HSteamPipe g_OnlineFixGamePipe = 0;
    thread_local uint32 g_userStatsAppIdOverrideDepth = 0;
    // True once the game starts SteamNetworkingSockets P2P (see GetAppID handler).
    bool      g_NetworkingSocketsActive;
    // True once GamesPlayed has listed 480 for this -onlinefix launch; the
    // session ends when a later GamesPlayed no longer does.
    bool      g_OnlineFixSeenRunning = false;
    std::unordered_map<AppId_t, std::string> g_GameNameCache;


    // ── SpawnProcess interception ────────────────────────────────────────────
    // CUser_SpawnProcess(pCUser, pExePath, pCommandLine, pWorkingDir,
    //                    pGameID, ...)
    // arg1=pCUser, arg2=pExePath, arg3=pCommandLine, arg4=pWorkingDir
    // arg5=pGameID (CGameID*; low 24 bits = AppId)
    static void OnSpawnProcessHit(OSTPlatform::Trap::Context& ctx, const VehCommon::Int3Site& /*site*/) {
        CGameID* pGameID = VehCommon::GetArg<CGameID*>(ctx, 5);
        AppId_t appId = static_cast<AppId_t>(pGameID->AppID(true));
        const char* cmdLine = VehCommon::GetArg<const char*>(ctx, 3);

        if (LuaConfig::HasDepot(appId) && cmdLine && strstr(cmdLine, "-onlinefix")) 
        {
            g_OnlineFixRealAppId = appId;
            g_OnlineFixUserStatsPipe = 0;
            g_OnlineFixGamePipe = 0;
            g_NetworkingSocketsActive = false;
            g_OnlineFixSeenRunning = false;
            pGameID->SetAppID(kOnlineFixAppId);
            LOG_MISC_INFO("SpawnProcess: appid {} -> {}, cmd=\"{}\"",appId, kOnlineFixAppId, cmdLine);
        } else {
            g_OnlineFixRealAppId = 0;
            g_OnlineFixUserStatsPipe = 0;
            g_OnlineFixGamePipe = 0;
            g_OnlineFixSeenRunning = false;
        }
    }

    // ── GetAppIDForCurrentPipe ───────────────────────────────────────────────
    HOOK_FUNC(GetAppIDForCurrentPipe, AppId_t, void* pEngine)
    {
        g_steamEngine = pEngine;
        const AppId_t appId = oGetAppIDForCurrentPipe(pEngine);
        if (g_userStatsAppIdOverrideDepth && g_OnlineFixRealAppId
            && appId == kOnlineFixAppId) {
            LOG_MISC_TRACE("GetAppIDForCurrentPipe: user-stats OnlineFix AppId={} -> {}",
                           appId, g_OnlineFixRealAppId);
            return g_OnlineFixRealAppId;
        }
        return appId;
    }

    // ── SteamController_OptedInMask ──────────────────────────────────────────
    // Called by CUser_BuildSpawnEnvBlock with pGameID's appid to
    // compute EnableConfiguratorSupport and the SDL_* env vars.
    // With 480 the spawned game inherits Spacewar's Steam Input
    // opt-in and gameoverlayrenderer hijacks the XInput stream.
    HOOK_FUNC(OptedInMask, int64,void* pThis, AppId_t appId)
    {
        if (appId == kOnlineFixAppId && g_OnlineFixRealAppId) {
            LOG_MISC_INFO("OptedInMask: appid {} -> {}",appId, g_OnlineFixRealAppId);
            appId = g_OnlineFixRealAppId;
        }
        return oOptedInMask(pThis, appId);
    }

    // ── CUser_BuildSpawnEnvBlock ─────────────────────────────────────────────
    // pOverlayCGameID drives SteamOverlayGameId, which the in-game
    // overlay reads for screenshot tags, community URLs, and asset
    // selection.  pCGameID drives SteamGameId / SteamAppId; leave it
    // at 480 so the in-game ownership bypass holds.
    HOOK_FUNC(BuildSpawnEnvBlock, int64,
              void* pThis, CGameID* pCGameID, void* a3, void* env,
              CGameID* pOverlayCGameID, void* a6, int a7,
              void* a8, void* a9, unsigned int a10, char a11)
    {
        if (g_OnlineFixRealAppId && pOverlayCGameID
            && pOverlayCGameID->AppID(true) == kOnlineFixAppId) 
        {
            LOG_MISC_INFO("BuildSpawnEnvBlock: SetAppID in OverlayCGameID {} -> {}",
                          pOverlayCGameID->AppID(true), g_OnlineFixRealAppId);
            pOverlayCGameID->SetAppID(g_OnlineFixRealAppId);
        }
        return oBuildSpawnEnvBlock(pThis, pCGameID, a3, env,
                                    pOverlayCGameID, a6, a7,
                                    a8, a9, a10, a11);
    }

    // ── Local playtime (localconfig Playtime / Playtime2wks / LastPlayed) ──
    // CUser keys its minutes-played bookkeeping by the running CGameID's
    // appid, which SpawnProcess rewrote to 480, so -onlinefix sessions were
    // credited to Spacewar.  Remap 480 -> real AppId in the three places that
    // take that appid:
    //   GetAppMinutesPlayedData  session start / pause / resume / stop, totals
    //   SaveAppMinutesPlayed     writes Apps\<id>\Playtime* to localconfig
    //   SetAppLastPlayedTime     writes Apps\<id>\LastPlayed + UI callback
    // Server-side playtime is not involved: Steam doesn't count it for
    // unowned apps, with or without -onlinefix.
    //
    // Server-sent playtimes (ApplyServerPlaytimes) are excluded: they carry
    // their own appid, and remapping them copied Spacewar's totals over.
    //
    // Signatures for all four are in Utils/SteamMetadata/BuiltinPatterns.h.

    // >0 while steamclient applies the server's per-app playtime list.  Those
    // entries are keyed by their own appid, so 480 there is Spacewar's real
    // server playtime and must not be remapped onto the -onlinefix game.
    thread_local uint32 g_serverPlaytimeDepth = 0;

    static AppId_t RemapOnlineFixPlaytimeAppId(AppId_t appId) {
        if (g_serverPlaytimeDepth) return appId;
        return (appId == kOnlineFixAppId && g_OnlineFixRealAppId) ? g_OnlineFixRealAppId : appId;
    }

    // CUser::ApplyServerPlaytimes(this, entries[], count) (unnamed in binary,
    // RVA 0x9EEE50).  Copies Player.ClientGetLastPlayedTimes results into the
    // records via SetAppLastPlayedTime / GetAppMinutesPlayedData / Save.
    // Returns the newest last-played time.
    HOOK_FUNC(ApplyServerPlaytimes, uint32, void* pUser, void** ppEntries, int32 count)
    {
        ++g_serverPlaytimeDepth;
        const uint32 result = oApplyServerPlaytimes(pUser, ppEntries, count);
        --g_serverPlaytimeDepth;
        return result;
    }

    // CUser::GetAppMinutesPlayedData(this, appId, bCreate) -> per-app record
    HOOK_FUNC(GetAppMinutesPlayedData, void*, void* pUser, AppId_t appId, bool bCreate)
    {
        return oGetAppMinutesPlayedData(pUser, RemapOnlineFixPlaytimeAppId(appId), bCreate);
    }

    // CUser::SaveAppMinutesPlayed(this, appId, pRecord) (unnamed in binary)
    HOOK_FUNC(SaveAppMinutesPlayed, void, void* pUser, AppId_t appId, void* pRecord)
    {
        const AppId_t mapped = RemapOnlineFixPlaytimeAppId(appId);
        if (mapped != appId)
            LOG_MISC_INFO("SaveAppMinutesPlayed: appid {} -> {}", appId, mapped);
        oSaveAppMinutesPlayed(pUser, mapped, pRecord);
    }

    // CUser::SetAppLastPlayedTime(this, appId, rtLastPlayed)
    HOOK_FUNC(SetAppLastPlayedTime, void, void* pUser, AppId_t appId, uint32 rtLastPlayed)
    {
        const AppId_t mapped = RemapOnlineFixPlaytimeAppId(appId);
        if (mapped != appId)
            LOG_MISC_INFO("SetAppLastPlayedTime: appid {} -> {} (rt={})", appId, mapped, rtLastPlayed);
        oSetAppLastPlayedTime(pUser, mapped, rtLastPlayed);
    }

    // CAppInfoCache::GetOrAddAppData
    // The injected package keeps Lua-provided ids in PackageInfo::AppIdVec.
    // Some of those ids can actually be depot ids, but we cannot trust the
    // Lua config to classify app ids and depot ids for us. In offline mode,
    // depot ids usually have only placeholder appinfo data. That blocks
    // CClientAppManager_ProcessPendingLicenseUpdates, because it waits for
    // every AppIdVec entry to have resolved appinfo unless the entry has been
    // marked as a known-unknown id by the PICS path. For injected ids that
    // still have placeholder appinfo, set skip_flag so Steam treats them like
    // PICS unknown_appids instead of keeping the license update pending.
    HOOK_FUNC(GetOrAddAppData,CAppData*,void* pCache, AppId_t appId,bool bCreate)
    {
        CAppData* pData = oGetOrAddAppData(pCache, appId, bCreate);
        // LOG_MISC_TRACE("GetOrAddAppData: appId={} bCreate={} -> pData={}", appId, bCreate, pData ? pData->DebugString() : "null");
        // TODO: find a more robust way
        if (LuaConfig::HasDepot(appId, false) && pData && !bCreate && pData->IsUnresolvedAppInfo()) {
            LOG_MISC_DEBUG("GetOrAddAppData: Marking appId {} as skip_flag=true to bypass license update blocking", appId);
            pData->bSkipFlag = true;
        }
        return pData;
    }
}

namespace Hooks_Misc {
    void Install() {
        RESOLVE_C(CUtlBufferEnsureCapacity);

        //ARM_CAPTURE_C(GetAppIDForCurrentPipe);
        ARM_CAPTURE_C(GetAppDataFromAppInfo);

        ARM_INT3_C(SpawnProcess, true, &OnSpawnProcessHit, nullptr);

        HOOK_BEGIN();
        INSTALL_HOOK_D(GetAppIDForCurrentPipe);
        INSTALL_HOOK_C(BuildSpawnEnvBlock);
        INSTALL_HOOK_C(OptedInMask);
        INSTALL_HOOK_C(GetAppMinutesPlayedData);
        INSTALL_HOOK_C(SaveAppMinutesPlayed);
        INSTALL_HOOK_C(SetAppLastPlayedTime);
        INSTALL_HOOK_C(ApplyServerPlaytimes);
        // INSTALL_HOOK_C(GetOrAddAppData);
        HOOK_END();
    }

    void Uninstall() {
        UNHOOK_BEGIN();
        UNINSTALL_HOOK(GetAppIDForCurrentPipe);
        UNINSTALL_HOOK(BuildSpawnEnvBlock);
        UNINSTALL_HOOK(OptedInMask);
        UNINSTALL_HOOK(GetAppMinutesPlayedData);
        UNINSTALL_HOOK(SaveAppMinutesPlayed);
        UNINSTALL_HOOK(SetAppLastPlayedTime);
        UNINSTALL_HOOK(ApplyServerPlaytimes);
        // UNINSTALL_HOOK(GetOrAddAppData);
        UNHOOK_END();
    }

    AppId_t GetAppIDForCurrentPipeWrap() {
        if (!g_steamEngine || !oGetAppIDForCurrentPipe) {
            LOG_MISC_WARN("GetAppIDForCurrentPipeWrap called before hook — returning 0");
            return 0;
        }
        auto appid = oGetAppIDForCurrentPipe(g_steamEngine);
        if (!appid) {
            LOG_MISC_TRACE("GetAppIDForCurrentPipeWrap: AppId=0(Not GamePipe)");
        } else {
            LOG_MISC_TRACE("GetAppIDForCurrentPipeWrap: AppId={}", appid);
        }
        return appid;
    }

    
    AppId_t ResolveAppId() {
        if (g_OnlineFixRealAppId) return g_OnlineFixRealAppId;
        return GetAppIDForCurrentPipeWrap();
    }

    bool IsOnlineFixActive() {
        return g_OnlineFixRealAppId != 0;
    }

    void NotifyNetworkingSocketsUsed() {
        if (g_OnlineFixRealAppId && !g_NetworkingSocketsActive) {
            g_NetworkingSocketsActive = true;
            LOG_MISC_INFO("NetworkingSockets active: GetAppID now reports 480 for cert match");
        }
    }

    bool ShouldReportOnlineFixAppId() {
        return g_OnlineFixRealAppId != 0 && g_NetworkingSocketsActive;
    }

    bool EnsureBufferCapacity(CUtlBuffer* pWrite, uint32 newCapacity,bool updatePut)
    {
        if (oCUtlBufferEnsureCapacity) {
            LOG_MISC_DEBUG("Before ensuring CUtlBuffer capacity: {}", pWrite->DebugString());
            oCUtlBufferEnsureCapacity(pWrite, newCapacity);
            LOG_MISC_DEBUG("After ensuring CUtlBuffer capacity: {}", pWrite->DebugString());
            if(updatePut) pWrite->m_Put = newCapacity;
            return true;
        }
        LOG_MISC_WARN("EnsureBufferCapacity: oCUtlBufferEnsureCapacity not resolved");
        return false;
    }

    // ── Game name ────────────────────────────────────────────────
    std::string GetGameNameByAppID(AppId_t appId)
    {
        auto it = g_GameNameCache.find(appId);
        if (it != g_GameNameCache.end()) return it->second;

        std::string name;

        if (CAPTURE_READY(GetAppDataFromAppInfo)) {
            char buf[256] = {};
            // "common/name" triggers auto-localization: the function detects
            // prefix "common" (keyType=2) + key "name", then tries
            // "name_localized/<current_lang>" before falling back to "name".
            // Returns strlen+1 on success, -1 on failure.
            int64 len = oGetAppDataFromAppInfo(g_pCAppInfoCache, appId, "common/name",
                reinterpret_cast<uint8*>(buf), sizeof(buf));
            if (len > 1)
                name.assign(buf, static_cast<size_t>(len - 1));
        }

        LOG_MISC_DEBUG("GetGameNameByAppID({}): {}", appId, name);
        // Don't cache misses: appinfo may not be loaded yet (or the capture
        // hasn't fired), and a cached "" would keep the name blank forever.
        if (!name.empty()) g_GameNameCache[appId] = name;
        return name;
    }

    void SetUserStatsContext(HSteamPipe hSteamPipe, bool active)
    {
        if (active) {
            if (g_OnlineFixRealAppId)
                g_OnlineFixUserStatsPipe = hSteamPipe;
            ++g_userStatsAppIdOverrideDepth;
        } else if (g_userStatsAppIdOverrideDepth) {
            --g_userStatsAppIdOverrideDepth;
        }
    }

    void NotifyOnlineFixGamesPlayed(bool lists480)
    {
        if (!g_OnlineFixRealAppId) return;
        if (lists480) {
            g_OnlineFixSeenRunning = true;
            return;
        }
        if (!g_OnlineFixSeenRunning) return;   // game not started yet

        // Game exited.  Steam has already saved its playtime / LastPlayed
        // (that happens before this GamesPlayed is sent), so drop all
        // OnlineFix state now: otherwise 480 lookups (Spacewar's library page)
        // keep being redirected, and other processes keep being told they are
        // the real app, until the next launch.
        LOG_MISC_INFO("OnlineFix: game {} exited, ending session", g_OnlineFixRealAppId);
        g_OnlineFixRealAppId      = 0;
        g_OnlineFixUserStatsPipe  = 0;
        g_OnlineFixGamePipe       = 0;
        g_NetworkingSocketsActive = false;
        g_OnlineFixSeenRunning    = false;
    }

    bool IsOnlineFixGamePipe(HSteamPipe hSteamPipe)
    {
        return IsOnlineFixStatsPipe(hSteamPipe);
    }

    void NotifyPipeHandshake(HSteamPipe hSteamPipe, AppId_t envSteamAppId,
                             AppId_t envSteamGameId, bool steamClientProcess)
    {
        if (!g_OnlineFixRealAppId || steamClientProcess) return;
        if (envSteamAppId != kOnlineFixAppId && envSteamGameId != kOnlineFixAppId) return;
        g_OnlineFixGamePipe = hSteamPipe;
        LOG_MISC_INFO("OnlineFix: game pipe {:#x} (real appid {})", hSteamPipe, g_OnlineFixRealAppId);
    }

    bool IsOnlineFixStatsPipe(HSteamPipe hSteamPipe)
    {
        if (!g_OnlineFixRealAppId) return false;
        // Not identified yet: the game's first IPC message is its handshake,
        // so until then no pipe can be the game.  (The session only starts at
        // SpawnProcess, after we're loaded, so the handshake is never missed;
        // treating every pipe as the game here let the Steam UI's stats calls
        // be rewritten to 480 during the seconds the game takes to start.)
        if (!g_OnlineFixGamePipe) return false;
        return hSteamPipe == g_OnlineFixGamePipe;
    }

    bool RewriteOnlineFixUserStatsCallback(HSteamPipe hSteamPipe, uint64& gameId)
    {
        constexpr uint64 appIdMask = 0xFFFFFF;
        if (!g_OnlineFixRealAppId || hSteamPipe != g_OnlineFixUserStatsPipe
            || static_cast<AppId_t>(gameId & appIdMask) != g_OnlineFixRealAppId) {
            return false;
        }

        gameId = (gameId & ~appIdMask) | kOnlineFixAppId;
        return true;
    }

    bool ShouldRouteOnlineFixUserStatsCallback(AppId_t routeAppId)
    {
        return g_OnlineFixRealAppId && g_OnlineFixUserStatsPipe
            && routeAppId == g_OnlineFixRealAppId;
    }

}
