#include "Hooks_IPC.h"
#include "Hooks_IPC_ISteamUtils.h"
#include "Hooks_Misc.h"
#include "PendingAPICalls.h"
#include "Steam/Callback.h"
#include "Utils/Logging/Log.h"

#include <type_traits>

namespace {
    using namespace IPCMessages::IClientUtils;

    template <class CallbackT>
    bool WriteAPICallResult(CUtlBuffer* pWrite,uint32 callbackCapacity,const CallbackT& callback)
    {
        static_assert(std::is_trivially_copyable_v<CallbackT>);
        if (callbackCapacity < sizeof(CallbackT)) return false;

        GetAPICallResultResp resp{pWrite, callbackCapacity};
        if (!resp.ok()) return false;
        if (!resp.set_pCallback(IPCMessages::asBytes(callback))) return false;
        resp.set_returnValue(true);
        resp.set_pbFailed(false);
        return true;
    }

    // [Post-Handler]: IClientUtils::GetAppID
    //  Once P2P is up, return 480 so the socket matches the 480 session cert.
    void HandlerPost_IClientUtils_GetAppID(CPipeClient* pipe, CUtlBuffer* pRead, CUtlBuffer* pWrite)
    {
        GetAppIDResp resp{pWrite};
        if (!resp.ok()) {
            LOG_IPC_WARN("GetAppID: resp not ok");
            return;
        }

        AppId_t currentAppId = resp.returnValue();
        LOG_IPC_DEBUG("GetAppID: current={}, IsOnlineFixActive={}, ShouldReportOnlineFixAppId={}", 
                      currentAppId, Hooks_Misc::IsOnlineFixActive(), Hooks_Misc::ShouldReportOnlineFixAppId());

        // For onlinefix games, always leave 480
        if (Hooks_Misc::IsOnlineFixActive()) {
            if (currentAppId != 480) {
                LOG_IPC_WARN("GetAppID: onlinefix active but appid={} not 480", currentAppId);
            }
            return;
        }

        // Not an onlinefix game - might need to spoof
        AppId_t realAppId = Hooks_Misc::GetRealAppId();
        if (!realAppId) {
            LOG_IPC_TRACE("GetAppID: realAppId=0, skip spoofing");
            return;
        }

        if (currentAppId == realAppId) {
            LOG_IPC_TRACE("GetAppID: already correct ({})", realAppId);
            return;
        }

        resp.set_returnValue(realAppId);
        LOG_IPC_INFO("GetAppID: spoofed {} -> {}", currentAppId, realAppId);
    }

    // ════════════════════════════════════════════════════════════════
    //  GetAPICallResult per-callback handlers
    // ════════════════════════════════════════════════════════════════

    bool HandleCallback_EncryptedAppTicketResponse(CUtlBuffer* pWrite, uint64 hAsyncCall, uint32 cubCallback)
    {
        const auto appId = PendingAPICalls::TakeEncryptedTicket(hAsyncCall);
        if (!appId) return false;

        EncryptedAppTicketResponse_t callback{};
        callback.m_eResult = k_EResultOK;
        if (!WriteAPICallResult(pWrite, cubCallback, callback)) {
            PendingAPICalls::RecordEncryptedTicket(hAsyncCall, *appId);
            LOG_IPC_WARN("Failed to write EncryptedAppTicketResponse for AppId={} hAsyncCall=0x{:X}", 
                            *appId, hAsyncCall);
            return false;
        }
        LOG_IPC_DEBUG("Set K_EResultOK for EncryptedAppTicketResponse callback, AppId={} hAsyncCall=0x{:X}",
                        *appId, hAsyncCall);
        return true;
    }

    struct APICallResultHandlerEntry {
        uint32 callbackId;
        bool (*handler)(CUtlBuffer* pWrite, uint64 hAsyncCall, uint32 cubCallback);
    };

    constexpr APICallResultHandlerEntry kAPICallResultHandlers[] = {
        { EncryptedAppTicketResponse_t::k_iCallback, HandleCallback_EncryptedAppTicketResponse },
    };

    // [Post-Handler]: IClientUtils::GetAPICallResult
    void HandlerPost_IClientUtils_GetAPICallResult(CPipeClient*, CUtlBuffer* pRead, CUtlBuffer* pWrite)
    {
        GetAPICallResultReq req{pRead};
        if (!req.ok()) return;

        AppId_t appId = Hooks_Misc::ResolveAppId();
        LOG_IPC_DEBUG("{}, AppId={}", req.DebugString(),appId);
        for (const auto& entry : kAPICallResultHandlers) {
            if (entry.callbackId == req.iCallbackExpected()) {
                entry.handler(pWrite, req.hSteamAPICall(), req.cubCallback());
                return;
            }
        }
    }

} // namespace

namespace Hooks_IPC_ISteamUtils {
    void Register() {
        IPCHandlerEntry UtilsEntries[] = {
            ADD_IPC_POST_HANDLER(IClientUtils, GetAppID),
            ADD_IPC_POST_HANDLER(IClientUtils, GetAPICallResult),
        };
        Hooks_IPC::RegisterHandlers(UtilsEntries);
    }
}
