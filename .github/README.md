# mod-rce

This repository documents a well known critical Remote Code Execution (RCE) vulnerability in the World of Warcraft: Wrath of the Lich King 3.3.5a client. Historically, knowledge of this vulnerability has been limited to a small number of well known actors within the WoW emulation scene. We have decided to publish this research and AzerothCore module publicly because restricting awareness of a vulnerability of this severity only benefits those already exploiting it. The combination of arbitrary memory writes and an executable writable memory segment makes this issue exceptionally dangerous for any *unpatched* 3.3.5a client. Public disclosure ensures that the wider community can properly understand the risk, validate mitigations, and prevent continued private abuse of the vulnerability.

This RCE combines two distinct security failures that enable arbitrary code execution: a historical compiler bug from approximately 2008 that misconfigured the `.zdata` memory segment with both *write* and *execute* permissions, and a fundamental design flaw in the `CDataStore::GetInt64` function that performs *unchecked* memory writes to attacker-controlled addresses.

The exploitation chain begins with the `MSG_BATTLEGROUND_PLAYER_POSITIONS` packet handler, which uses the critically flawed `CDataStore::GetInt64` function. Despite its name implying a read operation, this function actually writes data from the packet buffer directly to arbitrary memory locations without any bounds checking or address validation. By manipulating the packet's iteration count and leveraging the predictable address calculation formula `(8 * iteration + base_address)`, an attacker can systematically write shellcode across memory until reaching the vulnerable `.zdata` segment at address `0xDD1000`.

Once the payload is written to the writable and executable `.zdata` segment, it can be triggered through a modified Warden anti-cheat initialization packet, which redirects execution from the legitimate `FrameScript::Execute` function to the injected code. For the purposes of this report, we create a messagebox pop-up by using the GM or console command `rce <charactername>`.

This specific exploit can be prevented by patching your `WoW.exe` by making the `.zdata` segment read only. To do this, visit the repository: [RCEPatcher](https://github.com/stoneharry/RCEPatcher) created by [stoneharry](https://github.com/stoneharry/). Executing the payload with these newly set flags will always result in a crash.

![GIF](/.github/demo.gif)

## Module installation
1. Modify the following file:
```txt
.\azerothcore-wotlk\src\server\game\Warden\WardenWin.cpp
```
```diff
- Request.Function2 = 0x00419210;
+ Request.Function2 = 0x009D1000;
```
2.  Clone this module into the modules directory
3.  Re-run cmake
4.  Compile.

# 1. Technical Writeup: .zdata Segment Vulnerability

## 1.1 The Compiler Bug (circa 2008)

In approximately 2008, a bug existed in certain compiler versions that caused the `.zdata` segment to be marked with incorrect memory permissions. Specifically, this segment was configured as both writable and executable simultaneously.

> **What is .zdata?**
>
> The .zdata segment is a data section in compiled binaries. Under normal circumstances, data segments should be writable but **not** executable, while code segments should be executable but **not** writable. This separation is a fundamental security principle known as W^X (Write XOR Execute).

## 1.2 Security Implications

When a memory segment is both writable and executable (W+X), it creates a critical security vulnerability:

- An attacker can write arbitrary data to this segment
- The written data can then be executed as machine code
- This bypasses modern security mitigations like DEP (Data Execution Prevention)
- Enables direct code injection and execution

> **Critical Flaw:** The combination of writable and executable permissions on the .zdata segment effectively disables one of the most important memory protection mechanisms in modern operating systems.

# 2. Vulnerability Details

## 2.1 Attack Entry Point

The exploitation chain begins at the `MSG_BATTLEGROUND_PLAYER_POSITIONS` message handler within the World of Warcraft client. This handler processes battleground position updates sent from the server to the client during gameplay.

## 2.2 Exploitation Mechanism

The vulnerability is triggered through a custom malicious payload that exploits the `CDataStore::GetInt64` function. This function, despite its name suggesting a read operation, actually performs an **unchecked memory write** to an attacker-controlled address.

> **Critical Misnomer:** The function CDataStore::GetInt64 is deceptively named. While "Get" implies reading data FROM the data store, the function actually WRITES data TO arbitrary memory locations. The second parameter (a2) is treated as a destination pointer where 8 bytes from the packet buffer are written, with absolutely no bounds checking or validation.

> **Attack Process Overview**
> The exploit takes advantage of how the client processes incoming byte streams from the server. By sending specially crafted position update packets, an attacker can trigger a buffer overflow that writes arbitrary data to a controlled memory location.

## 2.3 Precise Memory Manipulation

The attack operates through an iterative memory writing technique that leverages the packet handler's loop structure:

- **Target Address:** 0xDD1000 (within the writable and executable .zdata segment)
- **Write Increment:** 8 bytes per iteration
- **Loop Control:** dword_BEA5B0 is read from the malicious packet and controls how many iterations occur
- **Address Calculation:** Each iteration writes to (8 * i + 12493184), where i is the current loop counter

> **Loop Exploitation in Detail**
>
> **Iteration 0:** Writes to address 12493184 + (8 × 0) = 12493184 (0xBEA000)
> **Iteration 1:** Writes to address 12493184 + (8 × 1) = 12493192 (0xBEA008)
> **Iteration 2:** Writes to address 12493184 + (8 × 2) = 12493200 (0xBEA010)
> **Iteration 10000:** Writes to address 12493184 + (8 × 10000) = 12573184 (0xBFE000)
> **Key Insight:** By controlling dword_BEA5B0 in the packet, the attacker determines exactly how many 8-byte chunks to write and can precisely target the .zdata segment at 0xDD1000. The calculation is deterministic: target_iteration = (0xDD1000 - 12493184) / 8 = 257,488 iterations.

Through this method, the attacker can systematically write arbitrary bytecode across memory until reaching the .zdata segment. Each iteration advances the write position by exactly 8 bytes, allowing the construction of a complete shellcode payload at a predictable, executable memory location.

> **Critical Detail:** Because the .zdata segment has both write and execute permissions due to the compiler bug, the injected bytecode can be executed immediately after being written, completing the RCE exploitation chain.

## 2.4 Vulnerable Code Analysis

The following decompiled code shows the vulnerable packet handler and the data store function used to write arbitrary data:

```cpp
// MSG_BATTLEGROUND_PLAYER_POSITIONS Packet Handler
int __cdecl Packet_MSG_BATTLEGROUND_PLAYER_POSITIONS(
    int a1, int _1C, int a3, CDataStore *this)
{
    unsigned int i;     // edi - Loop counter
    int v5;             // eax - Temporary variable
    int a2;             // [esp+Ch] [ebp-4h] BYREF
    // STEP 1: Read attacker-controlled iteration count
    CDataStore::GetInt32(this, &dword_BEA5B0);
    // STEP 2: THE EXPLOIT LOOP - memory corruption occurs here
    // VULNERABILITY: Loop count is attacker-controlled with NO validation
    for ( i = 0; i < dword_BEA5B0; ++i )
    {
        // Address: 12493184 + (8 * i) — reaches 0xDD1000 after 257488 iterations
        // CRITICAL: GetInt64 WRITES 8 bytes to the calculated address
        CDataStore::GetInt64(this, (QWORD *)(8 * i + 12493184));
        CDataStore::GetFloat(this, (float *)(8 * i + 12494288));
        CDataStore::GetFloat(this, (float *)(8 * i + 12494292));
    }
    // STEP 3: Read secondary loop count (also attacker-controlled)
    CDataStore::GetInt32(this, &a2);
    ...
}
// CDataStore::GetInt64 - The critically flawed write primitive
int __thiscall CDataStore::GetInt64(CDataStore *this, QWORD *a2)
{
    if ( CDataStore::CanRead(this, this->m_read, 8) )
    {
        // CRITICAL FLAW: This WRITES to a2 — no validation, no bounds check!
        // Attacker controls: destination address, data written, iteration count
        *a2 = *(_QWORD *)&this->m_buffer[this->m_read - this->m_base];
        this->m_read += 8;
    }
    return (int)this;
}
```

> **How the Memory Write Works**
>
> **Step 1:** Attacker sends payload with dword_BEA5B0 set to control iteration count
> **Step 2:** Each iteration calls CDataStore::GetInt64(this, (QWORD *)(8 * i + 12493184))
> **Step 3:** The calculated address progresses through memory in 8-byte increments
> **Step 4:** After ~257,488 iterations, the write address reaches 0xDD1000 in the vulnerable .zdata segment
> **Step 5:** Arbitrary shellcode from the packet is written directly to this executable memory region

# 3. Injected Payload Analysis

## 3.1 The Warmane Payload

Once the attacker successfully writes their code to 0xDD1000, the following malicious payload is executed. This code demonstrates a sophisticated multi-stage attack designed to establish persistent control while evading detection:

```cpp
void sub_DD1000()
{
    int v0;    // ebx
    _BYTE *v1; // eax
    _BYTE *v2; // edx
    // ANTI-DEBUGGING: Exit immediately if debugger is attached
    if ( !IsDebuggerPresent() )
    {
        sub_54E220();  // Unknown initialization function
        v0 = dword_DD0FFC;
        if ( !dword_DD0FFC )
        {
            // STAGE 1: Allocate 4KB RWX memory region
            // VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
            v1 = VirtualAlloc(0, 0x1000u, 0x1000u, 0x40u);
            v0 = (int)v1;
            dword_DD0FFC = (int)v1;
            // STAGE 2: Copy secondary payload to new memory
            v2 = &off_DD15A0;
            do
                *v1++ = *v2++;
            while ( v2 != (_BYTE *)&unk_DD15FE );
        }
        // STAGE 3: Hook CMSG_UNUSED5 as covert C2 channel
        ClientServices::SetMessageHandler(CMSG_UNUSED5, v0 + 32, (void *)(v0 + 32));
        // STAGE 4: Jump to newly allocated payload
        __asm { jmp ebx }
    }
    // If debugger detected, crash/exit
    JUMPOUT(0);
}
```

## 3.2 Payload Behavior Breakdown

> **Attack Stages**
>
> **1. Anti-Debugging Protection:** Uses IsDebuggerPresent() to detect analysis attempts and terminates if debugging is detected, making reverse engineering more difficult.
> **2. Memory Allocation:** Allocates a new 4KB memory region with Read-Write-Execute permissions using VirtualAlloc(). This creates a clean, permanent location for the backdoor code.
> **3. Payload Deployment:** Copies the secondary payload from embedded data at off_DD15A0 to the newly allocated memory. This payload is the actual backdoor handler.
> **4. Message Handler Hijacking:** Registers the backdoor as the handler for CMSG_UNUSED5, an unused client message opcode. This creates a covert command-and-control (C2) channel that can be triggered by sending specially crafted packets.
> **5. Execution Transfer:** Jumps to the newly installed backdoor code, establishing persistence.

## 3.3 Self-Cleaning Mechanism

After the payload successfully executes and establishes persistence, it erases evidence of the initial infection to avoid detection:

```cpp
// Cleanup function - destroys forensic evidence
char *sub_12E70000()
{
    // ANTI-FORENSICS: Zero out the entire .zdata injection site
    // Clears 4KB (0x1000 bytes) starting at 0xDD1000
    memset(&unk_DD1000, 0, 0x1000u);
    return &byte_C79620;
}
```

> **Evasion Technique:** By zeroing out the injection site at 0xDD1000, the attacker removes evidence of the initial exploit. Since the backdoor has been copied to a new memory region and registered as a message handler, it continues to function even after the injection site is cleaned. This makes post-infection forensic analysis significantly more difficult.

## 3.4 Runtime Extension Access

Once installed, the payload provides runtime extension capabilities through the CMSG_UNUSED5 message channel. The extension operates within the client's process space and remains active for the duration of the client session. The attacker can send commands disguised as legitimate game traffic, enabling various extended functionalities:

- Execute arbitrary code within the client process
- Access and exfiltrate data from the client's memory space (credentials, game data, system information)
- Deploy additional runtime modules or extensions
- Establish client-side automation capabilities
- Monitor and intercept game communications in real-time

> **Persistence Model**
>
> This extension operates entirely in memory during runtime and does not persist across client restarts. When the game client is closed, all injected code is removed from memory. This transient nature means the extension must be re-deployed each time the client launches, making it a session-based rather than system-level modification.

# 4. Execution Trigger Mechanism

## 4.1 Warden Packet Hijacking

The injected payload at 0xDD1000 is triggered through a clever manipulation of the Warden anti-cheat system's initialization packet. The attacker modifies the Warden initialization process to redirect code execution to their malicious payload.

> **Normal Warden Flow**
>
> Under normal circumstances, the Warden initialization packet calls FrameScript::Execute to perform Lua string validation checks as part of the anti-cheat verification process.

## 4.2 Address Substitution Attack

The exploit modifies the Warden initialization packet to replace the legitimate function pointer:

```cpp
// NORMAL EXECUTION PATH:
// Warden Init Packet -> calls FrameScript::Execute -> Lua string check
// EXPLOITED EXECUTION PATH:
// Warden Init Packet -> function pointer changed to 0xDD1000 -> malicious payload
//
// The attacker replaces the address of FrameScript::Execute with 0xDD1000.
// When Warden initialization occurs, it unknowingly executes injected code.
```

## 4.3 Why This Works

This exploitation technique is particularly effective for several reasons:

- **Trusted Code Path:** Warden is a legitimate anti-cheat system, so its initialization is trusted by the client
- **Expected Execution:** Warden regularly performs checks, making the execution of code during initialization normal behavior
- **Lua String Check Context:** The execution occurs in the context of a Lua string validation, which typically has elevated privileges for game state inspection
- **Timing Control:** The attacker can control when the payload executes by controlling when the modified Warden packet is sent

> **Ironic Security Failure:** The attacker weaponizes the Warden anti-cheat system itself to execute malicious code. The very system designed to protect the game becomes the vehicle for the exploit, demonstrating a complete subversion of the security architecture.

## 4.4 Thanks to:
- [TechMecca](https://github.com/TechMecca) - Research & detailed writeup
- [stoneharry](https://github.com/stoneharry/) - RCEPatcher
- [Saty](https://github.com/SatyPardus) - Proof of concept 2.0 final using Warden
- [brian8544](https://github.com/brian8544) - Proof of concept 1.0 & module