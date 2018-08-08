rule VMP_Enter
{
    meta:
        description = "VMProtect VMP_Enter Handler"
    strings:
        $hex_string = {55 9C [0-20] 50 [0-20] 53 [0-20] 57 [0-20] 52 [0-20] 51 [0-20] 56 [0-20] B8 ?? ?? ?? ?? 50 [0-20] 8B 74 24 28 [0-20] F7 DE 81 F6 95 64 57 2E 46 [0-20] 81 F6 A1 78 BE 18 [0-20] 03 F0 [0-20] 8B EC [0-20] 81 EC C0 00 00 00 [0-20] 8B DE B8 ?? ?? ?? ?? [0-20] 2B D8 [0-20] 8D 3D ?? ?? ?? ?? [0-20] 8D B6 FC FF FF FF [0-20] 8B 06 33 C3 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 C1 C8 02 [0-20] 33 D8 03 F8 [0-20] FF E7}
    condition:
        $hex_string
}

rule VMP_PopReg32
{
    meta:
        description = "VMProtect VMP_PopReg32 Handler"
    strings:
        $hex_string = {(8D B6 FF FF FF FF | 81 EE 01 00 00 00) [0-20] 0F B6 06 [0-20] 32 C3 [0-20] FE C0 [0-20] 34 48 [0-20] F6 D8 [0-20] FE C0 [0-20] D0 C8 [0-20] 04 65 [0-20] 32 D8 [0-20] 8B 4C 25 00 [0-20] (81 C5 | 8D AD) 04 00 00 00 [0-20] 89 0C 04 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}

rule VMP_PopReg16
{
    meta:
        description = "VMProtect VMP_PopReg16 Handler"
    strings:
        $hex_string = {(8D B6 FF FF FF FF | 81 EE 01 00 00 00) [0-20] 0F B6 06 [0-20] 32 C3 [0-20] FE C8 [0-20] F6 D0 [0-20] D0 C8 [0-20] FE C8 [0-20] 32 D8 [0-20] 66 8B 4C 25 00 [0-20] (81 C5 | 8D AD) 02 00 00 00 [0-20] 66 89 0C 04 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}

rule VMP_PushReg32
{
    meta:
        description = "VMProtect VMP_PushReg32 Handler"
    strings:
        $hex_string = {(8D B6 FF FF FF FF | 81 EE 01 00 00 00) [0-20] 0F B6 06 [0-20] 32 C3 [0-20] FE C0 [0-20] 34 48 [0-20] F6 D8 [0-20] FE C0 [0-20] D0 C8 [0-20] 04 65 [0-20] 32 D8 [0-20] 8B 04 04 [0-20] (81 ED 04 00 00 00 | 8D AD FC FF FF FF) [0-20] 89 44 25 00 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] 8D 44 24 60 3B E8 0F 87 ?? ?? ?? ?? 8B D4 [0-20] B9 40 00 00 00 8D 44 25 80 24 FC 2B C1 [0-20] 8B E0 57 9C [0-20] 56 [0-20] 8B F2 8B F8 [0-20] FC [0-20] F3 A4 [0-20] 5E [0-20] 9D [0-20] 5F [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}

rule VMP_PushReg16
{
    meta:
        description = "VMProtect VMP_PushReg16 Handler"
    strings:
        $hex_string = {(8D B6 FF FF FF FF | 81 EE 01 00 00 00) [0-20] 0F B6 06 [0-20] 32 C3 [0-20] FE C8 [0-20] F6 D0 [0-20] D0 C8 [0-20] FE C8 [0-20] 32 D8 [0-20] 66 8B 04 04 [0-20] (8D AD FE FF FF FF | 81 ED 02 00 00 00) [0-20] 66 89 44 25 00 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] 8D 44 24 60 3B E8 0F 87 ?? ?? ?? ?? 8B D4 [0-20] B9 40 00 00 00 8D 44 25 80 24 FC 2B C1 [0-20] 8B E0 57 9C [0-20] 56 [0-20] 8B F2 8B F8 [0-20] FC [0-20] F3 A4 [0-20] 5E [0-20] 9D [0-20] 5F [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}

rule VMP_PushEsp
{
    meta:
        description = "VMProtect VMP_PushEsp Handler"
    strings:
        $hex_string = {8B C5 [0-20] (81 ED 04 00 00 00 | 8D AD FC FF FF FF) [0-20] 89 44 25 00 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] 8D 44 24 60 3B E8 0F 87 ?? ?? ?? ?? 8B D4 [0-20] B9 40 00 00 00 8D 44 25 80 24 FC 2B C1 [0-20] 8B E0 57 9C [0-20] 56 [0-20] 8B F2 8B F8 [0-20] FC [0-20] F3 A4 [0-20] 5E [0-20] 9D [0-20] 5F [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}

rule VMP_PopEsp
{
    meta:
        description = "VMProtect VMP_PopEsp Handler"
    strings:
        $hex_string = {8B 6C 25 00 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] 8D 44 24 60 3B E8 0F 87 ?? ?? ?? ?? 8B D4 [0-20] B9 40 00 00 00 8D 44 25 80 24 FC 2B C1 [0-20] 8B E0 57 9C [0-20] 56 [0-20] 8B F2 8B F8 [0-20] FC [0-20] F3 A4 [0-20] 5E [0-20] 9D [0-20] 5F [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}

rule VMP_PushImm32
{
    meta:
        description = "VMProtect VMP_PushImm32 Handler"
    strings:
        $hex_string = {(8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 0F C8 [0-20] 35 65 02 D4 5E [0-20] (2D 0D 02 9C 28 | 8D 80 F3 FD 63 D7) [0-20] 35 D1 52 CA 66 [0-20] 33 D8 [0-20] (81 ED 04 00 00 00 | 8D AD FC FF FF FF) [0-20] 89 44 25 00 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] 8D 44 24 60 3B E8 0F 87 ?? ?? ?? ?? 8B D4 [0-20] B9 40 00 00 00 8D 44 25 80 24 FC 2B C1 [0-20] 8B E0 57 9C [0-20] 56 [0-20] 8B F2 8B F8 [0-20] FC [0-20] F3 A4 [0-20] 5E [0-20] 9D [0-20] 5F [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}

rule VMP_PushImm16
{
    meta:
        description = "VMProtect VMP_PushImm16 Handler"
    strings:
        $hex_string = {(81 EE 02 00 00 00 | 8D B6 FE FF FF FF) [0-20] 0F B7 06 [0-20] 66 33 C3 [0-20] 66 F7 D0 [0-20] 66 05 84 7F [0-20] 66 D1 C8 [0-20] 66 2D D5 77 [0-20] 66 33 D8 [0-20] 81 ED 02 00 00 00 [0-20] 66 89 44 25 00 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] 8D 44 24 60 3B E8 0F 87 ?? ?? ?? ?? 8B D4 [0-20] B9 40 00 00 00 8D 44 25 80 24 FC 2B C1 [0-20] 8B E0 57 9C [0-20] 56 [0-20] 8B F2 8B F8 [0-20] FC [0-20] F3 A4 [0-20] 5E [0-20] 9D [0-20] 5F [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}

rule VMP_PushImm8
{
    meta:
        description = "VMProtect VMP_PushImm8 Handler"
    strings:
        $hex_string = {(8D B6 FF FF FF FF | 81 EE 01 00 00 00) [0-20] 0F B6 06 [0-20] 32 C3 [0-20] F6 D8 [0-20] FE C8 [0-20] F6 D8 [0-20] F6 D0 [0-20] 04 0A [0-20] D0 C0 [0-20] 34 03 [0-20] D0 C0 [0-20] 34 00 [0-20] 04 4D [0-20] D0 C8 [0-20] 34 6F [0-20] FE C0 [0-20] 32 D8 [0-20] (81 ED 02 00 00 00 | 8D AD FE FF FF FF) [0-20] 66 89 44 25 00 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] 8D 44 24 60 3B E8 0F 87 ?? ?? ?? ?? 8B D4 [0-20] B9 40 00 00 00 8D 44 25 80 24 FC 2B C1 [0-20] 8B E0 57 9C [0-20] 56 [0-20] 8B F2 8B F8 [0-20] FC [0-20] F3 A4 [0-20] 5E [0-20] 9D [0-20] 5F [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}

rule VMP_Add32
{
    meta:
        description = "VMProtect VMP_Add32 Handler"
    strings:
        $hex_string = {8B 44 25 00 [0-20] 8B 4C 25 04 [0-20] 03 C1 [0-20] 89 44 25 04 [0-20] 9C [0-20] 8F 44 25 00 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] (FF E7 | 57 C3) }
    condition:
        $hex_string
}

rule VMP_Add16
{
    meta:
        description = "VMProtect VMP_Add16 Handler"
    strings:
        $hex_string = {66 8B 44 25 00 [0-20] 66 8B 4C 25 02 [0-20] (81 ED 02 00 00 00 | 8D AD FE FF FF FF) [0-20] 66 03 C1 [0-20] 66 89 44 25 04 [0-20] 9C [0-20] 8F 44 25 00 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] 8D 44 24 60 3B E8 0F 87 ?? ?? ?? ?? 8B D4 [0-20] B9 40 00 00 00 8D 44 25 80 24 FC 2B C1 [0-20] 8B E0 57 9C [0-20] 56 [0-20] 8B F2 8B F8 [0-20] FC [0-20] F3 A4 [0-20] 5E [0-20] 9D [0-20] 5F [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}

rule VMP_Nand32
{
    meta:
        description = "VMProtect VMP_Nand32 Handler"
    strings:
        $hex_string = {8B 44 25 00 [0-20] 8B 4C 25 04 [0-20] F7 D0 [0-20] F7 D1 [0-20] 23 C1 [0-20] 89 44 25 04 [0-20] 9C [0-20] 8F 44 25 00  [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] (FF E7 | 57 C3) }
    condition:
        $hex_string
}

rule VMP_Nand16
{
    meta:
        description = "VMProtect VMP_Nand16 Handler"
    strings:
        $hex_string = {66 8B 44 25 00 [0-20] 66 8B 4C 25 02 [0-20] (81 ED 02 00 00 00 | 8D AD FE FF FF FF) [0-20] 66 F7 D0 [0-20] 66 F7 D1 [0-20] 66 23 C1 [0-20] 66 89 44 25 04 [0-20] 9C [0-20] 8F 44 25 00 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] 8D 44 24 60 3B E8 0F 87 ?? ?? ?? ?? 8B D4 [0-20] B9 40 00 00 00 8D 44 25 80 24 FC 2B C1 [0-20] 8B E0 57 9C [0-20] 56 [0-20] 8B F2 8B F8 [0-20] FC [0-20] F3 A4 [0-20] 5E [0-20] 9D [0-20] 5F [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}

rule VMP_DerefMemSs32
{
    meta:
        description = "VMProtect VMP_DerefMemSs32 Handler"
    strings:
        $hex_string = {8B 4C 25 00 [0-20] 36 8B 01 [0-20] 89 44 25 00 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}

rule VMP_DerefMemSs16
{
    meta:
        description = "VMProtect VMP_DerefMemSs16 Handler"
    strings:
        $hex_string = {8B 4C 25 00 [0-20] 36 66 8B 01 [0-20] (81 C5 | 8D AD) 02 00 00 00 [0-20] 66 89 44 25 00 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}

rule VMP_DerefMemSs8
{
    meta:
        description = "VMProtect VMP_DerefMemSs8 Handler"
    strings:
        $hex_string = {8B 4C 25 00 [0-20] 36 66 0F B6 01 [0-20] 81 C5 02 00 00 00 [0-20] 66 89 44 25 00 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 8D B6 04 00 00 00 [0-20] 33 C3 [0-20] D1 C0 [0-20] 35 3D 7F EC 2D [0-20] 40 [0-20] 35 16 5A FA 6C [0-20] 33 D8 [0-20] 03 F8 [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}

rule VMP_SetMemSs32
{
    meta:
        description = "VMProtect VMP_SetMemSs32 Handler"
    strings:
        $hex_string = {8B 4C 25 00 [0-20] 8B 44 25 04 [0-20] 81 C5 08 00 00 00 [0-20] 36 89 01 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] (FF E7 | 57 C3) }
    condition:
        $hex_string
}

rule VMP_DerefMem32
{
    meta:
        description = "VMProtect VMP_DerefMem32 Handler"
    strings:
        $hex_string = {8B 4C 25 00 [0-20] 8B 01 [0-20] 89 44 25 00 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] (FF E7 | 57 C3) }
    condition:
        $hex_string and not VMP_DerefMemSs32 and not VMP_DerefMemSs16
}

rule VMP_Exit
{
    meta:
        description = "VMProtect VMP_Exit Handler"
    strings:
        $hex_string = {8B E5 [0-20] 5E [0-20] 59 [0-20] 5A [0-20] 5F [0-20] 5B [0-20] 58 [0-20] 9D [0-20] 5D C3}
    condition:
        $hex_string
}

rule VMP_Shr32
{
    meta:
        description = "VMProtect VMP_Shr32 Handler"
    strings:
        $hex_string = {8B 44 25 00 [0-20] 8A 4C 25 04 [0-20] (8D AD FE FF FF FF | 81 ED 02 00 00 00) [0-20] D3 E8 [0-20] 89 44 25 04 [0-20] 9C [0-20] 8F 44 25 00 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] 8D 44 24 60 3B E8 0F 87 ?? ?? ?? ?? 8B D4 [0-20] B9 40 00 00 00 8D 44 25 80 24 FC 2B C1 [0-20] 8B E0 57 9C [0-20] 56 [0-20] 8B F2 8B F8 [0-20] FC [0-20] F3 A4 [0-20] 5E [0-20] 9D [0-20] 5F [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}

rule VMP_Shl32
{
    meta:
        description = "VMProtect VMP_Shl32 Handler"
    strings:
        $hex_string = {8B 44 25 00 [0-20] 8A 4C 25 04 [0-20] (8D AD FE FF FF FF | 81 ED 02 00 00 00) [0-20] D3 E0 [0-20] 89 44 25 04 [0-20] 9C [0-20] 8F 44 25 00 [0-20] (8D B6 FC FF FF FF | 81 EE 04 00 00 00) [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] 8D 44 24 60 3B E8 0F 87 ?? ?? ?? ?? 8B D4 [0-20] B9 40 00 00 00 8D 44 25 80 24 FC 2B C1 [0-20] 8B E0 57 9C [0-20] 56 [0-20] 8B F2 8B F8 [0-20] FC [0-20] F3 A4 [0-20] 5E [0-20] 9D [0-20] 5F [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}

rule VMP_Jump
{
    meta:
        description = "VMProtect VMP_Jump Handler"
    strings:
        $hex_string = {8B 74 25 00 [0-20] (81 C5 | 8D AD) 04 00 00 00 [0-20] 8B DE B8 ?? ?? ?? ?? [0-20] 2B D8 [0-20] 8D 3D ?? ?? ?? ?? [0-20] 8D B6 FC FF FF FF [0-20] 8B 06 33 C3 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 C1 C8 02 [0-20] 33 D8 03 F8 [0-20] FF E7}
    condition:
        $hex_string
}

rule VMP_ResetJumpDisplacement
{
    meta:
        description = "VMProtect VMP_ResetJumpDisplacement Handler"
    strings:
        $hex_string = {8D 3D ?? ?? ?? ?? [0-20] 8D B6 FC FF FF FF [0-20] 8B 06 33 C3 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 C1 C8 02 [0-20] 33 D8 03 F8 [0-20] FF E7}
    condition:
        $hex_string and not VMP_Enter and not VMP_Jump
}

rule VMP_Mul32
{
    meta:
        description = "VMProtect VMP_Mul32 Handler"
    strings:
        $hex_string = {8B 44 25 04 [0-20] 8B 54 25 00 [0-20] 8D AD FC FF FF FF [0-20] F7 E2 [0-20] 89 54 25 04 [0-20] 89 44 25 08 [0-20] 9C [0-20] 8F 44 25 00 [0-20] 8D B6 FC FF FF FF [0-20] 8B 06 [0-20] 33 C3 [0-20] 35 2F 26 BC 13 [0-20] 0F C8 [0-20] D1 C0 [0-20] F7 D0 [0-20] C1 C8 02 [0-20] 33 D8 [0-20] 03 F8 [0-20] 8D 44 24 60 3B E8 0F 87 ?? ?? ?? ?? 8B D4 [0-20] B9 40 00 00 00 8D 44 25 80 24 FC 2B C1 [0-20] 8B E0 57 9C [0-20] 56 [0-20] 8B F2 8B F8 [0-20] FC [0-20] F3 A4 [0-20] 5E [0-20] 9D [0-20] 5F [0-20] (FF E7 | 57 C3)}
    condition:
        $hex_string
}
