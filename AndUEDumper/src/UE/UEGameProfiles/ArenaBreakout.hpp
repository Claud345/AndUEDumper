#pragma once

#include "../UEGameProfile.hpp"
using namespace UEMemory;

class ArenaBreakoutProfile : public IGameProfile
{
public:
    ArenaBreakoutProfile() = default;

    bool ArchSupprted() const override
    {
        auto e_machine = GetUnrealELF().header().e_machine;
        return e_machine == EM_AARCH64;
    }

    std::string GetAppName() const override
    {
        return "Arena Breakout";
    }

    std::vector<std::string> GetAppIDs() const override
    {
        return {"com.proximabeta.mf.uamo"};
    }

    bool isUsingCasePreservingName() const override
    {
        return false;
    }

    bool IsUsingFNamePool() const override
    {
        return true;
    }

    bool isUsingOutlineNumberName() const override
    {
        return false;
    }

    uintptr_t GetGUObjectArrayPtr() const override
    {
        std::vector<std::pair<std::string, int>> idaPatterns = {
            // CMP W8,#0 / LDR X10,[X10,#off_DDBBA68@PAGEOFF] / CSEL / ASR W11,W9,#0x10
            {"1F 01 00 71 4A ?? ?? F9 29 B1 88 1A 2B 7D 10 13", -12},
            // ASR #0x10 / AND #FFFF0000 / SUB / MOV #0x18 / LDR [X10,#ObjObjects] / LDR [X10,#?]
            {"2B 7D 10 13 29 3D 10 12 08 01 09 4B 09 03 80 52 4A ?? ?? F9 4A ?? ?? F8", -32},
            // LDR-W8,[X2,#0xC] / ADRP / MOV#FFFF / ADD / CMP / LDR-guobjectarray
            {"48 0C 40 B9 4A ?? ?? F0 E9 FF 9F 52 09 01 09 0B 1F 01 00 71 4A ?? ?? F9", 4},
            // MOV #0x18 / LDR ObjObjects / LDR entry
            {"09 03 80 52 4A ?? ?? F9 4A ?? ?? F8 1F 20 03 D5 08 29 29 9B", -36},
            // LDR from pointer table with ASR+AND object index resolution
            {"4A ?? ?? F9 29 B1 88 1A 2B 7D 10 13 29 3D 10 12 08 01 09 4B", -20},
            // MOV #0x18 (24-byte object stride) + LDR obj ptr + LDR entry
            {"09 03 80 52 4A ?? ?? F9 4A ?? ?? F8", -36},
        };

        PATTERN_MAP_TYPE map_type = isEmulator() ? PATTERN_MAP_TYPE::ANY_R : PATTERN_MAP_TYPE::ANY_X;

        for (const auto &it : idaPatterns)
        {
            std::string ida_pattern = it.first;
            const int step = it.second;

            uintptr_t adrl = Arm64::DecodeADRL(findIdaPattern(map_type, ida_pattern, step));
            if (adrl != 0) return adrl;
        }

        return 0;
    }

    uintptr_t GetNamesPtr() const override
    {
        std::vector<std::pair<std::string, int>> idaPatterns = {
            // sub_6341A70: STP / ADRP X8 / LDR X21 / CBZ / ADD X20,X21,#0x20
            {"F4 4F 02 A9 28 ?? ?? B0 15 ?? ?? F9 75 06 00 B4 B4 82 00 91", 4},
            // sub_63438A8 / sub_6343D0C: MRS / ADRP X10 / LDR X9 / MOV X19,X8 / STR
            {"56 D0 3B D5 0A ?? ?? F0 C9 16 40 F9 F3 03 08 AA", 4},
            // sub_6348E18: STP / ADRP X21 / LDR X8 / CBZ
            {"F4 4F 05 A9 F5 ?? ?? D0 A8 06 46 F9 E8 07 00 B4", 4},
            // sub_710A8B4 (wrapper): ADRP X8 / LDR X8 / CBZ
            {"E8 ?? ?? 90 08 ?? ?? F9 A8 00 00 B4", 0},
            // sub_710A8B4 full: RET / ADRP X8 / LDR X8 / CBZ
            {"C0 03 5F D6 E8 ?? ?? 90 08 ?? ?? F9 A8 00 00 B4", 4},
            // 0x712861c: MRS / ADRP X27 / LDR X8 / STUR
            {"5A D0 3B D5 FB ?? ?? D0 48 17 40 F9 A8 83 1F F8", 4},
            // sub_7FD1ACC: BLR / ADRP X22 / LDR X0 / CBZ / ADD
            {"20 01 3F D6 B6 ?? ?? B0 C0 ?? ?? F9 80 00 00 B4 E2 23 00 91", 4},
        };

        PATTERN_MAP_TYPE map_type = isEmulator() ? PATTERN_MAP_TYPE::ANY_R : PATTERN_MAP_TYPE::ANY_X;

        for (const auto &it : idaPatterns)
        {
            std::string ida_pattern = it.first;
            const int step = it.second;

            uintptr_t adrl = Arm64::DecodeADRL(findIdaPattern(map_type, ida_pattern, step));
            if (adrl != 0) return adrl;
        }

        return 0;
    }

    UE_Offsets *GetOffsets() const override
    {
        static UE_Offsets offsets = UE_DefaultOffsets::UE4_25_27(isUsingCasePreservingName());

        static bool once = false;
        if (!once)
        {
            once = true;
            offsets.FNamePool.BlocksOff += sizeof(void *);

            // https://github.com/MJx0/AndUEDumper/issues/42
            offsets.UStruct.SuperStruct += sizeof(void *);
            offsets.UStruct.Children += sizeof(void *);
            offsets.UStruct.ChildProperties += sizeof(void *);
            offsets.UStruct.PropertiesSize += sizeof(void *);

            offsets.UField.Next += sizeof(void *);
            offsets.UEnum.Names += sizeof(void *);

            offsets.UFunction.EFunctionFlags += sizeof(void *);
            offsets.UFunction.NumParams += sizeof(void *);
            offsets.UFunction.ParamSize += sizeof(void *);
            offsets.UFunction.Func += sizeof(void *);
        }

        return &offsets;
    }
};
