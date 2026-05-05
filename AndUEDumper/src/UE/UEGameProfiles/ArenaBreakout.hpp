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
              // ADRP X25, #off_DDBBA68@PAGE / LDR X25, [X25, #PAGEOFF] @ 0x71091A4
              {"99 65 03 D0 39 37 45 F9", 0},
              // ADRP X0, #off_DDBBA68@PAGE / LDR X0, [X0, #PAGEOFF] @ 0x71091C4
              {"80 65 03 D0 00 34 45 F9", 0},
              // ADRP X9, #off_DDBBA68@PAGE / LDR X9, [X9, #PAGEOFF] @ 0x32C0E08 (with MOV between)
              {"C9 57 05 F0 ?? ?? ?? ?? 29 35 45 F9", 0},
              // ADRP X10, #off_DDBBA68@PAGE (common pattern: LDR W8,[Xreg,#0xC] / ADRP X10 / ADD W9,W8,W9)
              {"48 0C 40 B9 4A 59 05 ??", 4},
              // ADRP X9, #off_DDBBA68@PAGE (alt register variant)
              {"48 0C 40 B9 49 59 05 ??", 4},
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
              // ADRL X8, unk_E427F40 @ 0x58EBBC8 (back-to-back ADRP+ADD, direct struct)
              {"E8 59 04 90 08 01 3D 91", 0},
              // ADRP X0, #unk_E427F40@PAGE / MOV W20,W2 / ADD X0,X0,#PAGEOFF @ 0x56E95D4
              {"E0 69 04 D0 ?? ?? ?? ?? 00 00 3D 91", 0},
              // ADRP X8, #unk_E427F40@PAGE / ADD X8,X8,#PAGEOFF (wildcarded reg)
              {"?? 59 04 90 ?? 01 3D 91", 0},
              // ADRP X20, #unk_E427F40@PAGE / ADD X20,X20,#PAGEOFF @ 0x6318830
              {"74 08 04 F0 ?? ?? ?? ?? 94 02 3D 91", 0},
              // ADRP X21, #unk_E427F40@PAGE / MOV X19,X1 / MOV X20,X0 / ADD X21,X21,#PAGEOFF @ 0x6939B38
              {"75 D7 03 D0 F3 03 01 AA F4 03 00 AA B5 02 3D 91", 0},
              // ADRP X21, #unk_E427F40@PAGE / MOV X19,X1 / MOV X20,X0 @ 0x572ADE8 (ADD at +16)
              {"F5 67 04 B0 F3 03 01 AA F4 03 00 AA", 0},
              // ADRP X10, #unk_E427F40@PAGE / ADD X10,X10,#PAGEOFF @ 0x5B155E4 (ADRL)
              {"8A 48 04 D0 4A 01 3D 91", 0},
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
