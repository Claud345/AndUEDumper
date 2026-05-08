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
              // --- NEW: verified against current binary (0xE447DB0) ---
              //
              // Pattern A: function prologue at 0x572766C → ADRP X8,guobjectarray at +16
              //   FF 43 01 D1 = SUB SP,SP,#0x50
              //   FD 7B 04 A9 = STP X29,X30,[SP,#0x40]
              //   FD 03 01 91 = ADD X29,SP,#0x40
              //   E1 13 00 F9 = STR X1,[SP,#0x20]
              //   08 ?? ?? 90  = ADRP X8,#guobjectarray@PAGE (page bytes wildcarded)
              {"FF 43 01 D1 FD 7B 04 A9 FD 03 01 91 E1 13 00 F9 08 ? ? 90", 16},

              // Pattern A2: post-ADRL store+load at 0x5727684 → ADRP at -8
              //   A8 83 1E F8 = STUR X8,[X29,#-0x18]
              //   09 80 40 F9 = LDR  X9,[X0,#0x100]
              {"A8 83 1E F8 09 80 40 F9", -8},

              // --- Old fallbacks ---
              {"91 E1 03 ? AA E0 03 08 AA E2 03 1F 2A", -7},
              {"B4 21 0C 40 B9 ? ? ? ? ? ? ? 91", 5},
              {"9F E5 00 ? 00 E3 FF ? 40 E3 ? ? A0 E1", -2},
              {"96 df 02 17 ? ? ? ? 54 ? ? ? ? ? ? ? 91 e1 03 13 aa", 9},
              {"f4 03 01 2a ? 00 00 34 ? ? ? ? ? ? ? ? ? ? 00 54 ? 00 00 14 ? ? ? ? ? ? ? 91", 0x18},
              {"69 3e 40 b9 1f 01 09 6b ? ? ? 54 e1 03 13 aa ? ? ? ? f4 4f ? a9 ? ? ? ? ? ? ? 91", 0x18},
          };

          PATTERN_MAP_TYPE map_type = isEmulator() ? PATTERN_MAP_TYPE::ANY_R : PATTERN_MAP_TYPE::ANY_X;

          for (const auto &it : idaPatterns)
          {
              uintptr_t adrl = Arm64::DecodeADRL(findIdaPattern(map_type, it.first, it.second));
              if (adrl != 0) return adrl;
          }

          return 0;
      }

      uintptr_t GetNamesPtr() const override
      {
          PATTERN_MAP_TYPE map_type = isEmulator() ? PATTERN_MAP_TYPE::ANY_R : PATTERN_MAP_TYPE::ANY_X;

          // --- NEW: direct-step patterns (step lands on ADRP for unk_E427F40) ---
          std::vector<std::pair<std::string, int>> directPatterns = {
              // Pattern G: MOV+ADD after ADRP at sub_56E95D4 → ADRP X0,unk_E427F40 at -4
              //   F4 03 02 2A = MOV W20,W2
              //   00 00 3D 91 = ADD X0,X0,#unk_E427F40@PAGEOFF
              // DecodeADRL auto-scan skips the MOV to find ADD at +8
              {"F4 03 02 2A 00 00 3D 91", -4},

              // Pattern K: ADRP itself at sub_56E95D4 entry point
              //   E0 69 04 D0 = ADRP X0,#unk_E427F40@PAGE
              {"E0 69 04 D0", 0},
          };

          for (const auto &it : directPatterns)
          {
              uintptr_t adrl = Arm64::DecodeADRL(findIdaPattern(map_type, it.first, it.second));
              if (adrl != 0) return adrl;
          }

          // --- Old fallback: manual second-ADRP scan ---
          std::string pattern = "F4 4F 01 A9 FD 7B 02 A9 FD 83 00 91 ? ? ? ? A8 02 ? 39";

          uintptr_t find = findIdaPattern(map_type, pattern, 0);
          if (find != 0)
          {
              bool skippedFirst = false;
              intptr_t adrp_adr = 0;
              for (int i = 0; i < 8; i++)
              {
                  uint32_t insn = vm_rpm_ptr<uint32_t>((void*)(find + (i * 4)));
                  if (KittyArm64::decodeInsnType(insn) != EKittyInsnTypeArm64::ADRP)
                      continue;

                  if (!skippedFirst)
                  {
                      skippedFirst = true;
                      continue;
                  }

                  adrp_adr = find + (i * 4);
                  break;
              }

              if (adrp_adr != 0)
                  return Arm64::DecodeADRL(adrp_adr, 0);
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
              offsets.UField.Next += sizeof(void *);
              offsets.UEnum.Names += sizeof(void *);

              offsets.UFunction.EFunctionFlags += sizeof(void *);
              offsets.UFunction.NumParams += sizeof(void *);
              offsets.UFunction.ParamSize += sizeof(void *);
              offsets.UFunction.Func += sizeof(void *);
         
              // FProperty - corrected from IDA
              offsets.FProperty.ArrayDim        = 0x38;
              offsets.FProperty.ElementSize     = 0x3C;
              offsets.FProperty.Offset_Internal = 0x44;


          }

          return &offsets;
      }
  };


