# PS2 MagicGate continuation v25: fix DNAS applier refusal on both SCUS-97269 binaries

**Branch**: testing. Previous [v24 correct disc recovery](PS2_MagicGate_Continuation_Handoff_20261016_v24.md).

## User evidence

User attempted `AnnotatePlayOnlineDnas97269_20261016_v1.java`; script refused metadata application. Supplied exported Ghidra Java-serialization/embedded-zip `.gzf` archives for **both** `SCUS_972.69` and `POL_HDD.ELF` (both were actual PS2 PlayOnline Viewer *second-disc* programs, not first-disc FFXI `INSTALL.ELF`). Their Java-serialization header identifies respective program names; embedded zip starts byte offset `0x34` with FOLDER_ITEM and raw-DEFLATE stream. Verified `.gzf` byte streams inflate to 18,169,856 and 18,415,616 bytes of Ghidra folder databases, respectively. This does not by itself permit a precise memory map reconstruction; script now reports actual Ghidra memory byte probes instead of assuming the original ELF's map was reproduced.

## Exact original script bugs, proven against BOTH original ELF files

1. `verifyString()` expected `ascii + NUL` but all selected DNAS messages are `ascii + LF + NUL`. Both candidate variants fail verification due to this exact off-by-one terminator assumption, including `sceDNAS1_SS_DIFFERENT_HDD retry\n` and `playonline DNAS slot ID = ...\n`.
2. **CD only**: original script checked `0x0080F0E0` for MIPS `addiu v0,zero,-109`. The actual instruction bytes `93 ff 02 24`, corresponding to `0x2402ff93`, are at `0x0080F0DC`. `0x0080F0E0` is the following conditional-branch opcode `0x5462000f`. The **HDD comparison address `0x0080E8EC` was already correct**.

| Item | SCUS_972.69 CD | POL_HDD.ELF |
| --- | --- | --- |
| Verified handler prologue (`0x27bdfd10`) | `0x0080EAF8` | `0x0080E308` |
| Verified -109 instruction (`0x2402ff93`) | `0x0080F0DC` | `0x0080E8EC` |
| Retry log call | `0x0080F0EC` | `0x0080E8FC` |
| Verified retry-helper JAL | `0x0080F0F4` -> `0x0080DB98` | `0x0080E904` -> `0x0080D3A8` |
| DNAS retry diagnostic | `0x0089FD48` | `0x0089F498` |
| Slot ID format | `0x0089FD00` | `0x0089F450` |

Original raw-image SHA256 remains CD `b3c429e3691f3198e18ca76a4e2640596206da3b40272a2ff1d3cb94658abcea` and HDD `90d8dbeb0b48b377ef471de184dcdaa207d6447abc5245df5a1df4371728cb41`.

## Replacement Ghidra Java script

Prepared unique user file `AnnotatePlayOnlineDnas97269_20261016_v2.java`, an **APPLY script**; does not reuse v1 filename. Validation improvements:
- Reads exact LITTLE-ENDIAN opcode bytes rather than using `Memory.getInt()` and requiring executable block flag in detector.
- Probes both variants and prints independently whether handler memory is initialized, handler prologue bytes match, -109 instruction matches, retry string has correct LF+NUL, slot ID string matches, and helper call matches. On unexpected mapping, reports offending bytes/address and **applies nothing**.
- Uses either CD or HDD address set only after its verified fingerprints uniquely match.
- Labels **all 21 verified DNAS diagnostic string locations** in each program (state/progress, initialization, shutdown, status error, slot ID, DIFFERENT_HDD, crypt init). Actual bytes of each string are checked individually before labeling.
- Creates `/PlayOnline/DNAS/Dnas1ObservedStatusCode` enum size 4 with one **observed** value `DifferentHdd=-109`, preserving any preexisting datatype.
- Creates/generalizes confirmed DNAS status function `ProcessDnas1AuthenticationStatus` when mapped as an instruction and no user/imported function name would be replaced. Adds function and relevant instruction comments. Preserves all unresolved function signatures, program bytes and preexisting specific/user metadata.
- Source-verified offline against BOTH original executables: **21/21 DNAS messages** and ALL expected prologue, `-109`, helper JAL bytes match in each program; cross-variant differentiation holds. Ghidra 12.1.3 in-app compilation/execution **not yet tested**.

Do NOT claim code -109 is Sony DNAS -404. The status branch says DIFFERENT_HDD retry, but the -404 HDD binding rejection provenance remains untraced. Do not restart irrelevant first-disc `INSTALL.ELF` analyses or request nonexistent original Sony HDD.

## Next action

User: run `AnnotatePlayOnlineDnas97269_20261016_v2.java` in the **SCUS_972.69** Ghidra program and again in the **POL_HDD.ELF** program; report `[DNAS97269V2] PROBE`, VARIANT and SUMMARY lines, or Java compilation error. Once annotations apply, decompile `ProcessDnas1AuthenticationStatus` and investigate how other statuses, especially -404, are obtained from IOP services and DEV9/MechaCon. All future scripts apply useful metadata as previously requested.
