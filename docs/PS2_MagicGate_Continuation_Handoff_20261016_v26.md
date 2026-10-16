# PS2 MagicGate continuation v26: successful dual-disc DNAS annotation and next status-source recovery

**Branch:** `testing`. Prior [v25](PS2_MagicGate_Continuation_Handoff_20261016_v25.md).

## User-confirmed Ghidra runtime success

`AnnotatePlayOnlineDnas97269_20261016_v2.java` was run independently against the correct PlayOnline Viewer and Tetra Master disc's **both** Ghidra databases:

- HDD program `POL_HDD.ELF`: probe matched HDD exclusively, handler `0x0080E308` renamed `ProcessDnas1AuthenticationStatus`, 21 DNAS labels, 1 four-byte enum with `DifferentHdd=-109`, 7 comments, **failures=0**.
- CD program `SCUS_972.69`: probe matched CD exclusively, handler `0x0080EAF8` renamed to same generalized name, 21 labels, 1 enum and 7 comments, **failures=0**.
- Cross-variant probe failures are **expected/healthy differentiation** and do not indicate script error. v1's string terminator and CD instruction offset mistakes fully resolved. No need to rerun v2.

## New verified details from actual CD and HDD EE instructions

- Both DNAS handlers compare the current status buffer's **+0x04** 32-bit word against signed `-109`; CD source load at `0x0080F0D8`, compare constant `0x0080F0DC`, HDD load `0x0080E8E8`, compare constant `0x0080E8EC`. Branch emits `DIFFERENT_HDD retry` and calls a cleanup/retry helper.
- CD helper `0x0080DB98`, HDD helper `0x0080D3A8`. These load a runtime context pointer at **CD `0x008C7940` vs HDD `0x008C1E00`** and call a verified byte-zeroing routine twice: first context+0x10078 length 0x10, then context+0x10068 length 0x10.
- Zeroing function CD `0x00135178`, HDD `0x00135238` writes exactly `length` zero bytes in descending address order, returns the original requested length (32-bit). Proven generalized signature: `uint ZeroByteSpan(byte * buffer, uint length)`.
- State classifier CD `0x0080DB60`, HDD `0x0080D370`: returns int 1 precisely for input state **2 or 5, 6, 7**, otherwise 0. Proven generalized declaration: `int IsDnas1ProcessingState(int state)`.
- Status diagnostic/logging routine CD `0x0080DE08`, HDD `0x0080D618` takes current state snapshot pointer in a0, reads +0 state, +4 status/flags, +8 progress, compares to **cached** snapshot at context+0x10068, logs changes and copies the three words to the cache. Name `LogDnas1StateChanges`; return type remains unresolved.
- Current snapshot is context+0x10078. Both it and cached snapshot occupy 16-byte windows reset by retry. Contents beyond the first 3 words unverified.

Useful new datatype definitions, in dependency order:

```text
Structure: /PlayOnline/DNAS/Dnas1StatusSnapshot
Size: 0x10
0x00 int state
0x04 int statusOrFlags
0x08 int progress
0x0C byte[4] unresolved0C

Structure: /PlayOnline/DNAS/DnasRetryClearedWindows
Size: 0x20
0x00 Dnas1StatusSnapshot lastReported
0x10 Dnas1StatusSnapshot current
```

**Don't equate the -109 DIFFERENT_HDD branch to the separate alleged -404 invalid-HDD binding status.** Search of direct `addiu rt,zero,-404` instructions across both program file-backed PT_LOAD segments finds multiple sites (including code outside the DNAS handler). Their meaning requires caller-context decompilation. Not all -404 occurrences are DNAS.

## Next metadata applier + report exporter

Created unique user-facing `ApplyAndTracePlayOnlineDnas97269_20261016_v3.java`, which auto-detects CD or HDD by byte-exact evidence; applies the two verified datatypes, safely labels/types the context-pointer global as `void *` when memory mapped and not already specifically typed; names/comments three newly confirmed functions, refines return/params of ZeroByteSpan and classifier only where existing signatures are not user-defined; leaves other parameters unresolved; adds source comments to critical buffer and status instructions. Then optionally exports decompiled handler, logger, predicate, retry, byte-zeroer and initialization helpers, XREFs, and `-404` constant locations. **Script has NOT been compiled/runtime-tested against Ghidra 12.1.3**. Cancelling report export retains applied metadata. The exporter doesn't modify executable bytes.

**Next action:** Run v3 in the existing **CD** Ghidra database first and supply `[DNAS97269V3]` console log and (if saved) the report .txt. Can run same script against HDD afterward to compare. Do not request user to redo v2 or hunt FFXI disc; exact correct-disc image and Ghidra GZF archives already provided. No original Sony HDD is available, so do not ask for one.

All binary disassembly verified against locally provided `SCUS_972.69` and `POL_HDD.ELF`; **new v3 runtime unverified**. No emulator/Ghidra-extension source changes in this pass.
