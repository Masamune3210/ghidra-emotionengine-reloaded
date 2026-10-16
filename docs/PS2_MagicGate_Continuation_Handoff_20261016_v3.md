# PS2 MagicGate continuation handoff (2026-10-16 v3)

**Repository:** `Masamune3210/ghidra-emotionengine-reloaded`  
**Active branch:** `testing`  
**Supersedes:** [Continuation handoff v2](PS2_MagicGate_Continuation_Handoff_20261016_v2.md)

## Immediate next action
Run [`TraceDragon612CommandStateEdges_20261016_v5.java`](../ghidra_scripts/TraceDragon612CommandStateEdges_20261016_v5.java) in the **existing analyzed** Dragon MechaCon 6.12 Ghidra database. The script is **read-only**, preserves all metadata and firmware bytes, verifies the full `0x44000`-byte ROM against SHA-256 `18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b`, then verifies the exact callback pointer table. It creates and writes **only to `Downloads\1`**, not directly to `Downloads`:

- `Dragon612_CommandStateEdges_20261016_v5_<timestamp>.txt`
- `Dragon612_CallbackBodies_20261016_v5_<timestamp>.txt`

**Version history:** v3 originally hashed too-short `0x40000` ROM input; v4 corrected to `0x44000`; v5 additionally moves output to `Downloads\1` and corrects its report header. Use **v5**, not v3/v4. Source changes committed; **v5 has not yet been user-run**.

## Last completed verification
The user ran `TraceDragon612ControllerCallbacks_20261016_v2.java` successfully. ROM hash, 18 Thumb callback entries, call site/dispatcher opcodes and three MMIO pointer literals all verified. Database operations: 5 renames, 22 labels, 32 comments, 20 references, 0 new typed tables, 1 preserved. Full reports archived in [callback audit](evidence/Dragon612_ControllerCallbackAudit_20261016_v2_1792111994991.txt) and [selected decompilations](evidence/Dragon612_CommandIngressCandidates_20261016_v2_1792111994991.txt). No ROM bytes, function bodies or signatures modified. Callback table has 18 slots, 16 distinct targets.

Important established path: call `0x29AF2` -> `0x2A604` -> pointer table `0x38680` -> `0x3585E BX R7`. RAM selector `0x02000488`; substate `0x02000489`; transfer `0x0200048C`; pending `0x02000496`. Internal state dispatchers `0x2AFC8` (`0x70..0x73`), `0x2B070` (`0x80..0x83`), separate `0x15DD0` (`0x90..0x93`). The `0x31B84` routine has 20 selector-byte cases; external ingress semantics remain unknown. The `0x38438..0x3849B` region is a BCD lookup, **not** an SCMD table.

## Scope and remaining verification
Recover an externally visible firmware command ingress, transfer and response/status path. Then compare an individually verified command/result against PCSX2 `pcsx2/CDVD/CDVD.cpp` and `pcsx2/SIO/Memcard/MemoryCardProtocol.cpp`. The real IOP SECRMAN module and PCSX2's existing partial MechaCon/MagicGate handlers must not be conflated. Fixed authentication outputs and decrypted-KELF assumptions are candidate mismatches, not proven firmware deviations. Do not infer an SCMD from an internal state number. The PlayOnline/DNAS test may be useful later as an acceptance oracle.

Previous analyzed EE/IOP boot programs, SECRMAN, SYSMEM and LOADCORE work are preserved. No reimports or repeated v1/v2 scripts required. Return any newly proven Ghidra metadata in directly applicable function-editor/datatype/label form. For future Dragon tracing reports use **`Downloads\1`** by default.

Detailed handoff: [Dragon command/state edge handoff v4](ps2-dragon612-command-state-edges-handoff-20261016-v4.md).
