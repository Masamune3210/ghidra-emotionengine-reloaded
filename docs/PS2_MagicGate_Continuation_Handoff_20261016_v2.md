# PS2 MagicGate / SECRMAN / Dragon MechaCon continuation handoff (2026-10-16 v2)

**Repository:** `Masamune3210/ghidra-emotionengine-reloaded`  
**Branch:** `testing`  
**Supersedes:** `docs/PS2_MagicGate_Continuation_Handoff_20261016_v1.md`

## Current objective
Establish where, if anywhere, PCSX2's partial MechaCon/MagicGate emulation diverges from firmware by recovering the **external command ingress, command bytes, packet/transfer handling, and response/status path** in Dragon MechaCon 6.12. Compare only behavior actually established by firmware against PCSX2's CDVD and memory-card implementations. PlayOnline Viewer/DNAS is a possible later software test oracle, not proof of a MagicGate failure by itself.

## Newly completed
The user ran `TraceDragon612ControllerCallbacks_20261016_v2.java` successfully:
- All 18 callback words and source opcode/MMIO anchors verified against ROM SHA-256 `18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b`.
- 5 renames, 22 labels, 32 comments and 20 references applied; existing callback table markup preserved. No firmware byte or signature edits.
- Both original reports are archived under `docs/evidence/`.
- There are 18 slots and 16 distinct callback target addresses; the callback selector at `0x02000488` and the substate at `0x02000489` are distinct.
- v2 decompilation found `0x2A66E`'s apparent `0x30..0x34` computed dispatch (jump table unresolved) and `0x31B84`'s 20-way selector-to-byte-handler dispatch. These are **not identified as external MagicGate SCMDs**.

See [Dragon v3 detailed handoff](ps2-dragon612-command-state-edges-handoff-20261016-v3.md), [original callback audit](evidence/Dragon612_ControllerCallbackAudit_20261016_v2_1792111994991.txt), and [selected ingress decompilations](evidence/Dragon612_CommandIngressCandidates_20261016_v2_1792111994991.txt).

## Next task, exact order
1. In the existing Dragon 6.12 Ghidra database run [`TraceDragon612CommandStateEdges_20261016_v4.java`](../ghidra_scripts/TraceDragon612CommandStateEdges_20261016_v4.java) through Script Manager. **v4, not v3:** the v3 script used `0x40000` instead of the verified `0x44000` ROM length and would fail SHA verification. The v4 source has not yet been runtime-tested.
2. Collect both timestamped files from **Downloads**: `Dragon612_CommandStateEdges_20261016_v4_*.txt` and `Dragon612_CallbackBodies_20261016_v4_*.txt`, plus the run log.
3. Follow producer references to `0x02000488` and `0x02000489`, MMIO at `0x036000A0`, `0x03005000` and `0x03808000`, then identify a host command-to-controller transfer and genuine response/error signaling. The `0x15DD0` state dispatcher is separate.
4. Only once an external opcode and returned data are proven, compare precisely with `pcsx2/CDVD/CDVD.cpp` and `pcsx2/SIO/Memcard/MemoryCardProtocol.cpp`. Prior suspected gaps (fixed auth responses; already decrypted KELF input assumptions) remain hypotheses.

## Existing work not to repeat
- `AuditDragon612SecurityStateMachines_20261016_v1.java` and `TraceDragon612ControllerCallbacks_20261016_v2.java` already ran successfully.
- The 100-byte table at `0x38438..0x3849B` is packed BCD, **not** a command table.
- Previous SCPH-39001/79001 module byte-equivalence and SYSMEM/LOADCORE label/import work are established. Don't reimport or rerun without new reasons.
- The broader EE/IOP boot handoff is `docs/ps2-79001-iop-boot-and-ee-handoff-20261016-v10.md`. SECRMAN analysis continues from the existing database.
- All scripts report to **Downloads**, avoid assumptions about external SCMD mapping, preserve existing user annotations and type declarations, and return Ghidra-applicable metadata where established.

## Verification matrix
| Artifact | Verified status |
|---|---|
| Original Dragon 6.12 firmware hash | Verified |
| Dragon state dispatch audit v1 | User-run, passed |
| Dragon 18-slot callback annotation v2 | User-run, passed |
| v2 audit/decomp reports | Provided and archived |
| Command/state edge trace v4 | Source checked; **not yet user-run** |
| External MagicGate SCMD and response mapping | **Unresolved** |
| PCSX2 firmware-observed behavioral mismatch | **Unproven** |
