# PS2 MagicGate continuation handoff: Dragon storage-queue correction (2026-10-16 v6)

**Repository:** `Masamune3210/ghidra-emotionengine-reloaded`  
**Active branch:** `testing`  
**Supersedes:** [v5 continuation](PS2_MagicGate_Continuation_Handoff_20261016_v5.md)  
**Detailed current state and metadata:** [Dragon storage queue handoff v7](ps2-dragon612-storage-queue-handoff-20261016-v7.md)

## Objective
Establish a **real** MechaCon/MagicGate external command flow, authentication state and returned response before modifying PCSX2. Do not mistake internal controller states or storage addresses for 8-bit external S-command values. PCSX2 already has partial CDVD/MechaCon and memory-card authentication implementations; preserve that distinction from the genuine IOP's SECRMAN.

## Most recent completed script
The user ran `TraceDragon612SecurityCommandBoundary_20261016_v6.java` on the **existing** Dragon 6.12 Ghidra database and uploaded both reports. They are archived in `docs/evidence/Dragon612_SecurityCommandBoundary_20261016_v6_1792114423568.txt` and `docs/evidence/Dragon612_SecurityCommandBodies_20261016_v6_1792114423568.txt`. The read-only log confirms ROM SHA-256 `18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b`, all 18 callback table words exact, and **no metadata changes**.

**Important correction:** First arguments `0xC0`, `0xE3`, `0xE8` passed to `0x8658` and `0x86D0` are **storage offsets/locations**, not established external SCMD opcodes. Those routines store the first argument in a 16-bit field and queue a transfer with `length >> 1`; the synchronous version waits and reads back to verify data. Other calls use offsets `0x138`, `0x158`, and decimal 400, which rules out the simple 8-bit opcode interpretation. The earlier "0xC0 -> 0xE3 -> 0xE8 SCMD sequence" is invalidated as a firm or preferred hypothesis.

`0x14270` enqueues a 12-byte write at offset C0 and, on accepted queue status, prepares eight bytes for transformed 10-byte writes at E3 and E8. `0x364C` reads both latter offsets and validates a relationship. The actual storage hardware and transformation engine at `0x2F6C` are not yet established; this might be security-related but is not a proven MagicGate exchange.

## Next exact action
Run [`ghidra_scripts/TraceDragon612StorageQueueWorkers_20261016_v7.java`](../ghidra_scripts/TraceDragon612StorageQueueWorkers_20261016_v7.java) against the *same* existing Dragon program. It is read-only, source committed, **not yet Ghidra runtime tested**, and verifies full 0x44000-byte firmware ROM and 18 callback entries. It traces `0x8464`, `0x8658`, `0x86D0`, `0x87D0`, `0x88F0` and other focused related functions, examining exact queue shared RAM pointer literals and their other ROM consumers, rather than repeating v5's broad ROM scan.

Two report files written directly into **`Downloads\1`**:
- `Dragon612_StorageQueueWorkers_20261016_v7_<timestamp>.txt`
- `Dragon612_StorageQueueBodies_20261016_v7_<timestamp>.txt`

Return both reports and the script log. Find the actual queue worker, storage backing and readback path. Separately investigate hardware-transform peripheral `0x2F6C` before assigning cryptosystem identities.

## Decisions/preserved work
- State audit v1, controller callback annotations v2, broad state scan v5, and security-command boundary trace v6 all ran; do not repeat.
- The callback dispatcher table contains 18 slots, 16 distinct targets. The apparent controller state numbers (including 0x70, 0x80, 0x90 families) are not established external SCMDs.
- The packed BCD table `0x38438..0x3849B` is not a command table.
- Reuse existing SECRMAN/KELF, Dragon, EE/IOP boot and SYSMEM/LOADCORE analysis. Do not reimport or redo byte-equivalence checks.
- Return Ghidra metadata as directly usable function-editor declarations, preserve `undefined` / `undefined4` unresolved types and user-defined names. See detailed handoff for v6-supported proposed renames.
- Scripts write **`Downloads\1`** by default.
- PCSX2 MagicGate firmware-observed mismatch remains **unproven**.
