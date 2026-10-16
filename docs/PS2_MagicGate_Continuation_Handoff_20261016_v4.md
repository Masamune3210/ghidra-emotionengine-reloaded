# PS2 MagicGate / Dragon continuation handoff (2026-10-16 v4)

**Branch:** `testing` on `Masamune3210/ghidra-emotionengine-reloaded`  
**Supersedes:** [v3](PS2_MagicGate_Continuation_Handoff_20261016_v3.md)  
**Current detailed findings:** [Dragon v5 result and command-boundary handoff](ps2-dragon612-command-boundary-handoff-20261016-v5.md)

## Objective
Identify *verified* firmware-facing MechaCon/MagicGate command flow and compare it with PCSX2 CDVD/memory-card protocol handling, without claiming unsupported firmware command equivalences or redoing existing boot/SECRMAN/IOP analyses. The PlayOnline Viewer/DNAS installer may serve as a later acceptance oracle, not proof by itself.

## Last successful user-run analysis
`TraceDragon612CommandStateEdges_20261016_v5.java` completed; its two uploaded reports from `Downloads\1` confirm the Dragon 6.12 full-ROM SHA-256 `18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b` and all 18 controller callback words. The script was read-only and made **no database changes**.

The full 18-entry controller table and its 16 distinct Thumb targets are established. Internal families include states `0x30..0x34`, `0x40/0x41`, `0x50/0x51`, `0x60..0x65`, `0x70..0x73`, `0x80..0x83`, `0x90..0x94`, `0xA0..0xA3`, `0xE0..0xE6`, and `0xF0..0xF5` (some via unresolved Thumb computed jumps). None are automatically external CDVD SCMD values. `0x31B84` appears in a measured control-setting search via `0x17384` and is deprioritized as security ingress.

**New key observation:** `FUN_00014270` calls `FUN_00008658(0xC0,12,buffer)` and, if successful, `FUN_00003558`. The latter transforms an eight-byte buffer and conditionally calls `FUN_000086D0(0xE3,10,payload)` then `FUN_000086D0(0xE8,10,payload)`. This command exchange is an **authentication candidate only**, not yet proven MagicGate or an externally visible SCMD. The exact command destination, result transport and semantic cryptography remain unresolved.

## Do next
Run [`ghidra_scripts/TraceDragon612SecurityCommandBoundary_20261016_v6.java`](../ghidra_scripts/TraceDragon612SecurityCommandBoundary_20261016_v6.java) against the **existing analyzed** Dragon MechaCon 6.12 Ghidra database. It validates the `0x44000`-byte ROM and exact callback pointer table before read-only analysis and focuses on the `0xC0/0xE3/0xE8` transport and transform subgraph. It omits the v5 broad 1041-literal listing. **Source committed; Ghidra runtime execution unverified.** Reports go to **`Downloads\1`**:

- `Dragon612_SecurityCommandBoundary_20261016_v6_<timestamp>.txt`
- `Dragon612_SecurityCommandBodies_20261016_v6_<timestamp>.txt`

Return the run log and both reports. Trace the transport at `0x8658` and `0x86D0` into hardware-facing MMIO and verify received response bytes. After that compare only proven behavior with PCSX2 `pcsx2/CDVD/CDVD.cpp` and `pcsx2/SIO/Memcard/MemoryCardProtocol.cpp`.

## Preserve and do not repeat
- Completed Dragon state audit v1, callback audit v2 and command/state read-only v5. Full v2 reports already in `docs/evidence`; full v5 user reports remain in the project conversation and on disk in Downloads/1, with SHA-256 hashes in the detailed handoff.
- Existing Dragon Ghidra annotations/functions and separate SECRMAN/KELF work.
- SCPH-39001/79001 byte-identical SYSMEM/LOADCORE module findings; EE/IOP combined boot imports.
- `0x38438..0x3849B` is a packed BCD lookup, not an SCMD handler.
- Always target **`Downloads\1`** for new Ghidra script outputs. Preserve unresolved types/signatures; return any discovered labels or data declarations in directly applicable Ghidra syntax.

**Status:** PCSX2/firmware MagicGate mismatch **not proven**. Main open question: actual external command ingress/transport for `0xC0`, `0xE3`, `0xE8`.
