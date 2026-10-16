# Dragon 6.12 command/state edge tracing handoff (2026-10-16 v4)

**Repository/branch:** `Masamune3210/ghidra-emotionengine-reloaded` / `testing`  
**Supersedes:** [Dragon command/state edge handoff v3](ps2-dragon612-command-state-edges-handoff-20261016-v3.md)

## Current state
The user successfully ran `ghidra_scripts/TraceDragon612ControllerCallbacks_20261016_v2.java` on the **existing** Dragon MechaCon 6.12 Ghidra database. Full ROM SHA-256 `18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b` passed, all 18 Thumb callback slots and relevant pointer/opcode anchors passed. Five renames, 22 labels, 32 comments and 20 references were applied; no firmware bytes or function signatures changed. The original reports are committed in `docs/evidence/`.

Verified callback flow: call site `0x29AF2` -> `DispatchControllerCallbackByIndex` at `0x2A604` -> 18-slot table `0x38680..0x386C7` -> `BX R7` thunk `0x3585E`. There are 16 distinct callback addresses. Slot 5 -> `0x2AFC8` (internal states `0x70..0x73`); slot 6 -> `0x2B070` (internal states `0x80..0x83`). Separate `0x15DD0` (states `0x90..0x93`) is called from `0x151C2`. Selector RAM `0x02000488`, substate RAM `0x02000489`, transfer `0x0200048C`, pending `0x02000496`. MMIO literals `0x036000A0`, `0x03005000`, `0x03808000`. **None of these internal state bytes is proven to be an external MagicGate/CDVD SCMD.**

The v2 decompilation shows an unresolved five-way indirect dispatch at `0x2A66E` for values offset from `0x30` and a 20-case selector-byte dispatcher at `0x31B84`. Actual external host-byte ingress and response/status transport remain unresolved.

## Run next: v5, not v4
[`ghidra_scripts/TraceDragon612CommandStateEdges_20261016_v5.java`](../ghidra_scripts/TraceDragon612CommandStateEdges_20261016_v5.java) is a **read-only** source revision of v4. It retains the corrected verified ROM size `0x44000`, full SHA guard, callback pointer checks, bounded decompilation and limited xref/callback scans. It creates **`%USERPROFILE%\Downloads\1`** when missing, and writes both timestamped reports there:

- `Dragon612_CommandStateEdges_20261016_v5_<timestamp>.txt`
- `Dragon612_CallbackBodies_20261016_v5_<timestamp>.txt`

The report title is also corrected to v5. The previous v4 script writes directly to Downloads; use **v5** instead. No database updates, function renames or signature changes. The source change has been committed and read back, but **v5 has not yet been user-run inside Ghidra**.

## Next analysis
Run v5 in the existing Dragon 6.12 ARM/Thumb program, return the Script Manager log and the two reports from `Downloads\1`. Trace who writes the selector/substate, where host command bytes enter, how bytes cross the MMIO controller, and where status/results return. Only after that compare a fully identified command path against PCSX2 `CDVD.cpp` and `MemoryCardProtocol.cpp`. Do not rerun v1/v2, reimport Dragon, repeat proven module hashing, or infer MagicGate identity merely from numeric overlap.

For all future Dragon tracing scripts, default to `Downloads\1` unless explicitly changed.
