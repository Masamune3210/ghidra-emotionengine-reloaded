# PS2 MagicGate continuation: Dragon storage queue MMIO (2026-10-16 v8)

**Repository/branch:** `Masamune3210/ghidra-emotionengine-reloaded`, `testing`  
**Supersedes:** [continuation v7](PS2_MagicGate_Continuation_Handoff_20261016_v7.md)  
**Full v8 findings, verified source excerpts and Ghidra metadata:** [Dragon queue-worker/MMIO handoff v9](ps2-dragon612-queue-worker-mmio-handoff-20261016-v9.md)

## Goal
Recover genuine MechaCon external authentication/command flow relevant to PCSX2's MagicGate behavior. Preserve parallel SECRMAN/KELF, EE/IOP boot, controller-state and hardware-transform research. No PCSX2 MagicGate mismatch has yet been proven.

## Latest completed user Ghidra run: v8

`TraceDragon612StorageQueueWorkers_20261016_v8.java` ran successfully against the existing Dragon 6.12 ARMv4T/Thumb database; ROM bytes `0x44000`, SHA-256 `18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b`, and all 18 callback words verified; metadata changes: **none**. Exact reports committed:
- `docs/evidence/Dragon612_StorageQueueWorkers_20261016_v8_1792115048007.txt`
- `docs/evidence/Dragon612_StorageQueueBodies_20261016_v8_1792115048007.txt`

**Critical corrected interpretation:** `0xC0`, `0xE3`, `0xE8`, `0x138`, `0x158`, `0x190` are addressable storage locations in functions `0x8658/0x86D0/0x8464`, not proven external 8-bit CDVD SCMD opcodes. `0x88F0` encodes a **9-bit** storage location as hardware command `0xA8 | ((offset>>8)&1)` and an 8-bit low address, using halfword data in word-spaced MMIO buffers. The upper location bound observed in firmware is `0x1FF`. Storage technology is still unidentified.

**Queue state:** flags `0x02000028`, source descriptor `0x0200002C`, location `0x02000034`. **Readback MMIO:** `0x03003104`. **Independent eight-byte hardware transformation registers:** `0x03004100`, reached from `0x2F6C`, `0x3044`, `0x311C`, `0x322C`. Do not infer AES/MagicGate hardware type until validated.

**New candidate queue worker:** `0x30C40` references queue descriptor, flags, and storage location through pool literals `0x31018`, `0x3101C`, `0x3100C`. Related `0x83E8`, `0x8378` read shared queue/MMIO pointers. Worker role not yet established.

## Next Ghidra step

Run committed read-only [`TraceDragon612QueueWorkerMmio_20261016_v9.java`](../ghidra_scripts/TraceDragon612QueueWorkerMmio_20261016_v9.java) on same database. The code is **source checked but not runtime verified**. It preserves exact ROM and callback guards. Targeted xrefs/decompilations and assembly windows focus on `0x30C40`, `0x83E8`, `0x8378`, `0x899C`, `0x8A28`, `0x8AB0`, `0x8B9C`, `0x8168`, `0x88F0` and queue shared-memory readers. It does not redo broad v5/v8 scans.

Outputs in **`Downloads\1`**:
- `Dragon612_QueueWorkerMmio_20261016_v9_<timestamp>.txt`
- `Dragon612_QueueWorkerBodies_20261016_v9_<timestamp>.txt`

Return both reports and compile/runtime log. Focus on **queue consumer -> actual hardware transfer -> completion flag and readback** before comparing with PCSX2. Separately, resolve crypto engine semantics if queue work exposes a security-relevant path.

## Preserve and don't repeat
- Dragon v1/v2 controller analysis, v5 state audit, v6 transformed storage identification, v8 queue/MMIO reports are complete. v7 failed compilation due to a checked exception and was superseded by successful v8.
- Controller state numbers `0x70`, `0x80`, `0x90`, etc. are internal and **not** confirmed SCMD identities.
- BCD data at `0x38438..0x3849B` is not a command table.
- Existing firmware/SECRMAN analysis and user Ghidra names/types must be preserved.
- For Ghidra, return directly applicable function-editor declarations with existing `undefined`, `undefined4`, `undefined2` etc. Do not invent datatypes or structure sizes.
- All scripts export to `%USERPROFILE%\Downloads\1`. Never reuse an old filename.
