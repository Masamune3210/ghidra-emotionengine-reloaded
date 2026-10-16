# Dragon 6.12: storage queue reinterpretation and next trace (2026-10-16 v7)

**Branch:** `testing`  
**Supersedes:** [Dragon v6 handoff](ps2-dragon612-command-boundary-handoff-20261016-v6.md)  
**Program:** existing analyzed Dragon MechaCon 6.12 ARMv4T/Thumb Ghidra database  
**ROM:** `0x44000` bytes, SHA-256 `18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b`

## Verified v6 user run

The user ran `ghidra_scripts/TraceDragon612SecurityCommandBoundary_20261016_v6.java`. Both files were returned. The index header reports **full-ROM hash verified, all 18 callback pointers exact** and the script explicitly records **no metadata changes**. Archive copies are on this branch:
- [Security-command boundary xrefs/instruction windows](evidence/Dragon612_SecurityCommandBoundary_20261016_v6_1792114423568.txt)
- [Selected decompilations](evidence/Dragon612_SecurityCommandBodies_20261016_v6_1792114423568.txt)

### Critical correction: `0xC0 / 0xE3 / 0xE8` are location/offset arguments, *not demonstrated external SCMDs*

Earlier handoffs characterized `FUN_00008658(0xC0,...)`, `FUN_000086D0(0xE3,...)`, and `FUN_000086D0(0xE8,...)` as a possible chained external command exchange. **That interpretation is contradicted by newly decompiled transport bodies and must not be retained as a working conclusion.**

- `0x00008658` takes a first `int` compared against a limit `DAT_000086C0`, saves it as a 16-bit value at a queue-state pointer (ROM literal `0x086CC`), records source pointer, stores `byteLength >> 1` as the queue length, sets queue flags and returns an enqueue/status result. It **does not wait for completion**, so return zero establishes queue acceptance, not durable storage success.
- `0x000086D0` uses the same style of slot/length setup, **waits** for the queue pending flag to clear using the system wait primitive, calls `FUN_000088F0((short)offset,byteLength)`, then compares bytes read back to the original submitted buffer. It returns mismatch error **8** when a compared byte differs (other observed status includes **4** when offset bounds fail).
- The same write helper `0x8658` is called with offsets `0x138`, `0x158`, and `400` (decimal, `0x190`) as well as `0xC0`. These cannot be individual 8-bit S-command opcodes; `0xC0`, `0xE3`, and `0xE8` are almost certainly location arguments into some addressable region. The exact *backing device* (flash, EEPROM, special register window, etc.) is **not yet proven**.
- `0x00014270` builds a 12-byte block from a RAM source, enqueues it at `0xC0`, then under success conditions assembles an eight-byte input for `0x00003558`. The latter uses `0x00003410`, `0x00003430`, `0x00002F6C` transformations and submits two 10-byte checksummed blocks at offsets `0xE3` and `0xE8` through the synchronous write-and-verify helper. The exact cryptographic algorithm and purpose are unresolved.
- `0x0000364C` reads/checks blocks at `0xE3` and `0xE8` via `FUN_00008464`, further supporting a **storage/verification** interpretation. `0x00003924` calls `0x364C` in the success branch.
- `0x00002F6C` exchanges two eight-byte inputs with a control region (via `DAT_00003040`), waits on a status bit, and copies the eight-byte output. Its peripheral identity, exact input ordering and algorithm remain unproven; avoid calling it AES or MagicGate prematurely.

### Precise v6 code behavior

- `0x86D0` stores `byteLength >> 1`, performs a wait using `thunk_FUN_000336E4(1)`, then invokes `0x88F0` and checks pairs of bytes with the readback buffer advancing by 4 bytes for each logical two-byte pair. This may reflect packed storage layout in a word-spaced buffer and needs exact worker verification.
- `0x8658` uses `thunk_FUN_00033340(1,-1)` to acquire a synchronization resource; `0x86D0` also uses this primitive and `thunk_FUN_000334E8(1)` to release. Names and semantics of system primitives are provisional.
- Separate `0x31B84` selector dispatch has been observed under the `0x17384` measured-setting search; it is not an established external security-command decoder.
- Older controller state families `0x30/0x60/0x70/0x80/0x90/0xA0/0xE0/0xF0` are also internal; do **not** treat their numeric overlap with PCSX2 SCMD values as authentication evidence.

## Applicable partial Ghidra metadata

These are **proposed descriptive names**, not recovered original manufacturer symbols. Preserve existing non-generic user-defined names, storage, and the current Ghidra function-editor parameter/return types:

```text
0x00008658 -> QueueStorageWrite
undefined4 QueueStorageWrite(int storageOffset, uint byteLength, undefined4 sourceBuffer)

0x000086D0 -> QueueAndVerifyStorageWrite
undefined4 QueueAndVerifyStorageWrite(int storageOffset, uint byteLength, int sourceBuffer)

0x00014270 -> PrepareAndQueueTransformedStorageData
undefined PrepareAndQueueTransformedStorageData(void)

0x00003558 -> PrepareAndVerifyTwoStorageBlocks
int PrepareAndVerifyTwoStorageBlocks(int inputEightBytes)

0x00003410 -> XorInputBlockIntoGlobalState
undefined XorInputBlockIntoGlobalState(uint * inputWords)

0x0000364C -> ReadAndCheckStoredBlocks
undefined4 ReadAndCheckStoredBlocks(void)

0x00002F6C -> ExecuteEightByteHardwareTransform
undefined ExecuteEightByteHardwareTransform(undefined1 * inputA, undefined1 * inputB, undefined4 * outputWords)
```

Function names deliberately avoid asserting flash/EEPROM, specific cryptosystem or MagicGate identity. Preserve unresolved return types `undefined` and `undefined4`, not decompiled-C `void`. No safe storage structure offsets or bitfield types have been established yet; do not invent a structure.

## Next script, not yet runtime verified

[`ghidra_scripts/TraceDragon612StorageQueueWorkers_20261016_v7.java`](../ghidra_scripts/TraceDragon612StorageQueueWorkers_20261016_v7.java) is **read-only**, guarded by full `0x44000`-byte SHA and all 18 callback words. It targets `0x8464`, `0x8658`, `0x86D0`, `0x87D0`, `0x88F0`, `0x364C`, `0x14270`, `0x3558`, `0x2F6C` and the immediate caller graph. It also reports the actual pointer values at queue literal pools `0x86C0..0x86CC`, `0x87BC..0x87CC`, `0x3040`, searching for matching ROM pointers and references to identify queue workers, transfer routines or device MMIO. **Literal equality is not proof of a runtime memory access**. It is bounded (maximum 40 occurrences per value, 12 references per occurrence, 28 decompilations) and preserves database contents.

Reports go to **`%USERPROFILE%\Downloads\1`**:
- `Dragon612_StorageQueueWorkers_20261016_v7_<timestamp>.txt`
- `Dragon612_StorageQueueBodies_20261016_v7_<timestamp>.txt`

Next action: run this script on the existing Dragon Ghidra program, return both reports and run log. Determine actual queue backing storage, its worker and readback implementation. Separately trace the peripheral behind `DAT_00003040` to assess whether it is cryptographic and/or relevant to SECRMAN/MagicGate. No firmware-observed PCSX2 mismatch has yet been proven.

## Avoid redundant work

Previous Dragon v1 state audit, v2 callback annotation, v5 broad read-only trace and v6 focused read-only trace already ran. Do not re-run, reimport ROM or rehash known equivalent SCPH-39001/79001 modules. The packed BCD table at `0x38438..0x3849B` remains a negative control, not an SCMD table. The [latest MagicGate continuation handoff](PS2_MagicGate_Continuation_Handoff_20261016_v6.md) tracks next steps. Maintain `Downloads\1` for Ghidra output scripts.
