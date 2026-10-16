# Dragon 6.12 storage queue / MMIO handoff (2026-10-16 v9)

**Branch:** `testing`  
**Supersedes:** [Dragon storage queue v8 handoff](ps2-dragon612-storage-queue-handoff-20261016-v8.md)  
**Existing database:** Dragon MechaCon 6.12, ARMv4T/Thumb, full ROM `0x44000` bytes, SHA-256 `18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b`. **No reimport needed.**

## v8 was executed successfully, no DB changes

The user ran `ghidra_scripts/TraceDragon612StorageQueueWorkers_20261016_v8.java`. The returned index confirms exact SHA-256, **all 18 callback entries verified**, and "Metadata changes: NONE". The reports were archived on this branch:
- [Storage queue control/ref/MMIO index](evidence/Dragon612_StorageQueueWorkers_20261016_v8_1792115048007.txt) (472 lines)
- [Selected function bodies](evidence/Dragon612_StorageQueueBodies_20261016_v8_1792115048007.txt) (1016 lines)

## Now confirmed with firmware-level evidence

### Internal queue RAM and likely worker

V8 scanned the exact 32-bit literal values in the SHA-guarded ROM:

| Literal(s) | Runtime pointer / value | Established usage |
|---|---|---|
| `0x86C0`, `0x87BC` | `0x000001FF` | Bounds check for storage offset |
| `0x86C4`, `0x87C0` | `0x02000028` | Shared 32-bit queue control flags |
| `0x86C8`, `0x87C4` | `0x0200002C` | Shared queue descriptor base / source pointer |
| `0x86CC`, `0x87C8` | `0x02000034` | Descriptor 16-bit storage location |
| `0x87CC`, `0x8654` | `0x03003104` | Readback MMIO buffer/window |
| `0x3040`, `0x3118`, `0x3228`, `0x3338` | `0x03004100` | Independent 8-byte hardware transform engine |

**Leading queue worker candidate `0x00030C40`** references matching ROM literals `0x3100C` (queue storage location), `0x31018` (descriptor) and `0x3101C` (control flags). Closely related functions `0x83E8` and `0x8378` share these pointers or `0x03003104`. This is a reference-level link, not yet proof of task scheduling or a backing memory chip.

### Storage transfer and 9-bit addressing

`0x000088F0` first waits for status, then sets up a read over MMIO. It constructs the control byte `0xA8 | ((storageOffset >> 8) & 1)`, writes `storageOffset & 0xFF` next, and sets up a two-byte payload per four-byte MMIO data lane. It calls `0x00008168(byteLength + 1)` before waiting for completion.

Therefore the helper genuinely encodes a **9-bit storage location** (the caller limit is `0x1FF`) rather than issuing an external 8-bit CDVD command `0xC0/E3/E8`. The firmware does not yet establish whether backing memory is serial EEPROM, flash, volatile registers, or another technology.

`0x00008658` is an asynchronous write enqueuer. It populates shared descriptor fields (source buffer, operation byte, requested length **in 16-bit units**, pending flag, and 16-bit location), raises queue control bits. Success means **accepted for queuing**, not written to storage.

`0x000086D0` queues a similar write, waits for completion, invokes `0x88F0` to read it back, compares two bytes from each four-byte MMIO lane, and reports mismatch status `8`; out-of-bound location reports `4`. Neither this nor `0x8658` identifies an external SCMD.

`0x000087D0` queues a fill operation using a caller-supplied byte (initializes a sixteen-byte buffer and sets a separate control bit). Verify exact fill length/worker behavior before assuming it fills arbitrary-length requests.

`0x00008464` is a reader with four output validation modes: `mode=0` checks periodic checksum conditions across blocks, `mode=1` checks a leading complement-of-sum, `mode=2` checks a trailing complement-of-sum, and other modes copy raw byte pairs. The MMIO buffer uses four bytes of spacing per two logical payload bytes. It retries failed validation under a bounded retry counter.

### Transform engine separate

`0x00002F6C` accesses `0x03004100` and submits two eight-byte inputs to hardware registers while polling status for eight-byte output. `0x3044`, `0x311C`, and `0x322C` also reference that base. Its **exact cryptographic function is unproven**, even though it processes transformed data later stored at offsets `0xE3/E8`. Do not label it AES/MagicGate without further evidence.

## Directly applicable provisional Ghidra metadata

Names below are descriptive and generalized. No script has applied them; retain user-defined names and the **exact current editor return/parameter types**:

```text
0x00008464
undefined ReadStorageWithValidation(undefined2 storageOffset, uint byteLength, byte * outputBuffer, int validationMode)

0x00008658
undefined4 QueueStorageWrite(int storageOffset, uint byteLength, undefined4 sourceBuffer)

0x000086D0
undefined4 QueueAndVerifyStorageWrite(int storageOffset, uint byteLength, int sourceBuffer)

0x000087D0
undefined4 QueueStorageFill(int storageOffset, uint byteLength, undefined1 fillByte)

0x000088F0
uint ReadStorageIntoMmioWindow(undefined2 storageOffset, uint byteLength)

0x00002F6C
undefined ExecuteEightByteHardwareTransform(undefined1 * inputA, undefined1 * inputB, undefined4 * outputWords)
```

ROM observations suggest possible RAM labels (do not replace conflicting user-defined names and avoid typing overlapping data before inspecting existing declarations):

```text
0x02000028 -> StorageQueueFlags
0x0200002C -> StorageQueueSourceBuffer
0x02000030 -> StorageQueueOperationByte
0x02000031 -> StorageQueueHalfwordCount
0x02000032 -> StorageQueuePending
0x02000034 -> StorageQueueLocation
0x03003104 -> StorageReadbackMmioWindow
0x03004100 -> EightByteTransformMmio
```

No complete structure size is proven. **Do not invent a full queue descriptor.** In Ghidra, keep existing types and only annotate address fields that exist in the database.

## Next: v9 targeted queue worker/MMIO audit

[`ghidra_scripts/TraceDragon612QueueWorkerMmio_20261016_v9.java`](../ghidra_scripts/TraceDragon612QueueWorkerMmio_20261016_v9.java) committed to `testing` and **not yet run**. It is read-only with the same ROM hash and 18 callback-word guard; captures both decompilation and selected instruction/xref windows. It directly targets `0x30C40`, `0x8378`, `0x83E8`, `0x899C`, `0x8A28`, `0x8AB0`, `0x8B9C`, `0x8168`, `0x88F0`, and other focused references. No repetition of v5's broad ROM literal scan or v8's shared-pointer sweep. Keep the storage queue and transform engine investigations separate until proven linked.

Outputs automatically into **`%USERPROFILE%\Downloads\1`**:
- `Dragon612_QueueWorkerMmio_20261016_v9_<timestamp>.txt`
- `Dragon612_QueueWorkerBodies_20261016_v9_<timestamp>.txt`

Run in the existing Ghidra database and return both files plus any compiler/Script Manager log. Next proof target: identify **who consumes `0x02000028/2C/34` and turns a queued write into a device transaction**. Then determine actual storage hardware. Reconcile any MMIO command semantics against PCSX2 only after firmware flow is confirmed. No observed PCSX2 MagicGate bug has yet been proven.
