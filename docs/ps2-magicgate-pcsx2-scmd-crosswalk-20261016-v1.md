# PS2 MagicGate: PCSX2-first SCMD crosswalk and Dragon v9 closure (2026-10-16)

**Branch:** `testing`  
**Primary goal:** Find what PCSX2 already receives and returns for real IOP/CDVD/MechaCon commands, isolate verifiable MagicGate deficits, then use SECRMAN and real Dragon MechaCon firmware for targeted proof. **Do not continue unbounded firmware peripheral tracing.**

## Source and provenance

- Upstream PCSX2 **master**, inspected 2026-10-16: [`pcsx2/CDVD/CDVD.cpp`](https://github.com/PCSX2/pcsx2/blob/master/pcsx2/CDVD/CDVD.cpp); current source uses `cdvdWrite16(u8 rt)` for S-command dispatch, `cdvdWrite17(u8 rt)` to collect outgoing parameter bytes, and `cdvdRead18()` for response bytes. `cdvdWrite(u8 key,u8 rt)` dispatches register key `0x16` to `cdvdWrite16`, key `0x17` to param accumulation.
- [`pcsx2/CDVD/CDVD_internal.h`](https://github.com/PCSX2/pcsx2/blob/master/pcsx2/CDVD/CDVD_internal.h) contains named `sCmdName[0x100]` table, including MagicGate command names for `0x80..0x98`.
- The **real PS2 IOP CDVD I/O register space** maps the S-command byte to `0x1F402016`, S-command status at `0x1F402017`, and input/output byte port `0x1F402018` (direction-dependent). Do not confuse these addresses with Dragon's private `0x0300xxxx` bus registers.
- GitHub source analysis is **static**. It identifies handlers, not which instructions PlayOnline executes at runtime nor what real MechaCon returns.

## Source-observed MagicGate S-command map

| SCMD | Name/role | Upstream PCSX2 behavior | Risk |
|---|---|---|---|
| `0x80`, `0x81` | SECRMAN auth initiation | Set `mg_datatype=0`; return status 0, no crypto | Stub-like |
| `0x82`, `0x83` | SECRMAN auth input | Return status 0, do not validate input | Stub-like |
| `0x84` | Auth response 1 | Hardcoded 12-byte payload plus status 0 | Static value, challenge dependence unmodeled |
| `0x85` | Auth response 2 | Hardcoded 12-byte payload plus status 0 | Static value, challenge dependence unmodeled |
| `0x86`, `0x87` | Additional auth input | Return status 0, ignore input | Stub-like |
| `0x88`, `0x8F` | SECRMAN header/data auth completion | Same handler; header mode validates structural length/BIT region and extracts Kbit/Kcon from buffer; data mode immediately succeeds | Distinct command semantics and actual authentication uncertain |
| `0x8D` | `sceMgWriteData` | Append up to 16 incoming bytes per call to `mg_buffer`, enforce `mg_maxsize` | Staging, not cryptographic |
| `0x8E` | `sceMgReadData` | Remove up to 16 bytes per call from `mg_buffer` | Staging, not cryptographic |
| `0x90` | `sceMgWriteHeaderStart` | Set header mode, expected length, reset size | Structural |
| `0x91` | `sceMgReadBITLength` | Extract BIT block from buffered header, calculate length | Structural |
| `0x92` | `sceMgWriteDatainLength` | Set data mode and expected input length | Structural |
| `0x93` | `sceMgWriteDataoutLength` | Validate expected length/data mode | Structural |
| `0x94`, `0x95` | `sceMgReadKbit`, half 1/2 | Copy bytes from staged `mg_kbit`, no cryptographic operation at read point | Depends entirely on upstream preparation |
| `0x96`, `0x97` | `sceMgReadKcon`, half 1/2 | Copy bytes from staged `mg_kcon`, no cryptographic operation at read point | Depends entirely on upstream preparation |
| `0x98` | `sceMgReadIcvPs2` | Named in `sCmdName` but **no `case 0x98` in `cdvdWrite16`**, so generic unknown SCMD result `0x80` | Missing handler |
| `0x89..0x8C` | Unknown in name table | No specific handler, generic unknown status `0x80` | Only relevant if actually requested |

Important: no claim that any simplification necessarily causes the user's observed installation/DNAS failure. The PlayOnline test must first reveal the actual sequence and error boundary. DNAS and MagicGate are distinct mechanisms that can interact with installation/boot gating.

## Concrete PCSX2 logging plan, not implemented yet

The existing `CDVD_LOG("cdvdWrite16: SCMD %s (%x) (ParamP = %x)", ...)` records command **number and count**, but not input buffer bytes or final result. Rather than guessing firmware opcodes:

1. Add a targeted, optional **read-only protocol trace** at entry to `cdvdWrite16`, *before the command's handler clears/changes `SCMDParamCnt`*, capturing command id, count, parameter bytes and a monotonic sequence.
2. After the command switch, snapshot `SCMDResultCnt` and `SCMDResultBuff` from the completed handler. Avoid duplicate raw/secret dumps by default: authentication inputs/outputs and keys should be redacted or emitted as lengths/digests unless a controlled, user-owned local test explicitly requires bytes.
3. Capture relevant S-ready/result-port behavior through `cdvdRead18` if timing, pending state or incremental reads matter. Include `0x03` nested MechaCon subcommand dispatch and N-command paths only when observations point to them.
4. Run PlayOnline installer in controlled conditions and correlate the first failing command/status with IOP-side SECRMAN, loader and DNAS behavior. Do not treat lack of network services as proof of emulator protocol failure.
5. Match actual used SCMDs against Ghidra real Dragon/SECRMAN handlers; for challenge-response SCMDs `0x80..0x88`, `0x8F` and possible `0x98`, verify command input layout, state transitions, status codes, returned bytes and crypto dependencies. Preserve user-supplied real device data privacy.
6. Only then consider PCSX2 changes, with tests. Avoid implementing all guessed unknown SCMDs up front.

## Final Dragon v9 result closes queue-worker detour

User ran `TraceDragon612QueueWorkerMmio_20261016_v9.java`. Reports:

- [v9 worker/MMIO index](evidence/Dragon612_QueueWorkerMmio_20261016_v9_1792115615678.txt) (1318 file lines)
- [v9 decompiled function bodies](evidence/Dragon612_QueueWorkerBodies_20261016_v9_1792115615678.txt) (1390 file lines)

Verified full Dragon ROM SHA `18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b`, all 18 callback pointers, and **no metadata writes**. Crucial results:

- `0x30C40` **is** the actual queue worker, a four-stage state machine (state 1: command `0xA3`; state 2: page/offset write `0xA4 | ((offset >> 8)&1)`, low address, up to eight halfwords per chunk; state 3: finalization `0xA0`; state 4: clear flags, signal/release).
- `0x6B28` conditionally invokes `0x30C40` whenever shared queue control `0x02000028` has bit `0x2` set, in its periodic processing function. This demonstrates queue scheduling/completion.
- `0x02000028` holds flags; `0x0200002C` source pointer; `0x02000030` operation; `0x02000031` halfword count; `0x02000032` pending; `0x02000034` 16-bit location. `0x03003100` starts MMIO transaction slot, `0x03003104` is data-lane buffer, read command `0xA8/A9` from `0x88F0`.
- Hardware transformation engine at `0x03004100` from `0x2F6C` is **separate**, with cryptographic identity not yet proven. These private hardware commands (`0xA3/A4/A0/A8/A9`) are **not** the IOP-visible CDVD S-command opcodes. No particular EEPROM model/technology has been identified.
- No deeper investigation of this private storage bus is justified until a verified MagicGate command chain depends on it.

### Directly applicable Ghidra metadata (proposals only)

Keep all existing Ghidra editor types and storage. Names are descriptive/generalized, not verified vendor symbols:

```text
0x00030C40
uint ServiceQueuedStorageTransfer(void)

0x00006B28
undefined ServicePeriodicHardwareState(void)

0x00008378
undefined4 ReadTwoByteStorageValue(int storageOffset, undefined1 * outTwoBytes)

0x000083E8
undefined4 QueueTwoByteStorageWrite(int storageOffset, undefined2 value)
```

Optional labels (validate existing declarations before applying):

```text
0x02000028 -> StorageQueueFlags
0x0200002C -> StorageQueueSourceBuffer
0x02000030 -> StorageQueueOperation
0x02000031 -> StorageQueueHalfwordCount
0x02000032 -> StorageQueuePending
0x02000034 -> StorageQueueLocation
0x03003100 -> StorageTransactionMmioWindow
0x03003104 -> StorageReadbackMmioWindow
0x03004100 -> EightByteTransformMmio
```

Avoid inventing a complete RAM structure or renaming user-defined symbols. Ghidra work is deferred, not discarded.

## Next action

**Instrument and audit PCSX2, not Dragon v10.** A real command trace followed by a *targeted* SECRMAN/MechaCon comparison is the shortest route to a specific emulator fix. Update this crosswalk with which SCMDs PlayOnline actually uses and their results.
