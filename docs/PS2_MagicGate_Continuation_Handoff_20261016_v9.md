# PS2 MagicGate continuation: PCSX2-first pivot (2026-10-16 v9)

**Branch:** `testing`  
**Supersedes:** [v8 continuation](PS2_MagicGate_Continuation_Handoff_20261016_v8.md)  
**Authoritative current handoff and source-derived SCMD map:** [PCSX2 MagicGate SCMD crosswalk](ps2-magicgate-pcsx2-scmd-crosswalk-20261016-v1.md)

## User intervention and scope decision
The user rightly observed that looking at **what PCSX2 receives and responds to** is a more direct way to identify actual MechaCon commands than chasing unrelated firmware internal state machines. This is now the mainline strategy. No Dragon v10 or more queue-worker scans unless an actual SCMD/SECRMAN trace makes those internals necessary.

## Latest completed Dragon Ghidra run: v9
Read-only `TraceDragon612QueueWorkerMmio_20261016_v9.java` ran successfully. Both reports are archived:
- `docs/evidence/Dragon612_QueueWorkerBodies_20261016_v9_1792115615678.txt`
- `docs/evidence/Dragon612_QueueWorkerMmio_20261016_v9_1792115615678.txt`

Firmware checked: SHA-256 `18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b`, `0x44000` ROM bytes, all 18 callback pointers exact. No DB metadata writes. `0x30C40` is queue-write worker: MMIO sequences `A3` (start), `A4/A5` (addressed 9-bit write in 8-halfword chunks), `A0` (completion), then clear flags and signal completion. `0x6B28` calls it when queue flag bit 1 set, in periodic processing. `0x88F0` uses `A8/A9` for addressed read. `0x02000028/2C/34` queue RAM and `0x03003100/104` private MMIO. These **do not establish IOP SCMD** identities. Targeted Ghidra declarations/labels in crosswalk; storage investigation parked.

## Upstream PCSX2 confirmed
Upstream `PCSX2/pcsx2` master, `pcsx2/CDVD/CDVD.cpp`, `cdvdWrite16()`: SCMD `0x80-0x83,0x86-0x87` mostly status-zero stubs; `0x84,0x85` static authentication payloads; `0x88/0x8F` share structural KELF validation, no obvious full cryptographic challenge flow; `0x8D/0x8E` staging; `0x90-0x93` size/offset bookkeeping; `0x94-0x97` transfer staged Kbit/Kcon; **named `0x98` (`sceMgReadIcvPs2`) lacks an explicit dispatch case and returns generic unknown `0x80`**. The source already has `CDVD_LOG` for SCMD id and param count but does not log full inputs/results. No runtime usage yet verified.

## Next action (do not substitute speculation)
Identify correct user's PCSX2 working branch, add optional read-only SCMD entry+exit tracing with input/result lengths, opaque/redacted challenge/key fields by default, and event order. Run known PlayOnline installer attempt, correlate actually exercised commands and errors, then select only those relevant commands for firmware/SECRMAN Ghidra comparison. Do not infer a DNAS error is caused by MagicGate without trace evidence. Leave control register protocol and crypto engine details alone until the trace implicates them.

Avoid redoing Dragon v1/v2/v5/v6/v8/v9. Use unique filenames, single-line terminal commands, branch docs, and Ghidra reports into `Downloads\1`.
