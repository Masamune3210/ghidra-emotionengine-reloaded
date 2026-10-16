# Dragon MechaCon 6.12: protocol-state evidence, 2026-10-16

## Scope

The user supplied the **already analyzed** Ghidra archive `Dragon_MechaCon_6_12_ARMv4T_Ghidra_20261015_v2.elf.gzf`. This is not an ELF that needs importing again. The matching previously provided raw firmware `6.12.bin` and Ghidra-import wrapper are available. The original firmware is exactly `0x44000` bytes, SHA-256:

`18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b`

Architecture: little-endian ARMv4T, including Thumb functions. The wrapper maps ROM at `0x00000000..0x00043FFF` and uninitialized SRAM at `0x02000000..0x02003FFF`; the raw firmware bytes are unchanged. Its ROM build text at `0x00008C6C` is `$Date: 2007/01/29 03:47:05 $`. The previous script `ApplyDragonMechaCon612VerifiedMetadata_20261015_v1.java` already annotated reset, exception vectors, RAM initialization, and the SVC dispatcher. **Do not rerun or delete that work.**

The `.gzf` is a Ghidra Java-serialization export whose first compressed ZIP entry contains a Ghidra database. The extracted metadata contains the already recognized function symbols listed below. Static ROM inspections were independently corroborated with LLVM's ARM/Thumb disassembly. The archive by itself does **not** establish runtime authentication or a PCSX2 mismatch.

## Verified Thumb state dispatchers

Three code entry points and their source variables are established by explicit Thumb `LDR (literal)`, `LDRB`, and `CMP immediate` instruction sequences. **These are state-machine observations, not established external MechaCon SCMD command decoders.**

| Existing entry (Thumb) | CMP values | RAM byte actually read | ROM base-pointer literal | Other evidence |
|---|---|---|---|---|
| `0x00015DD0` | `0x90,0x91,0x92,0x93` | `0x02000277` | `0x00015EBC`: `0x02000274`, byte +3 | Called by `BL` at `0x000151C2`; has calls to `0x000040BC`, `0x00004204`, `0x0001610C`, `0x00024DC8` |
| `0x0002AFC8` | `0x70,0x71,0x72,0x73` | `0x02000489` | `0x0002B068`: `0x02000488`, byte +1 | Calls `0x0002BAC4`, `0x0002BC24`, `0x00029E0C` on different state branches |
| `0x0002B070` | `0x80,0x81,0x82,0x83` | `0x02000489` | `0x0002B110`: `0x02000488`, byte +1 | Calls the same helpers under different state conditions |

Each entry matches a generic `FUN_XXXXXXXX` symbol in the uploaded Ghidra archive. The script renames it only when it remains generically named and does not override an analyst name. Values `0x80` and `0x90` resemble PCSX2's documented MechaCon MagicGate SCMD opcodes, but **the presence of these values in a firmware state byte does not prove correspondence to those commands**. No actual SCMD packet ingress, challenge buffer, or result/error register has yet been traced to any of these functions.

### Negative control: NOT a command table

At `0x00038438..0x0003849B` the ROM contains **exactly 100 bytes** of packed decimal values (`0x00..0x09`, `0x10..0x19`, ..., `0x90..0x99`). Thus the visually tempting contiguous `0x80..0x97` region at `0x00038488` belongs to a **packed-BCD lookup**, not a MechaCon opcode dispatch table. References to the table include a literal at `0x00025F04` containing `0x00038438`. The script defines this table only if no existing code/data markup overlaps.

## Ghidra-applicable metadata

These are backed by source instruction bytes and can be applied using the script below. No function parameter or return semantics are established, so existing signatures must be preserved.

```text
0x00015DD0 -> DispatchState90To93
0x0002AFC8 -> DispatchState70To73
0x0002B070 -> DispatchState80To83
0x02000277 -> StateByte_02000277
0x02000489 -> StateByte_02000489
0x00038438 -> PackedBcd00To99_Lookup

0x02000277 - 0x02000277
Type: byte
0x02000489 - 0x02000489
Type: byte
0x00038438 - 0x0003849B
Type: byte[100]
```

All three procedure names describe *observed internal state dispatch* and deliberately avoid claiming MagicGate authentication. The script also attaches comments at `0x000151C2` and the RAM state bytes, creates bookmarks for unresolved command-origin questions, and exports Ghidra-decoded `CMP` candidates for `0x70..0x97` plus selected decompilations.

## Directly runnable application script

`ghidra_scripts/AuditDragon612SecurityStateMachines_20261016_v1.java`

- Targets the **existing Dragon MechaCon 6.12 Ghidra program**, not SECRMAN, DECKARD or SYSMEM.
- Validates SHA-256 of all `0x44000` ROM bytes and exact Thumb opcode/ROM literal evidence **before any metadata changes**; aborts on mismatches.
- Preserves analyst-defined function names, parameter signatures, existing function boundaries and already-defined data. Never alters executable bytes.
- Writes exactly three timestamped reports into the user's Downloads directory: `Dragon612_SecurityStateAudit_20261016_v1_*.txt`, `Dragon612_CmpImmediateCandidates_20261016_v1_*.tsv`, `Dragon612_ProtocolDecomp_20261016_v1_*.txt`.
- Decompiles at most eight selected preexisting functions, each with a bounded timeout, without affecting the program's code/data markup.
- Static source checked but **not yet compiled or executed against Ghidra 12.1.3**; wait for the user's run log, then continue analysis.

## What the ROM does NOT yet establish

- **No verified relationship** between the three firmware internal state machines and external MechaCon S-command values `0x80..0x97`.
- No verified SECRMAN-to-MechaCon packet flow, cryptographic handshake, KELF key agreement, or Kbit/Kcon derivation at these addresses.
- No demonstrated difference between this Dragon firmware's responses and PCSX2's CDVD emulation.

Current upstream PCSX2 does implement numerous MechaCon MagicGate S-command cases in `pcsx2/CDVD/CDVD.cpp`, and memory-card authentication commands in `pcsx2/SIO/Memcard/MemoryCardProtocol.cpp`. Those handlers remain the correct comparison target, particularly SCMD `0x80..0x87` fixed responses and `0x8F..0x97` KELF header/keys. **Do not conclude implementation gaps solely from different firmware constants.**

## Next evidence needed

Run the script in the existing Dragon Ghidra database, return the `SecurityStateAudit`, `CmpImmediateCandidates`, and `ProtocolDecomp` reports. Use those call graphs and decompilations to follow actual command reception from hardware-facing ports, packet lengths and return/status data toward these or other routines. Only once the byte/command origin is established should a firmware function receive a MechaCon/MagicGate-specific name and be compared with specific PCSX2 implementation branches. Preserve the already verified dual-model equivalence for SYSMEM, LOADCORE and other shared IOP modules; no fresh import needed.