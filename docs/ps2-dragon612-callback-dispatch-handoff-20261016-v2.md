# Dragon 6.12 indirect controller callbacks: verified ROM findings (2026-10-16 v2)

## Context and verification

Existing Dragon MechaCon 6.12 ARMv4T Ghidra analysis was preserved. User ran `AuditDragon612SecurityStateMachines_20261016_v1.java` successfully: SHA-256 `18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b`, 3 Thumb four-state dispatchers, packed BCD lookup, 3 renamed functions, 3 labels, 7 comments, one data application, three bookmarks, and two preexisting RAM declarations preserved. The user uploaded all three reports, including 43 Ghidra-decoded CMP immediate candidates and eight selected decompilations. Original 0x44000-byte ROM was available for independent static evidence checks and the uploaded `.gzf` already contains extensive analyst work.

## Newly recovered and verified *indirect call graph*

The previous report showed **zero** incoming Ghidra references to `0x2AFC8` and `0x2B070`, but the original ROM proves their invocation through a Thumb function-pointer table, not through direct BL instructions.

- `0x00029AF2`: Thumb `BL 0x0002A604` from the controller polling loop.
- `0x0002A604`: `push {r7,lr}`; loads `uint8_t` callback index from `0x02000488`; shifts by two; loads table base from literal at `0x0002A65C = 0x00038680`; `ldr r7,[r1,r0]` at `0x0002A60E`; calls `0x0003585E` at `0x0002A610`.
- `0x0003585E`: Thumb `BX R7` trampoline (`0x4738`), which branches to selected odd (Thumb-bit-set) callback address.
- Table `0x00038680..0x000386C7`: **18** verified contiguous 32-bit Thumb addresses; index **5** (slot `0x00038694`)=`0x0002AFC9` (function at even `0x2AFC8`, internal states `0x70..0x73`); index **6** (slot `0x00038698`)=`0x0002B071` (function at even `0x2B070`, internal states `0x80..0x83`). Index zero and ten both point to no-op at `0x2A66C`. Selector at `0x02000488` is **distinct** from the substate byte at `0x02000489`.
- The third `0x90..0x93` state dispatcher `0x00015DD0` is in another subsystem, sourced from `0x02000277`; direct Thumb `BL` at `0x000151C2` proves a caller despite Ghidra showing no xrefs. Neither subsystem is established as CDVD S-command ingress or MagicGate authentication.

Table in index order, raw Thumb pointers:

```text
0x00038680: [ 0]=0002A66D  [ 1]=0002A66F  [ 2]=0002A9D5  [ 3]=0002AA9D
0x00038690: [ 4]=0002AB65  [ 5]=0002AFC9  [ 6]=0002B071  [ 7]=0002B119
0x000386A0: [ 8]=0002B205  [ 9]=0002B2AD  [10]=0002A66D  [11]=0002B43D
0x000386B0: [12]=0002B491  [13]=0002B841  [14]=0002B843  [15]=0002B9E9
0x000386C0: [16]=0002BA3D  [17]=0002B2AD
```

Ghidra-applicable data declaration:

```text
0x00038680 - 0x000386C7
Type: uint32_t[18] (raw Thumb function addresses, bit 0 set)
Label: ControllerCallbackTable18_ThumbPointers

0x02000488 -> ControllerCallbackIndex
0x02000489 -> StateByte_02000489 (existing; preserve)
0x0200048C -> ControllerTransferByte
0x02000496 -> ControllerPendingByte

0x0002A604 -> DispatchControllerCallbackByIndex
0x0003585E -> BranchToR7
0x0002BAC4 -> TryStartControllerTransfer
0x0002BC24 -> TrySendControllerByte
0x00029E0C -> TriggerControllerCommand
```

Names are generalized control-flow/MMIO roles and do not claim the hardware peripheral is a MagicGate port.

## Hardware-facing I/O chain (not yet assigned to MagicGate)

The previous selected decompilations showed that `0x2BAC4` and `0x2BC24` read a peripheral status register and write bytes into a peripheral control block. ROM literal validation establishes:

```text
0x0002BAF8 -> 0x036000A0
0x0002BC74 -> 0x036000A0
0x0002BAFC -> 0x0200048C
0x0002BC78 -> 0x0200048C
0x0002BC7C -> 0x02000496
0x00029E30 -> 0x03005000
0x00029E34 -> 0x03808000
```

`0x2BAC4` checks `0x036000A1` low three status bits and, when ready, sets `0x036000A4=0x20`, `0x036000A8=state byte from 0x0200048C`, `0x036000A5=2`; updates RAM control flags. `0x2BC24` checks the same status, sets `0x036000A4=0x20`, writes the pending byte from `0x02000496` to `0x036000A8`, and sets `0x036000A5=5`. `0x29E0C` places the input byte in peripheral `0x03005004`, adjusts control bits in `0x03005000`, and triggers `0x03808004` with `0x00010000`. The exact peripheral identity and the origin/meaning of those bytes are *not yet identified*.

This establishes that internal state values `0x70..0x83` are selected by a callback index and advanced via an MMIO-backed peripheral operation. They are **not** a demonstrated implementation of PCSX2 `0x70..0x83` CDVD SCMD. The `0x90..0x93` dispatcher remains a separate internal state machine. The apparent contiguous `0x80..0x97` bytes at `0x38488` are conclusively part of the 100-byte packed-BCD table at `0x38438`.

## Next script and verification

`ghidra_scripts/TraceDragon612ControllerCallbacks_20261016_v2.java` runs on the **existing** Dragon `.gzf` database; it validates the full ROM SHA-256, all 18 table entries, the dispatcher Thumb instruction anchors and memory-mapped pointer literals *before modifying metadata*. It adds guarded labels/comments, optionally declares the raw 18-dword table only if completely undefined, and adds missing DATA refs from the table cells to even Thumb function addresses and three verified direct BL call references. Existing function bodies and signatures are not modified. It exports `Dragon612_ControllerCallbackAudit_20261016_v2_<timestamp>.txt` and `Dragon612_CommandIngressCandidates_20261016_v2_<timestamp>.txt` to the Windows Downloads folder. The decompilation focuses on the polling loop, table dispatcher, external ingress suspects (`0x12614`, `0x12694`, `0x12760`, `0x30380`, `0x16F94`, `0x2EA18`, `0x2EA88`, `0x31B84`), and helper calls. Script is source-reviewed and exact firmware bytes prechecked, **but not yet Ghidra runtime-verified**.

## Remaining MagicGate objectives

The firmware callback dispatcher and the PCSX2 SCMD protocol **must not be equated** without tracing actual command input and response buffers. Once external ingress is identified, compare against existing PCSX2 `pcsx2/CDVD/CDVD.cpp` commands `0x80..0x97` and `pcsx2/SIO/Memcard/MemoryCardProtocol.cpp`, with special attention to fixed responses and the pre-decrypted KELF requirement. Do not spend new analysis on generic LOADCORE infrastructure unless needed for the security dataflow. Preserve verified SCPH-39001/79001 byte-identical module context and previous `.gzf` analysis. Nothing found so far proves a PCSX2 behavioral divergence.