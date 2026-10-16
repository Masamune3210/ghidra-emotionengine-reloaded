# PS3 GXEMU VUART transport / MagicGate investigation
**Checkpoint:** 2026-10-16, after `RecoverPs3GxemuVuartControlFunctions_20261016_v1.java` and the next audit script.
**Repository:** `Masamune3210/ghidra-emotionengine-reloaded`, branch `testing`.
**Database:** 64-bit `ps2_gxemu.elf`, `PowerPC:BE:64:A2ALT`.

## Purpose and scope
Trace the PS3 GXEMU virtual UART transport as one possible route carrying PlayStation 2 MagicGate-related operations. This work is distinct from the PS2-side `SECRMAN`/`DECKARD` and Dragon/KELF contract being handled separately in `ps2mgdecomp`. **Nothing in the UART state-machine output identifies a native MechaCon S-command or proves that a specific 16-byte transfer contains MagicGate authentication payload.**

## Verified recovery (user's Ghidra execution log)
`RecoverPs3GxemuVuartControlFunctions_20261016_v1.java` reported 13 descriptor candidates, 10 verified/recovered functions, 3 refused for additional internal stack prologues. All 13 checked descriptor records are ELFv1-style 24-byte triplets using TOC `0x00678548`. Existing instructions and executable bytes were not modified.

Verified generic name opportunities:
- `0x0024FD08..0x0025030B` (OPD `0x00670488`): first argument is a byte result/output pointer; second is a source address. Copies 16 bytes into transfer buffer at `+0x40` (state 1) or `+0x48` (state 6), advances cursor by `0x10`, and may transition 1→2 or 6→7 at limit. Existing unresolved datatype details must be preserved.
- `0x0025030C..0x002506AB` (OPD `0x006704A0`): reads 16 bytes to caller buffer from `+0x40` (state 4) or `+0x48` (state 9), advances cursor by `0x10`, and may transition 4→5 or 9→10.
- `0x00250978..0x00250C83` (OPD `0x00670500`): resets cursor, advances 0x10-byte descriptor chain, and can transition 5/10→6; two caller-supplied metadata bytes are copied into transfer state. Exact descriptor layout remains unknown.
- `0x0024F90C` `QueueVuartDispatchState4`; `0x0024FC4C` `QueueVuartDispatchState2`. Both use runtime state slot `0x00677788`. Existing `DispatchVirtualUartPacketTransfers` starts at `0x00250D70`.

Additional verified runtime label: `0x02BBA8E0` `gVuart10DispatchState` (`GxemuVuart10DispatchState`, 4 bytes), accessed via slot `0x00677788`.

## Deliberately unresolved
- `0x0025075C..0x0025085B` (OPD `0x006704D0`)
- `0x0025085C..0x00250977` (OPD `0x006704E8`)
- `0x00250C84..0x00250D6F` (OPD `0x00670518`)

All three were refused due to one extra internal stack-prologue pattern per region. Do not split or force-create them until actual prologue offsets, branch/reference evidence, and ABI conventions have been checked.

For `0x0024FD08`, `0x0025030C`, and `0x00250978`, the old script refused a broad `r2` context assignment because it detected writes to `r2` at `0x0024FD70`, `0x00250370`, and `0x00250BD4` respectively (all `ld r2,0x8(r9)`). These may be part of indirect ELFv1 descriptor calls. Do not set TOC across entire function without checking the matching save/call/restore sequences and control-flow paths.

## Follow-up committed
`ghidra_scripts/AuditPs3GxemuVuartTransferPhases_20261016_v1.java`:
- Confirms exact OPD and function boundaries before applying conservative generic names `TransferWriteChunk16`, `TransferReadChunk16`, `AdvanceTransferSegment`, and appending decomp-supported comments.
- Leaves signatures, unknown parameter types, register contexts, and executable bytes unchanged.
- Prints internal-prologue locations and references for each refused region.
- Prints each `r2` writer, surrounding disassembly, and calls/xrefs to known UART transfer functions for TOC and control-flow assessment.

## Next expected step
1. Run `AuditPs3GxemuVuartTransferPhases_20261016_v1.java` in the existing `ps2_gxemu` Ghidra program after pulling `testing`.
2. Use its `INTERNAL_PROLOGUE`, `FOREIGN_INTERNAL_FLOW`, `R2_WRITE`, and window output to determine whether the three refused entries can be safely split and whether any scoped `r2` context can be restored.
3. Trace caller/callee relationships from chunk transfer callbacks into actual VUART port 10 packet construction and receipt; obtain packet IDs and fields from direct dataflow, not MagicGate guesses.
4. Cross-correlate verified packet evidence against PS2-side `SECRMAN`/`DECKARD` work and PlayOnline/DNAS observations, keeping transport states distinct from MechaCon commands.

**Verification:** The recovery log was user-provided; the new audit script is committed but has not yet been executed in Ghidra. No signatures or datatype layouts were forced from speculation.
