# PS3 GXEMU UART10 handoff v13: identify dispatch producers (2026-10-16)

Branch: `testing`. Continue from `docs/PS3_GXEMU_VUART10_MAGICGATE_HANDOFF_20261016_v12.md`. Target remains Ghidra 12.1.3, decrypted PS3 `ps2_gxemu.elf`, `PowerPC:BE:64:A2ALT`.

## Completed in last user-run script

`AnnotatePs3GxemuVuartDispatchStates_20261016_v1.java` **finished successfully**, APPLY=true:
- Verified `DispatchVirtualUartPacketTransfers@0x00250D70`, body `0x250D70..0x25109B`, OPD `0x00670530` with entry `0x250D70`, TOC `0x678548`, environment zero.
- Created `/PS3/GXEMU/GxemuVuart10DispatchState` (4-byte enum, Idle=0, SendSubtype09=1, ProcessResponse=2, SendSubtype0A=3, ProcessResponseLimit=4).
- Applied pointer-to-enum datatype and label `gVuart10DispatchStatePointer@0x00677788` (TOC-0xDC0), dword pointer and label `gVuart10DispatchStatusPointer@0x00677770` (TOC-0xDD8).
- Applied existing `Ppc64FunctionDescriptor24` at `0x00670530..0x00670547`, preserving the automatically generated symbol `Ppc64FunctionDescriptor24_00670530`.
- Callback at `0x250EE8..0x250EFC`: `std r2,0x28(r1)`, `ld r11,0x10(r9)`, `mtspr CTR,r0`, `ld r2,0x8(r9)`, `bctrl`, `ld r2,0x28(r1)`. Intentional TOC save/swap/call/restore. **Do not force scoped r2 context across the entire dispatcher.**
- Global scan found 20 `ld rd, offset(r2)` sites for offsets `-0xDC0` (state pointer) or `-0xDD8` (status pointer). These were concentrated in the `0x24Fxxx..0x2510xx` code neighborhood.

## Immediate confirmed state-producer leads

- `0x0024F914 ld r11,-0xDC0(r2)`, `0x0024F910 li r0,4`, `0x0024F91C stw r0,0(r11)`: local writer of **state 4** (`ProcessResponseLimit`). Ghidra containing function **none**.
- `0x0024FC50 li r0,2`, `0x0024FC54 ld r11,-0xDC0(r2)`, `0x0024FC5C stw r0,0(r11)`: local writer of **state 2** (`ProcessResponse`). Ghidra containing function **none**.
- Unassigned neighboring routines around `0x0024F8F0` and `0x0024FC08` are probable candidates for reclassification, not yet proven function boundaries.
- **State 1 and state 3 producers remain unidentified.** Do not label source routines as MagicGate functions until packet dataflow establishes native S-command handling. Real PS3 UART transport state values are distinct from Dragon MechaCon internal states/SCmd numerics.
- Other `-0xDD8` status accesses occur in `FUN_0024F890` and ownerless routines `0x0025030C`, `0x00250764`, `0x00250864`, `0x00250C8C` and dispatcher `0x250D70`. Status codes 3,8,11 are still unexplained.
- Code has not been patched; all 9 prior UART names, `TranslateMappedBufferAddress@0x24F718`, frame/transfer structs, OPDs and scoped contexts remain in user Ghidra.

## Next script committed, pending user execution

`ghidra_scripts/TracePs3GxemuVuartDispatchProducers_20261016_v1.java`, commit `e272147bda3f05bb00a5dedd71cc6ccb73dc21d1`, on `testing`.

The script:
- Verifies existing dispatcher/OPD and exact local PPC instructions that store state 4 at `0x24F91C` and state 2 at `0x24FC5C`, adds only grounded EOL comments.
- Searches `0x24E000..0x252000` for direct `stw rs,0(rA)` with a same-straight-line `ld rA,-0xDC0(r2)` or `-0xDD8(r2)`. Prints immediate values only if local `li` is proven without intervening writers/calls/branches; this scan is **not exhaustive** and ignores indirect/cross-block state writers.
- Scans candidate 24-byte BE64 descriptors in `0x6703C0..0x670578` (TOC 0x678548, environment=0), prints candidate entries and incoming xrefs.
- Prints prologue/return boundaries and ±disassembly for `0x24F8F0`, `0x24F91C`, `0x24F95C`, `0x24FC08`, `0x24FC5C`, `0x24FD08`.
- Re-checks six instructions of dispatcher callback TOC swap and restore without changing r2 context.
- No automatic function promotion, signatures, data-type change or byte patch. Not yet compiled or run in user's Ghidra; report compile issues/failures for fix before proceeding.

## Next decision after script output

If descriptor entry+TOC+environment, contiguous decoded function body, boundaries and incoming call/refs match at `0x24F8F0`/`0x24FC08`, apply metadata and decompile those producers. Trace state 1/3 writers separately if needed. Keep PS2 firmware distinction: native Dragon 6.12 is being analyzed in separate `Masamune3210/ps2mgdecomp` Codex task `TASK_NEXT_DragonMagicGateCipherContract_20261016_v1.md` on master. Do not duplicate that work here. Original PCSX2 S-command 0x90/0x8D/0x8F header decryption remains blocked on real hardware-equivalent behavior, not Ghidra function names. DNAS parked.
