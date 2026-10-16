# PS3 GXEMU MagicGate VUART10 handoff v9: callback TOC and dispatch (2026-10-16)

Branch: `testing`. Previous state document: `docs/PS3_GXEMU_VUART10_MAGICGATE_HANDOFF_20261016_v8.md`. Original PS3 `ps2_gxemu.elf` Ghidra 12.1.3 `PowerPC:BE:64:A2ALT`. The user executes scripts and returns logs.

## Newly verified from user-run audit v1

`AuditPs3GxemuVuart10CallChain_20261016_v1.java` completed, read-only.

1. **PPC64 callback TOC handling at `ReceiveVirtualUartChunk@0x0008FC68` is intentional**. It stores old r2 at `0x0008FD14` (`std r2,0x28(r1)`), loads callback environment to r11 from descriptor +0x10 at `0x0008FD18`, loads callback's own r2 from descriptor +8 at `0x0008FD1C`, calls indirect via CTR at `0x0008FD20`, and restores r2 at `0x0008FD24`. This explains the prior `TOC_REFUSED r2 writer` warning. **Do not set r2 globally or across that entire function.** Entry OPD at `0x0064F6F8` verifies entry `0x8FC68`, TOC `0x00678548`, environment 0.
2. `FUN_0024F718` is a **conditional mapped-address/alias translator**, not a cryptographic transform. Decompiled current type `ulong FUN_0024f718(ulong param_1)`, compares `(param_1 & 0xFFFFFFFFFFFDFFFF)` against stored `*(ulong*)PTR_DAT_00677720`, if match returns adjusted address `(param_1-base)+*(long*)PTR_DAT_00677728`, otherwise returns input unchanged. Used by the UART receive routine and three transmit routines. Apply-eligible generic name `TranslateMappedBufferAddress`, existing return/param type `ulong`, useful param rename `candidateAddress`. No extra parameters should be invented.
3. `FUN_0024F95C` is upstream of `SendVirtualUartFrame@0x000900FC` through code call `0x0024F9A4`, then invokes `sc 0` at `0x0024F9B4`. Its decomp accesses three optional 16-byte source fields at offsets +0x40,+0x50,+0x60 selected by bits 2/1/0 of a byte at source+0x38; reverses bytes of up to three 8-byte values and XORs **5 bytes each** with the nonzero low byte of time-base register `TBLr`; stores flags and selector back at source+0x38/0x39. This is evidence of protocol/timebase-derived transformations, **not yet proof of native MagicGate crypto**. Existing inferred 13+ function parameters and `unaff_r2` are unreliable ABI/decomp artifacts. Need verify OPD TOC.
4. `0x00251044` and `0x0025106C` are still unowned Ghidra instructions that call `SendVirtualUartVariablePacketAlternate@0x901FC` and `SendVirtualUartVariablePacket@0x8FD48`, respectively. Both belong to control-flow with branch targets `0x00250DC0`, `0x00250ECC`, `0x00250EE4`; they are not proven independent functions. Next known prologue `0x0025109C`. Recover surrounding function boundary/OPD rather than promoting isolated call sites.

Current Ghidra already has nine named UART-related functions, seven verified `Ppc64FunctionDescriptor24` triples, the `GxemuVuart10FramePrefixBE` (0x10) and `GxemuVuart10TransferState` (0x18) datatypes, and four TOC slot pointer names/types from previous handoffs. Do not duplicate.

## New directly applicable metadata / pending Java script

`ghidra_scripts/RefinePs3GxemuCallbackAndDispatcher_20261016_v1.java` committed to `testing`. **Not yet executed/compiled by the user.**

It:
- Checks the exact six PowerPC instructions at `0x8FD10..0x8FD24` and existing receiver OPD, then, if matching, refines `GxemuVuart10TransferState` +0x00 from `void*` to `Ppc64FunctionDescriptor24 *completionFunctionDescriptor`, preserving meaningful incompatible prior types.
- Adds a comment at indirect `bctrl` explaining callback r2 switch and restoration.
- Conditionally names `FUN_0024F718 -> TranslateMappedBufferAddress` and names its already-established `ulong` parameter `candidateAddress` only if decomp verifies alias mask `0xFFFFFFFFFFFDFFFF`, both mapped globals and four expected UART call refs. Preserves existing return/param types.
- Reads and verifies possible upstream OPD `0x00670428 -> 0x0024F95C`, toc `0x00678548`, environment zero; sets **only function-scoped r2 context** at `0x24F95C` if no r2 writes and no preexisting context.
- Decompiles the upstream `0x24F95C` routine after its guarded TOC improvement.
- Read-only scans `0x0024FF00..0x0025109B` for credible `stdu r1` function starts / `blr` and xrefs and prints ownership/flow around the unowned sender calls. Does **not** promote uncertain dispatch code.
- Does not modify executable bytes or unproven function signatures.

### Direct Ghidra function editor when only existing type/parameter verified

```text
0x0024F718
ulong TranslateMappedBufferAddress(ulong candidateAddress)
```

The signature is a proposed change in the new script, **not yet actually applied**. The callback datatype refinement is likewise proposed.

## Remaining work

Follow UART port 10 send/receive and identify an actual native MechaCon command dispatcher / MagicGate transformation, rather than equating outer UART class `0x90` with native MagicGate S-command `0x90`. Native PCSX2 HDD Utility `SCUS_973.95` sends `0x1A0` encrypted header via `0x90 -> 0x8D*26 -> 0x8F`, currently rejected by ciphertext-as-BIT stub; DNAS parked. Keep PS3 source separate from PCSX2 fixes until behavior proven. “REPORT TO BRIAN!” string at `0x002B1A80` has no attributable identity or algorithm.
