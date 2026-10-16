# PS3 GXEMU virtual UART 10 dispatch state machine handoff v12 (2026-10-16)

Branch: `testing`. Prior handoff [v11](PS3_GXEMU_VUART10_MAGICGATE_HANDOFF_20261016_v11.md). Target: decrypted PS3 firmware 4.93 `ps2_gxemu.elf`, Ghidra 12.1.3 `PowerPC:BE:64:A2ALT`. Real PS2 MagicGate goal, DNAS parked.

## User-executed Ghidra script and applied findings

`RecoverPs3GxemuVuartDispatch_20261016_v1.java` **finished successfully**, APPLY=true:
- BE64 PPC ELFv1-like function descriptor at `0x00670530` has `entry=0x00250D70`, `toc=0x00678548`, `environment=0`. Checked without error.
- Code body `0x00250D70..0x0025109B` in `SECTION11`, next separate `SECTION12` begins at `0x0025109C`. 203 contiguous decoded PPC instructions, 22 branch instructions, **0 `blr`** returns, **0 internal prologues**, no existing function overlaps, only one foreign reference (descriptor data reference), **0 foreign calls into body**.
- **Created and named function** `0x00250D70 -> DispatchVirtualUartPacketTransfers`. Existing decompiler signature includes unresolved `undefined8 param_1...param_13`; leave them unchanged.
- Explicit `r2` writer found at `0x00250EF4: ld r2,0x8(r9)`. Script correctly **did NOT impose body-wide r2 context**. This may be another ELFv1 function descriptor callback, but exact save/load/call/restore sequence is **not yet verified**.
- This is a long-lived (infinite-loop) dispatcher, not an ordinary returning procedure.

## State mapping from user's decompilation

Variable `iVar8` comes from an `int *` loaded from TOC offset `-0xDC0` with validated dispatch function's OPD TOC `0x00678548`; therefore the *TOC pointer slot* is **`0x00677788`**, pointing to runtime `uint32` or signed int dispatch state. Do not fabricate the pointed-to address. Distinct another status pointer TOC slot at `r2-0xDD8 = 0x00677770`.

```
Enum: GxemuVuart10DispatchState
Size: 4
Idle = 0
SendSubtype09 = 1
ProcessResponse = 2
SendSubtype0A = 3
ProcessResponseLimit = 4
```

State 0: no state-specific action; state 1 calls alternate variable sender `SendVirtualUartVariablePacketAlternate@0x901FC` via `bl @0x251044`, frame byte +0x17=0x09; state 3 calls `SendVirtualUartVariablePacket@0x8FD48` via `bl @0x25106C`, subtype +0x17=0x0A. State 2 reads response flags from +0x38, subtype/parameter from +0x3E and a **BE32 field at +0x20**, checks zero, 0x24 and current status 0x0B; optionally invokes callback through the pointer loaded from TOC `-0xE18` with args 2 and byte +0x3E. State 4 checks **BE64** response field +0x40 and bounds values greater than 0xFFFF by replacing with 0x40; then updates status based on response field +0x20. At end, sets dispatch state `*piVar11=0` and response-pointer `*plVar17=0` and loops. The meanings of status codes 3, 8, 11 and BE fields remain unknown; never label them as cryptographic error codes without evidence.

Known derived globals (source-level evidence):
```
0x00677788 -> gVuart10DispatchStatePointer   GxemuVuart10DispatchState *64
0x00677770 -> gVuart10DispatchStatusPointer  dword *64
```
These are **proposed datatypes and labels, not yet applied**.

All previous useful Ghidra names remain applied, including `TranslateMappedBufferAddress@0x24F718` signature `ulong TranslateMappedBufferAddress(ulong candidateAddress)`, 9 generic VUART names, 7 verified typed PPC64 OPDs, the 0x10 frame prefix, 0x18 transfer-state structure with callback descriptor pointer, and four VUART-related TOC pointer slots.

## New runnable Ghidra Java script

`ghidra_scripts/AnnotatePs3GxemuVuartDispatchStates_20261016_v1.java`, committed to `testing`, **NOT YET RUN/COMPILED by user**.

It:
1. Requires verified dispatcher at `0x00250D70` containing `0x251044` and `0x25106C`, both known sender CALLs, and verified OPD at `0x00670530` with TOC `0x00678548`.
2. Creates enum `GxemuVuart10DispatchState` size 4 with all 5 observed values (0..4).
3. Guardedly applies enum pointer to TOC slot `0x00677788`, dword pointer to status slot `0x00677770`, and existing `Ppc64FunctionDescriptor24` at `0x00670530..0x00670547` if conflicting data are default only. Labels them without replacing intentional names.
4. Adds comments on dispatcher and both explicit UART send call instructions.
5. READ-ONLY scans disassembly for `ld register, -0xdc0(r2)` and `ld register, -0xdd8(r2)` (exact PPC opcode 58) to surface potential state setters in the surrounding firmware. Does not presume all functions using same offset share same TOC.
6. Inspects instructions at `0x250EE4/0x250EF4/0x250F04` to identify whether dispatcher has verified callback TOC switch. Does NOT set r2 context across function.
7. Does not alter function signatures or executable bytes.

If script fails, preserve applied metadata and report failure. Next, follow state-setting writers/upstream queue, callback responses and selected packets toward native MechaCon MagicGate auth header transform. Do not conflate UART framing `0x90` or state labels with native MechaCon S-command `0x90`/`0x8F`.
