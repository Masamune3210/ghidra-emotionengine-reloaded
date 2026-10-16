# PS3 GXEMU port-10 protocol: current handoff v8 (2026-10-16)

Branch: `testing`. Previous context: `docs/PS3_GXEMU_VUART10_MAGICGATE_HANDOFF_20261016_v7.md`.

## User-executed `RefinePs3GxemuVuart10Protocol_20261016_v2.java`: confirmed

On decrypted `ps2_gxemu.elf`, Ghidra 12.1.3, `PowerPC:BE:64:A2ALT`, APPLY=true:
- CREATED `/PS3/GXEMU/GxemuVuart10FramePrefixBE` (size 0x10) and `/PS3/GXEMU/GxemuVuart10TransferState` (size 0x18). Definitions described in previous handoff.
- Verified `0x000900FC SendVirtualUartFrame` and SET function-scoped `r2=0x00678548`.
- `0x0008FC68 ReceiveVirtualUartChunk` had `TOC_REFUSED r2 writer in ReceiveVirtualUartChunk`. Whether that is explicit PPC or injected call P-code remains unknown. **Do not force r2 context** before an instruction-level audit.
- Applied verified global-pointer declarations, preserving preceding underlying storage values:
```
0x00672B50 -> gVuart10SequenceCounterPointer    dword *64
0x00672B58 -> gVuart10TransferStatePointer     GxemuVuart10TransferState *64
0x00672B60 -> gVuart10ReceiveOffsetPointer    qword *64
0x00672B68 -> gVuart10RemainingBytesPointer   dword *64
```
- Code reference `0x0004946C -> ReceiveVirtualUartChunk@0x0008FC68`; call itself currently unowned by Ghidra.
- Call reference `0x0024F9A4 -> SendVirtualUartFrame@0x000900FC` belongs to function `FUN_0024F95C@0x0024F95C`, an upstream framing caller.
- Calls `0x00251044 -> SendVirtualUartVariablePacketAlternate@0x000901FC` and `0x0025106C -> SendVirtualUartVariablePacket@0x0008FD48`, both **unowned**; do not infer their function boundaries without checking.
- `0x0024F718` called by all three variable/fixed UART sender variants and the receiver, likely shared buffer/address conversion, but its function semantics are unproven. `0x00051528` has 227 refs and is a generic helper, so avoid broad caller sweeps.
- Ghidra reported diagnostic string at `0x002B1A80`: `******** REPORT TO BRIAN! ********\n`; identity and trigger unknown.
- **Partial console output received:** stops at `BRIAN_STRING`; the script's subsequent decompilations and DONE/Finished messages were not present. Do not state this run completely finished.

## Current directly applicable Ghidra state (already applied; do not duplicate)

Nine named VUART functions: `Lv1WriteVirtualUart@0x494A4`, `Lv1ReadVirtualUart@0x49544`, `Lv1VirtualUartParameterDispatch@0x495B8`, `Lv1ConfigureVirtualUartIrq@0x49664`, `ReceiveVirtualUartChunk@0x8FC68`, `SendVirtualUartFrame@0x900FC`, `SendVirtualUartVariablePacket@0x8FD48`, `SendVirtualUartFixed64BytePacket@0x8FF54`, `SendVirtualUartVariablePacketAlternate@0x901FC`.

Existing datatype: `/PS3/PPU/Ppc64FunctionDescriptor24`, size 0x18, 7 verified declarations at `0x6470A0`, `0x6470B8`, `0x6470E8`, `0x647100`, `0x64F728`, `0x64F740`, `0x64F770`. All TOC 0x678548 and third word zero. Current additional types above.

## Next action / new script

Committed `ghidra_scripts/AuditPs3GxemuVuart10CallChain_20261016_v1.java` on `testing`.

Read-only, not run or compiled in user's installation. It prints explicit instruction/P-code contributors to r2 writes in the receiver; verifies two remaining OPDs for receiver and fixed 0x70 sender; inspects instruction context at unowned upstream call sites `0x4946C`, `0x251044`, `0x25106C` and framing `0x24F9A4`; decompiles only containing functions at those sites and `0x24F718`; avoids generic 227-ref helper output. The upstream part of the previous log can also be supplied if the user has it.

No new signatures or packet-MagicGate semantic mappings established. Outer UART packet class 0x90 is not evidence of native MechaCon S-command 0x90. Continued goal is Sony MagicGate native header processing for HDD Utility (SCUS-97395), with DNAS parked; no PCSX2 code modified.
