# Dragon MechaCon 6.12: callback ingress and state-edge handoff (2026-10-16 v3)

## Goal and limits
Continue the MagicGate investigation using the **existing**, analyzed Dragon MechaCon 6.12 ARM/Thumb Ghidra database. Identify external command reception, transfer/result signaling, and the actual packet/command-to-state transition path before assigning any of the observed state values to MechaCon/CDVD SCMD or claiming a PCSX2 mismatch. The firmware ROM is **0x44000 bytes**, SHA-256 `18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b`.

## Completed and verified (user-run v2)
`ghidra_scripts/TraceDragon612ControllerCallbacks_20261016_v2.java` ran successfully on the existing Dragon Ghidra database:
- All 18 Thumb callback pointer words, dispatcher/call-site opcodes and MMIO literals passed verification.
- Metadata changed: 5 function renames; 22 labels; 32 comments; 20 references; 0 new typed tables; 1 existing callback table declaration preserved.
- No ROM bytes, existing function bodies, or signatures changed.
- Raw output is preserved in this repository:
  - [Controller callback audit](evidence/Dragon612_ControllerCallbackAudit_20261016_v2_1792111994991.txt)
  - [Command ingress candidate decompilations](evidence/Dragon612_CommandIngressCandidates_20261016_v2_1792111994991.txt)
- Controller callback table `0x00038680..0x000386C7`: **18 entries, 16 distinct entry addresses**. Slots 0 and 10 point to `0x2A66C`; slots 9 and 17 point to `0x2B2AC`. Index source RAM `0x02000488`; internal substate `0x02000489`.
- Observed path: Thumb BL at `0x29AF2` -> `DispatchControllerCallbackByIndex` at `0x2A604` -> ROM callback table -> `BX R7` thunk `0x3585E`.
- Slots 5 and 6 select `DispatchState70To73` at `0x2AFC8` and `DispatchState80To83` at `0x2B070`. Separate `DispatchState90To93` at `0x15DD0` has a direct call at `0x151C2`.
- Verified pointer literals for MMIO `0x036000A0`, `0x03005000`, `0x03808000`; transfer RAM `0x0200048C` and pending RAM `0x02000496`.
- The Ghidra decompiler's first dispatcher at `0x2A66E` subtracts `0x30` from a byte and conditionally indirect-jumps for five values. Its jump table is **not recovered** by the decompiler, so inspect assembly before making stronger semantic claims.
- `0x31B84` routes **20 observed selector constants** to byte-argument handlers: `0x02,0x03,0x0A,0x0B,0x0C,0x12,0x14,0x1A,0x1C,0x22,0x24,0x2A,0x2C,0x32,0x34,0x3A,0x3C,0x5C,0x74,0x7C`. Its upstream source and the meaning of selectors are **not yet proven**.
- `0x12614`, `0x12694`, `0x16F94`, `0x30380`, `0x2EA18` and `0x2EA88` were examined as candidates. Candidate does **not** mean confirmed MagicGate behavior.

## New read-only trace (committed, not yet user-run)
`ghidra_scripts/TraceDragon612CommandStateEdges_20261016_v4.java` is the **next** script. It is the v3 trace with two important corrections:
1. ROM length and full-image hash scope corrected from erroneous `0x40000` to the proven `0x44000` bytes. The original v3 would have failed the ROM hash guard.
2. New filename/report prefix `v4` and Script Manager category `PS2.MechaCon.MagicGate`.

The script verifies SHA-256 and all 18 callback words before collecting data; it is read-only and does **not** create functions, rename, change signatures, or apply metadata. It reports callback entries (including non-function starts), root instruction windows, up to two reference hops, relevant RAM/MMIO pointer literals, unresolved callback entry windows and bounded decompilations. It saves both reports in **Downloads**:
- `Dragon612_CommandStateEdges_20261016_v4_<timestamp>.txt`
- `Dragon612_CallbackBodies_20261016_v4_<timestamp>.txt`

**Verification status:** Java source and Ghidra API signatures checked; **no Ghidra runtime test for v4 yet**. Do not claim success until user's script log and reports are returned. No need to rerun v1/v2 or reimport ROM or existing IOP/EE modules.

## Directly applicable Ghidra metadata

Already applied in v2 (preserve user-defined names and existing datatypes):

```text
0x00038680 - 0x000386C7
Type: uint32_t[18] (raw odd Thumb pointers; previous typed table preserved)
0x00038680 -> ControllerCallbackTable18_ThumbPointers
0x02000488 -> ControllerCallbackIndex
0x02000489 -> StateByte_02000489
0x0200048C -> ControllerTransferByte
0x02000496 -> ControllerPendingByte
0x0002A604 -> DispatchControllerCallbackByIndex
0x0003585E -> BranchToR7
0x0002BAC4 -> TryStartControllerTransfer
0x0002BC24 -> TrySendControllerByte
0x00029E0C -> TriggerControllerCommand
```

**Optional naming refinements supported by the v2 decompilation, not auto-applied:**

```text
0x0002A66E -> DispatchCode30To34
uint DispatchCode30To34(void)

0x00031B84 -> DispatchSelectorByteToHandler
void DispatchSelectorByteToHandler(int selector, byte value)
```

These are generic descriptive candidates; the existing return and argument types shown here reflect the current decompiled prototypes, **not independent ABI verification**. Preserve custom user names/signatures, and do not promote internal selector values to external SCMD identities.

## Next decision point
Run the v4 script in the existing Dragon database, return both Downloads reports and the run log. Use its caller/reference map to find who writes the callback selector and pending transfer byte, where host-supplied bytes arrive, and where response/status returns. Compare a specific **verified** external command and observed result against PCSX2 `pcsx2/CDVD/CDVD.cpp` and `pcsx2/SIO/Memcard/MemoryCardProtocol.cpp`; avoid extrapolating from identical-looking `0x70/0x80/0x90` state values.

## Related repository handoffs
- [Previous Dragon callback evidence](ps2-dragon612-callback-dispatch-handoff-20261016-v2.md)
- [Previous Dragon state-machine evidence](ps2-dragon612-magicgate-interface-handoff-20261016-v1.md)
- [Current broader MagicGate continuation handoff](PS2_MagicGate_Continuation_Handoff_20261016_v2.md)
