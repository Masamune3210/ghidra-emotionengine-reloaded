# PS3 GXEMU virtual UART port-10 handoff v3 (2026-10-16)

Branch: `testing`. Previous [v2](PS3_GXEMU_VUART10_MAGICGATE_HANDOFF_20261016_v2.md). User's Ghidra 12.1.3 full-64-bit `ps2_gxemu.elf`.

## Completed: direct-call validation and wrapper renames

User successfully ran `TracePs3GxemuVuartCallers_20261016_v2.java`. All four wrapper entries and contained LV1 hypercall selectors matched; the script **applied** these function names (do not rename again):

```
0x000494A4 -> Lv1WriteVirtualUart
0x00049544 -> Lv1ReadVirtualUart
0x000495B8 -> Lv1VirtualUartParameterDispatch
0x00049664 -> Lv1ConfigureVirtualUartIrq
```

All 4 names are based on verified LV1 operations, not supposed MechaCon logic. No parameter types or return types established. The trace located **58 incoming references to wrapper entries**, plus no incoming reference to the scanned descriptor start addresses (that is not a failure; indirect data dispatch can still use them).

**Direct local port-10 caller candidates** (`r3=0xA` at a call to verified wrapper, local straight-line value only):
- `0x0008FCA0` read call to `0x00049544`; Ghidra function `FUN_0008FC68`.
- `0x0008FF24` write call to `0x000494A4`; no containing function defined.
- `0x000900D0` write call, no containing function.
- `0x000901C8` write call; Ghidra `FUN_000900FC`.
- `0x000903D8` write call, no containing function.

Other wrapper callers use direct candidates ports 0 or 2. A separate call at `0x000496B8` to virtual UART parameter wrapper has local `r3=0xA`; however that function also handles other ports. Do not assume all port-10 sites are MagicGate without tracing packet contents and actual control-flow paths.

**Potential 24-byte PPC64 function descriptors**, each stores a code entry pointer and `0x00678548` TOC pointer as first two BE64 words:
- `0x006470A0` -> `0x000494A4`
- `0x006470B8` -> `0x00049544`
- `0x006470E8` -> `0x000495B8`
- `0x00647100` -> `0x00049664`

Descriptor 3rd qword is not yet validated. No datatype applied yet. If validation confirms expected 24-byte layout, create reusable datatype in dependency order, then declare the four fields; do not blindly spread datatypes across an entire range.

**Another direct LV1 read at `0x00049748` remains ownerless.** Context shows `li r11,0xA2; or r3,r28,r28; or r4,r29,r29; or r5,r30,r30; sc 1`, and a branch-back logic nearby. Do not create arbitrary function boundary or port 10 assertion there without additional prologue evidence.

## Next script

`ghidra_scripts/InspectPs3GxemuVuart10Endpoints_20261016_v2.java` (v1 prototype removed; **use v2 only**).
- READ-ONLY; validates the five direct port-10 call targets;
- prints surrounding decoded PPC instructions and function boundaries of owning / ownerless sites;
- decompiles confirmed containing functions (`FUN_0008FC68`, `FUN_000900FC`);
- reports third qword of four candidate function descriptors and TOC;
- prints relevant immediate xrefs and disassembly near the missing `0x00049748` LV1 read function.

It is committed to `testing`, not yet executed by user. If Ghidra finds no containing function on the three write sites, avoid renaming them until their boundaries are proven by caller flow/prologue/disassembly.

Do not confuse LV1 hypercall `0x8F` with MechaCon S-command `0x8F`. The PCSX2 native HDD Utility `0x90 -> 26*0x8D -> 0x8F` remains the KELF oracle and cryptographic path is not yet recovered.

## Next step

User pulls `testing`, runs the read-only v2 probe and shares complete output. Trace VUART port 10 write/read messages, then identify native emulated MechaCon command forwarding or processor boundaries to reconstruct genuine crypto behavior.
