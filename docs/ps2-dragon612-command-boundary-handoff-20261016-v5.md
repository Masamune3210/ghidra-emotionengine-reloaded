# Dragon 6.12: v5 results and command-boundary investigation (2026-10-16 v5)

**Branch:** `testing`  
**Supersedes:** [Dragon v4 handoff](ps2-dragon612-command-state-edges-handoff-20261016-v4.md)  
**Source program:** existing Dragon MechaCon 6.12 ARMv4T/Thumb Ghidra database; do **not** reimport.  
**ROM identity:** full `0x44000` bytes SHA-256 `18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b`.

## Latest user-run v5: verified, read-only

`ghidra_scripts/TraceDragon612CommandStateEdges_20261016_v5.java` ran and produced both requested timestamped reports in **`Downloads\1`**:
- `Dragon612_CommandStateEdges_20261016_v5_1792113419514.txt` (4301 lines; SHA-256 `a99066dfb8688f09314e966721936d5ea6ad9447bac28f6bce634e9251b129a7`).
- `Dragon612_CallbackBodies_20261016_v5_1792113419514.txt` (5240 lines; SHA-256 `a76b38c1a0dc93a93ede99db525a20a758d1a89407de17661a204a9b9199da33`).

Both reports were uploaded in the current project conversation. They are larger research snapshots; this handoff captures the material results without adding over 400 KiB of raw, mostly repeated literal listings to the repository. The v5 header confirms the ROM hash and **all 18 callback words exact**; database changes: **none**.

### Controller callback families

The established 18-entry table `0x38680..0x386C7` has **16 distinct entries**. In addition to internal states `0x70..0x73` at `0x2AFC8`, `0x80..0x83` at `0x2B070`, and separate `0x90..0x93` at `0x15DD0`, v5 shows more controller families:
- `0x2A66E`: offset `state-0x30`, conditional 5-way Thumb computed jump `0x2A680`.
- `0x2AB64`: offset `state-0x60`, conditional 6-way computed jump `0x2AB76`; **Ghidra has decoded instructions but no distinct function**.
- `0x2B118`: `0x90..0x94`, computed dispatch with unresolved jump table.
- `0x2B204`: explicit `0xA0..0xA3` transfer/retry state handling.
- `0x2B490`: offset `state-0xE0`, conditional 7-way computed jump `0x2B4A2`; no distinct Ghidra function.
- `0x2B842`: `0xF0..0xF5`, conditional 6-way computed jump `0x2B854`.
- `0x2A66C` and `0x2B840`: shared/independent `BX LR` no-op callback entries; don't automatically create function bodies on overlapping bytes.
- Existing `0x2A9D4` and `0x2AA9C` state handling switches between `0x40/0x41` and `0x50/0x51`.

These are **internal** state values, not established PCSX2 CDVD SCMD opcodes. The `0x38438..0x3849B` 100-byte BCD negative-control table is still not an SCMD table.

The v5 report marks `0x29AF2` and `0x151C2` as **no current Ghidra instruction/owner**, even though the previous v2 audit byte-verified the ROM's Thumb `BL` call sites at those exact addresses. This is a Ghidra instruction/function-coverage caveat, **not** proof the calls do not exist. Recover Thumb code context later if these upstream callers become important.

### Hardware and control-calibration negative lead

`0x31B84` has 20 selector-byte cases, but caller `0x17384` iterates settings, programs corresponding selector/byte combinations (`0x3A,0x2C,0x2A,0x3C,0x74`, among others), samples `0x19154`, compares against a target value and chooses the setting with minimum absolute difference. The observed **call usage** is a control tuning/search loop, not evidence of an external MagicGate command decoder. Deprioritize as authentication ingress unless new callers prove another purpose.

`0x29E0C`, `0x2BAC4`, `0x2BC24` continue to establish controller MMIO `0x03005000`, `0x03808000` and `0x036000A0`; selector `0x02000488`, substate `0x02000489`, transfer `0x0200048C`, pending `0x02000496`. v5's 1041 RAM/MMIO pointer matches are **pointer literal observations**, not 1041 proven command reads/writes.

## New higher-priority candidate: 0xC0 -> 0xE3/0xE8 command transport

V5 decompilation of `FUN_00014270` shows the following **conditional**, ordered call sequence:
1. Under a flag check, prepare **12 bytes** copied from input at offsets `+5..+0x10`; call `FUN_00008658(0xC0, 0x0C, buffer)`.
2. Only when that call returns `0`, prepare an **8-byte** buffer from input offsets `+5..+0x0C`; call `FUN_00003558(buffer)`.
3. When this second call returns `0`, call `FUN_00003924()` and set a local result byte to `0`. Otherwise result byte remains `0x80`. Finally store it to a RAM field at offset `+9`.

Inside `FUN_00003558` the **eight input bytes** are copied to a local working area, transformed using `FUN_00003410` (two 32-bit XORs with global words) and `FUN_00003430` (three calls to `FUN_0000333C` plus XOR-based mixing), then checksummed according to Ghidra's diagnostic decompilation. It calls `FUN_000086D0(0xE3, 10, buffer)`; applies `FUN_000034E4`, `FUN_00002F6C` and further `FUN_00003430` stages; only if the first call returned 0 does it call `FUN_000086D0(0xE8, 10, buffer)`. No opcode has been proven to be external CDVD SCMD, and the specific algorithm/cryptographic identity cannot be assigned until the transport and transform code is studied.

**Why this matters:** It is an observed paired command exchange with transformed data and conditional success path, more plausible to investigate for security/authentication than state byte coincidences, **but is not yet proven MagicGate**.

### Directly applicable Ghidra partial metadata (proposals; do not overwrite custom names)

```text
0x00014270 -> ProcessCommandC0AndFollowup
void ProcessCommandC0AndFollowup(void)

0x00003558 -> TransformAndSendTwoCommandPayloads
int TransformAndSendTwoCommandPayloads(int inputEightBytes)

0x00003410 -> XorEightByteWorkingBlock
void XorEightByteWorkingBlock(uint * block)

0x00003430 -> TransformEightByteWorkingBlock
void TransformEightByteWorkingBlock(uint * block)

0x00017384 -> FindClosestMeasuredControlSetting
uint FindClosestMeasuredControlSetting(int settingGroup)

0x00031B84 -> DispatchSelectorByteToHandler
void DispatchSelectorByteToHandler(int selector, byte value)
```

The above parameter and return types are **existing Ghidra/decompiler types**; only names would change. The names are descriptive and generalized, not original Sony symbols and **not proven MagicGate names**. The new v6 script is read-only and does not apply them.

## Next script

[`ghidra_scripts/TraceDragon612SecurityCommandBoundary_20261016_v6.java`](../ghidra_scripts/TraceDragon612SecurityCommandBoundary_20261016_v6.java) is a **read-only**, ROM/hash and callback-word-guarded, bounded investigation of `0x14270`, `0x3558`, `0x8658`, `0x86D0`, `0x3410`, `0x3430`, `0x333C`, `0x2F6C`, `0x34E4`, `0x3924` and their immediate caller graph. It omits the v5 wide ROM literal scan and controller callback body sweep. Sources are committed; **runtime verification is pending**.

Run it on the same existing Dragon Ghidra database, upload its Script Manager log and its **two `Downloads\1` outputs**:
- `Dragon612_SecurityCommandBoundary_20261016_v6_<timestamp>.txt`
- `Dragon612_SecurityCommandBodies_20261016_v6_<timestamp>.txt`

**Next question:** Where do commands `0xC0`, `0xE3`, and `0xE8` actually go, which bytes come back, and what is the path from the host/CDVD interface? Compare a **verified** command exchange against PCSX2 only after this is established. Preserve existing analyzed firmware/SECRMAN work and do not rerun v1-v5.
