# DECKARD APU wrapper recovery (2026-10-15 v3)

## Source and observed failure
A fresh SCPH-79001 DECKARD ELF analyzed in Ghidra 12.1.3 using PowerPC:BE:32:DECKARD 1.0 produced 10,032 instructions and 217 functions. The original read-only APU decoder audit passed 6/9 checked sites, with byte mismatches=0, unmapped=0, and no instruction defined at three sites: 0x00A031A0, 0x00A031A8 and 0x00A031B0. The attached post-analysis GZF confirms this is a newly analyzed DECKARD program.

Original firmware .text bytes at 0x00A03198..0x00A031F7 were independently rechecked: 12 consecutive, separate two-instruction leaf wrappers, each of the form [documented APU opcode, 0x4E800020 (blr)]. Normal control-flow analysis does not automatically walk past a return into the adjacent leaf entry. Therefore a missing instruction at the next function entry does **not** by itself show an APU SLEIGH decoding bug. Do not weaken or add blanket opcode matches.

## Direct Ghidra recovery
Run ghidra_scripts/RecoverDeckardApuWrappers_20261015_v2.java on the **main** DECKARD.elf, with the PowerPC:BE:32:DECKARD language. It:
- Verifies language/name/mapped executable block and exact APU word + blr for each entry.
- Disassembles only the missing checked words; refuses to clear data, overlapping instructions, or existing function bodies.
- Creates missing functions and renames only default-sourced names, preserving analyst/importer names.
- Applies typed uint32_t/void PPC ABI signatures to functions whose signatures are still default with zero parameters; preserves prior analyst signature refinements.
- Marks recovered function entries with a short plate comment if no comment exists.
- Reports every skipped entry and summarizes the changes. Safe to rerun.

## Ghidra-editor signatures (no semicolon)
All parameter registers follow the stock PPC32 ABI: r3 for first argument / integer return, r4 for second argument. Identifiers here are generalized for BSim applicability. Signatures are asserted only for exact firmware word pairs verified by the recovery script.

| Address | Ghidra function declaration |
|---|---|
| 0x00A03198 | void ApuWriteGteRegister(uint32_t registerIndex, uint32_t value) |
| 0x00A031A0 | uint32_t ApuReadGteRegister(uint32_t registerIndex) |
| 0x00A031A8 | void ApuWriteMipsGpr(uint32_t registerIndex, uint32_t value) |
| 0x00A031B0 | uint32_t ApuReadMipsGpr(uint32_t registerIndex) |
| 0x00A031B8 | void ApuWriteMipsHi(uint32_t value) |
| 0x00A031C0 | uint32_t ApuReadMipsHi(void) |
| 0x00A031C8 | void ApuWriteMipsLo(uint32_t value) |
| 0x00A031D0 | uint32_t ApuReadMipsLo(void) |
| 0x00A031D8 | void ApuWriteMipsProgramCounter(uint32_t mipsPc) |
| 0x00A031E0 | uint32_t ApuReadMipsProgramCounter(void) |
| 0x00A031E8 | void ApuWriteMipsCycleCounter(uint32_t cycles) |
| 0x00A031F0 | uint32_t ApuReadMipsCycleCounter(void) |

No structures, enums, or new data declarations are needed for these functions. Existing APU userops remain opaque: this script only restores leaf function boundaries and register ABI declarations.

## Verification and next step
- Exact ELF bytes verified for all 12 wrapper pairs; Ghidra 12.1.3 language compilation and extension packaging were successful in user's build.
- The new recovery script is source-reviewed but **has not been run or compiled in Ghidra** in this environment. The extension's Gradle audit-script compile task includes it to catch Ghidra Java/API problems at the next build.
- After running recovery script, rerun AuditDeckardApuDecode_20261015_v1.java: the former three missing entries should be present and decode, making 9/9 if nothing else changes. If a failure remains, inspect its explicit SKIP reason and the GZF before changing the language spec.
