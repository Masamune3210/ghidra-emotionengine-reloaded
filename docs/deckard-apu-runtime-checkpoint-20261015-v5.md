# DECKARD APU runtime checkpoint, 2026-10-15 v5

## Verified in user's Ghidra 12.1.3 instance

Target: SCPH-79001 main DECKARD.elf, PowerPC:BE:32:DECKARD (1.0).

- Extension `buildExtension` and DECKARD SLEIGH compilation succeeded. No SLEIGH compile errors; stock PowerPC include files emitted nonfatal warnings.
- First APU audit: 6/9 matching mnemonics, zero byte mismatches, zero unmapped sites, three addresses without instructions.
- `RecoverDeckardApuWrappers_20261015_v2.java`: **verified=12/12**, recoveredInstructions=7, createdFunctions=7, renamedFunctions=5, refinedSignatures=7, skipped=0.
- `RefineDeckardApuWrapperSignatures_20261015_v3.java`: **updatedFunctions=5, returns=5, parameterTypes=4, parameterNames=4, skipped=0**. All five return types now concrete, and all twelve wrapper functions have typed Ghidra signatures.
- These results establish correct decoding of the known accessor instructions and disassembly coverage recovery without modifying the SLEIGH spec. A repeat of the original nine-site audit is still useful as confirmation, but no further work on the twelve wrapper names/signatures is pending.

## New read-only coverage test

`ghidra_scripts/AuditDeckardApuCoverage_20261015_v4.java` scans the entire main DECKARD ELF .text or DPATCH raw image (`0xFFFFD000..0xFFFFD823`). It reproduces all 32 known APU opcodes' OP/XOP and unused-register-field masks from `data/languages/deckard_apu.sinc`, then distinguishes:
- correctly decoded APU instructions;
- matching words not yet disassembled;
- matching words typed as data;
- instructions decoded with a different mnemonic;
- nonzero OP=0 candidates that do not match a documented APU form.

This scan **does not change program bytes, disassembly, data, or names**. It prints capped actionable missing/mismatch details and per-opcode totals. Candidate words can be embedded data; unclassified counts do not by themselves imply missing opcodes.

## Next actions

1. Pull `testing` and, with the existing DECKARD.elf open, run `AuditDeckardApuDecode_20261015_v1.java` to check the prior nine sites now pass.
2. Run `AuditDeckardApuCoverage_20261015_v4.java` and provide its summary and per-opcode counts. Do the same for DPATCH once imported with the DECKARD language at correct base `0xFFFFD000`.
3. Prioritize actual undecodable instructions in mapped executable regions over data-like candidate words; inspect p-code for APU state operations and control-flow that impacts the decompiler.

**No Ghidra extension rebuild is needed to run the new script.** The new broader audit script is source reviewed but not yet compiled or run in the user's Ghidra installation.
