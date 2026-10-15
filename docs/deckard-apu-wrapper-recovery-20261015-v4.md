# DECKARD APU signatures: runtime verification and partial refinement (2026-10-15 v4)

## Runtime results
Ghidra 12.1.3, main SCPH-79001 DECKARD.elf, language PowerPC:BE:32:DECKARD (1.0). User ran RecoverDeckardApuWrappers_20261015_v2.java:

- 12/12 exact APU wrapper words and matching blr verified; 7 instructions recovered.
- 7 new functions, 5 existing functions renamed, 7 signatures refined, skipped=0.
- Initial read-only decoder audit before recovery: good=6/9, unmapped=0, wrongBytes=0, notDecoded=3. Its 3 missing entries at 0xA031A0, 0xA031A8, 0xA031B0 were recovered by the wrapper script.
- No SLEIGH changes needed for those three missing instructions. Repeat the decoder audit to confirm 9/9, but the wrapper recovery itself verifies all 12 independently.

## Remaining partial-signature issue
Five preexisting functions had nondefault existing signatures and therefore were intentionally **not** rewritten by the v2 wrapper recovery script. These are valid incremental improvements, grounded in exact APU opcode semantics and verified r3/r4 register operand usage:

Address | Ghidra function declaration
--- | ---
0x00A03198 | void ApuWriteGteRegister(uint32_t registerIndex, uint32_t value)
0x00A031D8 | void ApuWriteMipsProgramCounter(uint32_t mipsPc)
0x00A031E0 | uint32_t ApuReadMipsProgramCounter(void)
0x00A031E8 | void ApuWriteMipsCycleCounter(uint32_t cycles)
0x00A031F0 | uint32_t ApuReadMipsCycleCounter(void)

The v3 script **RefineDeckardApuWrapperSignatures_20261015_v3.java** verifies exact APU/blr bytes, already established function name, language, and instruction mnemonics; then selectively replaces only Ghidra undefined return/parameter types and generic param_N names. It **skips** user-defined signatures, custom storage, and mismatched existing parameter counts, and preserves all concrete types. It is safe to run again.

## Next step / verification
Pull the changed script directly to the repository's ghidra_scripts folder. **No Gradle build and no extension reinstall is needed**. In the existing, post-recovery main DECKARD.elf Ghidra database, run RefineDeckardApuWrapperSignatures_20261015_v3.java from Script Manager. Re-run AuditDeckardApuDecode_20261015_v1.java afterward.

The v3 refinement script is source reviewed against Ghidra API but has **not** been compiled or executed against the user's installation. User's run log already validates SLEIGH and wrapper function recovery. Further work: audit wider APU instruction coverage and actual p-code/decompiler effects; keep stock PPC and EE/IOP specs untouched.
