# DECKARD PowerPC APU coverage handoff, 2026-10-15 v6

## Baseline and runtime evidence
- Working branch: `testing`; installed extension language `PowerPC:BE:32:DECKARD` (1.0), Ghidra 12.1.3.
- Sony SCPH-79001 DECKARD ELF imported and fully analyzed; existing APU wrappers recovered and typed by scripts. Verified: 12/12 wrappers, 7 recovered instructions, 7 new functions, 5 existing function renames, 12 total concrete wrapper signatures.
- `RefineDeckardApuWrapperSignatures_20261015_v3.java` **runtime verified**: updatedFunctions=5, returns=5, parameterTypes=4, parameterNames=4, skipped=0.
- `AuditDeckardApuCoverage_20261015_v4.java` **runtime verified** before user's manual disassembly: primary0Nonzero=251; documentedMatches=206; decoded=204; notDisassembled=1; definedData=0; wrongMnemonic=1; unclassifiedCandidateWords=45.
- The lone undisassembled matching word was `0x00A01138: 0x0060021C = amfpc r3`. User manually disassembled it; screenshot verifies correct mnemonic, and shows it belongs to a contiguous code sequence ending in `rfi` at `0x00A011A0`, not an isolated two-instruction function. Do **not** force a new function at 0x00A01138.
- The lone purported mnemonic mismatch was `0x00A0358C: 0x00C006DC`: expected `amf0B_u`, actual `amf0B_u`. It was caused by comparing the mixed-case expected name against `toLowerCase()` output. **Not a decoder bug**.

## Code change
`AuditDeckardApuCoverage_20261015_v5.java` supersedes v4. It changes mnemonic comparison to `equalsIgnoreCase()`, leaving all OP/XOP and operand mask checks untouched. This is an audit-only correction, not a SLEIGH language change. All other categories (defined data, undisassembled and unclassified words) remain reported separately.

Expected after re-running on user's manually updated database: 206 documented matches, 206 decoded, 0 notDisassembled, 0 definedData, 0 wrongMnemonic. This is a *prediction*, **not yet a validated v5 runtime result**.

## Next actions
1. `git pull`; in Ghidra Script Manager refresh and run `AuditDeckardApuCoverage_20261015_v5.java` on the **existing** DECKARD ELF. No extension rebuild/reinstall.
2. Investigate the 45 unmatched OP=0 candidates only in context; do not infer they are actual APU instructions from their top six bits. Use actual code/data boundaries and references.
3. Next target is DPATCH, mapped at `0xFFFFD000`, using the same DECKARD language. Validate opcode coverage and p-code for significant MIPS emulation paths. Avoid changing the PowerPC ISA spec without reproducible decode failures.
4. Preserve existing analyzed DECKARD Ghidra database, avoid unnecessarily creating functions in interrupt/exception code.

## Verification
- User visual and console evidence establish both previously reported issues are resolved or false positives.
- v5 source review completed against v4; **v5 has not yet been run inside Ghidra**.
