# DECKARD APU SLEIGH state (2026-10-15)

## Why

Ghidra 12.1.3 standard `PowerPC:BE:32:default` imported the SCPH-79001 main `DECKARD.elf` and `DPATCH` but could not decode custom PPC auxiliary-processor instructions. The user requested processor-specification work. EE/IOP disambiguation has already been handled on `testing` and is explicitly out of scope.

## Decisions

- Add standalone `PowerPC:BE:32:DECKARD` based on Ghidra's PPC4xx language; never patch generic PowerPC or change EE/IOP flags.
- Implement 32 instruction names from the PPC Monitor APU opcode reference; reuse the stock attached PPC register fields (D/A/B).
- Represent hardware side effects using opaque userops rather than wrong no-op semantics. `aexec` also produces a CR6 status via userop. No claim of full APU emulation.
- Require unused register fields to be zero for typed one/two-register APU forms, and reserve unspecified opcodes for investigation.

## Source evidence / completed work

- `SCPH-79001.bin` SHA-256 `e76d9c8f4019041fb17f41fff25d57d608c1a3f205c99bda9eb47402c43e8c93`.
- `3_DECKARD.elf.gzf` and `5_DPATCH.bin.gzf` recovered evidence has 291 possible `OP=0` nonzero words: 246 matched names, 45 excluded (candidate data or undocumented opcodes).
- Independently checked all 246 matching words against the original extracted ELF PT_LOAD bytes and original DPATCH raw bytes. No mismatches.
- New language declaration and installer do not overwrite existing stock Ghidra language files.
- Read-only in-Ghidra audit script checks raw words and resulting disassembly mnemonics for high-confidence addresses.

## Pending verification / next steps

1. With target Ghidra 12.1.3 installed, run `install_deckard_language_20261015_v1.py <Ghidra dir>` then `--install`. Fix any Sleigh compile diagnostics without weakening other PowerPC definitions.
2. Start a fresh import of `3_DECKARD.elf` and a corrected-address `5_DPATCH.bin` under `PowerPC:BE:32:DECKARD`. Run analysis and `AuditDeckardApuDecode_20261015_v1.java` on each.
3. Compare decode coverage and decompiler p-code against the original GZF databases. Only consider altering existing databases after the new language has been validated; back them up first.
4. If compiler succeeds but decompiler output is noisy, refine userops and CR6 status semantics based on firmware behavior, not guesses.

**Verification status:** source, XML, static field-pattern checks, all 246 source bytes verified; Ghidra/Sleigh compiler and live import not available in this execution environment, **not yet runtime verified**.
