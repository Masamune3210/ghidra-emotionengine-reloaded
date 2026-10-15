# DECKARD APU SLEIGH handoff v2 (2026-10-15)

## Scope and decisions
- Continue directly on `testing`. User requested **PowerPC APU specification support as part of the existing Ghidra extension**, not a standalone installer or separate branch.
- Additional language ID: `PowerPC:BE:32:DECKARD`; independent of generic PowerPC and existing PS2 EE/IOP languages.
- The 32 opcode constructors reside in `data/languages/deckard_apu.sinc`; the DECKARD language wrapper and declaration are also in `data/languages`. The read-only audit script resides in `ghidra_scripts`.
- Extend `buildExtension`: stage the installed Ghidra version's PowerPC 4xx includes (including transitive `ppc_instructions.sinc` and its includes) and `ppc_32.pspec/cspec` into extension-owned data; compile `ppc_32_deckard_be.sla` with the same Ghidra's `support/sleigh` launcher. Stage/generated files are ignored by Git. No changes to the installed `Ghidra/Processors/PowerPC` directory.
- Delete obsolete `deckard/apu/` copies and standalone Python installer.

## Evidence
- Original `SCPH-79001.bin` SHA-256: `e76d9c8f4019041fb17f41fff25d57d608c1a3f205c99bda9eb47402c43e8c93`.
- DECKARD/DPATCH primary opcode zero: 291 nonzero candidates, 246 documented opcode matches and 45 unresolved. Hardware effects are opaque userops. No firmware bytes changed.

## Verified / next steps
- Source and Gradle packaging layout reviewed; no Ghidra runtime or Sleigh compiler available in this execution environment. **Not yet build or runtime verified.**
- Build extension with Ghidra 12.1.3 and inspect Sleigh compilation output. Install ZIP using normal Ghidra Extension Manager.
- Fresh-import DECKARD ELF and corrected-address DPATCH using DECKARD variant; run `AuditDeckardApuDecode_20261015_v1.java`, then verify decompiler flow and hardware side-effects. Do not migrate existing databases or widen unknown opcode matches without evidence.
