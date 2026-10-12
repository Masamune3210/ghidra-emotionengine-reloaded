# CCC 2.x importer handoff (2026-10-12)

## Branch and purpose

Branch: `note-working/ccc2-symbol-import` (from `testing`).
Migrate directly to CCC 2.x / JSON formats 13–15. Do not repair the obsolete CCC 1.x v7 parser; its classes remain inert reference code.

## Implemented

- Existing `StabsAnalyzer` registration now delegates to `Ccc2SymbolImporter` and accepts MIPS/R5900 ELF inputs with mapped or unmapped symbol sections, plus an external ELF or JSON override.
- 2.x flat JSON tables: `data_types`, `functions`, `parameter_variables`, `local_variables`, `global_variables`, and `labels`.
- Recursive composites, enums, arrays, pointers/references, function-pointer signatures, typedefs, structures, globals, function sizes, parameters, stack locals, source paths, source-line comments, and inline source markers. Missing types remain unresolved rather than invented.
- Preserves user/imported signatures and names and never clears existing defined instructions/data. Program option `CCC 2.x Symbols / Imported` suppresses duplicate application.
- Runs `stdump json` (2.x), not the legacy `print_json` command.
- Gradle `prepareStdump` installs tagged CCC v2.1 for Windows, Linux musl and Apple Silicon; `os/download.sh` now delegates to Gradle.

## Decisions and limitations

- Stable CCC v2.1 generates JSON v14. Development CCC v2.2 generates v15 and adds DWARF 1; v15 JSON can be imported with a compatible separately supplied native executable.
- v14 bitfields are not applied because v15 changed their offset interpretation to storage-unit-relative; guessing would corrupt layouts.
- Register-only locals, precise parameter register storage, pointer-to-data-member types and unsupported nodes are not yet modeled.
- Native v2.1 asset SHA-256 digests are absent from GitHub's release metadata. Gradle prints the downloaded digest but does **not** authenticate it against a pinned trusted checksum unless the relevant `-PcccStdumpSha256Windows`, `-PcccStdumpSha256Linux` or `-PcccStdumpSha256Mac` property is supplied. The previous v1.2.1 checksum assurance is therefore **not retained by default**. For trusted offline builds use `-PuseLocalCcc2Stdump` with your own known-good executable.
- CCC does not support Metrowerks `.mwcats`; compressed binaries still require a separate unpacking step. CCC v2.1's macOS binary is for Apple Silicon, not Intel.
- Legacy `StabsImporter`, `StdumpParser`, and `StdumpAST` files are retained but no longer invoked; `StabsImporter.ImportOptions` is still used as the options holder.

## Verification status

- Inspected CCC upstream `symbol_json.cpp`, `ast_json.cpp`, `symbol_table.cpp` and `stdump.cpp` for fields, parser versions and command-line behavior.
- Checked relevant Ghidra API source for function-type constructors, parameter definitions, listing data creation, comments, composite fields and signature source.
- Compared the branch against `testing`; changes are limited to symbol importer, analyzer routing, provisioning and docs.
- **Not compiled, integration-tested, or executed in Ghidra.** There is no local Ghidra installation or CCC executable available here, and no CI success is claimed.

## Next step

Build once against Ghidra 12.1.x using a single-line command:
`gradle -PGHIDRA_INSTALL_DIR=<Ghidra-root> buildExtension`

Verify `os/win_x86_64/stdump.exe` is CCC 2.x and compare metadata on representative v14 `.mdebug` and `.symtab` ELFs. Test v15 DWARF 1 with a compatible development executable. Address compiler/runtime failures and remaining AST/storage semantics. Pin trusted release checksums before merging as a release-quality replacement.

No merge into `testing` or `main` has been performed.

## Build feedback (2026-10-12)

- User executed `gradle buildExtension` on Windows. `:compileJava` initially failed with one checked `InvalidDataTypeException` from `Structure.insertBitFieldAt()` and four removal warnings for `CodeUnit.getComment(int)` and `CodeUnit.EOL_COMMENT/PRE_COMMENT`.
- Commit `b49c7b2b724b9cd56c8f5222cc2fcfbc77c10984` catches `InvalidDataTypeException` alongside runtime exceptions, logs bitfield failure information, and uses `CommentType.EOL/PRE` in `getComment()`.
- **Post-fix compilation has not yet been observed.** The user should pull the branch and re-run `gradle buildExtension`; use remaining compiler output for focused follow-up.

- Ghidra 12.1.3 Windows runtime feedback: `AnalysisScheduler` rejected analyzer name `CCC 2.x Symbols` because a period is forbidden. Commit `22ac6e79f3f3b97660c213fecb9ddcbde94e621f` changes the analyzer display name to `CCC 2x Symbols`. Ghidra startup after the fix is not yet verified.

## First successful end-to-end Ghidra import (2026-10-12)

User confirmed Ghidra 12.1.3 runtime log:
`CCC 2.x> Imported types=73 functions=9 globals=16 labels=2 skipped=50 (JSON v14)`.

This verifies that the native CCC v2.1 executable ran, the JSON v14 schema was parsed and the import completed without a reported fatal error. It does **not** yet validate field layouts, function signatures, or source metadata against a known ground truth. The counts have narrower meanings: datatype manager add attempts succeeded 73 times (not necessarily 73 unique new definitions), 9 functions were processed, 16 globals were processed, and 2 labels were newly created.

Investigated the 50 skipped operations: before this change all causes were collapsed into a single counter. Notably CCC JSON v14 bitfields are deliberately omitted because v15 changes their storage-unit-relative offset semantics, but other failures were also counted silently. Commit `99ebfc64c545825f2f655823563f1029d940b7d1` now aggregates skipped operations by reason and prints two representative examples per category in the Ghidra analysis log. **The breakdown itself has not yet been observed on a second test run.**

Next verification: build the updated branch, import a *fresh copy* of the test ELF (preferred to overriding the importer-only-run-once guard on a previously modified database), then report the `Skip reason:` lines. This isolates skipped v14 bitfields from datatype conflicts, missing mapped symbols, and other recoverable errors.

## TESTSPU.bin IRX loader validation (2026-10-12)

User supplied the import-stage output for PS2 BIOS `TESTSPU.bin` (MD5 `6273b36b4200397fe43be82a06ff3e36`): linker symbols `etext`, `_etext`, `edata`, `_edata`, `_fbss`, `end`, `_end`, `_gp` all failed placement with section index `0xff1f`; relocation table reported recorded=323, applied=239, failed=0, unsupported=0, skipped=0; 9 import/0 export tables identified. This is from Ghidra's ELF/IOP loader, not a CCC analyzer error.

Important interpretation: `0xff1f` is **SHN_HIPROC**, upper bound of processor-specific ELF section indices. It is **not SHN_ABS** (`0xfff1`). Standard Ghidra `ElfProgramBuilder` explicitly logs "Unable to place symbol" for unsupported reserved section indices. Do not falsely relabel these symbols as absolute or force their addresses into RAM without validating IRX-specific semantics. The unplaced `_gp=0x97d0` also differs from the ELF loader's synthesized `%got.text gp=0x9ff0`; neither should be silently treated as authoritative.

Root cause of non-summing relocation counts: `IopIrxElfLoader` omitted enum statuses `PARTIAL` (processed, waits on later relocation) and `UNKNOWN` (prior-status unavailable) from both counters and logging. Commit `153fb6af4c35dc6cde8d108166f7f78d9dbd1379` adds explicit `partial` and `unknown` totals in log and program options. An explanatory future log is expected to show where the 84 unaccounted records fall. **No post-fix import was observed yet.** Existing IOP relocation application logic is unchanged.

Next validation: install rebuilt extension, reimport TESTSPU.bin, capture the full `IOP IRX relocations: ... partial=... unknown=...` line, the `IOP IRX module` line (if present), and the subsequent `CCC 2.x` analyzer breakdown. If symbols require recovery, inspect section mapping and actual IRX linker conventions before applying labels.
