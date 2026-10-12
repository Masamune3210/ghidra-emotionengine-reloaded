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
