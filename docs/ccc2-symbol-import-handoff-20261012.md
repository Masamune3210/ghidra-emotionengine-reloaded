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

### TESTSPU follow-up verification (2026-10-12)

After the accounting-only loader change, user reimported the same TESTSPU.bin (MD5 `6273b36b4200397fe43be82a06ff3e36`). Relocation summary: `recorded=323, applied=239, failed=0, unsupported=0, skipped=0, partial=84, unknown=0`. Thus all 84 previously unaccounted records are `PARTIAL` and no record is in an unknown/failure/unsupported/skipped state. This verifies the status-reporting fix. It is **not** a proof of fully correct paired relocation values; the original caveat about validating relocated code remains.

Eight special linker symbols (`etext`, `_etext`, `edata`, `_edata`, `_fbss`, `end`, `_end`, `_gp`) still trigger Ghidra placement warnings at processor-reserved section index `0xff1f`; no relocation-specific change was made to them. Got helper reports `gp=0x9ff0`, unplaced `_gp=0x97d0`. The loader again recognizes 9 import and 0 export tables. Next useful evidence is the CCC analyzer's `Skip reason` breakdown for this file and an IRX-specific review of the special symbol semantics if those symbols matter to decompilation.

## CCC v14 bitfield conversion (2026-10-12)

User reported `skipped=50` precisely decomposed into 47 v14 bitfields (examples `magic`, `attr`) and 3 unmapped labels (including `end`, `_end`). This identifies the intentionally omitted bitfields as the main metadata-loss category, **not** an error in CCC parsing. CCC v2.1 `stabs_to_ast.cpp` explicitly sets `offset_bytes = field.offset_bits / 8` and `bitfield_offset_bits = field.offset_bits % 8`. Development CCC v2.2 instead supplies the storage-unit start and within-unit bit offset. Ghidra `Structure.insertBitFieldAt()` expects a storage-unit base byte and a bit offset within that unit.

Commit `3165a14a28b5eef5e3e26189672a600b909ef37a` removes the unconditional v13/v14 skip and converts field positions using the underlying datatype length as the storage unit width: `firstBit = offset_bytes*8+bitfield_offset_bits`, `storageStart = floor(firstBit/unitBits)*unitBytes`, `shift = firstBit-storageStart*8`. Big-endian storage shifts are adjusted as `unitBits-shift-fieldWidth`. V15 uses its native storage-unit representation. Bounds, width and bad type checks explicitly skip unsafe placements with reason labels.

**This new conversion is source-reviewed but not compiled or tested in Ghidra.** Next step is a *fresh* TESTSPU import on the updated extension, inspect struct fields `magic`/`attr` and the categorized skip summary; if layout or overlaps are wrong, retain evidence and refine conversion rather than assuming success from a lower skip count. Importing the same database can conceal changes via the already-imported guard.

## CCC v14 bitfield conversion follow-up (2026-10-12)

After the conversion commit `3165a14a28b5eef5e3e26189672a600b909ef37a`, the user reimported TESTSPU.bin and confirmed **the exact same 47 bitfields are still skipped**, now all under `invalid bitfield metadata` (examples `magic` and `attr` at offset 0). The 3 unmapped labels remain unchanged, total skipped=50 and imported types=73/functions=9/globals=16/labels=2. Therefore the previous conversion did **not** improve applied metadata: every bitfield is rejected *before* reaching offset calculation. No claim of successful bitfield recovery should be made.

The guard was aggregating multiple possible failures (unresolved underlying type, invalid underlying length, zero/invalid field size, missing position). Commit `7e67367fc17ed9e02c6db2b362c5fce70afba486` now separates those categories and reports the underlying CCC JSON node or datatype name/length for representative cases. **No runtime output from this diagnostic commit yet.** Inspect the next run's `Skipped [unresolved bitfield underlying type]` / `invalid bitfield storage width` / `invalid bitfield size or position` breakdown and fix the actual schema or resolution mismatch. Do not guess a storage width or treat a short/missing field as valid without source evidence.

## CCC v14 unresolved underlying types (2026-10-12)

TESTSPU.bin Ghidra 12.1.3 log after `7e67367`: 47/47 bitfields fail `unresolved bitfield underlying type`; 3 unmapped labels unchanged. Representative CCC v14 nodes:

- `magic` at +0: `{"descriptor":"type_name","size_bytes":16,"source":"reference","data_type":4}`, where definition #4 has descriptor `builtin`.
- `attr` at +0: same `size_bytes:16` but points at definition #36 of descriptor `type_name`, a reference chain.

Existing `builtin(String)` omitted two valid CCC v2.1 builtin classes: `128-bit integer` (unqualified) and `128-bit floating point`. Ghidra provides `Integer16DataType` and `Float16DataType`, and the 16-byte type_name nodes are consistent with a missing 128-bit mapping. **The actual class at definition #4 has not yet been observed in the Ghidra log; this is a strongly motivated hypothesis, not yet a confirmed diagnosis.**

Commit `578fe23edfbf0e1a60e27187bb0695263c1cd262` adds the omitted canonical class mappings (unqualified 128-bit integer maps to signed 16-byte `Integer16DataType` in the absence of explicit signedness, floating 128 to `Float16DataType`). It also prints the full `type_name` reference chain for any remaining unresolved bitfields, making the final builtin class and alias loops visible. No Ghidra build or import result for this commit yet.

Next: rebuild the extension and import a **fresh** TESTSPU program, then inspect the `CCC 2.x` skip categories and verify `magic`/`attr` bitfield layouts rather than relying solely on reduced skip counts.
