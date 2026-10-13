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
- **Historical initial state:** The first implementation was not compiled in this environment. Subsequent user tests confirmed Ghidra 12.1.3 compilation and a successful TESTSPU CCC v14 import; Ghidra 12.1.3 GitHub Actions unit tests have since passed. See dated sections below for the current status.

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

## CCC v14 storage-window sizing after builtin recovery (2026-10-12)

Fresh TESTSPU result after `578fe23`: `Imported types=81 functions=9 globals=16 labels=2 skipped=14 (JSON v14)`. The 47 unresolved bitfield types are no longer reported; **11 bitfields now fail placement** as `bitfield outside storage unit` while 3 labels remain unmapped. Examples: `attr at +0 width=32 unit=16 shift=0` and `option at +4 width=32 unit=16 shift=32`. These represent a 32-bit field whose source base integer datatype is 16 bytes but whose containing structure is shorter than the 16-byte storage window assumed in the first conversion. The 36 other previously skipped bitfields are no longer included in skipped operations, but individual layout correctness is not yet independently audited.

Reviewed Ghidra `StructureDataType.insertBitFieldAt()`: `byteWidth` specifies the containing storage window and is **not required to equal** `baseDataType.getLength()`; the implementation checks only that it is large enough for the effective field width and bit shift, while `BitFieldDataType` retains the original base type. Commit `903d203e49b07f57d91d2f78e63f2b692aac2ad7` now tries v13/v14 storage windows, from the declared datatype width downward in powers of two, aligned to the original bit position, without extending past the existing structure or splitting the bitfield. v15's explicit storage-unit semantics are left unchanged. The base datatype is **not** changed; narrowing is counted separately, with two examples printed and `Bitfields placed=... narrowedStorageWindows=...` in the analysis log.

Pure arithmetic spot checks: `attr` at bit 0 and `option` at bit 32 both select an 8-byte window in a hypothetical 8-byte structure, and still occupy their original 32-bit ranges. A true 128-bit field in a 16-byte structure retains 16 bytes; a field exceeding its structure is still rejected. The test structure sizes are illustrative, not established from the user's file. **No new Ghidra build or import was observed for this commit.** Next: test on a fresh TESTSPU import and inspect the new bitfield counts; verify the actual layouts against CCC JSON, not just whether skips fall to 3. If unexpected shifts/overlaps appear, do not merge without a targeted correction.

## TESTSPU CCC v14 all bitfields inserted (2026-10-12)

Fresh Ghidra 12.1.3 runtime verification after storage-window commit `903d203e49b07f57d91d2f78e63f2b692aac2ad7`:

```text
CCC 2.x> Narrowed bitfield storage window attr: 16 -> 8 bytes (base type unchanged: unsigned int)
CCC 2.x> Narrowed bitfield storage window option: 16 -> 8 bytes (base type unchanged: unsigned int)
CCC 2.x> Skipped [unmapped labels]: end / address=6312
CCC 2.x> Skipped [unmapped labels]: _end / address=6312
CCC 2.x> Skip reason: unmapped labels = 3
CCC 2.x> Bitfields placed=47 narrowedStorageWindows=11
CCC 2.x> Imported types=81 functions=9 globals=16 labels=2 skipped=3 (JSON v14)
```

All 47 previously omitted bitfields were accepted for Ghidra insertion and 11 required a narrowed storage window; only 3 unmapped labels remain skipped. The original bitfield omission is resolved at the insertion/API level, **not yet verified byte-for-byte or field-for-field against CCC's original STABS definitions**. In particular, some reference chains report base type name `unsigned int` with a 16-byte width, which should be checked against the actual datatype aliases and metadata before asserting correct semantics. The test input's other symbol counts remain stable.

Next step: inspect representative structures containing `magic`, `attr`, `option`, compare offsets, widths, unions and total structure lengths against the CCC v14 JSON and disassembly. Audit whether `Structure.insertBitFieldAt()` shifted any neighboring fields, especially on structures containing both bitfields and ordinary fields. Keep the 3 unmapped labels separate from bitfield correctness; do not force labels outside memory without an IRX layout justification. No merge yet.

## CCC 2.x structure correctness pass and CI (2026-10-12)

The user said to continue after TESTSPU's first run with all 47 bitfields inserted. The critical distinction is that accepted calls to `Structure.insertBitFieldAt` do **not** guarantee fields stay in the correct place. Ghidra 12.1.3's `StructureDataType.replaceAtOffset` can consume existing bitfield components; `insertBitFieldAt` can shift components when a conflict occurs.

Commits on `note-working/ccc2-symbol-import`:

- `a992ada59ffbf3b6c053b0c21a4fd9e6863c5728`: before adding ordinary or bitfield structure fields, check against existing defined components using bit-accurate ranges, avoiding silent replacement/shift where already defined. After fill, audit names, sizes and normalized positions of inserted bitfields and compare modeled structure length to CCC source length. New log includes `Bitfields placed=... verifiedPositions=... narrowedStorageWindows=... structureLayoutWarnings=...`. Warnings are independent of the skipped count; **any layout warning must be investigated before merge**.
- `7fbf22d63c6c0af2587aa455a12642406dac317f`: make normalized-bit and overlap geometry package-visible static methods, deriving endian behavior from the containing structure, allowing unit tests.
- `15cfc41148b896519b7849b7918d804cd1006867`: Ghidra-backed JUnit tests for `attr`/`option` as adjacent 32-bit fields backed by a 16-byte integer and a neighboring ordinary field.
- `03104555928016d5283fe14715aec2012da242a1`: correct union handling: CCC bitfields are now inserted with Ghidra `Union.addBitField` rather than silently degrading to full-width ordinary union members. Nonzero-offset union bitfields cannot be represented correctly through that API and remain explicitly skipped. Out-of-bounds ordinary union members are skipped; union length discrepancies are logged.
- `dca178d9241d5f2beb9110a4f9b3b2f0bdfa393e`: union bitfield JUnit regression.
- `bf2a1f65683688e576934d5162edea25d8a5c06f`: distinguish unresolved ordinary members, unusable offsets (excluding deliberate static members), and source-bound overflows instead of silently omitting them.
- `7e27edda5921c728470c2b8fa11c1145b85c1081`: record CCC type-reference chain when narrowing suspiciously wide bitfield storage (e.g., `unsigned int` with a 16-byte underlying type). This still requires live input to decide whether CCC typed it incorrectly or the alias is valid; never silently force it to uint32.
- `9bd75f72450d0daee195ebb3cbeae05bd6969a15`, `a58249b4ea93ce47e765d1f9ab0efa5fec791177`: expose CCC builtin resolver to package-local tests and assert all four 128-bit classes remain supported.

CI: New temporary branch-scoped workflow `.github/workflows/ccc2-symbol-validation.yml` runs `gradle ... test --tests ghidra.emotionengine.symboltable.Ccc2BitfieldLayoutTest` against Ghidra **12.1.3**. First run, https://github.com/Masamune3210/ghidra-emotionengine-reloaded/actions/runs/38311159489, **completed successfully**. It covered the initial regression test commits through `2b056ac`, not every subsequent diagnostic change. Later push-triggered runs should be checked separately and recorded before claiming the latest code passed.

Still required before merge: a fresh TESTSPU import with the latest extension should report `verifiedPositions` and `structureLayoutWarnings`, and should show the `baseTypeChain` for suspicious 16-byte `unsigned int`. Compare representative full layouts with original CCC JSON. No direct source ELF/JSON was available for inspection in this environment, and no merge into `testing` was made.

## Latest continuation validation and audit tool (2026-10-12)

CI evidence: GitHub Actions `Validate CCC 2.x bitfield layout`, https://github.com/Masamune3210/ghidra-emotionengine-reloaded/actions/runs/38311406784, **succeeded** on Ghidra 12.1.3 at commit `a58249b4ea93ce47e765d1f9ab0efa5fec791177`. This run compiled the updated importer, JUnit test classes, and passed the targeted CCC bitfield test class (including union and 128-bit builtin regressions). Subsequent workflow revision `05b01a5fc7527f081356fdff0a94ef4d36383bf7` runs the **entire** repository JUnit suite against Ghidra 12.1.3. Verify its most recent non-cancelled run before claiming full-suite success; earlier push runs were cancelled as later commits arrived. `concurrency` now cancels superseded branch jobs; documentation and read-only script edits are excluded from the push trigger.

Added read-only Ghidra script `ghidra_scripts/AuditCccBitfieldLayouts_20261012_v1.java` at commit `649b49bcb388dca639360390e00d828964408174`. Run it in Ghidra's Script Manager against an **existing** imported program. It lists all structure and union bitfields, their normalized bit start, width, offset, underlying datatype name and width, checks for out-of-bounds and overlapping structure member spans, and calls out wide base types. Does not mutate the program or require reimport. It enumerates all Ghidra datatypes, including those not created by CCC. It has not been run in Ghidra yet.

Commit `96d46a2c1e96cf0c94c985da207e885a4faa3a04` prints up to 16 unmapped labels instead of just 2 so the *third* TESTSPU unresolved label can finally be identified, while most other categories retain two representative log messages.

Before merge: compare the script output and latest importer log on TESTSPU, especially `verifiedPositions`, `structureLayoutWarnings`, the third unmapped label, and the suspicious 16-byte `unsigned int` `baseTypeChain`. Avoid assuming that correct insertions prove all source bitfields are semantically sound. Preserve the IRX-specific `0xff1f` linker symbols unresolved until their placement can be supported by a valid memory mapping. The branch remains intentionally unmerged.

## Full Ghidra unit suite verification (2026-10-12)

**PASS:** https://github.com/Masamune3210/ghidra-emotionengine-reloaded/actions/runs/38311820380, Ghidra 12.1.3, Java 21, Gradle 8.14.4, `gradle ... test` (the full repository unit test suite). `BUILD SUCCESSFUL in 26s`; job and all steps completed successfully at commit `4180c7036a0699b8d8b5a25c896dc0c4eb85a09a`. This commit includes all importer corrections, overlap/geometry validation, the union/128-bit tests and third-unmapped-label diagnostics. Subsequent commits `06255b0e5b84822461419568b206de08d149463a` only update documentation and are intentionally excluded from CI. The read-only Ghidra script itself is not compiled by `gradle test` and still requires a real Ghidra Script Manager run.

Current merge readiness: **unit tests pass; functional structure validation on TESTSPU is still outstanding**. Before merging, inspect the post-import `Bitfields placed/verifiedPositions/structureLayoutWarnings` line and run `ghidra_scripts/AuditCccBitfieldLayouts_20261012_v1.java` on the imported program to inspect any base-type size anomalies and overlapping or shifted members. Do not reinterpret `SHN_HIPROC` unplaced symbols without validated IRX mapping evidence.

## TESTSPU supplied: legacy IOP STABS 0;-1 classification bug (2026-10-12)

The user supplied the actual 27 KiB PS2 IOP IRX `TESTSPU.bin` (MD5 `6273b36b4200397fe43be82a06ff3e36`). It has `.mdebug` and is ELF32 little-endian MIPS e_type 0xff80. Direct examination of the original `.mdebug` string content definitively shows `unsigned int:t4=r4;0;-1;` and `long unsigned int:t5=r5;0;-1;`. CCC v2.1 `classify_range()` explicitly maps `"0","-1"` to `UNQUALIFIED_128` (and latest CCC main still contains that classification). This behavior is inappropriate for these named **32-bit** IOP types. Note that `0;-1` is a documented standard GCC/STABS form for `unsigned int` and `unsigned long`, not evidence that this retail firmware used a homebrew toolchain. The importer correctly handled the JSON, but the source classifier's erroneous 128-bit width made 47 ordinary 32-bit members look like bitfields. Successful Ghidra placement was therefore not semantic validation. The prior audit returned 21 composites, 47 inserted bitfields, 0 geometry issues, and the compiler's original full-width integer aliases remained 16-byte types. One out-of-bounds `_libinfo.dummy` array required 32 bytes in a 20-byte structure because its element was spuriously 16 bytes; the original STABS `dummy:32=ar0;0;1;5,0,64;` proves that it is **two 32-bit unsigned longs**, 8 bytes at offset 0.

Source fields show a real bitfield use in `sceSifCmdHdr`: `psize:4,0,8;dsize:4,8,24`, then ordinary `daddr:4,32,32;fcode:4,64,32;opt:4,96,32`. Once the original aliases are 32 bits, only the 8-/24-bit members should remain actual bitfields.

Committed implementation on `note-working/ccc2-symbol-import`:
- `b7297b89170340ce94ffab5756866d39aee1f2b6`: `CccIopLegacyUnsignedRanges` reads the ELF input, checks Sony IOP e_type and MIPS machine, and recognizes only exact printable STABS declarations matching named `unsigned int` or `long unsigned int` of the form `tN=rN;0;-1;`; defaults to no correction when source/provenance is unavailable. Uses a streaming scan, not a large in-memory image.
- `d7e1e550ee2a92607b2f0c10ad45ac49df1aaacd`: CCC v13/v14 ONLY, resolves those specifically proven named builtin `128-bit integer` roots to `UnsignedIntegerDataType` (4-byte), preserves alias chains (`u_int`, `uint`, `u_long` etc.), and restores originally misclassified 32-bit full-width fields as ordinary members using the existing overlap/bounds guards. Genuine narrower source bitfields remain bitfields. The ordinary array field `_libinfo.dummy` should now fit; expected lower imported-bitfield count is **correct** in this case, not a regression. Adds logs for normalized roots and recovered ordinary fields.
- `16b7196a06d00c51b936089e02860451f5bb26bf`: JUnit tests for exact signed/STABS signatures, IOP-only gating, unsupported 128-bit classes and JSON v15 no-op.

Important limitation: CCC's JSON alone does not preserve the original range `0;-1`, so normalization is **never inferred from a 128-bit JSON builtin alone**, nor from PS2 architecture alone. An override JSON with no ELF input cannot prove this specific compiler artifact and is intentionally left unchanged. A source ELF override may be specified alongside an override JSON. The native CCC executable is not modified.

Verification pending as of this note: latest GitHub Actions full test workflow; a fresh TESTSPU runtime import should show `Legacy IOP unsigned types corrected=2`, a much smaller actual bitfield count (genuine `psize/dsize`), no `dummy` out-of-bounds complaint, and no newly introduced structure layout warnings. Do not edit the existing polluted database in place: use a fresh database import. Check Ghidra datatype `unsigned int` and `long unsigned int` both size 4.

## Corrected provenance: retail Sony BIOS, GNU STABS (2026-10-12)

**Historical attribution correction:** The uploaded `TESTSPU.bin` is a retail PS2 ROM0 component, not homebrew. Its ELF symbol table contains `gcc2_compiled.` and `__gnu_compiled_c`; its .mdebug section names `testspu.c`, and a generated stub-assembly path appears as `/tmp/ccpJ4NFg_ilb_stub.s`. These are GCC/GNU C build markers, but do not prove the precise compiler version or Sony's build configuration. Do not label the module "old homebrew" merely because CCC v2.1 attaches that remark to its `0;-1` special case.

The original GNU/GDB STABS documentation explicitly describes `0;-1` as a *traditional way to encode unsigned int / unsigned long* and illustrates `unsigned int:t4=r1;0;-1;`. This is an ordinary historical compiler/debug-format convention, **not a 128-bit size declaration**. See:
- https://sourceware.org/insight/onlinedocs/stabs_5.html
- https://gnu.googlesource.com/binutils-gdb/+/d01e823438c7dc264d6885fbbfeace4d8955dcb7/gdb/doc/stabs.texinfo

GNU Binutils also handles the `0;-1` case as a target-dependent unsigned integer, generally using 4 bytes (for old targets). CCC's `UNQUALIFIED_128` default here is the importer-accuracy issue. The current fix is conservative, requiring an IOP ELF and concrete matching STABS declarations instead of globally remapping all CCC `128-bit integer` types.

Validation of the uploaded ELF bytes (MD5 `6273b36b4200397fe43be82a06ff3e36`): both `unsigned int:t4=r4;0;-1;` and `long unsigned int:t5=r5;0;-1;` are exact NUL-delimited strings; the new helper's matching conditions hold. `_libinfo.dummy` really is a two-element array of 32-bit unsigned longs, within the declared 20-byte structure; `sceSifCmdHdr` has two genuinely narrow bitfields, `psize` (8 bits) and `dsize` (24 bits), and the three following 32-bit members should be normal fields.

Latest CI after the correction: `https://github.com/Masamune3210/ghidra-emotionengine-reloaded/actions/runs/38322664395`, Ghidra 12.1.3 full `gradle test`, **PASS** (`BUILD SUCCESSFUL in 24s`). This validates compilation and synthetic source-signature tests but not Ghidra behavior on the actual ELF.

At commit `71ba472255a10edca45f022b1d8df53b4b1317df`, added **read-only** `ghidra_scripts/AuditTestSpuLegacyUnsigned_20261012_v1.java`. It checks the four canonical 32-bit integer typedefs, `_libinfo.dummy` and associated offsets, `_libcaller.magic`, `EventFlagParam`, and the two legitimate `sceSifCmdHdr` bitfields. Run it on a **fresh Ghidra import** using the latest built extension. No full runtime import with the source-aware correction has yet been observed.

## Corrected importer runtime verification and audit script fix (2026-10-12)

User independently verified the source-aware correction on a fresh TESTSPU Ghidra 12.1.3 import:

```text
CCC 2.x> Legacy IOP STABS unsigned 0;-1 declarations detected: [unsigned int, long unsigned int]
CCC 2.x> Skip reason: unmapped labels = 3
CCC 2.x> Legacy IOP unsigned types corrected=2 false bitfields restored as ordinary fields=45
CCC 2.x> Bitfields placed=2 verifiedPositions=2 narrowedStorageWindows=0 structureLayoutWarnings=0
CCC 2.x> Imported types=81 functions=9 globals=16 labels=2 skipped=3 (JSON v14)
```

The only skipped symbols are `end` and `_end` at decimal 6312 (`0x18a8`), and `_gp` at decimal 38864 (`0x97d0`), matching the ELF loader's unmapped linker-value warnings. No normal structure field skips remain. This is conclusive *runtime* verification of the corrected 45 ordinary fields and 2 successfully placed narrow bitfields, subject to direct structure member audit.

The first TESTSPU-specific script **failed to compile in Ghidra Script Manager**: `datatype()` calls `monitor.checkCanceled()` without declaring `CancelledException`; its callers `typeWidth()` and `structure()` also need a throws declaration. The subsequent `class not found` was only a cascade from failed Java compilation. Commit `381f12899c4a53f095ec245ea538894862f012c0` creates fixed `ghidra_scripts/AuditTestSpuLegacyUnsigned_20261012_v2.java` with correct checked-exception propagation and matching public class name; commit `69c67c8116deeea0210662ee58ae97e890a96b36` deletes the broken v1 from the branch. Do not suggest running the old v1 again.

Commit `2eace1e77aad04061ae0b34eca6f99e024bc3c09` adds `compileCccAuditScripts` (JavaCompile) to Gradle and makes **both `test` and `buildExtension` depend on it**. This compiles v2 and the general CCC bitfield audit before packaging, catching script Java errors that normal extension compilation used to miss. **Verified:** Ghidra 12.1.3 GitHub Actions run [38324019087](https://github.com/Masamune3210/ghidra-emotionengine-reloaded/actions/runs/38324019087) completed successfully after the change; logs show `> Task :compileCccAuditScripts` followed by `BUILD SUCCESSFUL in 34s`. Both audit scripts now compile against the Ghidra SDK, and full `gradle test` also passes. This is compile-time validation; v2 execution in the user's Script Manager is still unverified.

Next: use the v2 script against the already corrected TESTSPU database, or simply compile/install the extension and run v2. Its expected baseline is 4-byte unsigned aliases; `_libinfo.dummy` 8-byte array of 2 x uint32; `sceSifCmdHdr` with `psize` 8-bit and `dsize` 24-bit as the only bitfields, subsequent members ordinary.

## TESTSPU audit: missing typedef names despite correct layouts (2026-10-12)

User ran the corrected `AuditTestSpuLegacyUnsigned_20261012_v2.java` on the freshly imported TESTSPU database. Result: `passed=23 failed=2`. Every verified structure length, field position, array length, base type width, and both genuine 8/24-bit bitfields passed. The **only failures** were `u_int expected=4 actual=MISSING` and `u_long expected=4 actual=MISSING`. The uploaded ELF's original STABS contains `u_int:t44=4`, `u_long:t45=5`, and `uint:t48=4` in addition to the canonical `unsigned int:t4=r4;0;-1;` and `long unsigned int:t5=r5;0;-1;`. Earlier CCC reference traces show `type_name[36](u_int)` resolving through `unsigned int`.

**Root cause:** `Ccc2SymbolImporter.resolveType()` suppressed a new named `TypedefDataType` whenever `resolveNode()` already returned a `TypedefDataType`, so CCC named references such as `u_int` and `u_long` silently collapsed to their already-created canonical aliases. This is an alias registration bug, not a structure layout or source-STABS failure.

Commit `56f4ecc7d3850ed9721201533c9b36c2015b0e1e` adds `preserveNamedAlias()`, creating distinct typedefs for named `type_name` references even when the destination is itself a typedef or composite; it skips duplicate names and honors `Import Typedefs` being off. Direct struct/union/enum definitions still stay as native datatypes. Commit `ea5bee7a9ddfd2f6103473f4fb678fe7560de767` introduced JUnit tests for `u_int`, `uint`, `u_long`, multi-hop bases, composite aliases and standalone datatype-manager registration. GitHub Actions run `38324745214` compiled the code but **failed the standalone-manager test at line 50**, where constructing `StandAloneDataTypeManager` without an initialized Ghidra application throws `ghidra.util.exception.AssertException`; this does not establish an importer failure. Commit `25e88db68b75c721f7b2221f69a46672aaa79c45` replaces the unsuitable headless-manager test with standalone alias-chain assertions and retains all other tests. Full CI **passed** after this correction: [Ghidra 12.1.3 run 38324942721](https://github.com/Masamune3210/ghidra-emotionengine-reloaded/actions/runs/38324942721), `compileCccAuditScripts` executed and `BUILD SUCCESSFUL in 27s` for the complete `gradle test`. Standalone alias-chain assertions passed. On-database registration of `u_int` and `u_long` remains to be verified with a fresh TESTSPU import. **The alias fix is not yet runtime-verified.**

Next check after CI: reimport TESTSPU into a new Ghidra program with `Import Typedefs` on (default) and rerun `AuditTestSpuLegacyUnsigned_20261012_v2.java`. Expected 25 pass/0 fail if the alias import fix works without disturbing the already-correct layouts. The count of `Imported types` may stay unchanged, since the original code counted registrations of reused references as imports. The three unmapped linker sentinels are independent.

## Post-alias-fix TESTSPU import summary (2026-10-12)

After the nested typedef preservation fix (`56f4ecc7d3850ed9721201533c9b36c2015b0e1e`, with full Ghidra 12.1.3 CI passing at `38324942721`), the user posted a fresh CCC v14 analysis log. Counts are identical to the previously corrected import: two source-proven `0;-1` unsigned roots normalized, 45 formerly false bitfields restored to ordinary members, two genuine bitfields inserted and position-verified, no storage narrowing or structure warnings, 81 imported datatype entries, 9 functions, 16 globals, 2 labels, and three unmapped linker labels (`end`, `_end`, `_gp`). This demonstrates **no visible regression in structure import** after the alias code change.

The summary does **not** count distinct registered typedef names. Retaining `u_int` and `u_long` still requires rerunning `ghidra_scripts/AuditTestSpuLegacyUnsigned_20261012_v2.java` against this newest import. The earlier pre-fix audit had 23 passed / 2 failed, with only these two alias names missing. Expected (not yet observed) result after the fix: 25 passed / 0 failed. No additional changes were justified by this log alone.
