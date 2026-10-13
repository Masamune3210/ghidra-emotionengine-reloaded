# CCC 2.x and IOP IRX integration handoff

## Scope
Merge the completed `note-working/ccc2-symbol-import` work into `testing`. Includes CCC 2.x JSON 13-15 symbol import, accurate nested typedefs and STABS layouts, Sony IOP IRX loading and metadata, verified linker boundary recovery and GP context for modules with or without `_gp`, plus CI/unit tests and read-only Ghidra audit scripts.

## Verified
- Ghidra 12.1.3 full Gradle test suite and audit-script compilation passed: https://github.com/Masamune3210/ghidra-emotionengine-reloaded/actions/runs/38328524736 .
- Retail ROM0 TESTSPU: 25/25 STABS datatype checks, 13/13 linker audit checks, 8/8 reserved ELF symbols verified, 3/3 linker pseudo-label values retained, CCC 0 skips.
- Retail ROM0 SECRMAN (stripped): GP value 0xB2E0 at verified module entry 0x18; module metadata audit v3 3/3 PASS; 487 relocation records = 377 applied + 110 partial, no failure/unsupported; 5 imports, 1 export. After analysis: 2,804 instructions and 70 functions. CCC 0 skips, as expected with no included type/function symbols.

## Decisions and limits
- Preserve genuine missing/ambiguous datatype info. Do not invent mapped RAM for `end`, `_end` or `_gp`.
- Synthetic Ghidra `%got.text`/GP allocation is distinct from the firmware's source GP, and nonzero PARTIAL relocation statuses alone are not a demonstrated defect.
- Generic ELF warnings for processor-reserved symbol section indices are expected and are repaired as source-verified metadata after ELF load.
- No outstanding observed loader/importer errors in these two test modules. Broader compatibility is not claimed.

## Next steps
Integrate into `testing` by fast-forward if it remains an ancestor, verify `testing` matches the integrated branch, then use these two programs as regression fixtures for future loader changes. The branch handoff with detailed historical findings is `docs/ccc2-symbol-import-handoff-20261012.md`.
