# Repository correctness audit — 2026-10-10

## Purpose, base, and branch

Audit the complete `ghidra-emotionengine-reloaded` repository, including ELF/memory/relocations, analyzers, STABS, R5900 SLEIGH and compiler metadata, DVP, scripts, and build/CI. `testing` was created from current `main` (fcc5deac45d8f5c27c632bfe0db928630939676e), then fast-forwarded to include all commits from `audit/repository-correctness-20261010`, which already included `fix/ps2-memory-map-20261010`. The full fixes and analysis are in `testing`; `main` remains unchanged. The earlier draft PR is superseded by the direct testing branch.

## Confirmed fixes

1. EE PSPEC: ROM0 4 MiB instead of 64 MiB; IOP RAM 2 MiB instead of 32 MiB. Correct range documentation.
2. ELF extension: 4 MiB cached/uncached BIOS aliases instead of Java octal 1 MiB; EE uncached alias 32 MiB, accelerated alias 31 MiB backed by physical 0x00100000. Skip EE mirror creation for R3000/IOP ELF imports.
3. Synthetic heap: treat section's limit as exclusive and skip invalid/empty spans.
4. MIPS constant reference analyzer: recognize the numbered `_mips_gp0_value` symbol observed in SCUS_972.13.
5. MIPS relocations: avoid null-symbol dereference in GOT_PAGE conversion; remove spurious global-pointer requirement from ordinary R_MIPS_HI16 (GP-dependent `_gp_disp` resolution checks GP at the deferred pair).
6. STABS built-ins: correct reversed signed/unsigned 16-bit types and map FLOAT_64 to a double, not a 64-bit integer.
7. STABS addresses: treat 32-bit function/global/comment locations as unsigned instead of rejecting addresses >= 0x80000000.
8. STABS stdump: redirect stderr while reading stdout to avoid subprocess pipe deadlock, record nonzero exit status, handle ANSI color codes and close JSON streams.
9. PCSX2 savestate importer: reject invalid/missing entries, enforce buffer bounds, avoid MMIO/mapped/overlay writes, and close streams plus caller-owned filesystem.
10. MMIO label script: retain user/analysis/ELF symbols instead of deleting them; avoid duplicating already imported labels.
11. SYM importer: accept hexadecimal addresses with or without `0x`/`0X` prefixes.
12. DVP export: retain VMA gaps in binary output, fail on overlapping/short chunks, and reject invalid VU addresses from the block totals.
13. Follow-up from live SCUS_972.13 memory-map verification: byte-mapped EE RAM aliases were incorrectly read-only. Set `Write` on both RAM mirror blocks so decompiler mutability reflects writable guest RAM. Keep both BIOS aliases read-only.

## Reviewed without behavior changes

- R5900 SLEIGH instruction groups, ABI/compiler specification, default register/MMIO descriptions, language/opinion definitions, patterns, and build metadata.
- R5900 pre-analyzer and constant propagation; relocation types/context/handler; STABS AST/parser/importer; DVP overlay parser/symbol synchronizer; scripts and CI/packaging.
- Existing TODOs around COP1 exact floating-point behavior, MIPS multi-GP relocation modeling, and disabled DVP overlay table importing remain unresolved. Do not treat those areas as fully verified without representative binaries/traces.

## Verification

- Source-level checks of 17 key corrections passed on the audit branch after patching. These are **static checks, not compilation or live Ghidra integration tests**.
- A draft PR was opened to request the repository's Ghidra 12.x workflow matrix. GitHub's Actions API reported zero workflow runs for this repository during the audit, so no compile/test success is claimed.
- No local Ghidra installation or network Git clone was available in the execution environment. The SCUS_972.13 database was **not** modified by repository changes. Its fresh import confirmed the expected mapping ranges and the fixed heap end at 0x01F64DFF. The two existing RAM-alias block permissions still require manual correction in the open Ghidra database, or another fresh import using the updated extension.

## Next steps

1. Run `gradle -PGHIDRA_INSTALL_DIR=<installed Ghidra root> test` and `gradle -PGHIDRA_INSTALL_DIR=<installed Ghidra root> buildExtension` (each terminal command on a single line), or enable GitHub Actions and inspect the PR test matrix.
2. Fresh-import SCUS_972.13 and another PS2 ELF; inspect code instructions, heap bounds, aliases, recovered GP, symbol and STABS declarations.
3. Load a PCSX2 savestate and exercise MMIO labels/.sym and DVP export on real samples, including noncontiguous and malformed blocks.
4. Follow up separately on COP1 numerical/p-code fidelity, full relocation semantics, and the disabled DVP importer. Preserve conservative unresolved behavior until measured.

## Testing branch handoff

- Branch: `testing`; includes both the memory-map fix and repository audit changes. No PR or merge to `main` is needed to access these changes.
- Current state: committed, with static source verification only; no Gradle/Ghidra integration run.
- Next step: compile extension against Ghidra 12.1.3 and fresh-import SCUS_972.13, then investigate remaining COP1/relocation/DVP concerns.

## Follow-up: live memory-map validation

- Verified user-reported ranges: 4 MiB ROM0; 2 MiB IOP; 32 MiB uncached RAM; 31 MiB accelerated uncached alias backed by 0x00100000; 4 MiB each for BIOS aliases; synthetic heap ends at 0x01F64DFF.
- The memory map revealed `Write=false` for both RAM aliases; now fixed in the loader on `testing`.
- For a database imported before this last change, change both RAM alias blocks' Write permission in Window > Memory Map. A rebuild/reimport is not necessary solely to adjust permissions.
- Build and full decompiler/integration verification remain outstanding.
