# IOP IRX loader work (2026-10-12)

## Why this branch exists

SECRMAN imported through the generic ELF loader as MIPS64 Release 6 even though it is PS2 IOP (R3000A-derived) code. Existing R5900 support targets Emotion Engine ELFs, not IOP IRX/SRX. This branch starts from testing (abe68307bd679fab1b94471ec513884b0dd8d590), preserving its EE/IOP memory-map separation.

## Decisions and implementation

- New Ghidra ELF loader accepts only little-endian ELF32 with machine 8/10 and Sony ET_IRX (0xff80), ET_IRX2 (0xff81), or ET_ERX2 (0xff91). Supplies a preferred MIPS:LE:32:default load spec. Ordinary MIPS/EE ELFs continue through the previous loader.
- Delegates bytes, ELF sections, and relocation records to Ghidra's native ELF loader rather than duplicating an ELF loader. Uses the specialized loader tier for IRX-only automatic selection and preserves the standard ELF executable-format identity for downstream analyzers. Performs a conservative post-load IOP metadata pass.
- Parses .iopmod fixed fields and its bounded NUL-terminated module name from original section bytes. Persists module fields under Program Options > PS2 IOP IRX, adds datatypes, and adds entry/GP labels only for mapped addresses.
- Detects validated PS2SDK-style import and export tables in loaded .text/.rodata/.data, adding table/ordinal labels and limited references to mapped executable exports. Does not invent function names for ordinal-only imports or clear existing instructions.
- Format parsers are pure Java to permit unit testing (malformed ELF, module headers, import stubs, export terminators).

## Important limitations

- The stock Ghidra MIPS 32-bit language is a fallback for IOP instructions, *not* a dedicated R3000A language. Validate actual IOP opcode decoding on firmware modules.
- Sony ET_IRX is not ELF ET_REL; Ghidra's underlying relocation execution is not established as correct. This change stores relocation counts by status and warns when .rel* sections exist. It intentionally does not claim a complete IRX runtime relocator, GP rebasing, or live LOADCORE linking.
- Import-table parsing is conservative and currently recognizes unpatched jr-ra/addiu (or ori) stubs. Already patched imports need additional heuristics.
- Older Ghidra databases do not change language in place. Reimport SECRMAN into a fresh program, explicitly selecting PlayStation 2 IOP IRX (ELF) and verifying MIPS:LE:32:default.

## Verification status and next step

- User build `gradle buildExtension` on 2026-10-12 reached `compileJava` and failed on unchecked `ghidra.app.util.bin.format.elf.ElfException` from `new ElfHeader(provider, null)`. Four deprecation warnings originated from the legacy integer-based plate-comment API. Follow-up commit 9d38e803 catches `ElfException` alongside `IOException` and updates to `CommentType.PLATE` with modern `Listing` overloads. This follow-up is source-verified; a successful repeat Gradle build is still pending.
Code and JUnit source committed. No Ghidra installation is available in the execution environment, and a Git clone could not resolve github.com from the container; the connected GitHub integration was used to commit the source. Gradle/Ghidra API compilation and fresh-import runtime behavior have **not** been verified. Run gradle test and buildExtension on Ghidra 12.1.x and import SECRMAN fresh. Report compile diagnostics, import log, language ID, .iopmod module name, import/export counts and relocation statuses (Program Options > PS2 IOP IRX). On verification, implement ET_IRX-specific relocation semantics guided by a representative original IRX ELF and compare original .rel.text against the loaded memory. Avoid importing as R5900 or retaining the existing R6 database as evidence of correct decoding.

Sources: PS2SDK iop/kernel/include/irx.h (import/export layouts and magic); original bigianb ghidra-emotionengine IopModSection (module header fields).

## TESTSPU.bin STABS failure follow-up (2026-10-12)

- On Ghidra 12.1.3, initial auto-analysis of TESTSPU.bin stopped in `StdumpParser.NodeDeserializer.readBuiltInClass` with `JsonParseException: Bad builtin class`. This was an uncaught exception in the STABS analyzer; it does not itself establish an IOP loader failure.
- Confirmed compatibility gap in supported stdump v1.2.1 source (`chaoticgd/ccc` tag `v1.2.1`, `ccc/stabs.cpp`): `BuiltInClass::UNKNOWN_PROBABLY_ARRAY` serializes to the literal class string `"error"`. The Java AST defined this enum and fallback already, but `StdumpParser` did not recognize the string.
- Added explicit `"error"` mapping to the unresolved built-in enum, preserving the existing conservative `undefined1` fallback and logging the name and `size_bits` when used. No arbitrary structural or type inference is performed.
- Other unrecognized class values now identify their exact value in diagnostics. The importer catches Gson `JsonParseException` and logs the cause rather than throwing an analyzer task exception.
- Added JUnit tests for `"error"`, established builtin classes, and an unrecognized class value. The actual TESTSPU stdump JSON is not available, so it is **not yet confirmed** that `"error"` was its offending class; if not, the next log should expose the exact value.
- Verification: upstream producer/parser source comparison and committed tests. Ghidra 12.1.3 build and rerun of TESTSPU are still pending.

## Mutually exclusive EE/IOP recognition (2026-10-14)

- Fixed incorrect Sony e_type classification: `0xff80` and `0xff81` are IOP relocatables, while `0xff90` and `0xff91` are EE relocatables. In particular, `0xff91` must **never** be recognized by the IOP IRX loader.
- The IOP predicate now rejects R5900 machine bits (`(e_flags & 0x00ff0000) == 0x00920000`) even when paired with an IOP e_type. Contradictory headers are not trusted as IOP.
- The EE `r5900.opinion` secondary mask now requires the R5900 machine variant (`0x00920000`) in addition to the previously required MIPS-III/ABI bits. Without the 5900 marker, generic MIPS ELF files cannot be selected as R5900 by this opinion.
- Regression tests cover both valid IOP types, exclusion of both EE relocatable types, contradictory R5900 flags, and unrelated MIPS machine variants.
- Scope: these rules govern specialized EE/IOP recognition; Ghidra's independent generic ELF loader can still list its own candidate. Existing Ghidra programs are not migrated by changing import rules. Runtime Ghidra Batch Import and Gradle tests still need verification against the rebuilt extension.
