# IOP IRX loader work (2026-10-12)

## Why this branch exists

SECRMAN imported through the generic ELF loader as MIPS64 Release 6 even though it is PS2 IOP (R3000A-derived) code. Existing R5900 support targets Emotion Engine ELFs, not IOP IRX/SRX. This branch starts from testing (abe68307bd679fab1b94471ec513884b0dd8d590), preserving its EE/IOP memory-map separation.

## Decisions and implementation

- New Ghidra ELF loader accepts only little-endian ELF32 with machine 8/10 and Sony ET_IRX (0xff80), ET_IRX2 (0xff81), or ET_ERX2 (0xff91). Supplies a preferred MIPS:LE:32:default load spec. Ordinary MIPS/EE ELFs continue through the previous loader.
- Delegates bytes, ELF sections, and relocation records to Ghidra's native ELF loader rather than duplicating an ELF loader. Performs a conservative post-load IOP metadata pass.
- Parses .iopmod fixed fields and its bounded NUL-terminated module name from original section bytes. Persists module fields under Program Options > PS2 IOP IRX, adds datatypes, and adds entry/GP labels only for mapped addresses.
- Detects validated PS2SDK-style import and export tables in loaded .text/.rodata/.data, adding table/ordinal labels and limited references to mapped executable exports. Does not invent function names for ordinal-only imports or clear existing instructions.
- Format parsers are pure Java to permit unit testing (malformed ELF, module headers, import stubs, export terminators).

## Important limitations

- The stock Ghidra MIPS 32-bit language is a fallback for IOP instructions, *not* a dedicated R3000A language. Validate actual IOP opcode decoding on firmware modules.
- Sony ET_IRX is not ELF ET_REL; Ghidra's underlying relocation execution is not established as correct. This change warns when .rel* sections exist and intentionally does not claim a complete IRX runtime relocator, GP rebasing, or live LOADCORE linking.
- Import-table parsing is conservative and currently recognizes unpatched jr-ra/addiu (or ori) stubs. Already patched imports need additional heuristics.
- Older Ghidra databases do not change language in place. Reimport SECRMAN into a fresh program, explicitly selecting PlayStation 2 IOP IRX (ELF) and verifying MIPS:LE:32:default.

## Verification status and next step

Code and JUnit source committed. No Ghidra installation is available in the execution environment, so Gradle/Ghidra API compilation and fresh-import runtime behavior have **not** been verified. Run gradle test and buildExtension on Ghidra 12.1.x and import SECRMAN fresh. Report compile diagnostics, import log, language ID, .iopmod module name, import/export counts and relocation statuses. On verification, implement ET_IRX-specific relocation semantics guided by a representative original IRX ELF and compare original .rel.text against the loaded memory. Avoid importing as R5900 or retaining the existing R6 database as evidence of correct decoding.

Sources: PS2SDK iop/kernel/include/irx.h (import/export layouts and magic); original bigianb ghidra-emotionengine IopModSection (module header fields).
