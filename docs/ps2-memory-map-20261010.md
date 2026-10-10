# PS2 EE memory-map correction (2026-10-10)

## Why this branch exists

A Ghidra 12.1.3 import of Dark Cloud 2 (SCUS_972.13) reported a language-defined ROM0 memory-block overlap. The original `r5900.pspec` reserved 0x04000000 bytes (64 MiB) at 0x1FC00000, overlapping the uncached EE RAM alias beginning at 0x20000000. The ELF and its symbol table imported; the complaint was about the processor-specification default block.

## Decisions and changes

- `data/languages/r5900.pspec`: set ROM0 to 0x00400000 (4 MiB), IOP RAM to 0x00200000 (2 MiB), and correct the address-range commentary.
- `EE_ElfExtension.createMirrorBlocks`: make BIOS aliases 0x00400000 each. Java's old literal `04000000` is octal and meant 1 MiB, not 4 MiB.
- Map `0x20000000..0x21FFFFFF` to `0x00000000..0x01FFFFFF` (32 MiB).
- Map `0x30100000..0x31FFFFFF` to `0x00100000..0x01FFFFFF` (31 MiB); the original mapped that alias to the wrong physical offset.
- Keep hardware, VU, GS, scratchpad, and the ELF-loaded game blocks unchanged.

Sources: https://www.psdevwiki.com/ps2/Memory_Map ; https://github.com/PCSX2/pcsx2/blob/master/pcsx2/Memory.cpp

## State and verification

Source modifications are committed on this branch. Address/length arithmetic and the Java octal-literal issue were inspected. A Ghidra/Gradle build and fresh game import have **not** yet been run, so runtime behavior is not verified. These changes affect future imports; they do **not** retroactively resize or remap blocks in an existing Ghidra program.

## Next step

Run `gradle -PGHIDRA_INSTALL_DIR=<Ghidra installation directory> test` (and `buildExtension`), install the extension, and import SCUS_972.13 into a fresh program. Confirm no ROM0 overlap, BIOS aliases are both 4 MiB, accelerated RAM points to 0x00100000, and imported executable instructions disassemble normally. If retaining analysis in the existing database is important, repair its memory blocks separately with a non-destructive migration plan.
