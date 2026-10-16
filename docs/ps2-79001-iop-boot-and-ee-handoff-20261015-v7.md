# PS2 IOP boot and MagicGate handoff, 2026-10-15 v7

## Already executed and verified
- Ghidra SCPH-79001 EE combined boot: RESET, ROMDIR, KERNEL, EELOAD, plus RDRAM imported from original BIOS; 65 verified words; 535 functions after script; script reported 10 created, 11 renamed, 143 labels, 172 comments, 7 bookmarks; existing markups preserved.
- Ghidra SCPH-79001 IOP combined boot: 5 verified ROM sections, 72 exact words, 105 ROMDIR entries, 29 default and 24 alternate config rows; script applied 9 function renames, 86 labels, 95 comments, 2 data types, and preserved preexisting ROMDIR markup once. It created no new function boundaries and modified no executable bytes. IOP GZF and TXT/TSV/DOT reports are already supplied. Do not request the user rerun either script.
- User confirmed TBIN is PS1 backward compatibility. Retail PS2 reset follows IOPBOOT, where the observed call passes boot selector 0: try IOPBTCON0, then fallback to IOPBTCONF (the ROMDIR has no IOPBTCON0). A later IOP reset may select a different config.
- Cold-boot IOPBTCONF initializes SECRMAN as module 28 of 29, but this does **not** prove MagicGate authentication. IOPBTCON2 initializes SECRMAN as module 22 of 24 followed by SIO2MAN and MCMAN.
- The objective remains MagicGate behavior and locating PCSX2 divergence, not isolated general DECKARD work.

## Newly verified original firmware discovery: exported ordinal zero may legitimately be zero

Inspected the original user-provided 4 MiB SCPH-79001 ROM at SHA-256 `e76d9c8f4019041fb17f41fff25d57d608c1a3f205c99bda9eb47402c43e8c93`, parsing its ROMDIR and ELF section/relocation tables (not merely scanning arbitrary bytes).

- 49 IOP export-table signatures in executable ELF text sections. **21** begin with a zero-valued first function pointer that is covered by a source `R_MIPS_32` relocation at that exact cell; each has a subsequent aligned nonzero function pointer. It is a legitimate *relocatable address of image offset zero*, not an empty table.
- Affected ROM module/export library pairs: LOADCORE/loadcore, EXCEPMAN/excepman, INTRMANP/intrman, INTRMANI/intrman, SSBUSC/ssbusc, TIMEMANP/timrman, TIMEMANI/timrman, SYSCLIB/sysclib, HEAPLIB/heaplib, VBLANK/vblank, IOMAN/ioman, MODLOAD/modload, STDIO/stdio, SIFMAN/sifman, EESYNC/eesync, NCDVDMAN/cdvdman, CDVDMAN/cdvdman, CDVDFSV/cdvdfsv, XCDVDMAN/cdvdman, XCDVDFSV/cdvdfsv, XRMMAN2/rmman2.
- Before this fix, `IopIrxFormat.readLibrary()` returned null on the first zero, silently missing these entire export tables (unless a nonzero relocation base had already resolved the first word). This could prevent automatic loadcore and other exports from being labeled, compromising later import/export dependency reconstruction.
- LOADCORE is genuine Sony ET_IRX (`0xFF80`), MIPS little endian, ELF image entry `0x0`, `.iopmod` library `Module_Manager` v1.01. ELF ROM offset 0x020070, size 0x257D; `.text` at ELF offset 0xA0 size 0x1C30; export table `loadcore` at **module .text+0x1B60**, file offset 0x1C00; ordinal 0 at .text+0x1B74 = zero with R_MIPS_32 relocation; ordinal 1 = .text+0x05DC.
- SYSMEM is Sony ET_IRX (`0xFF80`) module `System_Memory_Manager` v1.01; entry .text+0x60, GP ELF value 0x8C70; ROM offset 0x01EE50 size 0x1211; export library `sysmem` at .text+0x0; ordinal 0 = .text+0x60. It does not have the exceptional first zero.
- Ghidra extension fix: `IopIrxFormat.readLibrary(bytes,position,boolean)` only allows first-zero export *when explicitly authorized* by caller. `IopIrxElfLoader` authorizes it **only if the Ghidra relocation table contains an R_MIPS_32 entry at that exact first export cell in .text**. It also rejects empty tables and unaligned next entries; imports retain strict terminator semantics. Regression tests added. No speculative reinterpretation of arbitrary zeros.
- The loader still does not invent resolved cross-module addresses. Ghidra relocation results and GP context must be checked for each import. Existing Ghidra programs are not automatically revised by a Java loader change.

## Directly applicable Ghidra metadata for next two IRX imports

```text
SYSMEM ELF (.text-relative)
0x00000000 -> sysmem_ExportLibrary
0x00000060 -> SysmemModuleEntry
0x000000D8 -> SysmemInitializeHeapState [tentative name, confirm code before applying]

LOADCORE ELF (.text-relative)
0x00000000 -> LoadcoreModuleEntry
0x00001B60 -> loadcore_ExportLibrary
0x00001B74 -> LoadcoreExportOrdinal0 [0 + R_MIPS_32 relocation]
0x00001BF0 -> sysmem_ImportLibrary
```

The first two function entrypoints are verified from `.iopmod` and ELF headers; export/import labels from table magic+name and section location. `SysmemInitializeHeapState` is a prospective label, not applied by a script: function semantics need decompilation. All addresses above are relative to module code and may be rebased by Ghidra. **Do not claim they are physical IOP RAM run addresses**. No function argument/return types established yet.

## Next action

Rebuild and reinstall the Java extension, then import the existing extracted **SYSMEM** and **LOADCORE** ROM0 IRX files individually using the PlayStation 2 IOP IRX loader, not raw binary import. Let auto-analysis complete; return each `.gzf` plus any relocation messages. Then recover true first-two-module startup semantics, the LOADCORE relocation and linking pipeline, and the point at which later configured modules including SECRMAN are initialized. The already verified IOP combined boot program should be preserved without reimporting.

A source-level fix is committed but not tested in the user's Ghidra runtime. Pure parser regression tests were added; complete extension build is not available within the assistant environment.
