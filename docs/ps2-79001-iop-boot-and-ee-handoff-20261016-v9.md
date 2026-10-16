# PS2 IOP boot and MagicGate handoff, 2026-10-16 v9

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

## 2026-10-15 v8: recovered existing SYSMEM/LOADCORE Ghidra metadata

The user supplied their **existing**, already analyzed Ghidra `SYSMEM.bin.gzf` and `LOADCORE.bin.gzf` exported from SCPH-39001. The original SCPH-79001 extracted IRX SHA-256 fingerprints **exactly equal** those in the user-provided SCPH-39001 database properties:

- SYSMEM: `1b03e6ffd2042c2545cf1a78ab937b6b57ccda037783e7ad52467bb9f5556054`; existing 12 functions, 16 recognized export ordinals.
- LOADCORE: `b7eef224d6473362d49f9e890d89c3bbeb0d243c56f6961bdb4e772ba5b1632b`; existing 34 functions, sysmem imports ordinal 4, 5, 6, but no loadcore export labels in the archive (old loader rejected first zero entry).
- The difference in Ghidra's `# of Bytes` versus original ELF disk length is **not** a difference between firmware module payloads. Do not ask to recompare, reimport or re-analyze these files.

Directly verified from original ELF .text and .rel.text:

```text
SYSMEM:
  export header 0x0000, 16 entries, terminator 0x0054
  ordinal 3 -> 0x0460 GetSysmemInternalData
  ordinal 4 -> 0x02EC AllocSysMemory
  ordinal 5 -> 0x033C FreeSysMemory
  ordinal 6 -> 0x0204 QueryMemSize
  ordinal 7 -> 0x0230 QueryMaxFreeMemSize
  ordinal 8 -> 0x0294 QueryTotalFreeMemSize
  ordinal 9 -> 0x03A4 QueryBlockTopAddress
  ordinal 10 -> 0x040C QueryBlockSize
  ordinal 14 -> 0x0B90 Kprintf
  ordinal 15 -> 0x0BDC KprintfSet
  .bss state 0x0C80, pointer returned by GetSysmemInternalData

LOADCORE:
  module entry: 0x0000, bootstrap body 0x0030
  loadcore export header 0x1B60, 25 ordinals; terminator at 0x1BD8
  ordinal 0 slot 0x1B74 -> 0x0000, R_MIPS_32 relocation (not terminator)
  ordinal 3 -> 0x0E04 GetLoadcoreInternalData
  ordinal 4 -> 0x1910 FlushIcache
  ordinal 5 -> 0x1A14 FlushDcache
  ordinal 6 -> 0x0898 RegisterLibraryEntries
  ordinal 7 -> 0x0AB8 ReleaseLibraryEntries
  ordinal 8 -> 0x0C00 LinkLibraryEntries
  ordinal 9 -> 0x0CBC UnLinkLibraryEntries
  ordinal 10 -> 0x0A58 RegisterNonAutoLinkEntries
  ordinal 11 -> 0x0B94 QueryLibraryEntryTable
  ordinal 12 -> 0x0640 QueryBootMode
  ordinal 13 -> 0x05E4 RegisterBootMode
  ordinal 14 -> 0x0E14 LockLibraryClient
  ordinal 15 -> 0x0E28 UnLockLibraryClient
  ordinal 16 -> 0x0740 RegisterModule
  ordinal 17 -> 0x07BC ReleaseModule
  ordinal 20 -> 0x069C AddRebootNotifyHandler
  ordinal 21 -> 0x1B18 SetCacheCtrl
  ordinal 22 -> 0x1260 ProbeExecutableObject
  ordinal 23 -> 0x1450 LoadExecutableObject
  ordinal 24 -> 0x0828 SearchModuleCBByAddr
  sysmem import table: 0x1BF0
  0x1C04 sysmem ord4 AllocSysMemory -> SYSMEM .text+0x02EC
  0x1C0C sysmem ord5 FreeSysMemory -> SYSMEM .text+0x033C
  0x1C14 sysmem ord6 QueryMemSize -> SYSMEM .text+0x0204
```

The semantic mapping is corroborated with PS2SDK `iop/system/sysmem/include/sysmem.h` and `iop/system/loadcore/include/loadcore.h` declared ordinals; it is not inferred from mere function similarity. Entry offsets and relocation evidence independently match original ROM ELF sections. Ordinals without independently supported names retain ordinal-based labels. These are **module-relative addresses**; they do not establish actual IOP RAM load addresses or that SECRMAN authentication runs at boot.

Editor-valid useful signatures (optional manual application; script deliberately does not overwrite function signatures or storage):

```text
0x000002EC: void * AllocSysMemory(int mode, int size, void * address)
0x0000033C: int FreeSysMemory(void * address)
0x00000204: uint QueryMemSize(void)
0x00000898: int RegisterLibraryEntries(void * exportTable)
0x00000AB8: int ReleaseLibraryEntries(void * exportTable)
0x00000C00: int LinkLibraryEntries(void * image, int size)
0x00000CBC: int UnLinkLibraryEntries(void * image, int size)
0x00001260: int ProbeExecutableObject(void * image, void * outFileInfo)
0x00001450: int LoadExecutableObject(void * image, void * fileInfo)
```

New reusable directly runnable Ghidra Java script: `ghidra_scripts/RecoverExistingIopBootLibraryMetadata_20261015_v1.java`. Run it separately against existing SYSMEM.bin and LOADCORE.bin, no imports or extension rebuild. Script SHA-guards the program, verifies export contents and SYSMEM import stubs, creates correct labels and function names if generically named, links export table slots to in-program functions where mapped, annotates existing LOADCORE call sites to sysmem ordinal 4/5/6, creates an optional 0x14-byte IOP library-header structure only on undefined markup, and records unresolved details in timestamped reports under Downloads. It never clears code, changes preexisting signatures, or writes binary bytes. It is source-reviewed but **not yet run inside Ghidra**.

Important datatype caveat: the original SYSMEM `.bss` is only 0x10 bytes starting at 0x0C80. Although `GetSysmemInternalData` returns that address, do not blindly apply the newer, 0x14-byte PS2SDK `sysmem_internals_t` there without runtime-specific evidence; the script labels/comments the state but preserves its current type and layout.

Next analysis should use LOADCORE's now recoverable `RegisterLibraryEntries` / `LinkLibraryEntries` and `ProbeExecutableObject` / `LoadExecutableObject` to trace SECRMAN's load and export resolution. The source code cannot be treated as proof of PCSX2's runtime correctness: compare full BIOS boot later, using observed mode and load configuration.

## Updated execution state, Dragon firmware handoff (2026-10-16)

The user executed `RecoverExistingIopBootLibraryMetadata_20261015_v1.java` successfully in **both pre-existing, byte-identical SCPH-39001/SCPH-79001 module databases**. SYSMEM: 12 -> **16** functions, 4 created, 24 labels, 18 comments, 16 exports checked. LOADCORE: 34 -> **43** functions, 12 renamed, 9 created, 30 labels, 41 comments, relocated ordinal zero verified; 25 exports plus SYSMEM ordinals 4/5/6 identified. Existing library header markup and original bytes preserved. No duplicate imports needed.

The user supplied **Dragon MechaCon 6.12 ARMv4T Ghidra .gzf** for MagicGate follow-up. A firmware-grounded scan found three Thumb internal state dispatchers (0x15DD0 for 0x90-0x93 from SRAM 0x02000277, 0x2AFC8 for 0x70-0x73 and 0x2B070 for 0x80-0x83 from SRAM 0x02000489). These values are *not yet proven to be external MagicGate SCMDs*. Bytes 0x80-0x97 inside 0x38438..0x3849B belong to a verified 100-byte packed BCD lookup, **not an SCMD table**. See `docs/ps2-dragon612-magicgate-interface-handoff-20261016-v1.md` for verified ROM SHA, byte evidence, datatype changes, expected comments and next steps.

A directly runnable, read-mostly Ghidra script `ghidra_scripts/AuditDragon612SecurityStateMachines_20261016_v1.java` SHA-guards the already analyzed Dragon program and applies *only* verified generic state-machine labels/notes and conservative RAM/BCD data declarations. Exports a detailed audit, decoded CMP candidate TSV, and selected decompilations to Downloads. It **has not yet run inside the user's Ghidra**. Do not treat any candidate as proven MechaCon authentication before packet ingress/response data are traced.

**Priority:** stop expanding generic BOOTFLOW/LOADCORE metadata unless it blocks MagicGate. Compare actual MechaCon auth and KELF I/O against PCSX2 CDVD.cpp SCMD 0x80-0x97 and MemoryCardProtocol authentication. Preserve all existing Ghidra work; no firmware reimport, model-equivalence rehashing, or extra DECKARD work.
