# SCPH-79001 boot-chain reconstruction and MagicGate handoff, 2026-10-15 v6

## User-confirmed EE database state

Ghidra 12.1.3, `BOOTFLOW_EE_combined_20261015_v1.elf`, R5900 language. `AnnotateScph79001EeBootFlowAndRdram_20261015_v2.java` **ran successfully**. Its user-supplied log and Downloads reports verify:

- Four EE boot segments: RESET, ROMDIR, KERNEL, EELOAD. 65 exact instructions/syscall words. All 105 ROMDIR entries; aligned 4 MiB total.
- RDRAM module (ROM0 offset `0x41000`, SHA256 `e3ae825c718eaaa285cf2a3e000bcc85d2047e50881a2144537410f6398d929d`) imported intact at `0xBFC41000..0xBFC44153`, and mirrored bytes accessible at `0x9FC41000`.
- EE boot transfers: RESET `0xBFC00000` → EE `0xBFC00800` → RDRAM `0x9FC41000` → ROMDIR/KERNEL copy `0x9FC00C00` → KERNEL `0x80001000` → boot-thread creation `0x80005388` → resume `0x80005140` → EELOAD `0x00082008`.
- Function report: 535 total at report time, 10 created, 11 renamed, 143 labels, 172 comments, 7 bookmarks. 3 preserved data/function markup events. Syscall/exception tables were **not** retyped because valid data already existed.
- Important outstanding observation: function `InitializeRdramController` was named at `0x9FC41000` but **the report showed `instruction=null` there**. RDRAM bytes are present; RDRAM disassembly/flow and its device initialization have not yet been analyzed. Do not call it a completed function decompilation.
- Ghidra treats `0x80000280` and `0x800147F4` as part of an existing large exception function `EeExceptionVector000`, so the script correctly preserved its function body and attached labels/comments rather than destructively splitting it.
- The downloaded `.dot` file reflects **confirmed control transfers** plus explicitly dashed *conditional* EELOAD `rom0:OSDSYS` and `rom0:UDNL` launch paths, not runtime observations of MagicGate.

## Source-verified IOP input bytes (awaiting Ghidra import)

The same uploaded SCPH-79001 original boot components have been inspected directly:

| Region | Address | Size | SHA256 |
|---|---|---:|---|
| RESET | `0xBFC00000` | `0x2780` | `f6a6f7a72ed70bc320b36fd47cba33bb25d14cd6626ce2816bc5f3fb218f708b` |
| ROMDIR | `0xBFC02780` | `0x06A0` | `44e0cf76068658a9f35277aeea0b8b4dd189d2a75524c2157f5c456c9b9949ba` |
| IOPBTCONF | `0xBFC1EC90` | `0xEA` | `9424379b2c4efdd95ee9a9b2b1e786254ffa0a177324e631d5855b589384df75` |
| IOPBTCON2 | `0xBFC1ED80` | `0xC3` | `9225c34546e18cf3e947f9b221b01d887dfbb6895b5a15db9a82ede3e220e1e7` |
| IOPBOOT | `0xBFC4A000` | `0x1160` | `572e8acd6db6c7854cba1418b3ecfc02f23c3752e1073baa3ccd728a986abc54` |

All 72 instruction anchors in `ReconstructScph79001IopBootAndConfigurations_20261015_v1.java` were verified against these original bytes, including IOPRESET and IOPBOOT entry, dynamic module search, header inspection, module section loader and privileged transfer code.

### Boot selection nuance that PCSX2 must eventually reproduce

**User-confirmed correction:** `TBIN` is the PS1 backward-compatibility startup payload. It is **not** an alternate normal PS2 boot sequence. The two RESET names have different operational purposes: the TBIN path is for PS1 compatibility, while the IOPBOOT path is the one to trace for retail PS2 boot and subsequent MagicGate-related IOP module behavior. Do not conflate TBIN with an `IOPBTCON2` configuration or describe both as interchangeable PS2 boot modes.


1. Both CPUs start with the same reset ROM; COP0 PRId separates EE `0xBFC00800` and IOP `0xBFC02000`.
2. IOPRESET has a hardware-dependent choice of register initialization paths; the `0xBFC02680` ROMDIR finder is used to choose **TBIN (PS1 compatibility)** or **IOPBOOT (normal PS2 startup)** by module name. Do not describe the PS1 TBIN branch as a competing normal PS2 cold boot.
3. The IOPBOOT entry is `0xBFC4A000`. At `0xBFC4A0E8` it replaces the final byte of an `IOPBTCONF` string with ASCII `'0' + boot argument`; it tries this numbered variant (at `0xBFC4A100`) and falls back to the default name (at `0xBFC4A120`). This implements separate boot environments. For the specific observed RESET-to-IOPBOOT call, the configuration selector is `a1=0`: IOPBOOT tries `IOPBTCON0`, which is not in this ROMDIR, then falls back to `IOPBTCONF`. This is a specific flow, not proof that all later IOP resets select the same config.
4. IOPBOOT parses the configuration text and resolves each listed ROM module, with a module-format classifier at `0xBFC4A600`. Two initial module load/entry paths start at `0xBFC4A330` and `0xBFC4A3AC`; indirect transfers occur at `0xBFC4A39C` and `0xBFC4A44C`. Both configs begin with SYSMEM and LOADCORE, which then take over later module loading.
5. This is **ordinary startup/module loading**, not an established KELF decryption or MagicGate authentication step. Do not label any of these boot helpers as security/auth functions absent evidence.

### Ordered boot module lists and MagicGate implications

`IOPBTCONF` has **29** ordered modules:

```text
SYSMEM LOADCORE EXCEPMAN INTRMANP INTRMANI SSBUSC DMACMAN TIMEMANP
TIMEMANI SYSCLIB HEAPLIB EECONF THREADMAN VBLANK IOMAN MODLOAD ROMDRV
STDIO SIFMAN IGREETING SIFCMD REBOOT LOADFILE CDVDMAN CDVDFSV
SIFINIT FILEIO SECRMAN EESYNC
```

`IOPBTCON2` has **24** ordered modules:

```text
SYSMEM LOADCORE EXCEPMAN INTRMANP INTRMANI SSBUSC DMACMAN TIMEMANP
TIMEMANI SYSCLIB HEAPLIB THREADMAN VBLANK IOMAN MODLOAD ROMDRV
ADDDRV STDIO SIFMAN IGREETING CDVDMAN SECRMAN SIO2MAN MCMAN
```

21 modules occur in both. `SECRMAN` is **position 28/29** in IOPBTCONF and **position 22/24** in IOPBTCON2. Only the alternate config explicitly includes SIO2MAN and MCMAN, a relevant prerequisite for memory-card-side MagicGate interactions. The full/default config instead includes EESYNC, SIFCMD, REBOOT, LOADFILE, CDVDFSV, SIFINIT, FILEIO and EECONF. The alternate contains ADDDRV in addition to the card modules. **This is not proof that every device is initialized or that an authentication exchange happens in either boot.**

### Ghidra metadata for IOP, in dependency order

```text
Structure: IopBootRomdirRecord
Size: 0x10
0x00 char[10] name          (10)
0x0A uint16_t extinfoLength (2)
0x0C uint32_t fileLength    (4)

0xBFC02780 - 0xBFC02E1F
Type: IopBootRomdirRecord[105]
```

```text
Structure: IopBootContextHeaderView
Size: 0x20 (partial view only)
0x00 uint32_t bootArgument0
0x04 uint32_t bootArgument1
0x08 uint32_t optionalConfigurationPointer
0x0C uint32_t firstModuleEntryPoint
0x10 uint32_t optionalRomBase
0x14 uint32_t optionalRomSize
0x18 uint32_t configuredModuleCount
0x1C uint32_t loadArenaCursor
```

The context header corresponds to IOP RAM `0x00020000`, **which is not actually mapped in the small combined ROM-only IOP ELF**. Define the datatype without inventing RAM or declaring the structure over unmapped space. These names are deliberately conservative; later LOADCORE tracing may refine them.

Verified labels/function targets:

```text
0xBFC00000 -> BiosResetCpuDispatch
0xBFC02000 -> InitializeIopFromResetRom
0xBFC02680 -> FindResetRomModuleByName
0xBFC024B4 -> IopResetIopbootRomName
0xBFC024C4 -> IopResetTbinRomName
0xBFC4A000 -> IopBootMain
0xBFC4A4F0 -> CompareBootConfigText
0xBFC4A578 -> CopyIopBootString
0xBFC4A5C8 -> LengthOfIopBootString
0xBFC4A600 -> InspectIopBootModuleFormat
0xBFC4A7F0 -> LoadIopBootExecutableSections
0xBFC4ACB0 -> LocateIopBootRomDirectory
0xBFC4AD58 -> FindIopBootRomFile
0xBFC4AED0 -> IopBootCriticalTransferStub
0xBFC4B154 -> IopBootDefaultConfigurationName
```

No function signatures were invented; current Ghidra function parameters and return types are preserved for all unresolved routines. The script uses safe labels/comments and creates genuine function entries only if no existing function claims their bodies.

## Application script and next step

`ghidra_scripts/ReconstructScph79001IopBootAndConfigurations_20261015_v1.java`: five file SHA checks, 72 opcode anchors, full ROMDIR and both config lists, conservative code markers, two datatype definitions, memory-safe optional declarations, ASCII config markers, and three reports (TXT, TSV, DOT) to Downloads. No source ROM byte edits. Source-reviewed and successfully run in user's Ghidra 12.1.3; details above. The script is for **`BOOTFLOW_IOP_combined_20261015_v1.elf` only**, imported separately with the IOP's little-endian MIPS language. Do not run it against the EE combined image or SECRMAN.

**Executed and verified in user's Ghidra on 2026-10-15:** The IOP boot script passed five SHA-256 section checks, 72 original instruction words, all 105 ROMDIR entries and 29+24 configuration rows. It applied 9 function renames, 86 labels, 95 comments and 2 datatype declarations; preserved preexisting ROMDIR markup once; created no new functions; modified no firmware bytes. User provided an exported `BOOTFLOW_IOP_combined_20261015_v1.elf.gzf`. Exported IOP TXT, TSV and DOT reports are in user's Downloads but have not yet been provided in this conversation. **Do not ask to rerun or reimport the IOP program.** The first next reconstruction is LOADCORE's loading and relocations, followed by the actual point where SECRMAN gets initialized or where an EELOAD/UDNL reset changes the configuration. Eventually compare to PCSX2 full BIOS boot at the same observed milestones; fast boot is a separate control flow.

No need to rebuild the extension for Script Manager script changes. Preserve the already verified EE RDRAM block and both model-specific and user-confirmed shared firmware metadata. Avoid redundant hash checks of previously proved shared model binaries.