# Compilation fix: EE boot script v2 (2026-10-15)

The user attempted to compile v1 in Ghidra 12.1.3. Compiler reported exactly:

```text
AnnotateScph79001EeBootFlowAndRdram_20261015_v1.java:399: error: unreported exception ghidra.util.exception.CancelledException; must be caught or declared to be thrown
            monitor.checkCancelled();
```

Cause: `annotateRomdir()` omitted `throws Exception`; its caller `run() throws Exception` already propagates cancellation, and `validate() throws Exception` already handles the other `monitor.checkCancelled()` call. v2 adds the checked-exception declaration and retains the cancellation semantics (it does not suppress cancellations). The v1 script was removed from `testing` to prevent selection of an obsolete file. No Ghidra database metadata was modified by the failed compile.

Static source audit: these are the only two `monitor.checkCancelled()` calls, both now in functions declaring `throws Exception`. No Ghidra jar is installed in the assistant runtime, so a complete extension-bound Java compilation could not be performed. The updated script still needs its first runtime verification by the user.

# SCPH-79001 EE cold-boot reconstruction in Ghidra, 2026-10-15 v4

## Objective and current user-verified database

The objective is **MagicGate**, using a firmware-grounded PS2 boot chain as an oracle for later comparison with PCSX2. EE and IOP are separate processors and must not be disassembled together under one ISA. DECKARD and SECRMAN have previously been analyzed; shared SCPH-39001 / SCPH-79001 modules established identical by the user should reuse their existing Ghidra analysis.

Current EE program: `BOOTFLOW_EE_combined_20261015_v1.elf.gzf`, imported with extension language `r5900:LE:32:default (1.4)` into Ghidra 12.1.3. User's completed analysis metrics: **34,565 instructions, 524 functions, 2,027 defined data, 2,388 symbols, 46 datatypes, 22 memory blocks**. GZF is Java serialization with an embedded first ZIP `FOLDER_ITEM` payload; this pass extracted it and confirmed synthetic import symbols, initialized file layout, and metadata string tables. The total 76,846,729 mapped bytes includes extension EE aliases, not 76 MiB of original BIOS code. CCC 2.x applied four function records (JSON v14) without errors. Importer log's optional BIOS alias skip after the EE_ElfExtension overlap fix is benign; Ghidra completed analysis.

The ELF's four imported original sections were independently cross-checked against the exact 4 MiB SCPH-79001 ROM:

| Section | Ghidra base | File size | SHA-256 |
|---|---|---|---|
| RESET | `0xBFC00000` | `0x2780` | `f6a6f7a72ed70bc320b36fd47cba33bb25d14cd6626ce2816bc5f3fb218f708b` |
| ROMDIR | `0xBFC02780` | `0x6A0` | `44e0cf76068658a9f35277aeea0b8b4dd189d2a75524c2157f5c456c9b9949ba` |
| KERNEL | `0x80000000` | `0x173E8` | `da56e4697cee326e73f00dbfbd4d805109cea119d88b96addd6fb76a29dcffe9` |
| EELOAD | `0x00082000` | `0xF190` | `c94e3da87af7bc5ea90700947096ba9380cbdc4b40296c2253ed7a795f0fbce7` |

These are the SCPH-79001 bytes; **do not assume older SCPH-39001 kernel addresses apply**. ROMDIR has **105 entries** plus a zero terminator; the aligned module sizes sum to exactly `0x400000` bytes (the complete ROM). It locates RDRAM at ROM offset `0x041000` and KERNEL at `0x392F70`.

## Discovered EE boot flow (verified by original instruction words)

1. `0xBFC00000` reset reads COP0 PRId and compares against `0x59`. EE path is `0xBFC00800`; IOP path is `0xBFC02000` in a **separate IOP Ghidra program**.
2. EE reset initializes COP0/TLB, then at **`0xBFC00894` executes `jalr` to `0x9FC41000`**, the cached execution alias of ROMDIR `RDRAM` at file offset `0x41000`. It tests return `$v0` and loops on a negative initialization result (`0xBFC0094C`). **The original synthetic EE combined ELF omitted this RDRAM module**, so the loaded Ghidra database initially lacks source bytes for this real first-stage call.
3. Reset performs another `jalr` at `0xBFC008CC` to the cached alias `0x9FC00C00` (same original ROM code as `0xBFC00C00`), which scans for a valid ROMDIR at `0xBFC00CF8`, looks up literal `KERNEL` at `0xBFC00D90`, copies the KERNEL image to uncached EE RAM, and clears remaining memory.
4. At `0xBFC008DC` it calls the cache-flush routine at `0xBFC008FC`, then `jr` at `0xBFC008F4` transfers to **`0x80001000`**.
5. Kernel entry `0x80001000` sets up kernel state and COP0/exception infrastructure. It calls `0x80005C30` for multiple TLB mappings, along with several other initialization functions whose exact subsystem names remain unresolved.
6. At `0x800010B0`, kernel calls `0x80005388` to create the initial **`EELOAD`** thread (literal name at `0x80015A0C`, image base `0x00082000`, stack `0x00081000`). It then jumps to `0x80005140` with thread id; that routine restores EPC and executes `eret`. EELOAD has eight zero bytes and starts meaningful code at **`0x00082008`**.
7. EELOAD startup invokes syscall **`0x3C`** (`0x00082064`, kernel handler `0x80005190`) and **`0x3D`** (`0x00082080`, kernel handler `0x80005298`), performs its initialization, and calls the argv/module-load interpreter at **`0x00082388`**.
8. This EELOAD parser recognizes `moduleload`, `moduleload2`, `-m`, `-k`, `-x` and the runtime command strings `rom0:UDNL rom0:EELOADCNF`, `rom0:UDNL `, as well as default/alternate executable paths `rom0:OSDSYS` and `rom0:TESTMODE` at `0x00090700/710`. **UDNL and OSDSYS are conditional launch paths**, not unconditional cold-boot actions.
9. Kernel syscall dispatch at **`0x80000280`** indexes a **256-entry pointer table `0x80015500..0x800158FF`**. Known slots: `0x06 -> 0x80005598` (`LoadExecPS2`), `0x3C -> 0x80005190`, `0x3D -> 0x80005298`, `0x7B -> 0x80005988` (`ExecOSD`). The ExecOSD wrapper forwards the path `rom0:OSDSYS`. Exception handler pointer table has 14 entries `0x80015900..0x80015937`; `0x80015938` is saved k1, **not entry 14**. The interrupt table begins at `0x80015940`; length must not be guessed.

## Actionable Ghidra metadata

New datatype before data declaration:

```text
Structure: RomDirEntry
Size: 0x10
0x00 char[10] name        (10)
0x0A uint16_t extinfoSize (2)
0x0C uint32_t fileSize    (4)
```

Data declarations, only if existing declarations don't overlap:

```text
0xBFC02780 - 0xBFC02E0F  RomDirEntry[105]
0x80015500 - 0x800158FF  pointer[256]
0x80015900 - 0x80015937  pointer[14]
```

Verified, generalizable function/label candidates (the script preserves existing non-default names and function boundaries):

```text
0xBFC00000 -> BiosResetCpuDispatch
0xBFC00800 -> InitializeEeFromResetRom
0xBFC008FC -> FlushEeResetCaches
0xBFC00C00 -> FindAndCopyKernelRomImage
0xBFC00CF8 -> LocateResetRomdirHeader
0xBFC00D90 -> FindRomModuleByName
0x9FC41000 -> InitializeRdramController    (after RDRAM bytes are added)
0x80000000 -> EeExceptionVector000
0x80000200 -> EeInterruptVector200
0x80000280 -> DispatchEeKernelSyscall
0x80001000 -> InitializeEeKernel
0x80005140 -> EnterInitialEeThread
0x80005190 -> KernelSyscall3CHandler
0x80005298 -> KernelSyscall3DHandler
0x80005388 -> CreateInitialEeThread
0x80005598 -> LoadExecPS2
0x80005988 -> ExecOSD
0x800059A0 -> LaunchBootBrowser
0x80005C30 -> InitializeEeTlbMappings
0x00082008 -> EeLoadStartup
0x00082388 -> ParseEeLoadStartupArguments
0x00082BF8 -> InvokeEeLoadModuleRequest
```

Do not invent parameter signatures where their detailed ABI behavior is not yet established. Raw ROM offsets, physical addresses and cached/uncached CPU aliases are deliberately not conflated.

## Script and exact application behavior

`ghidra_scripts/AnnotateScph79001EeBootFlowAndRdram_20261015_v2.java` is the comprehensive database-application script. Before changing anything, it checks **all four section SHA-256 digests, 65 exact 32-bit ROM/kernel/loader anchor words, and all 105 ROMDIR entries**, confirming aligned total 4 MiB and key module sizes/positions. It requests **one** optional input file to fill the known missing RDRAM module: either an exact original 4 MiB SCPH-79001 BIOS (`SHA256 e76d9c8f4019041fb17f41fff25d57d608c1a3f205c99bda9eb47402c43e8c93`) or an extracted `RDRAM` file of exactly `0x3154` bytes (`SHA256 e3ae825c718eaaa285cf2a3e000bcc85d2047e50881a2144537410f6398d929d`). Incorrect bytes abort before modifications.

The script safely adds the genuine immutable RDRAM bytes to the **unoccupied uncached `0xBFC41000..0xBFC44153`** (not over any existing block). The EE extension already created a byte-mapped cached ROM alias at `0x9FC00000`; after loading it tests that the **actual call target** `0x9FC41000` reads the authentic RDRAM bytes. It then disassembles/names the RDRAM entry where safe, annotates the verified RESET/KERNEL/EELOAD handoffs, adds all 105 ROMDIR entry labels/comments, flags boot/security-related modules, types only free tables, and places bookmarks without clearing Ghidra's prior analysis.

The script emits two unique timestamped reports into **Windows Downloads**: `EEBootFlow_SCPH79001_20261015_v1_<timestamp>.txt` with all module offsets, known function states and direct call-edges, and `EEBootFlow_SCPH79001_20261015_v1_<timestamp>.dot` to visualize the verified EE boot graph. They do not imply that security modules actually loaded. No artifacts are written to the home directory.

**Verification:** every embedded constant and all 65 32-bit anchors were checked offline against exact uploaded file bytes, and the script uses the Ghidra 12.1.3 API method signatures for mappings, bookmarks and datatypes. The new Java script itself has **not** been executed inside the user's Ghidra instance. No Ghidra extension rebuild is required for script-only metadata changes.

## Next steps, toward MagicGate

1. User runs comprehensive EE metadata script and returns report/console output and updated `.gzf`. The RDRAM gap is the only known new binary requirement; do not reimport the combined EE ELF from scratch.
2. Import and analyze the already-prepared `BOOTFLOW_IOP_combined_20261015_v1.elf` in a distinct Ghidra program with appropriate IOP language. Trace `0xBFC02000 -> 0xBFC4A000`, the `IOPBTCONF` vs `IOPBTCON2` selection, and LOADCORE module list.
3. Reconcile IOP module boot states, including the precise cold-boot loading of SECRMAN, MCMAN, SIO2MAN and CDVD services, then follow EELOAD's UDNL/IOP reset paths and encrypted KELF loader calls. Differentiate actual module load from runtime authentication activity.
4. Compare these firmware-derived stages to **PCSX2 full BIOS boot** first; fast boot shortcuts are a separate mode and cannot prove MagicGate implementation correctness.