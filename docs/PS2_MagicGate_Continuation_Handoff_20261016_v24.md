# PS2 MagicGate continuation v24: PlayOnline Viewer second disc recovered

Branch `testing`. Previous: [v23](PS2_MagicGate_Continuation_Handoff_20261016_v23.md).

## Critical verified provenance

User supplied the **correct failing disc**, `PlayOnline Viewer and Tetra Master (USA, Canada).bin/.cue`, one CD-ROM XA MODE2/2352 track. ISO9660 `SYSTEM.CNF` says `BOOT2 = cdrom0:\SCUS_972.69;1`. It is **SCUS-97269**, distinct from FFXI first-disc SCUS-97266. Its 93,704 sectors were read directly as 2352-byte sectors with 2048-byte Mode2 Form1 payload at byte 24; extracted filesystem has 1,073 files and 37 directories (many empty DAT placeholders).

Two unique, stripped, EE MIPS R5900 ELF32 executables:
- `SCUS_972.69`: 1,735,512 bytes; SHA256 `b3c429e3691f3198e18ca76a4e2640596206da3b40272a2ff1d3cb94658abcea` ; entry `0x00100008`; PT_LOAD `0x00100000` size 0x105980/file, 0x130000/memory, and `0x00800000` size 0xA1880/file, 0xC7D00/memory.
- `_/POL_HDD.ELF`: 1,735,896 bytes; SHA256 `90d8dbeb0b48b377ef471de184dcdaa207d6447abc5245df5a1df4371728cb41`; entry `0x00100008`; PT_LOAD `0x00100000` 0x105B00/file, 0x130180/memory and `0x00800000` 0xA1000/file, 0xC2200/memory. This is a separate HDD-oriented executable variant. Both ELF `.symtab` and `.strtab` sections report zero size. **No CCC symbol metadata** as for first-disc INSTALL.ELF.

## Directly observed Sony DNAS status handling in correct disc

Both executables explicitly contain `sceDNAS1Init`, `sceDNAS1GetStatus() ERROR %d`, `sceDNAS2CryptInit() end %d`, `playonline DNAS slot ID = [%d][0x%08x][0x%08x]`, and `sceDNAS1_SS_DIFFERENT_HDD retry` diagnostics.

| Source-verified item | CD boot | HDD variant |
|---|---|---|
| DNAS authentication/status function prologue `addiu sp,sp,-0x2f0` | 0x0080EAF8 | 0x0080E308 |
| DNAS1 DIFFERENT_HDD message string | 0x0089FD48 | 0x0089F498 |
| `addiu v0,zero,-0x6d` compare literal | 0x0080F0E0 | 0x0080E8EC |
| Call site prints DIFFERENT_HDD retry message | 0x0080F0EC | 0x0080E8FC |
| Helper call immediately after retry message | 0x0080F0F4 | 0x0080E904 |
| `playonline DNAS slot ID` format string | 0x0089FD00 | 0x0089F450 |
| `call sceDNAS1Init()` string | 0x0089FC50 | 0x0089F3A0 |
| `sceDNAS2CryptInit() end %d` string | 0x0089F958 | 0x0089F0A8 |

Disassembly explicitly compares returned error/status field to **-109 (-0x6D)** in the DIFFERENT_HDD branch and restarts/helper-calls for this condition. This **does not establish that -404 is that status**. The slot ID format fields' actual meanings unresolved. `PsIIlibdnas2....` found in high-entropy embedded region around file offset 0x187570 on CD boot (0x187670 HDD variant); no verified extraction of DNAS2 client from there. Avoid assigning unknown API function signatures.

## IOP modules fully recovered from CORRECT disc

Nine encrypted `_/0/*.ERX` wrappers were successfully decoded with the previously established `SQIOPMEM.IRX` rolling-XOR LCG decoder. All recovered module payloads validated as PS2 IOP MIPS relocatable ELF32 type 0xFF80 with valid ELF section tables:

| Disc ERX | IRX internal name |
|---|---|
| LDR000 | sqloader.irx |
| NDI000 | pegas.irx |
| NDI002 | ndglue.irx |
| POE002 | ndglue.irx (distinct module variant; preserve separate file) |
| PPP008 | sdglue.irx |
| TCP000 | avetcp.irx |
| TCP001 | avetcp2.irx |
| TCP002 | avetcp3.irx |
| TCP003 | avetcp4.irx |

These are loader/network modules, none named BBSYS101/libid2. Their identities do not independently prove absence of DNAS IOP code elsewhere.

The second-disc `POLKEY.DAT` SHA256 is `20c5a40f33d6b8fe9bab4b88a85d6f432b1f24e7d8176be42854c0d13a8731f8`, length 0x10010; DIFFERENT from first-disc FFXI `POLKEY.DAT` SHA256 `4a33f8e439fe70d3767349bff7e78eea36108a901ed81027b72e0a1eb746d614` with same length. Treat as disc-specific data, semantics unresolved.

## User-facing artifacts and applying Ghidra metadata

Created and locally verified ZIP `PlayOnline_SCUS97269_Ghidra_Recovery_20261016_v1.zip`, containing **both original EE ELFs, nine recovered IOP IRX binaries, POLKEY.DAT, IOPRP.IMG, SYSTEM.CNF, README, SHA256 manifest, and Ghidra Java script**. ZIP CRC test passed. Also independent downloadable `AnnotatePlayOnlineDnas97269_20261016_v1.java` and README.

The Ghidra Java script **APPLIES METADATA**, not merely an audit. Detects CD/HDD variant by checking exact DNAS string bytes and instruction words. Idempotently labels five DNAS diagnostic messages; creates/renames generalized `ProcessDnas1AuthenticationStatus` function at verified prologue when safe; adds evidence-backed function and EOL comments on the -109 branch and DNAS calls. Preserves existing user-defined names, signatures and code; doesn't guess parameter types, create external IOP services, or use any first-disc addresses. **Script has NOT been compiled/tested in user Ghidra; treat as pending runtime verification**.

Next action is to import **SCUS_972.69** as EE executable in the fork's Ghidra (and optionally POL_HDD.ELF as a separate program), run `AnnotatePlayOnlineDnas97269_20261016_v1.java`, then send `[DNAS97269]` log and inspect the -404-producing path from decompilation. User indicated they need sleep; do not push a need to execute immediately. There is no genuine Sony HDD available and user should not be asked to supply one.

**Provenance and status:** raw ISO parse / ELF segments / ERX decoder and fixed byte comparisons verified offline. No PCSX2 build or emulator runtime debugging changes in this turn. Main CD/HDD ELF bytes were intentionally **not uploaded to GitHub**; all are user-provided private files in downloadable ZIP.
