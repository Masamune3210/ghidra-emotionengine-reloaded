# PS2 MagicGate continuation v15: INSTALL.ELF CCC BSS repair verified

Branch: Masamune3210/ghidra-emotionengine-reloaded, testing. Supersedes v14.

## Latest user verification, CCC JSON v14

| CCC category | Before | After | Delta |
| --- | ---: | ---: | ---: |
| Imported types | 0 | 0 | 0 |
| Imported functions | 11029 | 11029 | 0 |
| Imported globals | 6503 | 7855 | +1352 |
| Unmapped functions | 1219 | 1219 | 0 |
| Unmapped globals | 1483 | 131 | -1352 |
| Rejected labels | 542 | 542 | 0 |
| Unmapped labels | 2505 | 2179 | -326 |
| Total skips | 5749 | 4071 | -1678 |

The user reran CCC after the v2 main-BSS restoration script, proving that its virtual-address mapping fixed the 1352 missing global mappings and 326 additional symbol labels. No new binary bytes were invented. The remaining 1219 unmapped functions and 131 unmapped globals equal the original INSTALL.ELF symtab FUNC and OBJECT counts respectively inside the Dancer.bin PT_LOAD reservation, whose file size is ZERO. These runtime symbol addresses are valid, but no body bytes for them are stored in INSTALL.ELF.

The original ELF contains exactly 542 names beginning __vt__, per readelf -sW, matching CCC's 542 rejected names such as '_15FDtQuestionNode virtual table'. This exact match strongly suggests rejected entries are readable vtable aliases with spaces. Verify whether corresponding original mangled __vt__ labels already exist in Ghidra before suppressing failures or adding duplicate sanitized labels. Do not assume all 542 source aliases have been preserved in database until audited.

Dancer.bin region contains 2199 ELF STT_NOTYPE symbols compared with 2179 CCC unmapped labels; 20-record difference has not been reconciled.

## Directly applicable source-derived Dancer region metadata

0x0059C810 - 0x0062A97F: Dancer.bin runtime PT_LOAD reservation (p_filesz=0; p_memsz=0x8E170)
0x0059C850 - 0x0060CFCF: executable Dancer text (0x70780 bytes, missing from INSTALL.ELF)
0x0060CFD0 - 0x0061D5FF: Dancer data (0x10630 bytes, missing from INSTALL.ELF)
0x0061D600 - 0x0062A97F: Dancer BSS (0xD380 bytes, uninitialized)
0x0059C850 -> _Dancer_text_start
0x0060CFD0 -> _Dancer_text_end
0x0060CFD0 -> _Dancer_data_start
0x0061D600 -> _Dancer_static_init
0x0062A980 -> _Dancer_segment_end (exclusive; NO data at endpoint)

The first 0x40 bytes before Dancer text start are a header/reservation of unknown exact semantics. The original .relDancer.bin section contains 22692 relocation records of 8 bytes each. The disc directory listing contains DANCER.ENC, not supplied yet; do not presume the separate ERX wrapper XOR applies to this file.

## DNAS next step

Prepared a READ-ONLY Ghidra Java script AuditInstallElfDnasReferences_20261016_v1.java for the user's existing repaired INSTALL.ELF program, reporting mapping, original vtable labels, named DNAS/HDD/auth functions and xrefs to:
0x00593CD4 LastDnasError (original ELF NOTYPE, unknown datatype)
0x0043E408 p_polconData (OBJECT, size 4, do not invent pointer type)
0x002DCAF0 checkHdd__11FsInstallerFv
0x002DF2D0 _getError__5FsHddFi
0x0026ED98 sqPolconCheckNetDevice

The script was delivered as conversation artifact, NOT Ghidra-runtime verified. Missing XREFs do not mean absence of guest code usage; analyze indirect/GP-relative paths separately. Ask user to run audit and provide output. Separately request DANCER.ENC to recover missing overlay only if warranted; do not block DNAS work on it.

No new extension implementation changes in this pass. No root cause for PlayOnline's DNAS -404 proved.

Previous context: docs/PS2_MagicGate_Continuation_Handoff_20261016_v14.md
