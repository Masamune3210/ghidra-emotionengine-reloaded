# MagicGate continuation v14: INSTALL.ELF CCC 2.x mapping diagnosis (2026-10-16)

Supersedes [v13](PS2_MagicGate_Continuation_Handoff_20261016_v13.md). This pass only inspected the user's **actual** `INSTALL.ELF` from `SCUS-97266` and reviewed current `Ccc2SymbolImporter.java` on `testing`. No emulator or Ghidra extension implementation change made.

## Ground-truth ELF layout

`readelf -lW -SW` directly against uploaded file:

- PT_LOAD `main`: `vaddr=0x00100000`, `p_filesz=0x33DD80`, `p_memsz=0x49C800`. Loaded bytes `0x00100000..0x0043DD7F`; **uninitialized tail `0x0043DD80..0x0059C7FF`**.
- PT_LOAD `heap`: `0x0059C800..0x0059C80F`, 16 bytes.
- PT_LOAD `Dancer.bin`: `vaddr=0x0059C810`, `p_filesz=0`, `p_memsz=0x8E170`; **entire reserved interval `0x0059C810..0x0062A97F` has NO file-backed bytes in this ELF**. Its section name is `Dancer.bin`, and `.relDancer.bin` references its symbols.

The user's CCC v14 output `Imported types=0 functions=11029 globals=6503 labels=0 skipped=5749` divides exactly as:
`1219 unmapped/unnamed functions + 1483 unmapped globals + 542 rejected labels + 2505 unmapped labels = 5749`.

Independently counted from original ELF .symtab:
- File-backed main: 10,041 FUNC and 6,500 OBJECT symbols.
- Main uninitialized tail: **1,350 OBJECT, zero FUNC**.
- Dancer uninitialized segment: **1,219 FUNC, 131 OBJECT**.

Thus the **1,219 skipped CCC functions equal exactly all 1,219 functions whose symbols point into the empty Dancer memory reservation**. Their addresses are valid runtime symbols, but the code is *not* present in INSTALL.ELF; do not manufacture zero-filled instructions, dummy functions, or synthetic function signatures. Most missing globals are plausibly the 1,350+131 OBJECT symbols in these uninitialized areas; two residual skipped globals have not been reconciled, so do not claim perfect global match. The 2,505 unmapped labels likewise need mapped source ranges or deferred symbolic metadata.

Source `src/main/java/ghidra/emotionengine/symboltable/Ccc2SymbolImporter.java`:
- `mappedAddress()` (around line 104) rejects any source address for which `program.getMemory().getBlock(a) == null`.
- `importFunctions()` (around line 883), `importGlobals()` (around 1036), `importLabels()` (around 1062) therefore skip otherwise valid addresses if their PT_LOAD *virtual reservations* were not mapped by the loader.
- `createSafeLabel()` (around line 1099) hands descriptive symbol names to Ghidra unchanged. CCC symbolic labels such as `_15FDtQuestionNode virtual table` fail because Ghidra symbols cannot contain spaces. The original ELF still has legal mangled names `__vt__15FDtQuestionNode` at `0x00435C90` (OBJECT length=40) and `__vt__20FsShortcutConfigMenu` at `0x00438DF0` (OBJECT length=124). Check for original names before treating these rejected CCC aliases as metadata loss; preserve source spelling where names are useful as commentary, not fake duplicate primary labels.

## Targeted Ghidra metadata from ELF symtab

```text
0x00593CD4 -> LastDnasError
    ELF STT_NOTYPE size 0, inside main uninitialized tail. Keep datatype unresolved.

0x0043E408 -> p_polconData
    ELF STT_OBJECT size 4, inside main uninitialized tail. Do not infer pointer type from name.

0x002DCAF0 -> checkHdd__11FsInstallerFv
    ELF STT_FUNC size 292 (0x124); preserve existing function signature.

0x002DF2D0 -> _getError__5FsHddFi
    ELF STT_FUNC size 216 (0xD8); preserve existing function signature.

0x0059CE90 -> sq_memreadproc
    ELF STT_FUNC size 128; Dancer.bin runtime reservation ONLY, no original code.

0x0059CF68 -> sq_memseekproc
    ELF STT_FUNC size 292; Dancer.bin runtime reservation ONLY, no original code.

0x00435C90 -> __vt__15FDtQuestionNode
    ELF STT_OBJECT size 40; original valid label for rejected CCC vtable alias.

0x00438DF0 -> __vt__20FsShortcutConfigMenu
    ELF STT_OBJECT size 124; original valid label for rejected CCC vtable alias.
```

Original INSTALL.ELF executable strings directly mention `pfs2:/tmp/\\DANCER.ENC`, `pfs1:/image/ffxi/prog/ps2/dancer.enc`, `Dancer.bin not loaded at proper address` and `host0:/image/ffxi/prog/dancer/Dancer.bin`. These connect the reserved region to a separate loadable/encoded payload. **Do not conflate Dancer UI overlay with DNAS**: the direct DNAS investigation should prioritize accessible main executable functions and `LastDnasError` references.

## Next action / repair scope

A conservative standalone Ghidra script `RestoreInstallElfMainBss_20261016_v2.java` was prepared for user download; it maps only missing gaps in `0x0043DD80..0x0059C7FF` as **uninitialized, non-executable, read/write**, with source-verified labels `LastDnasError` and `p_polconData`. It neither touches existing blocks nor populates `Dancer.bin` with fake bytes. Script not compiled or run in user's Ghidra. CCC's import-once guard remains unchanged; reapplying CCC requires explicit flag reset and analyzer rerun, ideally on a fresh program copy. Do not automatically redo all CCC data or assume users wish to reset imports.

Longer-term extension fix candidate: map PT_LOAD `p_memsz > p_filesz` tails conservatively in EE ELF handling, honoring existing blocks, mapping only source-backed virtual ranges, without inventing bytes. Need separate tests (EE/IOP + ROM mirrored load) before merging. Script is lower risk for this particular ongoing database.

**Verification:** ELF section/segment headers and symbol types/addresses verified by `readelf` against uploaded `INSTALL.ELF`; CCC source checked on `testing`. No Ghidra runtime script verification or decryption of `DANCER.ENC` in this pass.
