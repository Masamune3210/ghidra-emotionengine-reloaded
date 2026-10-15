# EE BIOS boot ELF: imported ROM overlaps optional mirror (2026-10-15 v2)

## Issue reproduced from user's import log

Target file: `BOOTFLOW_EE_combined_20261015_v1.elf`, Ghidra 12.1.3, EE language `r5900:LE:32:default`.

Import log:

```text
Part of range (bfc00000, bfffffff) already exists in memory.
ghidra.program.model.mem.MemoryConflictException
  at ghidra.emotionengine.EE_ElfExtension.createMirrorBlocks(EE_ElfExtension.java:172)
```

The user stopped on the **import log**; no completed/usable import or analysis has been confirmed. Do not assume one exists.

The synthetic boot ELF contains initialized RESET and ROMDIR segments in the actual uncached BIOS execution alias starting at `0xBFC00000`. Before this fix `EE_ElfExtension.createMirrorBlocks` unconditionally allocated a single 4 MiB mirror at `0xBFC00000..0xBFFFFFFF`, colliding with those loaded segments. Moreover, its cached BIOS mirror always sourced the virtual bytes from physical `0x1FC00000` even if that source wasn't populated by the imported ELF.

## Fix in `src/main/java/ghidra/emotionengine/EE_ElfExtension.java`

- All four aliases (uncached RAM, accelerated RAM, BIOS cached, BIOS uncached) are attempted independently.
- Each candidate checks all existing blocks for any **partial or complete interval overlap** before creation; existing original bytes and definitions take precedence over optional virtual alias blocks.
- If physical `0x1FC00000` is directly initialized, retain it as the BIOS mirror source. Otherwise, if `0xBFC00000` is directly initialized by imported ROM, use **those real source bytes** for the cached mirror at `0x9FC00000`.
- The already occupied `0xBFC00000` region is preserved and the conflicting whole-ROM uncached mirror is skipped. The loader logs an informational skip rather than a Java exception stack trace.
- The physical EE RAM mappings (`0x20000000` from `0x00000000`, `0x30100000` from `0x00100000`) remain unchanged when their destination ranges are free.
- An unexpected failure creating one optional alias now logs the reason and continues with other aliases; it does not stop boot-ELF processing.
- CPU gate remains unchanged: EE mirror logic runs on R5900 only, not IOP. Does not modify source files, ROMDIR contents, ELF parsing, or instruction-language definitions.

### Known boundary

The 4 MiB alias may span bytes not physically present in the synthetic boot ELF (it imports specific ROM0 sections rather than the complete 4 MiB ROM). The directly imported segments remain authoritative; the optional cached alias provides views of backed bytes, not a guarantee that unimported ROM bytes suddenly exist. Later complete-ROM analysis can add the missing data deliberately.

## Verification and user action

Source checked against Ghidra's `MemoryBlock.isInitialized`, `MemoryBlock.isMapped`, `Memory.createByteMappedBlock`, `Address.addNoWrap`, and `ElfLoadHelper.log` APIs. **Not built or executed in user's Windows Ghidra 12.1.3 yet**.

Because this fix changes a Java extension class, the user must **rebuild and reinstall/update the extension**, then restart Ghidra before reimporting the EE combined boot ELF. Refreshing Ghidra Script Manager does **not** load this class change.

Expected log should contain an informational skip for `BIOS/rom0b(uncached)` instead of the reported `MemoryConflictException`. Then inspect `0xBFC00000` RESET bytes, `0xBFC02780` ROMDIR, `0x9FC00000` cached mirror, `0x80001000` kernel entry and `0x00082008` EELOAD code. The IOP combined boot image should be imported separately with the appropriate IOP language.

Overall objective remains reconstructing EE/IOP retail startup inside Ghidra to find the first PCSX2 discrepancy relevant to MagicGate. Do not resume unrelated DECKARD firmware expansion.
