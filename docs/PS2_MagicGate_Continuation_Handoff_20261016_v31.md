# PS2 MagicGate continuation v31: clean-HDD official installer blocked at protected ELF (2026-10-16)

**Branch:** `testing`. Previous: [v30](PS2_MagicGate_Continuation_Handoff_20261016_v30.md).

## Why this test was run

The user's existing 40-GB HDD image had hacked HDDOSD; the four empty files `__net/etc/access_flag`, `access_flag2`, `access_flag25`, `bnexe` are **not a trustworthy official-install baseline**. User attempted to boot **official Sony HDD Utility Disc v1.10 (USA)** with a new 40-GB image `testdrive.raw` to observe what official setup creates.

## Runtime evidence (user PCSX2 log Pasted text 20261016-165242.txt)

- Disc detected `SCUS_973.95`, v1.10, CRC `E2B8E3DC`, initial 5,616-byte EE boot ELF, entry `0x00200008`. This is **HDD Utility**, separate from PlayOnline Viewer `SCUS_972.69`, and FFXI first disc `SCUS_972.66`.
- PCSX2 DEV9 opens 40,960 MiB / 83,886,080 sectors of the newly selected HDD image.
- BIOS loads `rom0:ATAD` and `rom0:HDDLOAD -osd`, and logs ATA identify string `PCSX2-DEV9-ATA-HDD`, `I-security: 0000`, and then `HDL:read 0 sec`, `ATA: C_READ_SECTOR`, `cannot alloc memory`, `new power off`. These are early observations **not proven causal** for later MagicGate message, and deserve independent investigation if needed.
- Once the utility's on-disc bootstrap is executed, protected loader logs:

```text
[MG] hcode=0 cnum=0 a2=0 length=0x1A0
[MG] ELF_size=0x5370 Hdr_size=0x1A0 unk=0x100 flags=0x22C count=0 zones=USA
[MG] ERROR - Make sure the file is already decrypted!!!
```

- Followed by restart and `# Syscall: undefined (0)`; this run **did not provide evidence of successful official HDD formatting/partition or flag creation**. Do not treat as official `__net/etc` baseline.
- The exact three-line `[MG]` log, including ALL listed header values, appears in upstream PCSX2 issue [#8432](https://github.com/PCSX2/pcsx2/issues/8432) about a **different official DVD Player install disc**, opened Mar 18, 2023. A PCSX2 maintainer stated MagicGate was unsupported for possible legal reasons. Thus corroborates **generic MagicGate-protected loader limitation** but does not establish identical protected file or identical call path as Sony HDD Utility disc.

## Scope and next actions

Keep separate:
1. FFXI first-disc `SCUS_972.66` static auth work.
2. PlayOnline Viewer second-disc `SCUS_972.69` local DNAS identity-check `-404` -> POL-1562, protected __net path `hdd0:__net,,<8 bytes>`, and access_flag references.
3. HDD Utility `SCUS_973.95` protected executable boot failing with MagicGate-decryption warning **before official baseline was established**.

HDD Utility test is a new independent useful MagicGate test target. Do **not** infer the official installer created empty access flags or proves their expected file sizes, or that the same MagicGate failure directly causes DNAS -404. No fresh Ghidra database metadata is established from a runtime error log alone. If user wishes to proceed, prioritize determining exact KELF path/data and whether failure comes from PCSX2's current missing security/decrypt implementation, not guessing from the status line. Avoid recommending a genuine Sony HDD (user lacks one).

Current Ghidra metadata: v6 applier succeeded independently on CD/HDD PlayOnline executables, eight names/seven labels per program with zero failures. Do not rerun.

**Verification:** User runtime log + public upstream issue. No code changes or new Ghidra annotation in this test.
