# SCPH-79001 PS2 boot import preparation (2026-10-15 v1)

## Objective
Reconstruct authentic PS2 EE/IOP cold-boot flow inside Ghidra, then use it to locate PCSX2's first deviation relevant to MagicGate. The immediate task was to import raw RESET, IOPBOOT, IOPBTCONF, IOPBTCON2, KERNEL, EELOAD properly. This is **not** a separate DECKARD analysis project.

## Original data and verification
- 4 MiB SCPH-79001 ROM SHA-256 `e76d9c8f4019041fb17f41fff25d57d608c1a3f205c99bda9eb47402c43e8c93`.
- User uploaded both matched sets of raw components. Previously established shared modules between the models must be reused rather than re-analyzed or rehashed unnecessarily.
- All six supplied selected raw modules were checked against their exact ROMDIR spans. Their bytes were unchanged in every generated ELF.
- RESET (10,112 bytes) ROM offset `0x000000`, maps `0xBFC00000`; shared CPU reset vector. COP0 PRId comparator at `BFC00008` chooses EE `BFC00800` (PRId >= 0x59) versus IOP `BFC02000` (< 0x59).
- ROMDIR itself at ROM offset `0x002780` (1,696 bytes), runtime alias `0xBFC02780`.
- IOPBOOT 4,448 bytes, ROM offset `0x04A000`, execution in ROM at `0xBFC4A000`.
- IOPBTCONF 234 bytes, ROM offset `0x01EC90`, address `0xBFC1EC90`; `@800` followed by **29 modules**, with SECRMAN at #28 and EESYNC at #29.
- IOPBTCON2 195 bytes, ROM offset `0x01ED80`, address `0xBFC1ED80`; `@800` followed by **24 modules**, with SECRMAN at #22, SIO2MAN at #23 and MCMAN at #24.
- EELOAD 61,840 bytes, ROM offset `0x0D0FF0`, copied into EE RAM at `0x00082000`; first nonzero code word at `0x00082008`.
- KERNEL 95,208 bytes, ROM offset `0x392F70`, copied into EE RAM at `0x80000000` and entered at `0x80001000` (offset +0x1000). Do not load raw KERNEL bytes at the entry address.

## Prepared imports, not yet executed by user
A local user-downloadable ZIP was generated and verified containing nine analysis-only ELF32-MIPS wrappers, the ASCII boot configs, a README, JSON SHA-256/segment manifest, and a reproducible Python generator. The ZIP exists as a conversation artifact, not in this GitHub repository. No proprietary BIOS payload was pushed to GitHub.

**Primary imports** (two separate Ghidra programs):
1. `BOOTFLOW_EE_combined_20261015_v1.elf`: RAM EELOAD `0x00082000`, RAM KERNEL `0x80000000`, ROM RESET `0xBFC00000`, ROMDIR `0xBFC02780`. Entry reset vector `0xBFC00000`; ELF `e_flags=0x20920000` (MIPS III + R5900 machine) for extension language `r5900:LE:32:default`.
2. `BOOTFLOW_IOP_combined_20261015_v1.elf`: ROM RESET, ROMDIR, IOPBTCONF, IOPBTCON2, IOPBOOT mapped at addresses above. Entry reset `0xBFC00000`; ELF `e_flags=0` MIPS I for IOP language (Ghidra typically `MIPS:LE:32:default`).

**Optional standalone wrappers:** RESET_EE, RESET_IOP, IOPBOOT_IOP, KERNEL_EE, EELOAD_EE, IOPBTCONF_IOP, IOPBTCON2_IOP.

All ELF program headers, section mappings, entry points, flags, symbols, and mapped payload SHA-256 hashes were verified using `readelf`, `llvm-objdump`, and a ZIP manifest integrity pass. They are **synthetic analysis containers**, not authentic Sony ELF files, and have not yet been imported into the user's actual Ghidra 12.1.3 installation. The user needs only to select the two combined ELFs through File → Import File and verify Ghidra's selected languages before auto-analysis.

## Important context to preserve
- Earlier successful SECRMAN and DECKARD programs already exist. They should remain separate, not discarded or treated as boot entry points.
- Last completed DECKARD work recovered `void UpdateSerialControlStateWithTiming(uint controlWord)` at `0xFFFFD5EC`, verified 87 original firmware words, applied two datatypes, one new function, one rename, three signature refinements, eight labels and 26 comments, preserved one existing `undefined4` declaration. Do not repeat that work without a reason.
- The overall objective is MagicGate, especially differences between retail PS2 startup, disc/security/card/KELF boot paths, and PCSX2 behavior. Do not expand further into general DECKARD firmware details unless a direct security connection emerges.

## Next step
After the user imports the two combined ELF images and allows analysis, inspect the actual RESET branches and IOPBOOT/EE kernel/EELOAD entry references. Reconstruct verified boot handoffs before introducing SECRMAN and MagicGate-specific calls. IOPBTCONF versus IOPBTCON2 are distinct boot configurations; do not flatten them into a single ordered module list.
