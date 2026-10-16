# PS2 MagicGate continuation v21: FFXI complete disc and Dancer overlay loader (2026-10-16)

**Branch:** `Masamune3210/ghidra-emotionengine-reloaded:testing`. Previous [v20](PS2_MagicGate_Continuation_Handoff_20261016_v20.md).

## User-supplied new evidence

Two-part `Final Fantasy XI - Online (USA, Canada).zip.001/.002`, ~641MB total. Joined locally without editing originals; indexed 101 entries, extracted target files for read-only analysis. This is unequivocally FFXI `SCUS_972.66`. Original archive is user-provided proprietary data, do not upload archive or decrypted binaries to public repository.

**DANCER.ENC**: 472,936 = `0x73768` bytes, SHA256 `42c599c13657bf7da7dfab1bacfca86ff973c47794c289bf0cbbf4f05db58aa9`, Shannon entropy ~7.99967 bits/byte. No recognizable ELF signature. Applying proven **SQIOPMEM IRX/ERX** decoder yields no ELF; the binary is **not** one of those ERX wrappers. Cipher/compression remain unknown, do not invent a decryption method.

**FFXI_POL.ENC**: 1,191,160 = `0x122CF8` bytes, SHA256 `90a3a4db4b4d7bff2cb5b2afd973c9097830e49bd2a7c6bd2f13d53fe28edc9d`, also opaque/high entropy. **POLKEY.DAT**: 65,552 = `0x10010` bytes, SHA256 `4a33f8e439fe70d3767349bff7e78eea36108a901ed81027b72e0a1eb746d614`. Do not assert its format/key.

**Critical discovery**: `SCUS_972.66` is a second, larger EE ELF (22,863,156 bytes), entry `0x100008`, *distinct from* `INSTALL.ELF` (5,577,756 bytes). SCUS ELF declares its own `Dancer.bin` PT_LOAD at `0x006AC890` with `p_filesz=0`, `p_memsz=0x919F0`: **it also lacks executable Dancer bytes**, and its BSS/layout addresses differ from INSTALL.ELF. Do NOT apply INSTALL.ELF Ghidra labels/addresses to SCUS program without separate verification. `LastDnasError` is at `0x006A3D74` in SCUS vs `0x00593CD4` in INSTALL. Neither symbol table directly names BBSYS101/libid2 or a DNAS verification routine.

## Source-verified INSTALL.ELF installer and Dancer loader

- `0x002DC440` `installEncFile__11FsInstallerFPc`: invokes `sceOpen`, `sceRead`, `sceWrite` to copy encrypted files; **no software decryption call is present in this routine**, which does NOT establish the eventual crypto processing.
- `0x002DE2D0` `_installElf__11FsInstallerFv`: registers and copies installed encrypted content.
- Source `pfs2:/tmp/\\FFXI_POL.ENC` at `0x00426560` -> destination `pfs1:/image/ffxi/prog/ps2/ffxi_pol.pex.enc` at `0x00426580`.
- Source `pfs2:/tmp/\\DANCER.ENC` at `0x004265B0` -> destination `pfs1:/image/ffxi/prog/ps2/dancer.enc` at `0x004265D0`.
- Separate `0x00365A90` `StOverlayRequest` opens **literal `host0:/image/ffxi/prog/dancer/Dancer.bin`** at `0x0042CB50`; gets file size and reads it. It is NOT the `pfs1:...dancer.enc` path. No decode is visible in this particular function.
- `0x00365960` `_StOverlayReadFinish__FPciPv`: checks overlay self-pointer at +0x08, flushes cache, initializes BSS based on +0x14 value, calls `__initialize_cpp_rts` with +0x18/+0x1C and marks loaded state.
- `0x00365BD0` `StOverlayFini`: state cleanup, cancellation of pending I/O.
- `s_overlayAddr` at `0x0043EBDC`, 4 bytes, pointer; `s_overlayDancer` at `0x0043EBE0`, 4 byte scalar; `s_overlayState` at `0x0043EBE4`, 4 byte state with observed 0 Idle, 1 Requested, 2 Failed, 3 Ready.

## Applicable Ghidra metadata and user deliverables

Prepared downloadable `AnnotateFfxiDancerInstallPaths_20261016_v1.java` (Ghidra Java; on INSTALL.ELF only): creates `/PlayOnline/DancerOverlayLoadState` (4-byte enum 0..3), cautiously types three overlay globals preserving already typed/user data, appends verified notes to 6 file-backed installer/overlay/auth setter functions. **This is an APPLY script**, not just an audit, following user's explicit standing preference. No dummy Dancer memory or overlay functions created; script logs all changes. Runtime compilation/execution not yet tested.

Prepared detailed source report `FFXI_Dancer_Archive_Analysis_20261016_v1.md` linked via conversation artifact (never rely on user having the private ZIP on GitHub).

Original INSTALL ELF Dancer source bounds remain: `0x0059C810..0x0062A97F`, reserved zero file bytes, text `0x0059C850..0x0060CFCF`, data `0x0060CFD0..0x0061D5FF`, BSS `0x0061D600..0x0062A97F`, 22,692 relocations. New raw encrypted file is NOT directly importable to those addresses.

## Analysis status and next action

Available static evidence is insufficient to decrypt DANCER.ENC into Dancer.bin or tie Dancer to the DNAS `-404` verifier. The actual loader/decryption bridge is **still missing**. Investigate what service reads `pfs1:/image/ffxi/prog/ps2/dancer.enc`, console-specific POLKEY data and runtime decryption path before claiming recoverability. Independently, inspect the obfuscated IOP identity RPC and error-code source; do not repeat hardware-HDD dump suggestions, user has no genuine drive.

User action: run new Ghidra metadata applier on **INSTALL.ELF only**, share `[DANCERMETA]` output and any compile errors. No need to rerun earlier CCC/v4/v5 scripts. This turn did not modify emulator or Ghidra extension source.
