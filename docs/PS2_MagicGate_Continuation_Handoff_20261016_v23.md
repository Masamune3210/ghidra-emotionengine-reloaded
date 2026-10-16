# MagicGate / DNAS investigation v23: critical two-disc provenance correction (2026-10-16)

**Branch:** `testing`. Continue from [v22](PS2_MagicGate_Continuation_Handoff_20261016_v22.md).

## Correction from user

User discovered that **Final Fantasy XI Online** and **PlayOnline Viewer and Tetra Master** are separate installation discs. Earlier investigation accidentally treated the FFXI game disc as the failing PlayOnline installer because disc naming doesn't clearly identify which is disc one. The discs must no longer be conflated:

| Disc | Serial | Scope |
|---|---|---|
| Final Fantasy XI Online, first disc | `SCUS_972.66` | All previously uploaded `INSTALL.ELF`, `SCUS_972.66`, eight encoded `.ERX`, `DANCER.ENC`, `POLKEY.DAT`, and the split full FFXI disc archive |
| PlayOnline Viewer and Tetra Master, second disc | `SCUS_972.69` | The disc originally run in PCSX2 when pursuing the PlayOnline install / Sony DNAS `-404` issue |

**The identified failure cannot be attributed to the first disc solely because the game's INSTALL.ELF contains PlayOnline or auth-related function names**. First-disc's `LastDnasError` formatting and the `(s%04d)` suffix are valid discoveries in that file, not proven call paths in the second disc installer. Likewise FFXI `POLKEY.DAT` and Dancer are not established causes of second-disc DNAS rejection.

## Preserve useful finished work

Keep all provenance-tagged FFXI `SCUS_972.66` discoveries and Ghidra applied metadata:
- v4 and v5 scripts successfully applied error-flow structures, 9 returns, 12 parameter changes, 13 comments, and all four correctly typed globals in **FFXI first-disc INSTALL.ELF**.
- CCC main BSS mapping restored; remaining 1219 unmapped functions are absent Dancer overlay bytes, not general importer failure.
- All eight encrypted first-disc ERX wrappers recovered to IOP IRX ELF files using `SQIOPMEM.IRX`. No reason to discard decoder.
- `DANCER.ENC` and `POLKEY.DAT` were analyzed but did not reveal the failing disc's DNAS verifier.

## Highest priority next work

1. Inspect **second disc `SCUS_972.69`** and its own boot, `INSTALL.ELF` (if present), IRX/ERX modules, loader chain, and crypto/auth RPC. Collect exact second-disc executable/module names and bytes before assigning roles.
2. Locate the source of Sony DNAS `-404` and distinguish HDD bind/security identity RPC from PlayOnline/game key authentication and user-facing POL error formatting.
3. Compare second-disc IOP services with already characterized MechaCon SCMD, DEV9 ATA security-identify and candidate DNAS-specific RPC. Run targeted runtime trace as needed. PCSX2 existing `[DNASLBA]` instrumentation on `note-working/magicgate-scmd-boundary-trace-20261016` remains available but is not yet runtime-verified.
4. Investigate previous Ghidra export `SCUS_973_95_sectionless_import_v1.elf` only for HDD Utility context: it is a **different title**, not a substitute for the PlayOnline disc.

Do not request a genuine HDDID or genuine Sony HDD: user has no original Sony HDD. Do not re-run the already completed first-disc CCC metadata appliers or investigate Dancer further as a blocker.

**Project rule:** Every new Ghidra Java analysis script should apply verified metadata (datatypes, names, signatures, comments) as well as report findings; preserve unresolved signatures and named/typed user data.

## Verification

Correction based on user's explicit identification of two physical/software installation discs and their serials and previous PCSX2 logs, **not** a new decompilation of the second disc. Second-disc program bytes have not yet been supplied in this current thread. No new code changes or database modifications in this update.
