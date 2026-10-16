# PS2 MagicGate continuation v32: HDD Utility protected header failure; DNAS parked (2026-10-16)

**Branch:** `testing`. Previous [v31](PS2_MagicGate_Continuation_Handoff_20261016_v31.md).

The user explicitly requested **stop DNAS research** and prioritize making official **HDD Utility Disc v1.10 USA SCUS-97395** boot and format a fresh PCSX2 HDD image. Prior PlayOnline `SCUS_972.69` Ghidra work, `POL-1562`/DNAS `-404`, DES protected `__net` path, and both successfully applied v6 databases are **parked, not invalidated**. Do not ask to rerun scripts or drift back to DNAS.

New PCSX2 user-built diagnostic log `Pasted text(20261016-171555).txt` confirms:
```text
[MG] hcode=0 cnum=0 a2=0 length=0x1A0
[MG] ELF_size=0x5370 Hdr_size=0x1A0 unk=0x100 flags=0x22C count=0 zones=USA
[MGTRACE] BIT offset=0x48 blockCount=33350 reserved=82,F5,E1 calculatedHeader=0x824C0 declaredHeader=0x1A0
[MGTRACE] BIT_FORMAT_REJECT reservedNonzero=1 lengthMismatch=1
[MG] ERROR - Make sure the file is already decrypted!!!
```

`mg_buffer+0x4C..0x4F` reads `46 82 F5 E1`. If parser's BIT position is correct and header is in expected plaintext form, it requires 20 entries with zero reserved bytes, not 33350. This supports a **missing decryption/authentication transformation versus unsupported BIT format**; do not infer which without source/decryption evidence.

PCSX2 user fork `Masamune3210/pcsx2` dedicated branch `note-working/magicgate-hdd-utility-header-validation-20261016` now contains safe input-format instrumentation (v1 user-tested) and additional `[MGFLOW]` SCMD handshake logging (not yet runtime tested). Branch [v2 handoff](https://github.com/Masamune3210/pcsx2/blob/note-working/magicgate-hdd-utility-header-validation-20261016/docs/hdd-utility-magicgate-header-probe-20261016-v2.md) is authoritative for build/test instructions.

**Potential Ghidra follow-up:** use previously characterized SECRMAN and DECKARD modules to reconstruct exact `0x80..0x97` MagicGate authentication and KELF header decryption sequence, *after* capturing latest SCMD trace. Apply any new verified function names, types, globals in runnable Ghidra scripts as usual. No new Ghidra database modifications were made from this runtime-only trace.
