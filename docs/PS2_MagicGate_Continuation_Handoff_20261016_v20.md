# PS2 MagicGate continuation v20: auth globals applied successfully

Branch: `Masamune3210/ghidra-emotionengine-reloaded:testing`. Previous: [v19](PS2_MagicGate_Continuation_Handoff_20261016_v19.md).

## Verified user Ghidra runtime result

User ran `RefineInstallElfAuthGlobals_20261016_v5.java` on the existing SCUS-97266 `INSTALL.ELF` database. It compiled, executed and printed:

```text
[AUTHGLOBAL] APPLIED ErrorLevel @00593cd0 int evidence=32-bit SW/LW
[AUTHGLOBAL] APPLIED LastDnasError @00593cd4 int evidence=32-bit SW/LW, absolute signed auth error code
[AUTHGLOBAL] APPLIED LastAolError @00593cd8 int evidence=32-bit SW/LW, absolute signed AOL error code
[AUTHGLOBAL] APPLIED p_polconData @0043e408 void * evidence=32-bit null-checked connection data pointer; pointee unknown
[AUTHGLOBAL] FINAL ErrorLevel @00593cd0 type=int size=4
[AUTHGLOBAL] FINAL LastDnasError @00593cd4 type=int size=4
[AUTHGLOBAL] FINAL LastAolError @00593cd8 type=int size=4
[AUTHGLOBAL] FINAL p_polconData @0043e408 type=void * size=4
[AUTHGLOBAL] SUMMARY applied=4 alreadyMatching=0 preserved=0 failures=0
[AUTHGLOBAL] No existing specific types, program bytes, function signatures, or Dancer memory were overwritten.
```

**Status:** v4 combined apply-and-audit script had previously completed in Ghidra with return types=9, parameter updates=12, function comments=13, created two `/PlayOnline` structures, failures=0. Its limitation was that existing undefined global data remained untyped. v5 has now **resolved that exact gap**, correctly defining all four 4-byte globals. Do not ask user to rerun v4 or v5; do not supply those as unapplied metadata.

## Still unresolved

`__sqPolSetAuthErrorCode` at 0x0035F520 stores absolute error magnitude to `LastDnasError` (0x00593CD4). `SetError` at 0x0035F600 reads it and attaches `(s%04d)` to appropriate error categories such as POL-1562. **Neither identifies what code returned DNAS -404**. No direct JAL XREF into the setter from the original main executable was found; calling path could be indirect or in code absent from INSTALL.ELF.

Dancer overlay reservation 0x0059C810..0x0062A97F declares 1,219 function symbols but ZERO executable bytes in INSTALL.ELF. Original FFXI disc directory contains `DANCER.ENC`; user has not uploaded it. This is a useful next file to request for overlay reconstruction, but not yet confirmed to contain DNAS verifier. Do not apply the unrelated ERX decryption algorithm to DANCER.ENC without evidence.

## Next step

Request `DANCER.ENC` to investigate reconstruction of original Dancer code/relocations. Continue pursuing the *actual* DNAS -404 return path instead of just the formatted error display. All future applicable Ghidra script outputs must **apply supported metadata**, not merely report it, and must preserve unresolved signatures/data without guessing.

Verification: Ghidra v5 was run by user, 4 types applied, 0 failures; no new analysis of DNAS verifier in this update.
