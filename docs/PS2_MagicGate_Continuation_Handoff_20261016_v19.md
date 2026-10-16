# PS2 MagicGate continuation v19: v4 metadata applied, global-slot correction pending

Branch: Masamune3210/ghidra-emotionengine-reloaded testing. Previous: docs/PS2_MagicGate_Continuation_Handoff_20261016_v18.md.

## User's actual v4 execution output

User uploaded 1012-line text report `t` from `ApplyAndAuditInstallElfAuthFlow_20261016_v4.java` on SCUS-97266 `INSTALL.ELF`.

`[AUTHMETA] SUMMARY mapBlocks=0 definedData=0 labels=0 functionsRenamed=0 returns=9 parameterUpdates=12 comments=13 preserved=4 failures=0`.

CONFIRMED: script compiled and ran to completion; v4 registered `/PlayOnline/PlayOnlineErrorRangeEntry` size 0x10 and `/PlayOnline/PlayOnlineErrorMapHeader` size 0x8; refined 9 return types, 12 parameters, 13 function comments. Zero BSS blocks needed because earlier main BSS mapping is intact. This is actual database modification, not just an audit.

**Important limitation:** v4 preserved all four global data definitions because they already had defined data at their addresses; that log does *not* establish each existing datatype is correct. The exporter only showed names and reference flows, not the actual data types. Avoid describing them as refined until checked:
- 0x00593CD0 ErrorLevel : desired `int` (32-bit SW/LW)
- 0x00593CD4 LastDnasError : desired `int`
- 0x00593CD8 LastAolError : desired `int`
- 0x0043E408 p_polconData : opaque `void *` pointer only if current type is undefined; preserve existing more specific pointer type.

New unique conversation script `RefineInstallElfAuthGlobals_20261016_v5.java` repairs ONLY these four database slots if currently undefined; it uses `DataUtilities.createData(..., CLEAR_ALL_UNDEFINED_CONFLICT_DATA)` after checking every covered byte for non-undefined data/instructions. Preserves all concrete existing types, symbols and user defined definitions. Prints before/after effective datatype and action for each. Does not reexport the entire 1000-line flow report. Ghidra 12.1.3 runtime/compile pending user.

## Decompiler and call-graph details from v4

- `sqPlayOnlineSetErrorLevel`, getter, DNAS/AOL setters now typed `void`/`int` with readable parameters; SetError arg0 typed `PlayOnlineErrorMapHeader *` and remaining argument names have been applied. This header typing improves count access but does **not** represent the 16-byte records as an inline array in C. `PlayOnlineErrorRangeEntry` definition exists separately; do not mistakenly assume inferred `pPVar9`'s `PlayOnlineErrorMapHeader *` stride expresses an array type.
- `SetError` still only formats an error, with `POL-1562` = 0x61A in its Sony auth range; `LastDnasError` holds absolute value of negative `-404` for `(s0404)` suffix. No identified origin of DNAS -404.
- `sqPolconCheckNetDevice` is a network device enumeration path with `IrxDecrypt`, not verified DNAS verifier.
- `checkHdd__11FsInstallerFv` at 0x002DCAF0 failed decompilation again with `Recoverable Error: Unable to find unique hash for varnode`. Do not fabricate its signature or assume this is DNAS.
- `_getError__5FsHddFi` return corrected to `char *`, second arg named `hddErrorCode`.
- `__sqPolSetAuthErrorCode` setter still has no direct Ghidra internal XREF in main code. Further path can be in indirect calls, overlay or separately loaded code, but none established.

Off-line targeted `readelf -rW INSTALL.ELF` examination of `.relDancer.bin` (~22,692 records) found no relocation line whose *symbol name* contains Dnas, DNAS, Auth, Hdd, `sqPol`, or `SetError`. This negative does not rule out indirect or anonymous-symbol references; **do not conclude Dancer has no auth code**. User has not provided actual `DANCER.ENC`; it is not available for decompilation.

## Next user action

Run conversation Ghidra v5 script and supply only `[AUTHGLOBAL]` status output. No need to re-run the v4 decompiler export. Investigate actual DNAS-return code afterward, preferably with a verified identity module/guest function or DANCER.ENC if source indicates relevance. Continue to apply metadata in all future Ghidra scripts, unless intentionally read-only.

Verification: v4 Ghidra runtime passed (0 failures), v5 static API checked against Ghidra upstream but not yet runtime-tested.