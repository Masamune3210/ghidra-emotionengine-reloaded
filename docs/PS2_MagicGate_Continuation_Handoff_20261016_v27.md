# PS2 MagicGate continuation v27: correct-disc Ghidra v3 reports and DNAS -404 provenance (2026-10-16)

Branch: `testing`. Previous: [v26](PS2_MagicGate_Continuation_Handoff_20261016_v26.md).

## New user evidence and confirmation

User ran `ApplyAndTracePlayOnlineDnas97269_20261016_v3.java` on both **correct** second-disc Ghidra programs and supplied the complete 671-line decompilation reports `2(3)` (CD `SCUS_972.69`) and `3(3)` (HDD `POL_HDD.ELF`). Both decompile named `ProcessDnas1AuthenticationStatus`, `LogDnas1StateChanges`, `IsDnas1ProcessingState`, `ClearDnas1RetryScratchWindows`, `ZeroByteSpan` etc. The user did not supply console `[DNAS97269V3] SUMMARY` counts, so don't assert 0 failures for v3; the report itself confirms export and those names. V2 had already succeeded with 0 failures for each.

### Directly confirmed second-disc DNAS control-flow path

| Purpose | CD SCUS_972.69 | HDD POL_HDD.ELF |
|---|---|---|
| DNAS authentication/status handler | 0x0080EAF8 | 0x0080E308 |
| Authentication operation invoked in handler case 9 | 0x001984D8 | 0x001985D8 |
| Error-code translator, maps -404 to -1562 | 0x00192B80 | 0x00192C80 |
| Explicit -404 comparator in translator | 0x00192BCC | 0x00192CCC |
| -1562 value (delay slot of branch after matching -404) | 0x00192D50 | 0x00192E50 |
| Status setter with patcher Mode 3 status 6 site | 0x00192FE0 | 0x001930E0 |
| Status-6 literal, `addiu v0,zero,6` | 0x00193084 | 0x00193184 |
| Internal status triple/global | 0x001F5898 | 0x001F5998 |
| Authentication operation's explicit -404 value | 0x00198538 | 0x00198638 |
| Earlier initial auth check | 0x001B94E8 | 0x001B95E8 |
| Earlier secondary check controlling direct -404 | 0x001B9850 | 0x001B9950 |
| Other gate checked before operation continues | 0x00193408 | 0x00193508 |

The v3 handler calls the authentication operation (case 9, after local setup) and maps any negative result via the translator; on later state 10, state 6 and error -109 specifically trigger DIFFERENT_HDD retry. State 5/8 are handled as terminal/accepted by the status check. Thus -109 retry != -404 report.

**Important new finding:** Direct `llvm-objdump` of the actual uploaded original EE ELFs verifies the authentication operation **itself can return -404**: after a positive initial check, it calls a secondary check at CD 0x001B9850 / HDD 0x001B9950; if the secondary check returns 0, it branches to return with `addiu v0,zero,-404` at CD 0x00198538 / HDD 0x00198638. Source and semantics of secondary-check result are NOT yet resolved. **Do not simply assume -404 originated in hardware/HDD verification or server reply.** Next analysis should decompile secondary/initial checks and their callers.

**Patcher context:** Mode 5 reported BIN offsets 0x1987E8,0x198E1C (CD),0x3CBDD8,0x3CC40C (HDD). Prior source mapping translates these to the above `MapDnasErrorToClientCode` and status-setter code; direct disassembly verifies the Mode 3 instruction sets value 6 in a MIPS branch delay slot when result code 10 is handled, other nearby result codes set states 5/7. The patcher may force a software success status, which does NOT validate hardware identification or cryptographic binding.

### Mandatory correction of erroneous v3 metadata

The prior v3 handoff and script **incorrectly claimed `ZeroByteSpan` returns the requested length** and attempted signature `uint ZeroByteSpan(byte *buffer,uint length)`. Actual Ghidra decompilation AND original source disassembly at CD 0x00135178/HDD 0x00135238 establish:

```text
byte * ZeroByteSpan(byte * buffer, long length)
```

The return is the start `buffer` when `length != 0`, and null when length is zero. Routine performs reverse-order 8-bit stores; no return of count. Argument `length` is kept as existing Ghidra `long` because 64-bit EE register comparison appears in the decompilation; don't rewrite unresolved width without proof. Only correct return and first arg while preserving user-defined signature. Previous code comment must be corrected as well. This matters because called twice by `ClearDnas1RetryScratchWindows`.

### Directly applicable metadata additions

```text
Structure: /PlayOnline/DNAS/DnasClientStatusTriple
Size: 0xC
0x00 int state
0x04 int errorOrFlags
0x08 int progress

CD 0x001F5898 Type DnasClientStatusTriple
HDD 0x001F5998 Type DnasClientStatusTriple

CD 0x00192B80 -> MapDnasErrorToClientCode
HDD 0x00192C80 -> MapDnasErrorToClientCode
Return int; existing arg2 remains unresolved.

CD 0x00192FE0 -> UpdateAuthenticationStatusFromResult
HDD 0x001930E0 -> UpdateAuthenticationStatusFromResult
Signature unresolved.

CD 0x001984D8 -> PerformDnasAuthenticationOperation
HDD 0x001985D8 -> PerformDnasAuthenticationOperation
Signature unresolved; operation's direct -404 return may depend on secondary check result.

CD 0x00135178 -> ZeroByteSpan
HDD 0x00135238 -> ZeroByteSpan
byte * ZeroByteSpan(byte * buffer, long length)
```

### Deliverable and next step

Created user-facing **Ghidra metadata APPLY + optional focused decompiler exporter** `ApplyPlayOnlineDnasErrorPath_20261016_v4.java`. It verifies the actual source bytes of both variants, defines status-triple datatype (before use), cautiously applies when global is undefined, renames/comment four verified functions preserving user-created names and unresolved signatures, corrects the prior v3 ZeroByteSpan return and misleading comment, and optionally exports targeted code for translator, setter, authentication operation and checks at 0x1B94E8 and 0x1B9850, plus original zeroing routine. Never patches executable code or fabricates hardware IDs. **v4 has not yet been compiled/run in the user's Ghidra**.

Next user action: run v4 in CD Ghidra, save report, upload report and `[DNASERRV4]` console summary. HDD can then be compared. Avoid redoing prior v2/v3 or requiring genuine Sony HDD. Main question is the meaning of secondary-check return 0 and its relation to -404.
