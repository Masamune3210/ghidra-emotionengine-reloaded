# PS2 MagicGate continuation v18: applied metadata and auth-flow report (2026-10-16)

Supersedes [v17](PS2_MagicGate_Continuation_Handoff_20261016_v17.md). Database under examination: user's SCUS-97266 INSTALL.ELF, with main virtual BSS successfully mapped. User explicitly clarified that **future Ghidra scripts must apply verified metadata to the database**, not merely print audit findings. Audit-only scripts from earlier turns left useful types/signatures unapplied; do not repeat this failure.

## Evidence supplied by user

User ran corrected v3 `AuditInstallElfAuthErrorFlow_20261016_v3.java`, and supplied its complete 918-line output. The exported decompiler indicates:
- `ErrorLevel` 0x00593CD0, `LastDnasError` 0x00593CD4, `LastAolError` 0x00593CD8: SW/LW 32-bit scalar globals, source ELF STT_NOTYPE with 0 length.
- Setter/getter functions 0x0035F500, 0x0035F510, 0x0035F520 and 0x0035F540: established int parameters/return or void return. Setter normalizes signed negative error and stores magnitude.
- `SetError` 0x0035F600 has 5 existing parameters; first is pointer to a table whose count is at +0x04 and 0x10-byte entries start +0x08. Entry consists of two inclusive int range bounds (+0,+4), a debug string pointer (+8) and user string pointer (+C), each 32-bit. Confirmed in `sqPlayOnlineMapErrorCode` 0x0035F560, which decrypts table and relocates the two pointers per entry.
- `SetError` formats `(s%04d)` for primary absolute error codes 0x600..0x67F or 0x3181..0x3282, except special 0x814, if LastDnasError nonzero. POL-1562=0x61A is within this group. Error formatter is not site of DNAS -404 generation.
- `sqPlayOnlineIsRecoverableError` 0x0035F4A8 returns 1/0 based on MajorErrorCodeTab bit mask; signedness of original `uint` parameter remains unresolved.
- `sqPlayOnlineGetUserErrorCode` 0x0035F810 and `sqPlayOnlineGetDebugErrorCode` 0x0035F818 are tail-jump wrappers to SetError with mode 0 and 1 respectively; decompilers mistakenly inline much of SetError into wrappers.
- `gcPolLoginProcLoop` 0x001F2500 returns 0 or -1 and stores a pointer in `p_polconData` 0x0043E408.
- `sqPolconCheckNetDevice` 0x0026ED98 invokes `IrxDecrypt` on a provided buffer if length != -1 and checks available IOP network devices; no evidence it implements DNAS.
- `_getError__5FsHddFi` 0x002DF2D0 has a decompilation proving it writes an error message to its object at +0x104 and returns a pointer to this buffer (despite initial int return type). 2nd param is int HDD error code.
- `checkHdd__11FsInstallerFv` 0x002DCAF0 still does not decompile: `Recoverable Error: Unable to find unique hash for varnode`. Preserve unresolved prototype.

## Source-backed datatype definitions

Structure: `PlayOnlineErrorRangeEntry`, size 0x10, category `/PlayOnline`
```text
0x00 int firstErrorCode
0x04 int lastErrorCode
0x08 char * debugMessage
0x0C char * userMessage
```
Structure: `PlayOnlineErrorMapHeader`, size 0x08, category `/PlayOnline`
```text
0x00 undefined4 unknown00
0x04 int rangeCount
```
Immediately following header, a flexible sequence of the above 0x10-byte records. The field at 0x00 remains unresolved; do NOT invent a version or length.

## Database-apply script

Generated downloadable `ApplyAndAuditInstallElfAuthFlow_20261016_v4.java` (541 lines, unique name/class). It:
- Checks program identity/mapped executable functions, idempotently restores *only* gaps in main BSS 0x0043DD80..0x0059C7FF without inventing Dancer contents.
- Defines above two structured datatypes, then labels/types three error globals as 32-bit signed `int` and `p_polconData` as `void *` only if no existing defined data overlaps.
- Refines only established function returns, and parameter names/types where direct evidence supports them. **Preserves user-defined function signatures and parameter names, nontrivial existing return types, and unresolved parameters**. Applies a verified int -> char* repair to `_getError` unless signature is user-defined.
- Uses `/PlayOnline/PlayOnlineErrorMapHeader *` for SetError param0 if it currently has a 32-bit int/undefined and no user-defined signature; preserves all other unresolved types.
- Adds idempotent non-destructive function comments with the evidence and explicitly does NOT treat message formatting as DNAS verification.
- Prints change counts and prompts for an OPTIONAL new export destination to generate the same XREF/decompilation report as v3, now after metadata application. Cancelling export does not undo metadata; it refuses overwrite.
- Does **not** map, invent, disassemble, or type missing Dancer executable content. Does not rewrite original 542 invalid CCC vtable descriptive aliases.

Verification: local Java syntax check attempted without installed Ghidra JARs (unable to compile against runtime in this environment). Confirmed relevant API signatures from upstream Ghidra sources (`DataTypeManager.getDataType(CategoryPath,String)`, PointerDataType constructors, `Listing.createData(Address,DataType)`, `Function.setReturnType`, `Variable.setDataType`, `getSignatureSource`, `Undefined.isUndefined`). **Script v4 still requires actual user Ghidra 12.1.3 compile/execution validation**. No repo code implementation changed.

Next step: user runs v4 on existing repaired INSTALL.ELF, provides `[AUTHMETA]` output and if export chosen the `.txt` report; if Ghidra compiler reports an error, fix incrementally with a **new version suffix**, not same filename. Then trace the actual DNAS -404 origin, not just the error formatter.
