# PS2 MagicGate continuation v16: source-verified PlayOnline error presentation path

**Database:** user's SCUS-97266 `INSTALL.ELF`, post-main-BSS Ghidra repair. **Previous:** [v15](PS2_MagicGate_Continuation_Handoff_20261016_v15.md). Branch: `testing`.

## User Ghidra audit confirmed

The user's `AuditInstallElfDnasReferences_20261016_v1.java` log shows:
- `0x00593CD4` `LastDnasError`, in correctly mapped uninitialized `INSTALL_main_uninitialized_1`, has WRITE from `__sqPolSetAuthErrorCode` at `0x0035F53C`, READ from `SetError` at `0x0035F694` and `0x0035F6A0`. Three XREFs.
- `0x0043E408` `p_polconData` has two GP-relative xrefs from `gcPolLoginProcLoop` at `0x001F25BC` and `0x001F25C0`.
- `checkHdd__11FsInstallerFv` at `0x002DCAF0` called from `init__11XiInstallerFv` at `0x00320D74`.
- `_getError__5FsHddFi` at `0x002DF2D0` called by 7 HDD filesystem/partition operations.
- `sqPolconCheckNetDevice` at `0x0026ED98` has no direct internal Ghidra XREF recorded.
- mapped original vtable symbol instances=641, distinct addresses=641. Earlier *raw ELF* count of names beginning `__vt__` was 542; these represent DIFFERENT notions/counts. Do not equate current 641 Ghidra instances with 542 CCC rejected human-friendly virtual-table aliases and do not claim all alias names were recovered.

## Newly verified disassembly (LLVM MIPS disassembly directly on uploaded INSTALL.ELF)

```text
0x00593CD0 -> ErrorLevel      (ELF STT_NOTYPE size 0; effective 4-byte scalar)
0x00593CD4 -> LastDnasError   (ELF STT_NOTYPE size 0; effective 4-byte scalar)
0x00593CD8 -> LastAolError    (ELF STT_NOTYPE size 0; effective 4-byte scalar)

0x0035F500 -> sqPlayOnlineSetErrorLevel
void sqPlayOnlineSetErrorLevel(int level)

0x0035F510 -> sqPlayOnlineGetErrorLevel
int sqPlayOnlineGetErrorLevel(void)

0x0035F520 -> __sqPolSetAuthErrorCode
void __sqPolSetAuthErrorCode(int errorCode)

0x0035F540 -> __sqPolSetAolErrorCode
void __sqPolSetAolErrorCode(int errorCode)

0x0035F600 -> SetError
PROTOTYPE UNRESOLVED: keep existing type, parameters and calling convention.

0x0035F810 -> sqPlayOnlineGetUserErrorCode
0x0035F818 -> sqPlayOnlineGetDebugErrorCode
Both are wrappers using direct 'j 0x0035F600' with mode argument 0 and 1 respectively. Preserve unresolved signatures.
```

At `0x0035F520`, `__sqPolSetAuthErrorCode` normalizes a negative signed input to its absolute value (except signed-min overflow) and stores the result using a 32-bit SW to `LastDnasError` at `0x0035F53C`. Analogous logic at `0x0035F540` stores `LastAolError` at `0x0035F55C`.

`SetError` normalizes its main user-facing code to positive; branches at `0x0035F674..0x0035F698` explicitly choose the Sony authentication-error suffix for primary error ranges `0x600..0x67F` and `0x3181..0x3282` (unless the input matches the earlier special `0x814` branch), using `LastDnasError` if nonzero. Format string **at 0x0042C6D0** is the exact bytes `(s%04d)`. `LastAolError` is formatted with `(a%04d)` at 0x0042C6D8. The main fallback string at 0x0042C6E0 is `UNKNOWN ERROR [%d]%s`, and 0x0042C6F8 is `%s%s`.

The reported PlayOnline main error `POL-1562` corresponds to decimal 1562 / hex `0x61A`, which falls in the `0x600..0x67F` Sony authentication category. A lower-level negative `-404` passed to `__sqPolSetAuthErrorCode` would be stored as `404` and printed `(s0404)` by the matching branch. **This confirms error code presentation semantics, not yet the underlying DNAS verification/rejection site.**

Offline scan of ALL file-backed main executable instruction words (range `0x00100000..0x0043DD7F`) found ZERO direct JAL targets to `__sqPolSetAuthErrorCode`, `SetError`, `sqPlayOnlineMapErrorCode`, or `sqPlayOnlineGetUserErrorCode`. The getter wrappers instead use `j` to SetError. This is not evidence that the functions are unused: dynamic/indirect calls or the separate `Dancer.bin` overlay (whose ELF segment has zero file-backed bytes) may be their consumers.

## Concrete next script

A read-only report exporter `AuditInstallElfAuthErrorFlow_20261016_v2.java` has been generated as conversation download, **not compiled/tested in Ghidra**. It prompts for a fresh output text file path, refuses overwrite, and decompiles:
`sqPlayOnlineIsRecoverableError`, `sqPlayOnlineSetErrorLevel`, `sqPlayOnlineGetErrorLevel`, `__sqPolSetAuthErrorCode`, `__sqPolSetAolErrorCode`, `sqPlayOnlineMapErrorCode`, `SetError`, `sqPlayOnlineGetUserErrorCode`, `sqPlayOnlineGetDebugErrorCode`, `gcPolLoginProcLoop`, `sqPolconCheckNetDevice`, `checkHdd__11FsInstallerFv`, `_getError__5FsHddFi`, plus the globals above. It records Ghidra XREFs, function prototype, memory coverage and decompilation.

The user should run it on the repaired `INSTALL.ELF`, upload the resulting text file, and then follow the error setter backwards via actual caller evidence. The `DANCER.ENC` file remains a reasonable separate investigation since the reserved `Dancer.bin` code itself is missing, but it is *not proven* to implement DNAS.

**No new Ghidra extension code or PCSX2 code changes committed in this pass.** Source-supported metadata above can be applied manually. Unresolved prototypes must remain unresolved.
