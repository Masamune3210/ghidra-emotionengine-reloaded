# PS3 GXEMU MagicGate UART10 handoff v10 (2026-10-16)

Branch `testing`. Previous detailed [v9](PS3_GXEMU_VUART10_MAGICGATE_HANDOFF_20261016_v9.md). Treat v9 technical discoveries as valid, **but run the corrected script v2 rather than its now-deleted v1**.

Verified from user-supplied read-only audit:

- `ReceiveVirtualUartChunk@0x8FC68` has a real ELFv1 callback: at `0x8FD14` saves r2, at `0x8FD18` loads callback environment into r11, at `0x8FD1C` loads callback TOC into r2, at `0x8FD20` calls via CTR, and at `0x8FD24` restores r2. Do NOT force a single r2 context across the entire function.
- `FUN_0024F718` conditionally translates a buffer address using `address & 0xFFFFFFFFFFFDFFFF` and globals `PTR_DAT_00677720` and `PTR_DAT_00677728`. Directly Ghidra-applicable suggested name and signature: `ulong TranslateMappedBufferAddress(ulong candidateAddress)`. No extra args; only existing parameter name changed when safely available.
- `FUN_0024F95C` sends `0xFACE`/0x70 UART-10 control frame, issues a `sc 0`, conditionally copies 3×16-byte regions, byte-reverses up to 3×8-byte fields, XORs first five bytes of each with a nonzero timebase low byte, then saves flags and byte. This *might* be part of a handshake but is not confirmed native MagicGate crypto.
- Code instructions `0x251044` and `0x25106C` call the two alternate packet senders but are not assigned to functions. Branches within the `0x250Dxx..0x2510xx` flow suggest a missing larger dispatcher. Do NOT create arbitrary fragment functions.
- Ghidra database already has 9 verified generic transport function renames, 7 typed BE64 24-byte function descriptors, 4 named/typed TOC globals, `GxemuVuart10FramePrefixBE` (16-byte datatype) and `GxemuVuart10TransferState` (24-byte datatype). These remain applied.

## Next runnable Ghidra Java script

**`ghidra_scripts/RefinePs3GxemuCallbackAndDispatcher_20261016_v2.java`** committed to `testing`. v1 was deleted after discovering its translator-name evidence check expected literal global addresses while the Ghidra decompiler emits `PTR_DAT_00677720` and `PTR_DAT_00677728`. v2 recognizes both spellings.

V2:
- Verifies precise callback instructions and receiver OPD, refines transfer state field +0x00 to `Ppc64FunctionDescriptor24*` when safe and comments at the callback site.
- Renames `FUN_0024F718` only after decompilation validates mask, globals and all 4 expected references; only renames first existing 8-byte `param_1`, preserving return/arg types.
- Checks OPD `0x00670428` for `FUN_0024F95C`; only if entry/toc/environment match and no r2 writers/conflicting context, scopes r2 to TOC `0x678548`. Decompiles it regardless.
- Read-only scans prologues, return boundaries and cross-refs in the unowned dispatch region `0x24FF00..0x25109B`.
- Does not modify executable bytes or speculative function boundaries.

**Not yet run or compiled in user's Ghidra**. Upon receipt of output, use confirmed function/descriptor findings and pursue native KELF `0x8F` implementation through actual message semantics, never numeric coincidences with outer UART packet class `0x90`. PCSX2 branch `note-working/magicgate-hdd-utility-header-validation-20261016`, DNAS parked.
