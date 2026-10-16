# PS2 MagicGate continuation v22: correct Dancer/POLKEY research priorities (2026-10-16)

Branch: Masamune3210/ghidra-emotionengine-reloaded testing. Previous: docs/PS2_MagicGate_Continuation_Handoff_20261016_v21.md. This is a research prioritization correction, not evidence of decryption or recovered DNAS verification logic.

## User-supplied external research

The user found references indicating DANCER is associated with FFXI character creation, whereas POLKEY is used to authenticate the game with PlayOnline. These interpretations are relevant hypotheses; the precise characterization of each file was not independently established by direct static code inspection in this turn. External public search found a 2014 community discussion describing POLKEY.DAT as key material used with PlayOnline, but not an authoritative protocol/format specification. The installer evidence supports copying POLKEY.DAT, not its exact authentication semantics.

## Reassess scope

- Deprioritize expensive DANCER.ENC decryption as a prerequisite to MagicGate/DNAS investigation. Original overlay has 1219 function symbols, missing body bytes, and no independently established link to the Sony DNAS -404 verifier; possible character-creation use explains independent overlay path. Keep original Dancer source metadata intact and ready for separate investigation.
- PRIORITIZE POLKEY.DAT (opaque 0x10010 bytes). In the user's *actual* SCUS-97266 INSTALL.ELF, init__11FsInstallerFv references and copies `cdrom0:\\POLKEY.DAT;1` to `pfs1:/polkey.dat` via _copyFile. This establishes installation of the data file, NOT what authenticates it and NOT that POLKEY explains DNAS -404.
- Distinguish PlayOnline application/game authentication from Sony DNAS console/disc/HDD authentication. FFXI licensing describes Sony DNAS as a distinct PS2 platform authentication component. Do not infer a direct connection between POLKEY and HDD-binding failure without tracing consuming code.
- The `sqpolkey.bin` name in sqPlayOnlineGetFileName selector 4 should not be equated to disc POLKEY.DAT without evidence. SqPolKeyboardId/No/KeyCodeTable remain keyboard-related.

## Verified work to retain

- Auth flow error reporting: LastDnasError 0x00593CD4 gets magnitude from __sqPolSetAuthErrorCode 0x0035F520 and is formatted by SetError 0x0035F600. POL-1562 (0x61A) falls into (s%04d) formatting range, but -404 source remains unknown.
- v4 and v5 Ghidra apply scripts have already been run on INSTALL.ELF. v4 changed return types=9, parameter updates=12, comments=13, created error structures. v5 correctly typed ErrorLevel, LastDnasError, LastAolError int32 and p_polconData void*. No need to ask for repetition or hand out already-applied metadata.
- FFXI original disc archive 2-part ZIP and its contents including DANCER.ENC, POLKEY.DAT, SCUS_972.66 have been supplied previously. Do not ask user to re-upload available files.

## Next technical action

Investigate *consumers* of `pfs1:/polkey.dat` and the FFXI PlayOnline authentication path, then correlate only established interactions with the Sony DNAS error and IOP identity RPC. Use INSTALL.ELF/SCUS_972.66 symbols and the already recovered 8 ERX-to-IOP modules; pursue independent DNAS RPC tracing if needed. For any useful new Ghidra discoveries, provide a script that APPLIES verified types, function signatures, labels, and comments, rather than only printing them.

No new Ghidra metadata proved by external file-purpose claim alone, so this handoff changes priorities, not database annotations.
