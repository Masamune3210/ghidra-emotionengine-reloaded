# PlayOnline DNAS / MagicGate continuation v29: decrypted __net path and access flags (2026-10-16)

Branch: `Masamune3210/ghidra-emotionengine-reloaded:testing`. Previous: [v28](PS2_MagicGate_Continuation_Handoff_20261016_v28.md).

## User-supplied paired decompilation

User supplied mirror routines **CD** `FUN_001b7480(ulong param_1)` and **HDD** `FUN_001b7580(ulong param_1)`. Both call an 8+8-byte acquisition routine (CD 0x001B7178/HDD 0x001B7278), build a path, write 8 bytes at output offsets 0x0C..0x13, NUL at +0x14, wipe temporary stack buffers, return 0 on success and negative helper error otherwise. Caller CD `FUN_001b8900`/HDD `FUN_001b8a00` uses this 21-byte constructed value as a pathname in file-open, offset seek, transfer, and close operations. DO NOT treat it as just an opaque identity buffer or assume these are directly MechaCon command IDs. Its first helper uses libcdvd S-command RPC IDs/arguments 0x1CB and 0x3B4; precise function/credential semantics unresolved.

## Exact offline DES reversal of original, correct-disc ELFs

Both executables contain identical DES-obfuscated literals. CD literal addresses are HDD address minus **0x130** in data; CD helper functions are HDD address minus **0x100** in code. The embedded DES key at CD 0x00205680/HDD 0x002057B0 is 8-byte ASCII `EP395gbq`, and `FUN_001b6fe8`/HDD `FUN_001b70e8` calls DES block-transform operations to decrypt static strings. Used `openssl enc -des-ecb -d -nopad -provider legacy -provider default -K 4550333935676271` to verify recovered plaintext **exactly**, no modification to binaries:

| CD ciphertext address | HDD ciphertext address | Input size | Exact decoded string |
| --- | --- | --- | --- |
| 0x00205690 | 0x002057C0 | 24 | `cdrom0:\SYSTEM.CNF;1` |
| 0x002056A8 | 0x002057D8 | 8 | `pfs0:` |
| 0x002056B0 | 0x002057E0 | 24 | `pfs0:/etc/access_flag` |
| 0x002056D0 | 0x00205800 | 16 | `hdd0:__net` |

The NUL-padded plaintext is not stored in cleartext at those addresses. Static ASCII suffix `2` at CD 0x002056C8/HDD 0x002057F8 is appended by CD `FUN_001b70b0`/HDD `FUN_001b71b0` to produce `pfs0:/etc/access_flag2`. Literal `,,` at CD 0x002056E8/HDD 0x00205818 is appended to `hdd0:__net` by CD `FUN_001b7480`/HDD `FUN_001b7580`; then an 8-byte dynamic suffix from `FUN_001b7178`/HDD +0x100 is copied, giving `hdd0:__net,,<8 bytes>` and NUL at offset 0x14. Suffix is **likely an APA partition credential** but its actual bytes and authorization semantics need tracing, not assumed.

PS2 Developer Wiki `https://www.psdevwiki.com/ps2/Hard_Drive` publicly documents `__net` APA partition, FPWD/RPWD 8-byte strings, and DNAS access flag paths with LBAs: `__net/etc/access_flag` -> 0x41008, `access_flag2` -> 0x4100C, `access_flag25` -> 0x41010. Documented DNAS behavior reads 2 sectors and compares first 16 bytes between consecutive LBAs. This supports relevance of path construction to PCSX2 trace but exact runtime branch and producer of -404 still unproven. **Keep distinction between wrapped CDVD RPC selectors 0x24/0x26 and raw MechaCon S-command bytes**, not established as identical.

## Directly applicable Ghidra metadata

Verified names, CD/HDD:
- 0x001B6FE8 / 0x001B70E8 -> `DecodeEmbeddedDesLiteral` (wrapper for DES static literal decode)
- 0x001B7010 / 0x001B7110 -> `DecodeSystemCnfDiscPath`
- 0x001B7070 / 0x001B7170 -> `DecodePfsMountPrefix`
- 0x001B70B0 / 0x001B71B0 -> `BuildDnasAccessFlag2Path`
- 0x001B7128 / 0x001B7228 -> `DecodeProtectedPartitionPrefix`
- 0x001B7178 / 0x001B7278 -> `ReadPartitionPathSuffixComponents`
- 0x001B7480 / 0x001B7580 -> `BuildProtectedHddPartitionPath`
- 0x001B8900 / 0x001B8A00 -> `ReadHddPartitionDataBlock`

Source-established signature (Ghidra function editor) `int BuildProtectedHddPartitionPath(char * outPath)` where prior parameter was `ulong param_1`; preserve previous user-defined signature if one exists. No other unknown parameters are guessed.

Prepared new user-facing runnable Java `ApplyPlayOnlineNetPartitionPath_20261016_v6.java`; **metadata APPLY script**. Detects variants via 11 byte-exact memory fingerprints, conservatively renames 8 functions, labels and types 7 source arrays/literals as byte arrays, adds source-backed function/data/EOL comments, partially refines output-path pointer only when existing signature source is default or analysis. Does **not** decrypt/replace binary bytes, modify existing user-defined names/typed data, or invent structures. All **11/11 fingerprints passed offline** against each original user-supplied executable. Ghidra 12.1.3 script **not yet run/compiled in user environment**.

## Next step

User runs v6 in **CD SCUS_972.69** Ghidra first and, if desired, in **HDD POL_HDD.ELF**, supplying `[DNASNETV6]` console summary. Next trace the **actual two libcdvd RPC command responses supplying the 8-byte __net path suffix** and `pfs0:/etc/access_flag[2]` reads. Reconcile sector indices with PCSX2 `[DNASLBA]` tracing before attributing the source of -404 to HDDID rather than failed identity checks. No original Sony HDD exists; do not recommend acquiring one.

Completed read-only: exact DES string plaintext verification, original ELF comparison, v6 detector offline validation. Unverified: runtime contents of suffix, source of -404 in failing PCSX2 run, v6 in-app execution.
