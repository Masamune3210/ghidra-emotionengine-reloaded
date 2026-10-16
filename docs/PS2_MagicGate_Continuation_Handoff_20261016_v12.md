# PS2 MagicGate continuation: DNAS access-flag verification without Sony HDD (2026-10-16 v12)

**Research repo** `Masamune3210/ghidra-emotionengine-reloaded` at `testing`. Supersedes [v11 handoff](PS2_MagicGate_Continuation_Handoff_20261016_v11.md).

## User constraints / corrected plan

The user **does not have a genuine Sony HDD**. Do not suggest dumping one or sourcing an arbitrary external HDD ID as the primary next action. The user has directly confirmed `HDDOSD.hddid` **does not exist**, so PCSX2 synthesizes the HDD identity. Their PlayOnline test failed with DNAS -404, although the SCMD trace did not include a printed guest-code -404 return-site.

They supplied PS2 Developer Wiki's DNAS identity overview:
- DNAS can use **disc ID, console GUID, console model ID and Sony HDD ID**; HDD-ID fallback alone is **not proof of cause**.
- Depending on access-flag file selection, DNAS reads **two sectors** starting at LBA `0x41008`, `0x4100C`, or `0x41010` and compares the first 16 bytes of each; some entries are empty/missing.
- `BBSYS101/Sys1_driver02` and `libid2/Sys1_driver04` are potential IOP identity RPC sources.
- Relevant source [PS2 Dev Wiki DNAS](https://www.psdevwiki.com/ps2/DNAS) and [hard-drive security](https://www.psdevwiki.com/ps2/Hard_Drive).

## Completed code change and new user action

On [`Masamune3210/pcsx2:note-working/magicgate-scmd-boundary-trace-20261016`](https://github.com/Masamune3210/pcsx2/tree/note-working/magicgate-scmd-boundary-trace-20261016) an **additional read-only trace** has been committed to `pcsx2/DEV9/ATA/ATA_Transfer.cpp`, `ATA::IO_Read()`. It logs candidate read overlaps:
- `[DNASLBA] pair=41008...` etc on a complete two-sector read, indicating boolean `first16equal` and zero flags, no raw bytes;
- `[DNASLBA] partial pair=41008...` on a partial read.

Source and complete handoff: [PCSX2 v4 DNAS access-flag LBA trace](https://github.com/Masamune3210/pcsx2/blob/note-working/magicgate-scmd-boundary-trace-20261016/docs/playonline-dnas-access-flag-lba-trace-20261016-v4.md). **Not compiled yet**.

The user should `git pull --ff-only` on this exact local branch, rebuild, repeat the PlayOnline DNAS -404 test, then supply a log with both `[DNASLBA]` and `[SCMDTRACE]`. If none of candidate sector LBAs are read, target SIF RPC that supplies identity and guest return site, rather than inventing data for sectors.

## Important distinction

Existing PCSX2 source confirms `SCMD 0x03 sub=0x00` returns the **MechaCon version**; repeated occurrences in earlier trace are **not** observed Console ID requests. `SCMD 0x03 sub=0x45` is read Console ID, not seen in current SCMD trace. This may be due to another identity retrieval path. Do not assume the expected DNAS identity call chain until shown by runtime/IOP evidence.

## Preserved prior evidence

PlayOnline SCMD run `v2.9.92-5-gfab33873e` included 256 SCMD requests, three accepted authentication sequences, 0x8D/0x8F/0x90..93 KELF activity, several Sony ATA `0x8E` feature `0xEC` requests and no CDVD SCMD `0x98`. PCSX2 ATA default `sceSec` contains fixed `0x40..0x43` serial and zeroed `0x50..0x7F` security fields. All 18 Dragon callback pointers, v9 queue worker and internal private MMIO are already analyzed and archived in this repo; **no return to Dragon internal storage tracing without a verified MagicGate relation**.

Next action: get DNAS LBA trace, then instrument exact identity SIF RPC/guest error site if candidate is not supported.
