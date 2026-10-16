# PS2 MagicGate continuation v30: all three __net DNAS access flags observed (2026-10-16)

Branch: `testing`; previous [v29](PS2_MagicGate_Continuation_Handoff_20261016_v29.md).

## User's new visual evidence

User supplied screenshot showing directory `hdd0:/__net/etc/` with **`access_flag`, `access_flag2`, `access_flag25`, and `bnexe`**. Screenshot establishes directory entries, **not** each file's content, size, why one is highlighted, the source of this filesystem, or which DNAS flag the failing PlayOnline run chose. Do not assume all flags are active or valid solely because all three files exist. `bnexe` function unknown.

Public PS2 Developer Wiki Hard_Drive (https://www.psdevwiki.com/ps2/Hard_Drive) associates `__net/etc/access_flag` with raw LBA `0x41008`, `access_flag2` with `0x4100C`, and `access_flag25` with `0x41010`. Its description says flag files are empty and their *presence* selects a two-sector read followed by 16-byte prefix comparison; determine selection/priority when multiple flags are present from actual code or runtime, not guesses.

Previously verified in both EE source ELFs via DES string decode: `pfs0:/etc/access_flag` and the appended `2` variant. `access_flag25` has NOT been established as a constructed/referenceable literal in the PlayOnline program. No screenshot-only labels should be added to Ghidra.

## Completed Ghidra work

User confirmed v6 applier applied successfully on BOTH `SCUS_972.69` and `POL_HDD.ELF`: **each** functionsRenamed=8, labels=7, datatypes=6, comments=19, preserved=2, failures=0. v6 need not be rerun.

Next: trace `ReadPartitionPathSuffixComponents` CD 0x001B7178/HDD 0x001B7278 and the flag selection/presence-testing logic, then correlate with existing PCSX2 `[DNASLBA]` traces for 0x41008, 0x4100C, 0x41010. No original Sony HDD exists. No executable bytes modified or other code changed in this step.
