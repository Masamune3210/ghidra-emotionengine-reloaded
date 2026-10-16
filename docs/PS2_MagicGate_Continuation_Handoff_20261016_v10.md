# PS2 MagicGate continuation: PCSX2 SCMD trace ready to test (2026-10-16 v10)

**Research repository/branch:** `Masamune3210/ghidra-emotionengine-reloaded`, `testing`  
**Supersedes:** [v9 continuation](PS2_MagicGate_Continuation_Handoff_20261016_v9.md)  
**SCMD map:** [PCSX2 command crosswalk](ps2-magicgate-pcsx2-scmd-crosswalk-20261016-v1.md)

## Latest completed action

A **new PCSX2 fork branch** was created from `Masamune3210/pcsx2:master`, because this fork has no `testing` branch:

[`note-working/magicgate-scmd-boundary-trace-20261016`](https://github.com/Masamune3210/pcsx2/tree/note-working/magicgate-scmd-boundary-trace-20261016)

Direct source change: [`pcsx2/CDVD/CDVD.cpp`](https://github.com/Masamune3210/pcsx2/blob/note-working/magicgate-scmd-boundary-trace-20261016/pcsx2/CDVD/CDVD.cpp). It records `[SCMDTRACE]` request IDs, SCMD bytes, parameter counts, nested `0x03` MechaCon subcommand IDs, response byte counts, first response byte, and completed guest response consumption. It **does not log full payload/keys/challenges**, and does not change emulated command behavior. Logging is enabled with `static constexpr bool s_scmdTraceEnabled = true` only on this research branch.

Detailed branch state and exact test instructions:
[PCSX2 tracer branch handoff](https://github.com/Masamune3210/pcsx2/blob/note-working/magicgate-scmd-boundary-trace-20261016/docs/magicgate-scmd-trace-handoff-20261016-v1.md)

## User action now

In their existing PCSX2 checkout, after preserving uncommitted work, run as **two separate one-line commands**:

```powershell
git fetch origin note-working/magicgate-scmd-boundary-trace-20261016
git switch --track origin/note-working/magicgate-scmd-boundary-trace-20261016
```

Build using the existing PCSX2 Visual Studio/CMake build configuration; re-run the PlayOnline Viewer installation test. Return the full PCSX2 Program Log or `PCSX2.log` containing `[SCMDTRACE]` and the exact installer error code/screenshot. **C++ compilation and runtime are not yet verified**. If no `0x80..0x98` S-commands are issued, prioritize DNAS/network/IOP interactions rather than guessing MagicGate faults.

## Preserved Dragon firmware status

User Ghidra v9 reports were archived on this branch:
- [Queue worker MMIO index](evidence/Dragon612_QueueWorkerMmio_20261016_v9_1792115615678.txt)
- [Queue worker function bodies](evidence/Dragon612_QueueWorkerBodies_20261016_v9_1792115615678.txt)

At firmware address `0x30C40`, queued writes drive private storage commands `A3`, `A4/A5`, `A0`. `0x6B28` invokes it when the queue-active bit is set; `0x88F0` drives private reads `A8/A9`. **These are NOT IOP-visible CDVD S-command numbers.** No more Dragon storage exploration until an actual MagicGate call depends on it.

Next research step after user log: align actual SCMD sequence and first error against upstream PCSX2 implementation, then targeted SECRMAN/Dragon external-handler Ghidra comparison; fix verified mismatch only.
