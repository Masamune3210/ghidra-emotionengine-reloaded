# PS2 MagicGate / SECRMAN / Dragon MechaCon: continuation handoff
**Prepared:** 2026-10-16 (following the completed Dragon state audit)  
**Primary repository:** `Masamune3210/ghidra-emotionengine-reloaded`  
**Active branch:** `testing`  
**Latest branch head inspected while preparing this document:** `58ab1ac6a83a46f2568ef38ef66d7322bfd3b442` (recheck only if making a new write)  

## 1. Mission and immediate priorities

**Goal:** identify and substantiate where PCSX2's existing partial MechaCon / SECRMAN / MagicGate implementation diverges from genuine Sony PS2 firmware, particularly MechaCon authentication, encrypted KELF processing and memory-card authentication. Use verified firmware behavior and, eventually, the user's PlayOnline Viewer / DNAS installation test as evidence. **Do not treat boot-flow reconstruction or Ghidra symbol recovery as evidence that PCSX2 is missing a feature.**

Current upstream PCSX2 already has MechaCon/MagicGate-related command handlers in `pcsx2/CDVD/CDVD.cpp`: SCMD `0x80..0x87`, `0x8D..0x8F`, `0x90..0x97` with partial header/key-buffer semantics. `pcsx2/SIO/Memcard/MemoryCardProtocol.cpp` implements card-side authentication command responses, including `AuthXor`, `AuthF3`, `AuthF7`. Particularly interesting unverified compatibility gaps include **fixed authentication response bytes** (MechaCon `0x84`/`0x85`), and code paths that expect **already-decrypted KELF input**, rather than fully simulating genuine authentication/decryption. These are **candidate differences**, not yet proven against Dragon ROM response data.

**Next action:** run the already committed, **not yet user-executed** `ghidra_scripts/TraceDragon612ControllerCallbacks_20261016_v2.java` against the user's existing Dragon MechaCon 6.12 Ghidra database. Return its log and its two Downloads reports. Follow the recovered callback ingress and actual hardware data flow toward an externally visible command decoder and response/status byte. Only then compare individual cases against PCSX2.

The previous `AuditDragon612SecurityStateMachines_20261016_v1.java` **has already run successfully** and its three reports have been provided. **Do not ask to rerun it.**

## 2. Authoritative current repository handoffs and scripts

- [Current IOP/EE/MagicGate running handoff, v10](https://github.com/Masamune3210/ghidra-emotionengine-reloaded/blob/testing/docs/ps2-79001-iop-boot-and-ee-handoff-20261016-v10.md). It includes accumulated history; some older subsections saying "reimport SYSMEM/LOADCORE" or "run Dragon v1" are superseded by newer appended updates and by this document.
- [Dragon callback/indirect dispatch evidence, v2](https://github.com/Masamune3210/ghidra-emotionengine-reloaded/blob/testing/docs/ps2-dragon612-callback-dispatch-handoff-20261016-v2.md): verified table, individual raw pointers, MMIO literals, audit limits.
- [Dragon state-machine evidence, v1](https://github.com/Masamune3210/ghidra-emotionengine-reloaded/blob/testing/docs/ps2-dragon612-magicgate-interface-handoff-20261016-v1.md): original ROM identity, 3 state dispatchers, negative-control BCD table.
- [**NEXT SCRIPT** TraceDragon612ControllerCallbacks_20261016_v2.java](https://github.com/Masamune3210/ghidra-emotionengine-reloaded/blob/testing/ghidra_scripts/TraceDragon612ControllerCallbacks_20261016_v2.java): byte-guarded annotation and focused new decompilation roots; outputs only into Downloads; Java Script Manager script, **no extension rebuild**.
- [Already run] `ghidra_scripts/AuditDragon612SecurityStateMachines_20261016_v1.java`.
- [Already run] `ghidra_scripts/RecoverExistingIopBootLibraryMetadata_20261015_v1.java` against both existing SYSMEM and LOADCORE.
- Other previous EE/IOP boot scripts also ran successfully. Do not rerun them without a specific new reason.

## 3. Dragon MechaCon 6.12: established facts

**Input:** `Dragon_MechaCon_6_12_ARMv4T_Ghidra_20261015_v2.elf.gzf` from the user, already analyzed in Ghidra 12.1.3 (ARM little endian, Thumb code). Original ROM `6.12.bin` mapped at `0x00000000..0x00043FFF` (0x44000 bytes); SRAM mapped at `0x02000000..0x02003FFF`. ROM SHA-256 **`18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b`**. Original ROM preserved.

### Completed user-run Dragon audit

`AuditDragon612SecurityStateMachines_20261016_v1.java` completed successfully:
- Verified original ROM hash, three four-state Thumb dispatchers, RAM pointer literals, and 100-byte BCD negative-control table.
- Ghidra after run: **895 functions** (per audit), **3 renamed functions**, 3 labels, 7 comments, one data application, three bookmarks; **2 pre-existing state-byte declarations preserved**.
- 43 relevant decoded Thumb `CMP immediate` candidates and eight decompilations exported to Downloads and **uploaded back to the conversation**:
  - `Dragon612_SecurityStateAudit_20261016_v1_1792111289124.txt`
  - `Dragon612_CmpImmediateCandidates_20261016_v1_1792111289124.tsv`
  - `Dragon612_ProtocolDecomp_20261016_v1_1792111289124.txt`
- The audit showed zero Ghidra incoming xrefs to two of the dispatchers. This was **resolved by subsequent direct ROM analysis:** they are called indirectly via a verified function-pointer table. **Do not conclude they are unreachable.**

### Dispatchers, state bytes, and callback recovery

| Entry | Verified internal state comparisons | RAM source | Status |
|---|---|---|---|
| `0x00015DD0` → `DispatchState90To93` | `0x90–0x93` | `0x02000277` | Separate subsystem; direct `BL` at `0x000151C2` |
| `0x0002AFC8` → `DispatchState70To73` | `0x70–0x73` | `0x02000489` | controller callback index 5 |
| `0x0002B070` → `DispatchState80To83` | `0x80–0x83` | `0x02000489` | controller callback index 6 |

**Do not equate these internal state values with external MechaCon/CDVD SCMD values.** The numeric overlap is not sufficient evidence.

Verified callback call graph from the *original ROM*:
1. Polling loop Thumb `BL` at `0x00029AF2` calls `0x0002A604`.
2. `0x0002A604` reads callback index byte `0x02000488`, indexes a ROM table at `0x00038680`, loads an odd Thumb function address into `r7`, and branches via the `BX R7` trampoline at `0x0003585E`.
3. Table `0x00038680..0x000386C7` is **18 contiguous 32-bit function pointers**. Index 5 at slot `0x00038694` = **`0x0002AFC9`** (Thumb entry `0x2AFC8`); index 6 at `0x00038698` = **`0x0002B071`** (entry `0x2B070`).
4. `0x02000488` is the callback **index**, distinct from `0x02000489` (internal substate byte).

Other relevant literals and hardware paths:
- `0x0002BAC4` / `0x0002BC24` read hardware register block at **`0x036000A0`** and initiate transfers via offsets `+4`, `+5`, `+8`, consulting low three status bits at `+1`; RAM transfer byte `0x0200048C`, pending byte `0x02000496`.
- `0x00029E0C` writes/updates MMIO `0x03005000`, with command byte at `0x03005004`, and triggers `0x03808004` using bit pattern `0x00010000`.
- The hardware peripheral, meaning of the command byte, source of the payload, authentication semantics and outgoing response path **remain unidentified**.
- `0x00038438..0x0003849B`: **100-byte packed BCD lookup table** (`00..99`), **not** an SCMD handler table. Any apparent `0x80..0x97` run inside it is a false positive.

**Applicable labels already established by the verified ROM and prepared script:**
```text
0x00038680 -> ControllerCallbackTable18_ThumbPointers
0x02000488 -> ControllerCallbackIndex
0x02000489 -> StateByte_02000489
0x0200048C -> ControllerTransferByte
0x02000496 -> ControllerPendingByte
0x0002A604 -> DispatchControllerCallbackByIndex
0x0003585E -> BranchToR7
0x0002BAC4 -> TryStartControllerTransfer
0x0002BC24 -> TrySendControllerByte
0x00029E0C -> TriggerControllerCommand

0x00038680 - 0x000386C7
Type: uint32_t[18] (raw Thumb pointers with low address bit set)
```
These are generic evidence-based names, **not proven MagicGate identities**.

### Next Dragon script, status and expected artifacts

`TraceDragon612ControllerCallbacks_20261016_v2.java` exists on **`testing`**, currently source-reviewed/ROM-byte-checked but **not reported as user-executed**. It validates ROM SHA, callback table entries, opcode/pointer anchors before making any metadata changes; preserves existing bodies/signatures/ROM bytes; adds missing conservative refs/labels; focuses bounded decompilation on `0x12614`, `0x12694`, `0x12760`, `0x30380`, `0x16F94`, `0x2EA18`, `0x2EA88`, `0x31B84` and their caller chain. Expected exports in **Downloads**:
- `Dragon612_ControllerCallbackAudit_20261016_v2_<timestamp>.txt`
- `Dragon612_CommandIngressCandidates_20261016_v2_<timestamp>.txt`

After user returns them, find actual external command ingress, packet length validation, hardware read/write and response/status signaling. Be cautious with overlapping Thumb function boundaries and indirect branches.

## 4. Relevant prior Ghidra work already finished: do not repeat

**SCPH-39001 and SCPH-79001 shared modules:** User independently confirmed byte equivalence across many ROM0 modules. The particular SYSMEM/LOADCORE original SHA checks against both already proved byte-identical. **Do not ask to rehash, reimport, or create duplicate programs.** Ghidra program-name `.bin` versus `.irx` suffix does not imply a different binary. Ghidra's "# of Bytes" is not original disk file length.

### EE and IOP combined boot-flow programs

- `BOOTFLOW_EE_combined_20261015_v1.elf`: R5900 `r5900:LE:32:default`. Successful boot annotation: RESET / ROMDIR / KERNEL / EELOAD checks (4 segment SHA checks + 65 instruction words); original RDRAM module imported at `0xBFC41000..0xBFC44153`, cached alias at `0x9FC41000` verified. **535 functions**, 10 created and 11 renamed in the EE pass, 143 labels, 172 comments. One RDRAM cached entry previously reported instruction `null`, not evidence of invalid firmware. Original Ghidra loader BIOS-memory mirror conflict was fixed in the Java extension.
- `BOOTFLOW_IOP_combined_20261015_v1.elf`: IOP `MIPS:LE:32:default`. Successful boot annotation: 5 segment SHA checks + 72 instruction words, 105 ROMDIR records; IOPBTCONF has 29 entries, IOPBTCON2 has 24. Nine function renames, 86 labels, 95 comments, 2 datatypes. **TBIN is PS1-compatibility**, not a competing retail PS2 boot.
- Observed retail PS2 RESET → IOPBOOT call passes selector 0; tries absent `IOPBTCON0`, falls back to `IOPBTCONF`. In default boot list **SECRMAN 28/29**, alternate `IOPBTCON2` **SECRMAN 22/24**, followed by SIO2MAN and MCMAN. A configured module does **not** prove cryptographic authentication occurred.

### Existing SYSMEM / LOADCORE archives and completed run

User provided `SYSMEM.bin.gzf` and `LOADCORE.bin.gzf` from their **existing** SCPH-39001 analysis; hashes equal SCPH-79001 originals:
- SYSMEM SHA-256 `1b03e6ffd2042c2545cf1a78ab937b6b57ccda037783e7ad52467bb9f5556054`: 12 → **16 functions** after `RecoverExistingIopBootLibraryMetadata_20261015_v1.java`, 16 exports checked, four functions created.
- LOADCORE SHA-256 `b7eef224d6473362d49f9e890d89c3bbeb0d243c56f6961bdb4e772ba5b1632b`: 34 → **43 functions**, 25 exports, 12 renames + 9 created. Sysmem imports ordinal 4=AllocSysMemory, 5=FreeSysMemory, 6=QueryMemSize; call sites identified. LOADCORE export ordinal zero at `0x1B74` genuinely resolves to zero-relative entry and bears `R_MIPS_32` relocation. Java extension IRX parser was fixed to recognize these verified cases; **21 of 49** examined IOP export tables had such zero-first exports.
- Key existing LOADCORE function labels: `0x0898 RegisterLibraryEntries`, `0x0C00 LinkLibraryEntries`, `0x0740 RegisterModule`, `0x1260 ProbeExecutableObject`, `0x1450 LoadExecutableObject`. Useful context but **do not drift back to generic LOADCORE research without direct relevance to MagicGate**.
- Prior `SECRMAN.bin` Ghidra database has undergone several verified refinements to KELF loader/read routines, state structures and callbacks. Keep that work; no need to reimport SECRMAN. The precise security-handshake command mapping against MechaCon is still unresolved.

## 5. PCSX2 comparison scope

Do not claim PCSX2 has no SECRMAN. The real BIOS SECRMAN executes on emulated IOP; PCSX2 emulates relevant **hardware-side MechaCon/CDVD and memory-card protocol**. The source contains partial MagicGate handlers, fixed authentication bytes and KELF-buffer/key read functions. Target a concrete, *verified* mismatch:

1. Determine whether Dragon firmware's actual externally accepted SCMD command stream reaches a recovered routine, including command source and result/status writeback.
2. Link genuine firmware behavior through SECRMAN's existing Ghidra analysis where possible.
3. Compare against [PCSX2 CDVD.cpp](https://github.com/PCSX2/pcsx2/blob/master/pcsx2/CDVD/CDVD.cpp) and [PCSX2 MemoryCardProtocol.cpp](https://github.com/PCSX2/pcsx2/blob/master/pcsx2/SIO/Memcard/MemoryCardProtocol.cpp), identifying exact command/status, expected state transitions, and what PCSX2 returns.
4. If evidence is sufficient, implement a minimal testable fix on the user's PCSX2 fork and verify with a reproducible software oracle (potentially the PlayOnline Viewer/DNAS installer), rather than extrapolating from constants.

The user's past PlayOnline Viewer attempt in upstream PCSX2 was selected as a practical DNAS acceptance oracle, because the viewer refuses to install unless checks pass; nonexistent online servers may still block completion. Do not conflate that directly with every MagicGate path.

## 6. Project discipline / response contract

- Preserve existing project/chat decisions first, consult current `testing` handoff, then inspect narrow code paths. No redundant whole-ROM scans or repeat GZF imports.
- Repo branches/commits require concise up-to-date handoffs. Unique filenames/version suffixes for every revised downloadable artifact (avoid cache stale files). Terminal commands should each be one line.
- When Ghidra metadata is discovered, return **directly applicable Ghidra syntax**: structure members with size/offset, datatype dependencies first, enums with size/values, labels at addresses, and exact function editor signatures. Preserve unresolved Ghidra types and existing user signatures; **never invent `undefined16`** or alter `undefined1[16]` storage convention. For broad `.gzf` tasks produce a **runnable Ghidra Java script**, not prose alone.
- `.gzf` contains Java serialization with embedded zip in the first block; Ghidra executable is not required just for extraction. Interrogate unexpected archive data rather than assuming it is correct.
- Any generated Ghidra scripts should put reports in **Downloads**, not user home; preserve data/code and executable bytes, and make source/runtime verification states explicit.
- **Don't confuse internal state byte values with CDVD SCMD opcodes.** Don't treat authentication emulation gaps as proven until compared with actual firmware ingress/response behavior.
- This handoff exists to avoid rediscovering settled work. **Resume by reviewing `TraceDragon612ControllerCallbacks_20261016_v2.java`'s results when the user runs it, not by restarting the EE/IOP boot research.**

## 7. Copyable first message for a new chat

> Continue the PS2 MagicGate / MechaCon analysis from `docs/PS2_MagicGate_Continuation_Handoff_20261016_v1.md` on `Masamune3210/ghidra-emotionengine-reloaded` `testing`. The existing Dragon 6.12 Ghidra database already passed the state-machine audit, and SYSMEM, LOADCORE, SECRMAN, EE and IOP boot work is established. Current next script is `TraceDragon612ControllerCallbacks_20261016_v2.java`; I'll provide its Ghidra log and reports once run. Focus on proving real external MechaCon command ingress/response and identifying *actual* divergences from PCSX2's existing partial MagicGate implementation. Preserve existing metadata and do not restart or reimport previously analyzed firmware.
