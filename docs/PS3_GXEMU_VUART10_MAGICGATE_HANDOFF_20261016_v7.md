# PS3 GXEMU UART10 framed traffic handoff v7 (2026-10-16)

Branch: `testing`; previous [v5](PS3_GXEMU_VUART10_MAGICGATE_HANDOFF_20261016_v5.md). Keep PS3 port-10 reverse engineering distinct from PCSX2 S-command numbers.

## User-run verified function promotion and TOC

User successfully executed `PromotePs3GxemuVuart10Senders_20261016_v1.java` against `ps2_gxemu.elf` (Ghidra 12.1.3, `PowerPC:BE:64:A2ALT`), exporting updated `ps2_gxemu.elf-64(1).gzf` afterwards. All three descriptor tuples matched exactly (entry, `r2=0x00678548`, third word zero), and all three function bodies were contiguous pre-disassembled PPC with verified prologues, endings, internal `r3=10` and direct LV1 UART write wrapper calls.

**The following database objects have ALREADY BEEN APPLIED by the user, do not duplicate:**

```
0x0008FD48 -> SendVirtualUartVariablePacket
0x0008FF54 -> SendVirtualUartFixed64BytePacket
0x000901FC -> SendVirtualUartVariablePacketAlternate
```

All three return `1` in their decompilations (the exact Ghidra prototype still contains numerous `undefined8` placeholders; leave unproven parameter and storage details intact). Function-scoped `r2=0x678548` context was applied to all three; the protocol is now more comprehensible, although Ghidra's generic PPC64 ABI still introduces spurious-looking `param_N` forwarding and `extraout_f1`.

The Ghidra datatype `/PS3/PPU/Ppc64FunctionDescriptor24` (size 0x18; 0x00 `void *entry`, 0x08 `void *toc`, 0x10 `void *environment`) was applied at:

```
0x0064F728 - 0x0064F73F : Ppc64FunctionDescriptor24 ; entry=0x0008FD48, toc=0x00678548, environment=0
0x0064F740 - 0x0064F757 : Ppc64FunctionDescriptor24 ; entry=0x0008FF54, toc=0x00678548, environment=0
0x0064F770 - 0x0064F787 : Ppc64FunctionDescriptor24 ; entry=0x000901FC, toc=0x00678548, environment=0
```

Existing four Lv1 wrappers and two RX/TX functions remain named as recorded in v5.

## Actual outbound framing recovered from Ghidra decompilation

All three send on **virtual UART port 10** by calling `Lv1WriteVirtualUart@0x000494A4`.

`SendVirtualUartVariablePacket@0x0008FD48`:
- Reads 4 BE length bytes from caller's buffer **at offset +0x44**, constructs unsigned length `N`.
- Writes BE32 `N+0x38` into +0x08 **and** +0x0C of same packet.
- Sends `N+0x48` bytes, including the outer 0x10-byte prefix.
- In packet prefix, sequence counter at +0x00..+0x03, `0x50` at +0x06. Has `0x0A` at +0x17.

`SendVirtualUartVariablePacketAlternate@0x000901FC`:
- Reads BE length `N` at caller's buffer **+0x3C**.
- Writes BE32 `N+0x30` into packet +0x08 and +0x0C.
- Sends `N+0x40` bytes. Packet prefix sequence +0x00, class `0x50` at +0x06. Has `0x09` at +0x17.
- Compared to first variant, both embedded length and total wire length offsets differ by `0x08`; a related but not necessarily identical subprotocol.

`SendVirtualUartFixed64BytePacket@0x0008FF54`:
- Writes `0x40` bytes, class byte **`0x90` at +0x06**, +0x0C length field `0x00000008`, +0x17 `0x04`. Uses shared incrementing BE32 sequence at packet +0x00.
- This **outer UART class 0x90 is NOT established as MechaCon S-command 0x90**. Numeric coincidence is not a relationship.

Existing `SendVirtualUartFrame@0x000900FC` builds fixed `0x70`-byte frame with prefix `0x0000FACE` +0x00, `0x00005000` +0x04 (so frame class byte +0x06 = 0x50), and length +0x0C=0x60; it has caller-supplied bytes at +0x38,+0x39 and 32-bit field at +0x40.

The shared per-transmit state writer is probably `/PS3/GXEMU/GxemuVuart10TransferState` with callback descriptor pointer at +0x00, data buffer pointer at +0x08, requested bytes (uint32) at +0x10; remaining 4 bytes unknown. These are established field locations from decompilation but the struct and associated labels have **NOT YET been applied**.

Relevant TOC slots used by code:
`0x00672B50` pointer to incremented sequence counter, `0x00672B58` pointer to transfer state, `0x00672B60` pointer to read offset, `0x00672B68` pointer to byte count/remaining. No pointed-to storage addresses or values inferred.

## Updated GZF scan performed outside Ghidra

The new user archive is Java serialization with an embedded ZIP member beginning at offset 0x36; inflated `FOLDER_ITEM` DB payload is 39,600,128 bytes. Symbol strings verified current function names and applied descriptor type persisted. It is a database dump, **not a raw ELF image**; direct byte-address-to-file-offset inference from its payload is invalid. Code evidence for packet fields derives from user-run Ghidra decompilation included in chat.

A diagnostic string at `0x002B1A80` reportedly says `******** REPORT TO BRIAN! ********\n`. The identity of Brian is unknown; not evidence of any specific security algorithm. Future script will inspect exact bytes and references.

## Next script / required execution

Pushed to `testing`:
`ghidra_scripts/RefinePs3GxemuVuart10Protocol_20261016_v2.java`

- Checks four known port-10 callsite words and direct LV1 write targets.
- Defines portable `GxemuVuart10FramePrefixBE` size 0x10 with neutral field names:
  0x00 uint32 sequenceOrTag; 0x04 uint8 control4; 0x05 uint8 control5; 0x06 uint8 frameClass; 0x07 uint8 control7; 0x08 uint32 frameLengthField8; 0x0C uint32 frameLengthFieldC.
- Defines `GxemuVuart10TransferState` size 0x18:
  0x00 void* completionFunctionDescriptor; 0x08 void* dataBuffer; 0x10 uint32 requestedBytes; 0x14..0x17 unresolved.
- Applies guarded r2 context only for `ReceiveVirtualUartChunk@0x8FC68` and `SendVirtualUartFrame@0x900FC`, if their OPD tuples at `0x64F6F8`/`0x64F758` verify.
- Guardedly labels and attempts typed-pointer declarations for four referenced TOC globals; preserves conflicting deliberate types/user names.
- Adds evidence-based comments to four transmit builder functions without renaming.
- Prints upstream code/data references and decompilation of UART wrappers, RX/frame builders, `FUN_0024F718` address/buffer transformation, `FUN_00051528` buffer initializer and source around `0x0024F9A4`, plus Brian diagnostic string/xrefs.
- NOT YET COMPILED OR RUN by user. No source bytes or unresolved signatures modified.

**Next focus**: inspect the translation helper and upstream packet callers to distinguish MagicGate traffic from other port-10 services; only then investigate actual Sony MechaCon command `0x8F` crypto. Cross-project PCSX2 branch `note-working/magicgate-hdd-utility-header-validation-20261016`; DNAS parked.

## Latest correction (2026-10-16)

The original protocol-probe v1 was replaced by v2 and removed from the scripts directory. Run **RefinePs3GxemuVuart10Protocol_20261016_v2.java** only. It additionally decompiles the *containing functions* of cross-reference sites 0x0004946C and 0x0024F9A4 rather than expecting those call instructions to be function entries. Packet byte +0x17 varies across validated senders: 0x0A (0x8FD48), 0x04 (0x8FF54), 0x09 (0x901FC), candidate subtype tags without assigned meaning. Do not conflate transport frame class 0x90 with MechaCon SCMD 0x90. The v2 script is committed and still awaits user execution; no PCSX2 source change.
