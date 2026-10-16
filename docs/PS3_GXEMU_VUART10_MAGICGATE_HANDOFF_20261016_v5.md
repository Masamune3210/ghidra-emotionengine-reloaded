# PS3 GXEMU port-10 function recovery handoff v5 (2026-10-16)

Branch: `testing`. Previous [v4](PS3_GXEMU_VUART10_MAGICGATE_HANDOFF_20261016_v4.md). Target Ghidra 12.1.3 `ps2_gxemu.elf`, language `PowerPC:BE:64:A2ALT`.

## User-run result: OPD and two transport functions (complete)

`ApplyAuditPs3GxemuVuart10Frames_20261016_v1.java` succeeded. Four existing `Ppc64FunctionDescriptor24` instances are applied, all `entry`, TOC and environment fields verified, `PpuGlobalTocBase` labeled at `0x00678548`. Datatype `/PS3/PPU/Ppc64FunctionDescriptor24` is now **present**, total size `0x18`.

```
Structure: Ppc64FunctionDescriptor24
Size: 0x18
0x00 void * entry
0x08 void * toc
0x10 void * environment
```

Existing wrapper descriptors: `0x6470A0`, `0x6470B8`, `0x6470E8`, `0x647100`; same TOC `0x678548`, environment 0.

Function renames ALREADY APPLIED, preserve:
```
0x000494A4 -> Lv1WriteVirtualUart
0x00049544 -> Lv1ReadVirtualUart
0x000495B8 -> Lv1VirtualUartParameterDispatch
0x00049664 -> Lv1ConfigureVirtualUartIrq
0x0008FC68 -> ReceiveVirtualUartChunk
0x000900FC -> SendVirtualUartFrame
```

R2 relative slots from user log:
- `0x00672B58 = r2-0x59F0`, initially `undefined`;
- `0x00672B60 = r2-0x59E8`, `undefined *`;
- `0x00672B68 = r2-0x59E0`, `undefined *`;
- `0x00672B78 = r2-0x59D0`, `undefined`;
- `0x00672B80 = r2-0x59C8`, `undefined *`.
No global value type beyond what data declarations currently show; no global r2 context was written.

## Function boundary discovery

Audit `0x8FD30..0x90414` found 3 high-confidence **missing functions**, with a preceding `blr`, standard `stdu r1,-frame(r1)` start, end `blr`, and an entry data ref likely from a BE64 function descriptor:

| proposed start | end BLR instruction | port-10 UART write | code-entry data ref |
| - | - | - | - |
| `0x0008FD48` | `0x0008FF50` | `0x0008FF24` | `0x0064F728` |
| `0x0008FF54` | `0x000900F8` | `0x000900D0` | `0x0064F740` |
| `0x000901FC` | `0x00090404` | `0x000903D8` | `0x0064F770` |

All three UART write calls were previously unowned. The available evidence is strong but **a function cannot be marked fully validated until the script verifies no code holes/overlap and the descriptor's TOC/third field in the database**.

## New script

`ghidra_scripts/PromotePs3GxemuVuart10Senders_20261016_v1.java`, committed to this branch. **NOT YET RUN in user's Ghidra.**

- Validates preceding / ending BLR, `stdu r1` prologue, exact port 10 `li r3,0xA`, direct `bl 0x494A4`, and every 4-byte decoded instruction in intended function range. Rejects overlaps.
- Verifies `entry, r2 TOC=0x00678548, environment=0` in corresponding 24-byte BE64 descriptors before applying anything to each individual candidate.
- Creates only proved contiguous function bodies, names them generically `SendVirtualUartVariablePacket`, `SendVirtualUartFixed64BytePacket`, `SendVirtualUartVariablePacketAlternate`; preserves meaningful names on rerun. These labels describe known write site and length, **not verified message semantics**.
- Applies existing `/PS3/PPU/Ppc64FunctionDescriptor24` at only `0x0064F728`, `0x0064F740`, `0x0064F770` if prior default data allows; adds descriptor labels.
- Attempts to set **function-body-scoped** `r2=0x678548` only if no instruction in the body writes r2 and no previous initial context is defined. Prints skip messages. This is guided by verified OPD entries; does NOT set global context or infer r2 in all functions.
- Decompiles each recovered function and prints complete C or error. No signatures, packet structures, arbitrary data declarations or executable bytes changed.

Script is not compile-tested or run yet. If it fails verification on any entry, keep it unpromoted and inspect the specific failure. If successful, analyze actual outgoing packet builders and trace code-refs/callbacks toward the MechaCon S-command / real KELF `0x8F` path.

Cross-project branch: `Masamune3210/pcsx2` `note-working/magicgate-hdd-utility-header-validation-20261016`, DNAS parked.
