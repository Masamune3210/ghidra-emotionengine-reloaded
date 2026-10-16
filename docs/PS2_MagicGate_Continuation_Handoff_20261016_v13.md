# PS2 MagicGate continuation: decrypted FFXI ERX and IOP loader (2026-10-16 v13)

**Branch:** `testing`; supersedes [v12 handoff](PS2_MagicGate_Continuation_Handoff_20261016_v12.md).

## Crucial solved obstacle

The user supplied the actual `SCUS-97266` FFXI disc's files: 8 `.ERX`, 3 ordinary `.IRX`, `INSTALL.ELF`, `HDD.SYS`, `FFXI_POL.ENC`, `POLKEY.DAT`. The eight `.ERX` are NOT raw EE executables. All eight were successfully decrypted and **each contains an IOP MIPS ELF at offset `0x10`** of a 16-byte decoded wrapper. All eight validate with PS2 processor-specific ELF type `0xFF80` and in-bounds section headers. Encryption algorithm was reversed from plain `SQIOPMEM.IRX`, which declares `PlayOnline_Memory_Manager/SQUARE` v1.01.

```text
SQIOPMEM.IRX .text+0x94 -> NextPseudoRandom15
uint NextPseudoRandom15(void)

SQIOPMEM.IRX .text+0xC4 -> DecodeRollingXorBuffer
void DecodeRollingXorBuffer(byte * buffer, int length, uint seed)

SQIOPMEM.IRX .text+0x44C -> LoadIopModuleData (name-only; preserve unresolved prototype)
SQIOPMEM.IRX .text+0x69C -> calls DecodeRollingXorBuffer with seed=encrypted file size
SQIOPMEM.IRX .bss+0x100 (linked virtual 0x20C0) -> uint32_t g_ModulePseudoRandomState
```

Decode first `for i=n-1 down to 1: b[i]^=b[i-1]`, then `state=n; for i=0..n-1: state=(state*0x41C64E6B+0x3021)&0xffffffff; b[i]^=(state>>16)&0xff`. Wrapper bytes 4..15 are original IRX name; ELF begins at byte 16. First four bytes are **not** established as length. Full Python reproducible tool in [PCSX2 fork `tools/recover-ffxi-erx-20261016-v1.py`](https://github.com/Masamune3210/pcsx2/blob/note-working/magicgate-scmd-boundary-trace-20261016/tools/recover-ffxi-erx-20261016-v1.py).

Recovered modules:
- SCE000 -> sio2man.irx, sio2man v2.04
- SCE001 -> libsd.irx, Sound_Device_Library v3.01
- SCE002 -> dev9.irx, dev9 v2.05
- TCP000 -> avetcp.irx, AVE_TCP_31_Resident_Lib v1.01
- HID000 -> squsb.irx, USB_Device_Driver_Interface/SQUARE v1.01
- LDR000 -> sqloader.irx, PlayOnline_IRX_Loader/SQUARE v1.01
- NDI001 -> ndglue.irx, SQUARE_NETDEV_Lib v1.01, AN986 Ethernet
- NDI002 -> ndglue.irx, SQUARE_NETDEV_Lib v1.01, DEV9 SMAP Ethernet (**distinct from NDI001**)

Additional originals: IOPSOUND.IRX IopSoundDriver/SQUARE 1.44; SQIOPMEM.IRX PlayOnline_Memory_Manager/SQUARE 1.01; YMATPREV.IRX ymatprev_driver 1.01.

User received locally generated ZIP with 11 importable IRX modules (including distinct prefixed ndglue versions), CSV manifest, offline decoder and `AnnotateFFXI_SQIOPMEM_20261016_v1.java` Ghidra script. **No proprietary decrypted binaries uploaded to public GitHub**. The Ghidra script has not yet been compiled or run.

`INSTALL.ELF` itself is a genuine EE ELF, entry 0x100008, retaining 25,611 symbol entries:
- 0x00169B70 `XiHardInitialize__FiPPc`;
- 0x0026EC48 `crand`;
- 0x0026EC70 `IrxDecrypt` (used from sqPolconCheckNetDevice, not the ERX module loader);
- 0x0026ED98 `sqPolconCheckNetDevice`;
- 0x002AF808 `sqSysMemLoadModuleErxBase`, SIF RPC;
- 0x002AF9D8 `sqSysMemTransferLoadModuleErx`;
- 0x002AFA38 `sqSysMemLoadModuleErx`;
- 0x002AFA68 `sqSysMemPushModuleErx`;
- 0x00593CD4 `LastDnasError`, datatype and use unresolved.

`FFXI_POL.ENC` and `POLKEY.DAT` have high entropy and are NOT decrypted with the ERX algorithm; `HDD.SYS` indicates `/image/ffxi/prog/ps2/ffxi_pol.pex`. None of these decoded IRX modules declares BBSYS101/libid2/DNAS. Import and inspect but **do not assume this contains PlayOnline -404**: the failing executable came from `SCUS-97269`, whereas this supplied disc is FFXI `SCUS-97266`.

## Next expected step

Import recovered IRX files as **IOP** modules in the user's Ghidra Emotion Engine fork and apply provided SQIOPMEM annotation script; study network and loader dependency chain if needed. To investigate DNAS -404 itself, request/inspect *the failing PlayOnline disc*'s executables and IRX/ERX/crypted resources, or instrument the IOP BBSYS101/libid2 identity RPC at runtime. The PCSX2 `[DNASLBA]` trace branch change still awaits user build/test. No genuine HDD available; never suggest dumping one.

[Full source and versioned PCSX2 handoff](https://github.com/Masamune3210/pcsx2/blob/note-working/magicgate-scmd-boundary-trace-20261016/docs/playonline-ffxi-erx-recovery-handoff-20261016-v5.md).

## Verification

Offline binary decryption and ELF header/section validation succeeded for 8/8; `file` recognizes IOP MIPS ELF in each. Ghidra import, Java script, and runtime DNAS path still unverified.
