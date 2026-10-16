# PS3 ps2_gxemu MagicGate VUART investigation: state (2026-10-16)

Target database: user-provided decrypted PS3 `ps2_gxemu.elf` imported in Ghidra 12.1.3 as `PowerPC:BE:64:A2ALT`. The original 32addr DB remains separate. The user runs Ghidra scripts and supplies logs.

## Completed

The script `InspectAnnotatePs3GxemuPpu64_20261016_v2.java` succeeded:
- `FUNCTIONS=2997`, `INSTRUCTIONS=463567`, `LV1_SC1_SITES=313`.
- No memory blocks above 4 GiB; main initialized image low-mapped and BSS extends to `0x02BBAB27`. Does **not** rule out constructed 64-bit effective addresses.
- `entry` at `0x00000094` is genuinely `b 0x00000094`. Do not rename without distinct proven startup path.
- No MagicGate handlers/signatures recovered yet.

## Current script / next step

Run **`ghidra_scripts/TracePs3GxemuVuartHcalls_20261016_v2.java`** (read-only byte-wise, APPLY=true for comments/bookmarks). Script uses PPC instruction word decoding plus P-code register-output tracking in straight-line basic block windows to recover *local* constants for `r11` and `r3` preceding `sc 1`.

Sony PS3 LV1 hcall IDs relevant to the documented `ps2_gxemu` MagicGate **virtual UART port 10**:
- 162 read port (r3=port), 163 write port
- 164 set port parameter, 165 get port parameter
- 166 configure UART IRQ, where r3 **is an IRQ bitmap address, not a port**.

Sources: https://www.psdevwiki.com/ps3/PS2_Emulation ; https://www.psdevwiki.com/ps3/HV_Syscalls ; https://www.psdevwiki.com/ps3/HV_Syscall_Reference

The script is not user-run or compiled yet. Resolve exact call sites and evidence-backed names from next output. Do not claim that every `sc 1` is MagicGate, that a local `r3=10` pattern proves runtime path in all branches, or that a low ELF image proves 32-bit-only addressing. No invented signatures/data types; return directly applicable metadata when recovered. Superseded script v1 was removed.

Cross-repo PCSX2 working branch: `note-working/magicgate-hdd-utility-header-validation-20261016`; HHD Utility native MG `0x90 -> 0x8D*26 -> 0x8F`, `0x1A0` header data arriving intact but BIT offset `0x48` incorrectly read as ciphertext and rejected with `0x80`. Continue building the real Sony crypto behavior without bypassing or altering ciphertext. DNAS parked.
