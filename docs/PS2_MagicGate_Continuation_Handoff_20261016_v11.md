# PS2 MagicGate continuation: PlayOnline DNAS -404 traced to HDD identity candidate (2026-10-16 v11)

**Branch:** `testing`  
**Previous:** [v10 handoff](PS2_MagicGate_Continuation_Handoff_20261016_v10.md)

## Completed and verified

The user successfully built and ran PCSX2 fork `note-working/magicgate-scmd-boundary-trace-20261016`. Runtime log `v2.9.92-5-gfab33873e`, 6050 lines, 256 S-command requests/responses/consumptions. PlayOnline installation screenshot from previous run: `POL-1562 / DNAS -404`; current uploaded trace does *not* contain a printed -404 and ends around t=69.99s, so exact same-run frame correlation is pending.

Authentication sequences `80,81,82,83,8F,84,85,86,87,8F,88` are each seen **three times** around t=6.78, 7.29 and 13.50s. PCSX2 returns handler status first byte `00` throughout; this is emulator-level success, not proof real hardware verifies responses. KELF transfers execute `90/8D/8F/91/8E/92/93` and HDDOSD loads. **No SCMD `0x98` appears in this log**, so the known missing handler is not a demonstrated failure cause for this test.

At t=31.55,43.40,43.75,55.01,57.58,69.98s the guest submits Sony ATA security drive identification feature `0xEC` via ATA command `0x8E`. This is **NOT** CDVD SCMD `0x8E`. PCSX2 `ATA::SCE_IDENTIFY_DRIVE` responds using `sceSec[512]`.

Source `pcsx2/DEV9/ATA/ATA_State.cpp` reads optional `.hddid` file with name derived from image via `Path::ReplaceExtension`; otherwise synthesizes `sceSec` with fixed model, fixed serial and **zeroed `0x50..0x7F`**. This region is believed related to DNAS/encryption. No diagnostic in supplied log proves presence/absence of `.hddid` on user's host.

DNAS -404 is documented as `sceDNAS2_SS_INVALID_HDD_BINDING`, mismatched PS2/HDD pairing. This makes HDD identity a **strong testable candidate** rather than proof of exact failure site. Reference: [GameFAQs error code guide](https://gamefaqs.gamespot.com/ps2/915821-playstation-2/faqs/42217); [PS2 Dev Wiki hard drive](https://www.psdevwiki.com/ps2/Hard_Drive).

Full protocol table and narrow test: [PCSX2 trace findings v2](https://github.com/Masamune3210/pcsx2/blob/note-working/magicgate-scmd-boundary-trace-20261016/docs/playonline-dnas-hdd-binding-trace-findings-20261016-v2.md).

## One exact immediate user test

The log's HDD path is `F:\Emulation\Emulation Files\pcsx2\HDDOSD.raw`; the source expects `F:\Emulation\Emulation Files\pcsx2\HDDOSD.hddid`. Run **one PowerShell line**, which summarizes file presence, byte count, and only *count* of nonzero 0x50..0x7F bytes without dumping private unique data:

```powershell
$p='F:\Emulation\Emulation Files\pcsx2\HDDOSD.hddid'; if (Test-Path -LiteralPath $p) { $b=[IO.File]::ReadAllBytes($p); if ($b.Length -ge 0x80) { [pscustomobject]@{Found=$true;Bytes=$b.Length;UniqueRegionNonzero=@($b[0x50..0x7F] | Where-Object { $_ -ne 0 }).Count} } else { [pscustomobject]@{Found=$true;Bytes=$b.Length;UniqueRegionNonzero='Too short'} } } else { 'HDDOSD.hddid missing: PCSX2 uses synthesized HDD identity' }
```

After result, establish if authentic user-owned HDD ID is available, understand console key/binding expectations and network stage. Do not synthesize unique HDD identification bytes as if authentic, do not post secrets to public repos, do not detour into generic Dragon storage MMIO.

## Status

Source tracer branch **built and ran**; current source research docs committed; no MagicGate emulation fixes yet; no Ghidra new metadata obtained in this pass. Outstanding: verify presence/shape of `.hddid`, actual failure point/behavior, then a grounded PCSX2 test patch.
