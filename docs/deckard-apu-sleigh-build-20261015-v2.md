# DECKARD PowerPC APU support v2 (2026-10-15)

## Normal extension installation

This is part of **ghidra-emotionengine-reloaded**. Build the extension via its existing Gradle `buildExtension` task, then install the produced ZIP in **Ghidra > File > Install Extensions**. No separate installer is needed, and Ghidra's stock PowerPC files are never modified.

From the repository root, using your existing Ghidra installation:

```powershell
gradle -PGHIDRA_INSTALL_DIR="C:\path\to\ghidra_12.1.3_PUBLIC" buildExtension
```

Gradle stages PowerPC 4xx SLEIGH dependencies from **that exact Ghidra installation** into this extension's `data/languages` directory, compiles `ppc_32_deckard_be.slaspec` into `ppc_32_deckard_be.sla`, and bundles it with `deckard.ldefs`, the matching stock PPC processor/compiler specifications, and the read-only audit script in `ghidra_scripts`.

Restart Ghidra and select `PowerPC:BE:32:DECKARD` on fresh DECKARD firmware imports. The existing databases remain unchanged. DPATCH's mapped base is `0xFFFFD000`; LOADER's is `0xFFFFE000`, ending at reset vector `0xFFFFFFFC`.

The APU implementation contains 32 documented opcodes with opaque p-code userops for custom hardware effects, rather than fabricated emulator semantics. Firmware evidence: 246 documented instruction-word matches and 45 deliberately unclassified candidate words. Ghidra/SLEIGH compile and fresh-import behavior still require validation on Ghidra 12.1.3.

References: https://israpps.github.io/PPC-Monitor/docs/APU/APU_opcodes.html and stock Ghidra PowerPC 4xx language sources.
