# DECKARD DPATCH hooks and combined GZF scan, 2026-10-15 v10

## Input and state verified
- User supplied \`DECKARD.elf - DPATCH.bin.gzf\` (Java-serialization GZF). It contains an embedded deflated Ghidra FOLDER_ITEM payload, and metadata strings extracted without launching Ghidra.
- The new combined archive already includes \`DispatchRuntimeCodePatch\`, \`RuntimeCodePatchJumpTable\`, \`DeckardRuntimePatchMode\`, the APU accessor function names, and comments/labels \`CheckMipsRomPatchContext\`, \`CheckDataExceptionPatchAddress\`, \`DispatchPatchModeFromDear\`, and \`SkipFaultingPpcInstructionForPatch\`. Therefore **the fault-gate annotation script's metadata is already present in the exported database**, even though the latest console transcript only reran the earlier runtime patch script.
- The archive retains \`switchdataD_ffffd018\` and \`switchD_ffffd014\`: Ghidra has preexisting markup for the dispatch jump table. Do not force its replacement with \`pointer[32]\`.
- User reran \`AnnotateDeckardRuntimePatchModes_20261015_v1.java\`: 32/32 pointer slots/source words passed, dispatcher signature \`void DispatchRuntimeCodePatch(DeckardRuntimePatchMode patchMode)\`, 22 comments and 2 labels/renames applied; table declaration correctly preserved (occupied).

## Additional verified DPATCH behavior
Independent byte checks used original firmware files \`3_DECKARD.elf\` and \`5_DPATCH.bin\` extracted from SCPH-79001 ROMDIR archive. PowerPC instruction decoding below was cross-checked with LLVM PPC disassembler. No emulation or runtime game-specific triggers have been proved.

Four modes replace \`0x00A04778\` with absolute branches to DPATCH. After entering those runtime hook bodies, they apply distinct comparisons to **the low 21 bits of r3** (\`clrlwi r4,r3,11\`):

| Mode | Hook entry | Special path condition |
|---:|---|---|
| 1 | \`0xFFFFD0C4\` | bounded \`0x23000..0x232C0\`, then equal to one of \`0x23000\`, \`0x230E0\`, \`0x23170\`, \`0x231A0\`, \`0x231C0\`, \`0x231E0\`, \`0x232C0\` |
| 2 | \`0xFFFFD220\` | equals \`0x2C170\`, \`0x2C1E0\`, or \`0x2C2D0\` |
| 3 | \`0xFFFFD31C\` | equals zero |
| 4 | \`0xFFFFD3DC\` | equals \`0x27F00\` |

These comparisons occur **inside the hook**, after exception-driven mode selection, not in the selector gateway. They do not prove which MIPS code causes a triggering fault at \`0x02000001..0x02000007\`.

Mode 5 supplies two replacement code paths (\`0xFFFFD4DC\`, \`0xFFFFD554\`); the second polls/updates APU GTE state. Mode 6 rewrites the low halfword of the conditional branch at \`0x00A047B4\`. Mode 7 redirects a relative call to \`0xFFFFD5EC\`, whose code updates state at \`0x00BE07A8\` while reading the PPC timebase. Observed state offsets: \`+0x00\` 4-byte timebase, \`+0x08\`, \`+0x09\`, \`+0x0B\` 1-byte slots, \`+0x0C\` 2-byte slot, \`+0x0E\` 1-byte slot. Treat this as a **partial** layout; don't assume a full 16-byte struct.

## Compatibility parameter record datatype (define before using)

\`\`\`text
Structure: DeckardCompatibilityParameter
Size: 0x0C
0x00 uint32_t parameterId     (4)
0x04 uint32_t defaultValue    (4)
0x08 char * parameterName     (4)
\`\`\`

Original table:

\`\`\`text
0x00A0F14C - 0x00A0F223
Type: DeckardCompatibilityParameter[18]
Label: CompatibilityParameterDefaults
\`\`\`

All eighteen records were checked in the original firmware; their IDs are \`0..17\`, default values are \`500,2000,35,2000,20,0,1,32,0,0,0,0,0,8860,1772,1772,1,144\`, and their name pointers refer to readable ASCII strings near \`0x00A0EF3C..0x00A0F108\` such as \`PARAM_MDEC_DELAY_CYCLE\` and \`PARAM_CACHE_FLASH_CHANNELS\`. See reset logic at \`0xFFFFD770\` and setter \`0x00A0C7F0\`.

Function signature (only refine if Ghidra has no concrete return/parameters):

\`\`\`text
0xFFFFD770
void RestoreCompatibilityParameterDefaults(void)
\`\`\`

The loop at \`0xFFFFD770..0xFFFFD820\` copies the 18 defaults into a temporary local buffer, calls \`0x00A0C7F0\` once per ID, then clears globals at \`0x00BE0A28\` and \`0x00BE0A2C\`. It does not install new callback infrastructure.

## Direct application

\`ghidra_scripts/AnnotateDeckardPatchHookPredicates_20261015_v1.java\` is a metadata-only, directly runnable script for the combined database. It validates **32 exact DPATCH instruction words plus all 18 parameter records** before altering anything; adds verified hook labels and comments, declares the 0x0C record structure, defines the 18-record array only where Ghidra hasn't already created overlapping data, and conservatively renames/types an existing reset function. All user-defined names/signatures and existing typed data are preserved. Running twice is safe.

No extension rebuild needed. The script is source-reviewed, **not yet runtime-tested** in the user's Ghidra 12.1.3. Report any actual exception or byte mismatch rather than clearing data.

## Remaining research
- Identify the actual producer of PPC data-access faults to \`0x02000001..0x02000007\`. The DEAR gate + MIPS boot-ROM PC restriction tells us when the selector is accepted, not which guest firmware or title requests each mode.
- Audit broader p-code/decompiler behavior for custom APU userops and runtime-injected hooks. Static references need not follow branches that only exist after a patch is applied.
- Keep the DECKARD SLEIGH language unchanged unless an actual decode/p-code defect is shown.
