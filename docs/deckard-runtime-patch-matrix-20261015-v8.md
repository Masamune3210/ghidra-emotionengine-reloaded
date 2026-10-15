# DECKARD runtime instruction patch dispatcher (2026-10-15 v8)

## Source and evidence
- User supplied decompiled \`FUN_ffffd000(uint param_1)\` from the combined DECKARD.elf+DPATCH Ghidra program (12.1.3, \`PowerPC:BE:32:DECKARD\`).
- Decompiled cases visibly write instruction words/halfwords into main ELF \`.text\`, call \`instructionCacheBlockInvalidate\`, and issue \`instructionSynchronize\`: this is intentional firmware self-modifying code. Ghidra's "Read-only address ... is written" diagnostics are expected for static code blocks and **not** evidence that patching cannot work at runtime.
- All original instruction words and all DPATCH replacement words were independently verified against the ROM-extracted SCPH-79001 DECKARD ELF and DPATCH (2084 bytes). No ROM bytes were altered.
- The *actual* 32-entry dispatch table is at \`0xFFFFD018..0xFFFFD097\` (\`pointer[32]\`, size \`0x80\`). Slot 0 and slots 8..31 target \`0xFFFFD098\` (\`blr\`); only 1..7 select patch handlers. Consequently the decompiler's textual \`default:\` arm must not be interpreted as the exact runtime behavior of every unrecognized selector.

## Enum datatype before signatures

Enum: \`DeckardRuntimePatchMode\`
Size: **4 bytes**

\`\`\`text
NoChange = 0
PrimaryHookVariant1 = 1
PrimaryHookVariant2 = 2
PrimaryHookVariant3 = 3
PrimaryHookVariant4 = 4
InstallTwoHooks = 5
RedirectConditionalBranch = 6
RedirectCall = 7
\`\`\`

### Dispatcher function metadata

\`\`\`text
0xFFFFD000
void DispatchRuntimeCodePatch(DeckardRuntimePatchMode patchMode)
\`\`\`

The dispatcher masks the selector with 31 and transfers via the 32-entry pointer table. Other values (8..31) reach the return stub. The above signature is suitable for the Ghidra function editor, with the enum defined first. Existing user-defined signatures/names must be preserved.

### Patch table

\`\`\`text
0xFFFFD018 - 0xFFFFD097
Type: pointer[32]
Label: RuntimeCodePatchJumpTable
\`\`\`

Handlers by index:

| selector | pointer target |
|---:|---|
| 0 | \`0xFFFFD098\` (return without action) |
| 1 | \`0xFFFFD09C\` |
| 2 | \`0xFFFFD1F8\` |
| 3 | \`0xFFFFD2F4\` |
| 4 | \`0xFFFFD3B4\` |
| 5 | \`0xFFFFD494\` |
| 6 | \`0xFFFFD5A4\` |
| 7 | \`0xFFFFD5C8\` |
| 8..31 | \`0xFFFFD098\` |

## Verified instruction replacements

| Selector | Destination(s) and source data | Replacement / target | Original bytes |
|---|---|---|---|
| 1 | \`0x00A04778\` ← \`0xFFFFD0C0\` | \`4BFFD0C6\` = absolute b \`0xFFFFD0C4\` | \`7FA3EB78\` |
| 2 | \`0x00A04778\` ← \`0xFFFFD21C\` | \`4BFFD222\` = absolute b \`0xFFFFD220\` | \`7FA3EB78\` |
| 3 | \`0x00A04778\` ← \`0xFFFFD318\` | \`4BFFD31E\` = absolute b \`0xFFFFD31C\` | \`7FA3EB78\` |
| 4 | \`0x00A04778\` ← \`0xFFFFD3D8\` | \`4BFFD3DE\` = absolute b \`0xFFFFD3DC\` | \`7FA3EB78\` |
| 5 | \`0x00A03AE0\` ← \`0xFFFFD4D4\` and \`0x00A03350\` ← \`0xFFFFD4D8\` | \`4BFFD4DE\` = absolute b \`0xFFFFD4DC\`; \`4BFFD556\` = absolute b \`0xFFFFD554\` | \`001BD38C\`, \`7C651B78\` |
| 6 | **halfword** \`0x00A047B6\` | \`ED8C\` → \`FFB4\`, full word \`419BED8C\` → \`419BFFB4\`. Conditional branch at \`0x00A047B4\` redirects \`0x00A03540\` → \`0x00A04768\` | \`419BED8C\` |
| 7 | \`0x00A0B1B0\` | \`4BFFFDE1\` (relative \`bl 0x00A0AF90\`) → \`4B5F243D\` (relative \`bl 0xFFFFD5EC\`) | \`4BFFFDE1\` |

Also verified original \`0x00A097A0 = 54A3F87E\`, changed to \`54A3F0BE\` in mode 1 and restored by other patch paths shown in decompilation. Mode 1 also restores/maintains other patch locations via the shared tail code. Do not treat the static Ghidra image as though any of these runtime changes have already taken place.

## Directly runnable Ghidra script

\`ghidra_scripts/AnnotateDeckardRuntimePatchModes_20261015_v1.java\`:
- Requires combined main DECKARD ELF + DPATCH mapped at \`0xFFFFD000..0xFFFFD823\`.
- Verifies 14 source words and **all 32 jump table entries** against the original firmware before changing metadata; aborts entirely on mismatch.
- Adds a \`/DECKARD/DeckardRuntimePatchMode\` enum and a pointer-array declaration only if the corresponding datatype/data range is not already occupied or in conflict.
- Conservatively refines the dispatcher function name, return type, and existing one-argument signature if not user-defined, preserving unresolved or custom storage otherwise.
- Appends pre-comments to original patch sites, patch-word sources and runtime branch destinations. It never rewrites code/data bytes, replaces existing analyst comments, or creates false static control-flow references to runtime-only destinations.
- Is idempotent. No extension rebuild needed.

## Next work
1. Pull \`testing\` and run the script against the combined DECKARD database, then inspect its verification summary and signature.
2. Audit the actual DPATCH functions, its 32 pointer-table entries and cross-image branches. The ordinary \`AuditDeckardApuCoverage_20261015_v5.java\` covers only the original \`.text\` for a combined main ELF, so separate DPATCH coverage still needs to be verified.
3. Explore p-code and control-flow issues only where a real Ghidra decode/decompile failure remains. This patching mechanism is firmware behavior, not an argument for loosening custom APU opcode rules.

## Verification status
ROM bytes, PPC absolute and relative branch targets, branch halfword adjustment and dispatch pointers verified; this metadata-annotation script is **source reviewed but has not been compiled/run in the user's Ghidra environment**.
