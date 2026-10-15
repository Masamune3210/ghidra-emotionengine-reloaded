# DECKARD runtime patch fault trigger and metadata checkpoint (2026-10-15 v9)

## Current verified state
- Target: SCPH-79001 DECKARD.elf with DPATCH mapped at \`0xFFFFD000\`, Ghidra 12.1.3 language \`PowerPC:BE:32:DECKARD\`.
- SLEIGH extension builds successfully. Twelve APU accessor wrappers recovered and typed. Earlier complete ELF \`.text\` opcode scan: 206 documented APU patterns; 204 originally disassembled, one subsequently manually disassembled (\`amfpc\` at \`0xA01138\`), one false case-sensitive mnemonic mismatch. Remaining 45 OP=0 candidate words are not established opcodes.
- **Runtime verified user output from \`AnnotateDeckardRuntimePatchModes_20261015_v1.java\`:**
  \`\`\`
  PASS: source words and all 32 dispatch-table slots match SCPH-79001
  DISPATCHER void DispatchRuntimeCodePatch(DeckardRuntimePatchMode patchMode)
  PRESERVE existing code/data in patch table at ffffd018
  DONE runtime-patch metadata: comments=22 labelsAndFunctionRenames=2 signatureImprovements=3 pointerTableDeclarations=0
  \`\`\`
- The pointer-table declaration was **deliberately not applied**, since existing typed data or code occupies \`0xFFFFD018\`. This is a preservation result, not a script error. 32 actual pointers were still byte-verified. Do not clear existing table markup just to increase the declaration count. The enum, function signature, labels, and 22 comments applied.

## New finding: the patch-mode selector comes from DEAR, and is gated by MIPS PC

Original PPC instructions in the ELF, independently rechecked against extracted raw \`.text\` bytes:

| Address | Instruction | Verified meaning |
|---|---|---|
| \`0x00A01138\` | \`amfpc r3\` | Read emulated MIPS PC |
| \`0x00A0113C\` | \`clrlwi r3,r3,3\` | Normalize PC to \`MIPS_PC & 0x1FFFFFFF\` (clear **upper**, not lower, 3 bits) |
| \`0x00A01140..4C\` | \`lis/ori/cmplw/blt\` | Unsigned compare PC to \`0x1FC00000\`; branch to \`0xA011A4\` if below |
| \`0x00A01150\` | \`mfspr r3,61\` | SPR 61 is **DEAR**, the PPC440 Data Exception Address Register |
| \`0x00A01154\` | \`rlwinm r4,r3,16,16,10\` | Rotate/mask DEAR |
| \`0x00A01158..5C\` | \`cmplwi r4,0x200; bne\` | Accept only \`(DEAR & 0xFFFFFFE0) == 0x02000000\`; otherwise branch to \`0xA011A4\` |
| \`0x00A01160..68\` | \`mfsrr0/addi +4/mtsrr0\` | Skip PPC instruction that caused the exception |
| \`0x00A0116C\` | \`clrlwi r3,r3,27\` | \`patchMode = DEAR & 0x1F\` |
| \`0x00A01170\` | \`bla 0xFFFFD000\` | Call DPATCH 32-way dispatcher |
| \`0x00A011A0\` | \`rfi\` | Return from exception after context restoration |
| \`0x00A011A4\` | \`li r1,0x1100; mtspr 274,r1; b 0xA02054\` | Alternate exception path |

The branch gate therefore interprets a **Data Exception Address** within the range \`0x02000000..0x0200001F\` as a 5-bit patch selector, but only when the emulated MIPS PC is in the physical boot-ROM range \`0x1FC00000..\` (within the address space left by the 29-bit mask).

\`\`\`c
uint32_t mipsPc = readApuMipsPc();
if ((mipsPc & 0x1fffffffU) >= 0x1fc00000U) {
    uint32_t dear = readPpcDear();           // SPR 61
    if ((dear & 0xffffffe0U) == 0x02000000U) {
        SRR0 += 4;
        DispatchRuntimeCodePatch((DeckardRuntimePatchMode)(dear & 31U));
        // restore context, rfi
    }
}
// Else: alternate exception path 0x00A011A4, not the DPATCH dispatcher
\`\`\`

This identifies a **fault-address command interface** for the runtime patch modes, not ordinary function calls with explicit constants 1..7. An actual data-access fault at one of the 32 designated addresses is the likely command trigger; the precise upstream producer of those faulting accesses is **not yet identified**. The existence of these handler checks does not prove which games or conditions choose individual selectors.

## Directly applicable Ghidra metadata

Existing dispatcher signature (verified by user):

\`\`\`
0xFFFFD000
void DispatchRuntimeCodePatch(DeckardRuntimePatchMode patchMode)
\`\`\`

Datatypes: \`DeckardRuntimePatchMode\` enum of size 4 with \`NoChange=0\`, \`PrimaryHookVariant1..4=1..4\`, \`InstallTwoHooks=5\`, \`RedirectConditionalBranch=6\`, \`RedirectCall=7\`.

Extra **address labels** only (not new functions):

\`\`\`
0x00A01138 -> CheckMipsRomPatchContext
0x00A01150 -> CheckDataExceptionPatchAddress
0x00A01160 -> SkipFaultingPpcInstructionForPatch
0x00A0116C -> DispatchPatchModeFromDear
\`\`\`

\`AnnotateDeckardFaultPatchSelector_20261015_v1.java\` verifies 18 original instruction words in the combined database before adding these labels and five specific pre-comments. It leaves existing functions, source comments, bytes, and SLEIGH language unchanged. It can be run from Script Manager after pulling \`testing\`, without extension rebuilding.

## Verification and remaining work
- Dispatcher mode table, original patch bytes, function signature, 22 previous annotations **verified through user's execution of the v1 runtime patch script**.
- The new DEAR decoding is confirmed against original PPC instruction bytes; the algebraic gate equivalence has been checked. SPR 61 corresponds to DEAR in the PPC Book E architecture: https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/mpc5xxx/5564/2/EREFRM_2-0.pdf.
- New Java annotation script is source-reviewed only; **not yet compiled or runtime-tested**.
- Remaining useful work: determine which MIPS ROM fetch/data paths issue faults at \`0x02000000..0x0200001F\`; inspect DPATCH handler modes, and audit merged ELF+DPATCH complete APU coverage. Avoid changes to the SLEIGH specification unless decoding demonstrably fails.
