# DECKARD combined firmware control-plane and mode-7 recovery (2026-10-15 v14)

## Verified baseline, user-supplied execution results
- \`EnrichDeckardCompatibilityAndSerialPatch_20261015_v2.java\` ran successfully on the combined PowerPC:BE:32:DECKARD Ghidra program.
- Passed **46 exact instruction anchors + all 18 parameter IDs/defaults/ASCII names + complete DPATCH mapping**.
- Applied **three datatypes, six renamed functions, thirteen signature changes, 42 labels and 39 comments**; no new functions, no typed globals, 15 preserve decisions, no firmware-byte changes.
- Preserved six already typed/partly defined ranges: live values \`0x00BE09E0\`, two control words at \`0x00BE0A28/2C\`, name pointers \`0x00BE0A30\` (conflict from \`+0x04\`), callback pointers \`0x00BE0A78\`, serial state \`0x00BE07A8\`. **Do not clear existing data to force whole-array declarations.**
- Preserved eight DPATCH mode-handler/installer entry points (all reported as contained in \`DispatchRuntimeCodePatch\`). The dispatcher at \`0xFFFFD014\` ends its entry logic with \`bctr\` into a 32-entry jump table at \`0xFFFFD018\`. Those targets are Ghidra switch-case bodies, not automatically independent functions. Splitting them as standalone functions would damage valid analysis.
- \`0xFFFFD5EC\` was not disassembled. It is the separately entered serial-state replacement routine for mode 7, whose only static call word at \`0x00A0B1B0\` is generated **at runtime** (so ordinary flow analysis cannot discover it from the ROM). Recover it only when not occupied by an existing function/data range.

## Firmware findings expanded in this pass

### Parameter MMIO control interface, main firmware function 0x00A064C8
The PPC register-write handler masks its selector input to nine bits: \`r0 = r3 & 0x1FF\` at \`0x00A064F0\`. Two cases are connected to the compatibility API:

| Register/selector | Handler | Side effects |
|---|---|---|
| \`0x1A0\` | \`0x00A0664C\` | Store \`r4\` as selected parameter ID at \`0x00BE0400\`; call getter \`0x00A0C7C4\`; store result at \`0x00BE0404\` |
| \`0x1A4\` | \`0x00A06634\` | Read selected ID from \`0x00BE0400\`; store \`r4\` to \`0x00BE0404\`; call setter \`0x00A0C7F0\` |

Because the setter handles \`parameterId==-1\` with \`newValue==0\` by jumping to \`0xFFFFD770\`, this register interface can also reach the reset-defaults path. The firmware proves this wiring, **not** the identity of the guest program causing the request or its use of the DEAR patch-mode command range \`0x02000001..07\`.

**New datatype dependencies (define before data):**
\`\`\`text
Enum: DeckardCompatibilityMmioOffset
Size: 2
ParameterIndex = 0x01A0
ParameterValue = 0x01A4

Structure: DeckardCompatibilityMmioLatch
Size: 0x08
0x00 int32_t selectedParameterId   (4)
0x04 uint32_t lastValue            (4)
\`\`\`
The latch resides at \`0x00BE0400..0x00BE0407\`. Direct applicability: if that range is undefined, use \`DeckardCompatibilityMmioLatch\`. If Ghidra already has typed cells, preserve them and use named labels/comments.

### Compatibility parameter 16 is connected to MIPS cache/TLB mappings
- At \`0x00A06B38..0x00A06B44\`, the firmware registers \`0x00A05DF0\` as the callback for compatibility ID 16, \`PARAM_MIPS_DCACHE_ON\`, with the known registration API at \`0x00A0C948\`.
- It immediately calls \`0x00A05DF0\` once to apply the current state.
- \`0x00A05DF0\` reloads the **live value at 0x00BE0A20**, ignores incoming PPC argument registers, branches to \`0x00A05D0C\` when nonzero and to \`0x00A05DA4\` when zero.
- Both branches update **ten TLB entry pairs** using \`tlbrehi/tlbwehi/tlbsync\`; the nonzero branch additionally writes special-purpose PPC registers and MSR state. These are meaningful cache/mapping side effects, not a simple boolean flag write.
- Do not rename the TLB helpers speculatively based on guessed low-level SPR meanings. Conservative labels:
\`\`\`text
0x00A05DF0 -> ApplyMipsDcacheConfiguration
0x00A05D0C -> ConfigureMipsDcacheEnabledTlb
0x00A05DA4 -> ConfigureMipsDcacheDisabledTlb
0x00BE0A20 -> CompatibilityLiveValues[16]
\`\`\`

### Additional compatibility parameter override source at 0x00A09C0C
Within its larger peripheral initialization code, the firmware directly calls \`SetCompatibilityParameterValue\` six times, for IDs **0, 6, 7, 8, 12, 16**. The values are read from a runtime hardware/configuration data structure, **not** the original ROM defaults. Instruction sites, in order:
\`\`\`text
0x00A09CE4 -> SetCompatibilityParameterValue(0, sourceValue)
0x00A09CF4 -> SetCompatibilityParameterValue(6, sourceValue)
0x00A09D04 -> SetCompatibilityParameterValue(7, sourceValue)
0x00A09D14 -> SetCompatibilityParameterValue(8, sourceValue)
0x00A09D24 -> SetCompatibilityParameterValue(12, sourceValue)
0x00A09D34 -> SetCompatibilityParameterValue(16, sourceValue)
\`\`\`
The serial timing patch uses live compatibility parameter 13, whose default is 8860; this override site does *not* directly set index 13.

### True mode-7 runtime entry at 0xFFFFD5EC
- Original serial update is called by \`0x00A0B1B0\` with ROM word \`0x4BFFFDE1\` (relative \`bl 0x00A0AF90\`).
- Mode 7 installs \`0x4B5F243D\` at the same address, a runtime relative \`bl 0xFFFFD5EC\`.
- Routine \`0xFFFFD5EC\` starts \`andi. r0,r3,2\`; it branches internally, reads PPC timebase at \`0xFFFFD620\`, waits 5759 ticks on one phase path, consults live compatibility parameter 13 at \`0xFFFFD6C0\`, and handles serial phase state at \`0x00BE07A8\`.
- It has a valid \`blr\` at \`0xFFFFD634\` along a shorter execution path. Do **not** interpret that first return as the entire function; other conditionals reach instructions at \`0xFFFFD638..0xFFFFD73C\`.
- Direct Ghidra editor signature, **only if a true function entry is safely recoverable**:
\`\`\`text
0xFFFFD5EC
void UpdateSerialControlStateWithTiming(uint32_t controlWord)
\`\`\`
- Eight DPATCH selector jump-table arms are preserved within \`DispatchRuntimeCodePatch\`, and \`0xFFFFD740\` is an installer branch target from within the mode-7 switch case; do not split those into artificial functions.

**v2 correction:** the callback function is named/created before any additional label at the same entry, avoiding an avoidable duplicate-symbol conflict. The prior v1 script and handoff have been superseded before user execution.

## One-pass application script
\`ghidra_scripts/RecoverDeckardControlPlaneAndMode7_20261015_v2.java\`:
- Checks **87 exact executable words** in original ELF+DPATCH before writing any metadata; aborts on mismatches.
- Defines the MMIO offset enum and latch structure, and types the latch only if no other defined data/code exists.
- Applies relevant labels/comments to both MMIO commands, three cache/TLB entry points, the callback registration, all six override call sites, the boot setup call, and the runtime serial hook.
- Conservatively improves the callback's Ghidra function name and void return; refines the registration index to existing \`DeckardCompatibilityParameterId\` only if its concrete existing type is a compatible generic 32-bit integer and analyst has not specified a custom signature.
- Attempts to disassemble/create the true \`0xFFFFD5EC\` function **only if** not contained in an existing function or defined data. Preserves all overlapping DPATCH switch bodies.
- Never changes firmware bytes, deletes code/data, or creates a fake static call from the unpatched serial site.

## Verification/remaining work
Firmware bytes and control-flow relationships verified from original DECKARD ELF and DPATCH, cross-referenced to prior Ghidra script execution logs. Ghidra application script is source-reviewed but not runtime-tested.

Next productive research: identify the guest-side producer of memory accesses triggering DEAR 0x02000001..07. The host firmware alone establishes the fault gateway and consumers, not the guest instructions. For p-code improvements, investigate custom APU userop semantics separately; don't add unknown SLEIGH patterns just to silence audit counters.
