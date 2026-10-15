# DECKARD comprehensive compatibility and serial patch pass, 2026-10-15 v12


**Supersedes v11:** the array at 0x00BE0A30 is \`char *[18]\` of name pointers, *not* an array of numeric defaults. The original v1 script/document were removed from the current branch to avoid applying the wrong datatype. All other verified facts are retained.

## Proven state before this pass
User ran \`AnnotateDeckardPatchHookPredicates_20261015_v1.java\` against combined DECKARD ELF + DPATCH and reported: **32/32 DPATCH instruction anchors and 18/18 ROM compatibility records passed**, 10 labels, 11 pre-comments, 2 function refinements, zero skips/errors except intentional preservation of existing markup at 0x00A0F14C. Default restorer signature is \`void RestoreCompatibilityParameterDefaults(void)\`. The older dispatcher annotation likewise passed 32/32 mode pointers, kept Ghidra's existing jump-table markup, and applied 22 comments.

## Full ROM-level findings this pass

The original SCPH-79001 DECKARD ELF and 2,084-byte DPATCH raw binaries were inspected alongside the exported combined GZF's metadata. The ELF's \`.data\` 18-record table at \`0x00A0F14C..0x00A0F223\` contains \`{uint32_t id, uint32_t defaultValue, char *name}\` (12 bytes) for every parameter index \`0..17\`. The 18 exact string names and values were validated, not inferred.

| ID | Exact firmware string | Default |
|---:|---|---:|
| 0 | `PARAM_MDEC_DELAY_CYCLE` | 500 |
| 1 | `PARAM_SPU_INT_DELAY_LIMIT` | 2000 |
| 2 | `PARAM_SPU_INT_DELAY_PPC_COEFF` | 35 |
| 3 | `PARAM_SPU2_INT_DELAY_LIMIT` | 2000 |
| 4 | `PARAM_SPU2_INT_DELAY_PPC_COEFF` | 20 |
| 5 | `PARAM_DMAC_CH10_INT_DELAY` | 0 |
| 6 | `PARAM_CPU_DELAY` | 1 |
| 7 | `PARAM_SPU_DMA_WAIT_LIMIT` | 32 |
| 8 | `PARAM_GPU_DMA_WAIT_LIMIT` | 0 |
| 9 | `PARAM_DMAC_CH10_INT_DELAY_DPC` | 0 |
| 10 | `PARAM_CPU_DELAY_DPC` | 0 |
| 11 | `PARAM_USB_DELAYED_INT_ENABLE` | 0 |
| 12 | `PARAM_TIMER_LOAD_DELAY` | 0 |
| 13 | `PARAM_SIO0_DTR_SCK_DELAY` | 8860 |
| 14 | `PARAM_SIO0_DSR_SCK_DELAY_C` | 1772 |
| 15 | `PARAM_SIO0_DSR_SCK_DELAY_M` | 1772 |
| 16 | `PARAM_MIPS_DCACHE_ON` | 1 |
| 17 | `PARAM_CACHE_FLASH_CHANNELS` | 144 |

### New datatype dependencies, in order

\`\`\`text
Enum: DeckardCompatibilityParameterId
Size: 4
MdecDelayCycle = 0
SpuInterruptDelayLimit = 1
SpuInterruptDelayPpcCoefficient = 2
Spu2InterruptDelayLimit = 3
Spu2InterruptDelayPpcCoefficient = 4
DmacChannel10InterruptDelay = 5
CpuDelay = 6
SpuDmaWaitLimit = 7
GpuDmaWaitLimit = 8
DmacChannel10InterruptDelayDpc = 9
CpuDelayDpc = 10
UsbDelayedInterruptEnable = 11
TimerLoadDelay = 12
Sio0DtrSckDelay = 13
Sio0DsrSckDelayC = 14
Sio0DsrSckDelayM = 15
MipsDcacheOn = 16
CacheFlashChannels = 17
\`\`\`

\`\`\`text
Function typedef: DeckardCompatibilityValueCallback
void DeckardCompatibilityValueCallback(DeckardCompatibilityParameterId parameterId, uint32_t newValue)
\`\`\`

\`\`\`text
Structure: DeckardSerialTimingStateView
Size: 0x0F (partial; next byte at +0x0F not typed)
0x00 uint32_t referenceTicks0  [4]
0x04 uint32_t referenceTicks1  [4]
0x08 uint8_t phaseCode         [1]
0x09 uint8_t phaseCounter      [1]
0x0A uint8_t lastDataByte      [1]
0x0B uint8_t controlFlag       [1]
0x0C uint16_t controlBits      [2]
0x0E uint8_t controlNibble     [1]
\`\`\`

The serial structure is a conservative view of observed offsets at \`0x00BE07A8\`, accessed from both \`0x00A0AF90\` and the mode-7 replacement \`0xFFFFD5EC\`. The low-level register IO around this state is compatible with the PS1 SIO0 peripheral, and index 13 (\`PARAM_SIO0_DTR_SCK_DELAY\`) directly affects the patched wait path. Field names not established by access behavior are intentionally neutral.

### Global data declarations (apply only where no existing type overlaps)

\`\`\`text
0x00BE09E0 - 0x00BE0A27   uint32_t[18]       CompatibilityLiveValues
0x00BE0A28 - 0x00BE0A2B   uint32_t           CompatibilityControlWord0
0x00BE0A2C - 0x00BE0A2F   uint32_t           CompatibilityControlWord1
0x00BE0A30 - 0x00BE0A77   char *[18]         CompatibilityParameterNamePointers
0x00BE0A78 - 0x00BE0ABF   DeckardCompatibilityValueCallback *[18] CompatibilityCallbackPointers
0x00BE07A8 - 0x00BE07B6   DeckardSerialTimingStateView SerialControlTimingState
\`\`\`

Confirmed by original instructions: at \`0x00A0C8D4\`, \`lwz r11,8(r9)\` loads the **third field**, the ASCII-name pointer, from the ROM record. \`0x00A0C8DC\` stores it to \`0x00BE0A30[id]\`. This runtime table contains **char* names**, not numeric defaults. Numeric defaults come directly from the second record field (+4) when initializing live values.

### Function declarations (direct Ghidra function editor syntax, no semicolon)

\`\`\`text
0x00A0C7C4
uint32_t GetCompatibilityParameterValue(uint32_t parameterId)

0x00A0C7F0
void SetCompatibilityParameterValue(uint32_t parameterId, uint32_t newValue)

0x00A0C864
void InitializeCompatibilityParameterValues(void)

0x00A0C948
void RegisterCompatibilityParameterCallback(DeckardCompatibilityParameterId parameterId, DeckardCompatibilityValueCallback * callback)

0x00A0C964
uint32_t InitializeCompatibilityAndReportReady(void)

0x00A0AF90
void UpdateSerialControlState(uint32_t controlWord)

0xFFFFD5EC
void UpdateSerialControlStateWithTiming(uint32_t controlWord)

0xFFFFD770
void RestoreCompatibilityParameterDefaults(void)

0xFFFFD09C
void InstallRuntimePatchMode1(void)

0xFFFFD1F8
void InstallRuntimePatchMode2(void)

0xFFFFD2F4
void InstallRuntimePatchMode3(void)

0xFFFFD3B4
void InstallRuntimePatchMode4(void)

0xFFFFD494
void InstallRuntimePatchMode5(void)

0xFFFFD5A4
void InstallRuntimePatchMode6(void)

0xFFFFD5C8
void InstallRuntimePatchMode7(void)

0xFFFFD740
void WriteRuntimePatchMode7Branch(void)
\`\`\`

These signatures apply only to known entries with exact firmware words and no conflicting user-defined signatures. The setter's \`parameterId == -1\`, \`newValue == 0\` request is a special reset command: it tail-branches from \`0x00A0C860\` to DPATCH \`0xFFFFD770\`. Getter returns 0 for invalid indexes. Setter writes live array then calls registered callback using the existing \`r3=parameterId, r4=newValue\` calling convention. Callback definition is inferred from this actual indirect call setup; no callback return is consumed.

Initializer \`0x00A0C864\` clears bookkeeping, populates 18 parameter-name pointers, and initializes 18 live values via the setter. DPATCH \`0xFFFFD770\` is a separately implemented reset path. The original serial-state update \`0x00A0AF90\` is called by \`0x00A0B1B0\`. Runtime mode 7 replaces that call with a relative \`bl\` into \`0xFFFFD5EC\`. No executable bytes should be patched in the static Ghidra DB.

### Patch mode 7 timing coupling
- At \`0xFFFFD5EC\`, the replacement decodes serial control bits and updates the serial-state view. It adds timebase-driven waits absent from the original.
- One wait uses constant **5759 ticks** at \`0xFFFFD66C\` and \`0xFFFFD714\`.
- A later branch at \`0xFFFFD6C0\` reads live compatibility parameter 13 from \`0x00BE0A14\`. This is the firmware parameter \`PARAM_SIO0_DTR_SCK_DELAY\`, default **8860 ticks**.
- Thus game-specific parameter overrides can directly affect patch mode 7's timing behavior. This still does **not** identify the external guest program that causes the data-access fault selecting the patch.

## Script and safety

\`ghidra_scripts/EnrichDeckardCompatibilityAndSerialPatch_20261015_v2.java\` implements this batch. It checks **46 exact instruction anchors and all 18 IDs, values, pointer addresses, and ROM strings** before any metadata operation. It conditionally adds the enum, callback definition, partial serial view, named globals, typed global arrays, verified installer/compatibility/serial functions and signatures, 36 parameter/firmware-string labels, and comments. It leaves all already typed ranges, conflicting signatures, analyst labels and firmware bytes alone; no runtime-only branch references are fabricated. Re-running is safe.

Source-reviewed but **not yet compiled or executed in Ghidra**. Run after pulling \`testing\`; no extension rebuild. Return output, especially SKIP/PRESERVE reasons, so remaining work can focus on genuine code analysis rather than repeating these settled observations.

## Next research
Trace guest-side conditions producing \`DEAR=0x02000001..0x02000007\`, then examine downstream APU control semantics. A search for immediate \`0x02000000\` in the main PPC ELF cannot by itself establish which emulated MIPS instruction triggers a fault. Keep opcode specs unchanged pending a demonstrated issue.
