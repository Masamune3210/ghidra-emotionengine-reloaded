// Verify and annotate SCPH-79001 DECKARD runtime code-patch dispatcher.
// Applies metadata only, never changes executable bytes or SLEIGH definitions.
// Run in the combined DECKARD.elf+DPATCH program with PowerPC:BE:32:DECKARD.
//@category PS2.DECKARD
import java.util.Locale;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class AnnotateDeckardRuntimePatchModes_20261015_v1 extends GhidraScript {
    private static final long PATCH_BASE = 0xffffd000L;
    private static final long PATCH_END = 0xffffd823L;
    private static final int TABLE_COUNT = 32;

    private static final long[] PATCH_HANDLER = {
        0xffffd098L, 0xffffd09cL, 0xffffd1f8L, 0xffffd2f4L,
        0xffffd3b4L, 0xffffd494L, 0xffffd5a4L, 0xffffd5c8L
    };

    private static final String[] MODE_NAMES = {
        "NoChange", "PrimaryHookVariant1", "PrimaryHookVariant2",
        "PrimaryHookVariant3", "PrimaryHookVariant4", "InstallTwoHooks",
        "RedirectConditionalBranch", "RedirectCall"
    };

    // Address/word pairs are independently verified in the ROM-extracted
    // DECKARD ELF and DPATCH (big endian); do not apply to other revisions.
    private static final long[][] EXPECTED_WORDS = {
        {0xffffd000L, 0x3c80ffffL},
        {0xffffd0c0L, 0x4bffd0c6L},
        {0xffffd21cL, 0x4bffd222L},
        {0xffffd318L, 0x4bffd31eL},
        {0xffffd3d8L, 0x4bffd3deL},
        {0xffffd4d4L, 0x4bffd4deL},
        {0xffffd4d8L, 0x4bffd556L},
        {0x00a01170L, 0x4bffd003L},
        {0x00a04778L, 0x7fa3eb78L},
        {0x00a047b4L, 0x419bed8cL},
        {0x00a097a0L, 0x54a3f87eL},
        {0x00a0b1b0L, 0x4bfffde1L},
        {0x00a03ae0L, 0x001bd38cL},
        {0x00a03350L, 0x7c651b78L}
    };

    private static final long[][] PATCH_WORDS = {
        {0xffffd0c0L, 0x4bffd0c6L, 0x00a04778L, 0xffffd0c4L},
        {0xffffd21cL, 0x4bffd222L, 0x00a04778L, 0xffffd220L},
        {0xffffd318L, 0x4bffd31eL, 0x00a04778L, 0xffffd31cL},
        {0xffffd3d8L, 0x4bffd3deL, 0x00a04778L, 0xffffd3dcL},
        {0xffffd4d4L, 0x4bffd4deL, 0x00a03ae0L, 0xffffd4dcL},
        {0xffffd4d8L, 0x4bffd556L, 0x00a03350L, 0xffffd554L}
    };

    private int comments = 0;
    private int labels = 0;
    private int signatures = 0;
    private int tableDeclarations = 0;

    private int read32(Memory mem, long absolute) throws Exception {
        byte[] buf = new byte[4];
        if (mem.getBytes(toAddr(absolute), buf) != 4) {
            throw new IllegalStateException("Short memory read at " +
                Long.toHexString(absolute));
        }
        return ((buf[0] & 255) << 24) | ((buf[1] & 255) << 16) |
            ((buf[2] & 255) << 8) | (buf[3] & 255);
    }

    private void note(long absolute, String message) {
        Address addr = toAddr(absolute);
        Listing list = currentProgram.getListing();
        String marker = "DECKARD RUNTIME PATCH: ";
        String old = list.getComment(CommentType.PRE, addr);
        if (old != null && old.contains(marker)) {
            return; // idempotent, keep all earlier analyst comments
        }
        list.setComment(addr, CommentType.PRE,
            old == null || old.isEmpty() ? marker + message :
            old + "\n" + marker + message);
        comments++;
    }

    private void createNonPrimaryLabel(long absolute, String name) {
        Address address = toAddr(absolute);
        SymbolTable symbols = currentProgram.getSymbolTable();
        for (Symbol symbol : symbols.getSymbols(address)) {
            if (symbol.getName().equals(name)) {
                return;
            }
        }
        try {
            symbols.createLabel(address, name, SourceType.ANALYSIS);
            labels++;
        }
        catch (Exception e) {
            println("PRESERVE SYMBOL at " + address + ": " + e.getMessage());
        }
    }

    private DataType ensurePatchEnum() {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        CategoryPath category = new CategoryPath("/DECKARD");
        EnumDataType declaration =
            new EnumDataType(category, "DeckardRuntimePatchMode", 4);
        for (int i = 0; i < MODE_NAMES.length; i++) {
            declaration.add(MODE_NAMES[i], i);
        }
        DataType previous = dtm.getDataType(category, declaration.getName());
        if (previous != null) {
            if (!previous.isEquivalent(declaration)) {
                println("PRESERVE conflicting existing enum " + previous.getPathName());
                return null;
            }
            return previous;
        }
        return dtm.addDataType(declaration, DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private void annotateDispatcher(DataType enumType) {
        Function fun = currentProgram.getFunctionManager().getFunctionAt(toAddr(PATCH_BASE));
        if (fun == null) {
            println("PRESERVE 0xFFFFD000: no existing function entry");
            return;
        }
        if (fun.getSymbol().getSource() != SourceType.USER_DEFINED &&
            fun.getName().startsWith("FUN_")) {
            try {
                fun.setName("DispatchRuntimeCodePatch", SourceType.ANALYSIS);
                labels++;
            }
            catch (Exception e) {
                println("PRESERVE FUNCTION NAME " + fun.getName() + ": " + e.getMessage());
            }
        }
        if (fun.hasCustomVariableStorage() ||
            fun.getSignatureSource() == SourceType.USER_DEFINED) {
            println("PRESERVE existing function signature " + fun.getName());
            return;
        }
        try {
            if (Undefined.isUndefined(fun.getReturnType())) {
                fun.setReturnType(VoidDataType.dataType, SourceType.ANALYSIS);
                signatures++;
            }
            if (fun.getParameterCount() == 1 && enumType != null) {
                Parameter param = fun.getParameter(0);
                DataType old = param.getDataType();
                boolean generic32 = Undefined.isUndefined(old) ||
                    (old.getLength() == 4 &&
                     (old.isEquivalent(UnsignedIntegerDataType.dataType) ||
                      "uint".equals(old.getName())));
                if (generic32) {
                    param.setDataType(enumType, SourceType.ANALYSIS);
                    signatures++;
                }
                if (param.getName().matches("param_[0-9]+") &&
                    (param.getSymbol() == null ||
                     param.getSymbol().getSource() != SourceType.USER_DEFINED)) {
                    param.setName("patchMode", SourceType.ANALYSIS);
                    signatures++;
                }
            }
            else if (fun.getParameterCount() != 1) {
                println("PRESERVE parameters: dispatcher currently has " +
                    fun.getParameterCount() + " parameters, expected 1");
            }
        }
        catch (Exception e) {
            println("PRESERVE PARTIAL SIGNATURE " + fun.getName() + ": " + e.getMessage());
        }
        println("DISPATCHER " + fun.getPrototypeString(false, false));
    }

    private void applyTableIfUndefined() {
        Address start = toAddr(0xffffd018L);
        Listing list = currentProgram.getListing();
        for (int i = 0; i < TABLE_COUNT * 4; i++) {
            Address a = start.add(i);
            if (list.getDefinedDataContaining(a) != null ||
                list.getInstructionContaining(a) != null) {
                println("PRESERVE existing code/data in patch table at " + a);
                return;
            }
        }
        try {
            DataType ptr = new PointerDataType(VoidDataType.dataType, 4,
                currentProgram.getDataTypeManager());
            list.createData(start, new ArrayDataType(ptr, TABLE_COUNT, 4));
            tableDeclarations++;
            println("DECLARED 0xFFFFD018..0xFFFFD097 as pointer[32]");
        }
        catch (Exception e) {
            println("PRESERVE table data layout: " + e.getMessage());
        }
    }

    @Override
    protected void run() throws Exception {
        if (!"PowerPC:BE:32:DECKARD".equals(currentProgram.getLanguageID().toString()) ||
            !currentProgram.getName().toUpperCase(Locale.ROOT).contains("DECKARD")) {
            printerr("ABORT: expected main DECKARD program with DECKARD language");
            return;
        }

        Memory memory = currentProgram.getMemory();
        MemoryBlock patch = memory.getBlock(toAddr(PATCH_BASE));
        if (patch == null || !patch.isInitialized() ||
            patch.getStart().getOffset() != PATCH_BASE ||
            patch.getEnd().getOffset() < PATCH_END) {
            printerr("ABORT: DPATCH not fully mapped at 0xFFFFD000..0xFFFFD823");
            return;
        }
        int bad = 0;
        for (long[] pair : EXPECTED_WORDS) {
            int observed = read32(memory, pair[0]);
            if (Integer.toUnsignedLong(observed) != pair[1]) {
                println(String.format(Locale.ROOT,
                    "MISMATCH %08x: expected %08x actual %08x",
                    pair[0], pair[1], Integer.toUnsignedLong(observed)));
                bad++;
            }
        }

        for (int i = 0; i < TABLE_COUNT; i++) {
            long expected = (i < PATCH_HANDLER.length) ?
                PATCH_HANDLER[i] : 0xffffd098L;
            long observed = Integer.toUnsignedLong(
                read32(memory, 0xffffd018L + i * 4L));
            if (observed != expected) {
                println(String.format(Locale.ROOT,
                    "TABLE MISMATCH slot %d expected %08x got %08x",
                    i, expected, observed));
                bad++;
            }
        }
        if (bad != 0) {
            printerr("ABORT: " + bad + " byte/table mismatches; metadata unchanged");
            return;
        }

        println("PASS: source words and all 32 dispatch-table slots match SCPH-79001");

        DataType modeType = ensurePatchEnum();
        annotateDispatcher(modeType);
        createNonPrimaryLabel(0xffffd018L, "RuntimeCodePatchJumpTable");
        applyTableIfUndefined();

        note(PATCH_BASE,
            "32-entry selector uses (r3 & 31). Selectors 0 and 8..31 " +
            "go to 0xFFFFD098 (blr). Selectors 1..7 install runtime instruction " +
            "patches into DECKARD code; static ROM bytes are the baseline.");
        note(0xffffd018L,
            "Big-endian PPC pointer[32] dispatch table. 0 -> no-op; 1..7 -> patch " +
            "handlers; 8..31 -> no-op. Verified all 32 target pointers.");
        note(0x00a01170L,
            "Absolute branch-with-link from main exception path to patch dispatcher " +
            "0xFFFFD000; source instruction 0x4BFFD003.");
        note(0xffffd098L, "No-op dispatch target for selectors 0 and 8..31 (blr).");

        for (int i = 0; i < PATCH_WORDS.length; i++) {
            long[] entry = PATCH_WORDS[i];
            note(entry[0], String.format(Locale.ROOT,
                "Patch mode %d copies word 0x%08X into 0x%08X, installing " +
                "absolute branch to 0x%08X; code cache invalidation follows.",
                i <= 3 ? i + 1 : 5, entry[1], entry[2], entry[3]));
            note(entry[3], "Entry reached when copied runtime branch from 0x" +
                Long.toHexString(entry[2]) + " is executed.");
        }

        note(0x00a04778L,
            "Main hook: original 0x7FA3EB78 (mr r3,r29). Patch modes 1..4 " +
            "replace it with distinct absolute branches into DPATCH.");
        note(0x00a03ae0L,
            "Patch mode 5 may replace original 0x001BD38C with 0x4BFFD4DE " +
            "(ba 0xFFFFD4DC).");
        note(0x00a03350L,
            "Patch mode 5 may replace original 0x7C651B78 with 0x4BFFD556 " +
            "(ba 0xFFFFD554).");
        note(0x00a047b4L,
            "Conditional-branch instruction 0x419BED8C branches to 0x00A03540. " +
            "Patch mode 6 writes halfword 0xFFB4 at 0x00A047B6, producing " +
            "0x419BFFB4 (branch to 0x00A04768); cache invalidate at 0x00A047B4.");
        note(0x00a097a0L,
            "Baseline 0x54A3F87E. Patch mode 1 writes 0x54A3F0BE. " +
            "Other patch paths restore the baseline; instruction cache synchronized.");
        note(0x00a0b1b0L,
            "Baseline 0x4BFFFDE1 (relative bl to 0x00A0AF90). Patch mode 7 " +
            "writes 0x4B5F243D (relative bl to 0xFFFFD5EC). Do not replace " +
            "static reference with the runtime-only branch target.");

        println("DONE runtime-patch metadata: comments=" + comments +
            " labelsAndFunctionRenames=" + labels +
            " signatureImprovements=" + signatures +
            " pointerTableDeclarations=" + tableDeclarations);
        println("No firmware bytes, instruction disassembly, or existing source comments cleared.");
    }
}
