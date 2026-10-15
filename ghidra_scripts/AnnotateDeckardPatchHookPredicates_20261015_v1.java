// SCPH-79001 DECKARD/DPATCH: annotate exact hooked-address predicates,
// timing-state accesses and the 18-record APU compatibility default table.
// Requires combined PowerPC:BE:32:DECKARD program. No executable bytes changed.
//@category PS2.DECKARD
import java.util.Locale;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class AnnotateDeckardPatchHookPredicates_20261015_v1 extends GhidraScript {
    private static final long[][] REQUIRED = {
        {0xffffd0c4L, 0x7fa3eb78L},
        {0xffffd0d8L, 0x3ca00002L},
        {0xffffd0dcL, 0x60a53000L},
        {0xffffd0e0L, 0x3cc00002L},
        {0xffffd0e4L, 0x60c632c0L},
        {0xffffd0e8L, 0x546402feL},
        {0xffffd16cL, 0x001bd38cL},
        {0xffffd220L, 0x7fa3eb78L},
        {0xffffd234L, 0x3ca00002L},
        {0xffffd238L, 0x60a5c170L},
        {0xffffd23cL, 0x3cc00002L},
        {0xffffd240L, 0x60c6c1e0L},
        {0xffffd244L, 0x3ce00002L},
        {0xffffd248L, 0x60e7c2d0L},
        {0xffffd24cL, 0x546402feL},
        {0xffffd31cL, 0x7fa3eb78L},
        {0xffffd330L, 0x7d294a78L},
        {0xffffd334L, 0x546402feL},
        {0xffffd338L, 0x7c044840L},
        {0xffffd3dcL, 0x7fa3eb78L},
        {0xffffd3f0L, 0x3ca00002L},
        {0xffffd3f4L, 0x60a57f00L},
        {0xffffd3f8L, 0x546402feL},
        {0xffffd4dcL, 0x001bd38cL},
        {0xffffd554L, 0x7c651b78L},
        {0xffffd5ecL, 0x70600002L},
        {0xffffd5f8L, 0x396a07a8L},
        {0xffffd740L, 0x3d6000a1L},
        {0xffffd770L, 0x9421ff98L},
        {0xffffd77cL, 0x38000012L},
        {0xffffd7b4L, 0x3909f14cL},
        {0xffffd7ecL, 0x48a0f005L}
    };

    private static final int[] DEFAULT_VALUES = {
        500, 2000, 35, 2000, 20, 0, 1, 32, 0,
        0, 0, 0, 0, 8860, 1772, 1772, 1, 144
    };

    private int newLabels;
    private int newComments;
    private int dataDeclarations;
    private int functionRefinements;

    private long read32(Memory memory, long offset) throws Exception {
        byte[] bytes = new byte[4];
        Address a = toAddr(offset);
        if (!memory.contains(a) || memory.getBytes(a, bytes) != 4) {
            throw new IllegalStateException("Unmapped/unreadable " + a);
        }
        return Integer.toUnsignedLong(
            ((bytes[0] & 255) << 24) | ((bytes[1] & 255) << 16) |
            ((bytes[2] & 255) << 8) | (bytes[3] & 255));
    }

    private void comment(long address, String value) {
        Listing listing = currentProgram.getListing();
        Address at = toAddr(address);
        String marker = "DECKARD VERIFIED HOOK: ";
        String old = listing.getComment(CommentType.PRE, at);
        if (old != null && old.contains(marker)) {
            return;
        }
        listing.setComment(at, CommentType.PRE,
            old == null || old.isEmpty() ? marker + value :
            old + "\n" + marker + value);
        newComments++;
    }

    private void label(long address, String name) {
        Address at = toAddr(address);
        for (Symbol existing : currentProgram.getSymbolTable().getSymbols(at)) {
            if (name.equals(existing.getName())) return;
        }
        try {
            currentProgram.getSymbolTable().createLabel(at, name, SourceType.ANALYSIS);
            newLabels++;
        }
        catch (Exception e) {
            println("PRESERVE symbol " + at + ": " + e.getMessage());
        }
    }

    private DataType makeParameterRecord() {
        DataTypeManager manager = currentProgram.getDataTypeManager();
        CategoryPath path = new CategoryPath("/DECKARD");
        StructureDataType structure =
            new StructureDataType(path, "DeckardCompatibilityParameter", 0, manager);
        structure.add(UnsignedIntegerDataType.dataType, 4, "parameterId",
            "0..17 compatibility parameter index");
        structure.add(UnsignedIntegerDataType.dataType, 4, "defaultValue",
            "Firmware-defined initial value");
        structure.add(new PointerDataType(CharDataType.dataType, 4, manager),
            4, "parameterName", "Pointer to parameter name string");
        if (structure.getLength() != 12) {
            throw new IllegalStateException("Unexpected parameter record size");
        }
        DataType old = manager.getDataType(path, structure.getName());
        if (old != null) {
            if (!old.isEquivalent(structure)) {
                println("PRESERVE existing conflicting " + old.getPathName());
                return null;
            }
            return old;
        }
        return manager.addDataType(structure, DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private void applyRecordArray(DataType recordType) {
        if (recordType == null) return;
        Listing listing = currentProgram.getListing();
        Address at = toAddr(0x00a0f14cL);
        for (int i = 0; i < 18 * 12; i++) {
            Address cell = at.add(i);
            if (listing.getInstructionContaining(cell) != null ||
                listing.getDefinedDataContaining(cell) != null) {
                println("PRESERVE existing markup in compatibility table at " + cell);
                return;
            }
        }
        try {
            listing.createData(at, new ArrayDataType(recordType, 18, 12));
            dataDeclarations++;
            println("DEFINED 0x00A0F14C..0x00A0F223 as DeckardCompatibilityParameter[18]");
        }
        catch (Exception e) {
            println("PRESERVE table declaration: " + e.getMessage());
        }
    }

    private void refineDefaultRestorer() {
        Address address = toAddr(0xffffd770L);
        Function function = getFunctionAt(address);
        if (function == null) {
            println("PRESERVE 0xFFFFD770: function not defined; annotation only");
            return;
        }
        if (function.getName().startsWith("FUN_") &&
            function.getSymbol().getSource() != SourceType.USER_DEFINED) {
            try {
                function.setName("RestoreCompatibilityParameterDefaults", SourceType.ANALYSIS);
                functionRefinements++;
            }
            catch (Exception e) {
                println("PRESERVE existing function name: " + e.getMessage());
            }
        }
        if (function.getSignatureSource() != SourceType.USER_DEFINED &&
            !function.hasCustomVariableStorage() &&
            function.getParameterCount() == 0 &&
            Undefined.isUndefined(function.getReturnType())) {
            try {
                function.setReturnType(VoidDataType.dataType, SourceType.ANALYSIS);
                functionRefinements++;
            }
            catch (Exception e) {
                println("PRESERVE return type: " + e.getMessage());
            }
        }
        println("DEFAULT RESTORER " + function.getPrototypeString(false, false));
    }

    @Override
    protected void run() throws Exception {
        if (!"PowerPC:BE:32:DECKARD".equals(currentProgram.getLanguageID().toString()) ||
            !"DECKARD.elf".equalsIgnoreCase(currentProgram.getName())) {
            printerr("ABORT: requires combined DECKARD.elf with DECKARD language");
            return;
        }
        Memory memory = currentProgram.getMemory();
        MemoryBlock patch = memory.getBlock(toAddr(0xffffd000L));
        if (patch == null || !patch.isInitialized() ||
            patch.getEnd().getOffset() < 0xffffd823L) {
            printerr("ABORT: DPATCH not mapped at 0xFFFFD000..0xFFFFD823");
            return;
        }

        int mismatch = 0;
        for (long[] pair : REQUIRED) {
            long got;
            try {
                got = read32(memory, pair[0]);
            }
            catch (Exception e) {
                println("BAD ADDRESS " + Long.toHexString(pair[0]) + " " + e.getMessage());
                mismatch++;
                continue;
            }
            if (got != pair[1]) {
                println(String.format(Locale.ROOT,
                    "BAD WORD %08x expected=%08x actual=%08x",
                    pair[0], pair[1], got));
                mismatch++;
            }
        }
        for (int i = 0; i < DEFAULT_VALUES.length; i++) {
            long record = 0x00a0f14cL + i * 12L;
            long id = read32(memory, record);
            long value = read32(memory, record + 4);
            long ptr = read32(memory, record + 8);
            if (id != i || value != DEFAULT_VALUES[i] ||
                ptr < 0x00a0ef00L || ptr >= 0x00a0f14cL) {
                println("BAD COMPAT RECORD " + i + " id=" + id +
                    " value=" + value + " namePtr=0x" + Long.toHexString(ptr));
                mismatch++;
            }
        }
        if (mismatch > 0) {
            printerr("ABORT: " + mismatch +
                " firmware data mismatches. No annotations or types applied.");
            return;
        }
        println("PASS: 32 DPATCH instruction words + all 18 compatibility parameter records.");

        label(0xffffd0c4L, "PatchMode1Hook");
        label(0xffffd220L, "PatchMode2Hook");
        label(0xffffd31cL, "PatchMode3Hook");
        label(0xffffd3dcL, "PatchMode4Hook");
        label(0xffffd4dcL, "PatchMode5HookA");
        label(0xffffd554L, "PatchMode5HookB");
        label(0xffffd5ecL, "PatchMode7ReplacementRoutine");
        label(0xffffd740L, "InstallPatchMode7Branch");
        label(0x00be07a8L, "PatchMode7TimingState");
        label(0x00a0f14cL, "CompatibilityParameterDefaults");

        comment(0xffffd0c4L,
            "Mode 1 takes the low 21 bits of the APU hook's r3 input. It first " +
            "bounds the value to 0x23000..0x232C0, then compares it to " +
            "{0x23000,0x230E0,0x23170,0x231A0,0x231C0,0x231E0,0x232C0}. " +
            "Matched values take the special MIPS-emulation path; other values " +
            "take the shared instruction-class fallback. This does not select mode 1.");
        comment(0xffffd220L,
            "Mode 2 special path requires (r3 & 0x1FFFFF) to equal one of " +
            "{0x2C170,0x2C1E0,0x2C2D0}. Other values take the shared fallback.");
        comment(0xffffd31cL,
            "Mode 3 special path requires (r3 & 0x1FFFFF) == 0. " +
            "r9 is explicitly zeroed before comparison.");
        comment(0xffffd3dcL,
            "Mode 4 special path requires (r3 & 0x1FFFFF) == 0x27F00.");
        comment(0xffffd4dcL,
            "Mode 5 hook A replaces an APU instruction at 0x00A03AE0; " +
            "contains a conditional check and branch to main-firmware execution.");
        comment(0xffffd554L,
            "Mode 5 hook B replaces code at 0x00A03350, uses APU GTE register " +
            "polling and conditionally returns or writes APU state.");
        comment(0xffffd5ecL,
            "Mode 7 runtime replacement for call at 0x00A0B1B0. Writes a state " +
            "block at 0x00BE07A8 and consults the PPC timebase. This is " +
            "not a direct caller of DispatchRuntimeCodePatch.");
        comment(0xffffd740L,
            "Mode 7 installation routine computes a relative 'bl' to " +
            "0xFFFFD5EC and writes it into 0x00A0B1B0, followed by icbi/isync.");
        comment(0x00be07a8L,
            "Mode 7 state used by 0xFFFFD5EC: +0x00 timebase word; " +
            "+0x08/+0x09/+0x0B byte state fields; +0x0C halfword; " +
            "+0x0E byte field. Partial layout only; no inferred structure size.");
        comment(0x00a0f14cL,
            "18 records of {uint32_t parameterId, uint32_t defaultValue, " +
            "char *parameterName}. Reset routine 0xFFFFD770 builds defaults " +
            "and calls parameter setter 0x00A0C7F0 for IDs 0..17.");
        comment(0xffffd770L,
            "Builds a temporary 18-value table from 0x00A0F14C (record size 12), " +
            "calls 0x00A0C7F0 for each parameter, then clears 0x00BE0A28 " +
            "and 0x00BE0A2C. This restores defaults rather than defining " +
            "the per-parameter callbacks or names.");

        DataType record = makeParameterRecord();
        applyRecordArray(record);
        refineDefaultRestorer();

        println("DECKARD HOOK PREDICATES labels=" + newLabels +
            " comments=" + newComments +
            " dataDeclarations=" + dataDeclarations +
            " functionRefinements=" + functionRefinements);
        println("No instructions, existing functions, or firmware bytes modified.");
    }
}
