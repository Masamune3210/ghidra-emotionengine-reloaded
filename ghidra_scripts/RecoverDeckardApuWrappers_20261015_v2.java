// Recover exact two-instruction DECKARD APU accessors missed by linear auto-analysis.
// Run on a fresh DECKARD.elf imported using PowerPC:BE:32:DECKARD.
//@category PS2.DECKARD
import java.util.Locale;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;

public class RecoverDeckardApuWrappers_20261015_v2 extends GhidraScript {
    private static final int BLR = 0x4e800020;

    private static class Wrapper {
        final long address;
        final int opcode;
        final String mnemonic;
        final String name;
        final boolean returnsValue;
        final String[] parameters;
        Wrapper(long address, int opcode, String mnemonic, String name,
                boolean returnsValue, String... parameters) {
            this.address = address;
            this.opcode = opcode;
            this.mnemonic = mnemonic;
            this.name = name;
            this.returnsValue = returnsValue;
            this.parameters = parameters;
        }
    }

    // Every listed entry is exactly { one APU opcode, blr } in the original
    // SCPH-79001 DECKARD.elf .text. Do not extrapolate to other revisions.
    private static final Wrapper[] WRAPPERS = {
        new Wrapper(0x00a03198L, 0x000323cc, "amtgte", "ApuWriteGteRegister", false, "registerIndex", "value"),
        new Wrapper(0x00a031a0L, 0x006303dc, "amfgte", "ApuReadGteRegister", true, "registerIndex"),
        new Wrapper(0x00a031a8L, 0x0003238c, "amtgp", "ApuWriteMipsGpr", false, "registerIndex", "value"),
        new Wrapper(0x00a031b0L, 0x0063039c, "amfgp", "ApuReadMipsGpr", true, "registerIndex"),
        new Wrapper(0x00a031b8L, 0x0003028c, "amthi", "ApuWriteMipsHi", false, "value"),
        new Wrapper(0x00a031c0L, 0x0060029c, "amfhi", "ApuReadMipsHi", true),
        new Wrapper(0x00a031c8L, 0x000302cc, "amtlo", "ApuWriteMipsLo", false, "value"),
        new Wrapper(0x00a031d0L, 0x006002dc, "amflo", "ApuReadMipsLo", true),
        new Wrapper(0x00a031d8L, 0x0003020c, "amtpc", "ApuWriteMipsProgramCounter", false, "mipsPc"),
        new Wrapper(0x00a031e0L, 0x0060021c, "amfpc", "ApuReadMipsProgramCounter", true),
        new Wrapper(0x00a031e8L, 0x0003024c, "amtcc", "ApuWriteMipsCycleCounter", false, "cycles"),
        new Wrapper(0x00a031f0L, 0x0060025c, "amfcc", "ApuReadMipsCycleCounter", true)
    };

    private static int readBe32(Memory memory, Address address)
            throws MemoryAccessException {
        byte[] bytes = new byte[4];
        if (memory.getBytes(address, bytes) != 4) {
            throw new MemoryAccessException("Cannot read four bytes at " + address);
        }
        return ((bytes[0] & 255) << 24) | ((bytes[1] & 255) << 16) |
                ((bytes[2] & 255) << 8) | (bytes[3] & 255);
    }

    // Only refine signatures which were never specified by an analyst/importer.
    // Default PPC32 calling convention maps these uint32_t arguments to r3/r4
    // and uint32_t return values to r3, matching these exact two-word bodies.
    private boolean applyDefaultSignature(Function function, Wrapper wrapper) {
        if (function.getSignatureSource() != SourceType.DEFAULT ||
                function.hasCustomVariableStorage() || function.getParameterCount() != 0) {
            return false;
        }
        try {
            DataType u32 = UnsignedIntegerDataType.dataType;
            DataType result = wrapper.returnsValue ? u32 : VoidDataType.dataType;
            Variable ret = new ReturnParameterImpl(result, currentProgram);
            Variable[] arguments = new Variable[wrapper.parameters.length];
            for (int i = 0; i < arguments.length; i++) {
                arguments[i] = new ParameterImpl(wrapper.parameters[i], u32, currentProgram);
            }
            function.updateFunction(null, ret, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                false, SourceType.ANALYSIS, arguments);
            return true;
        }
        catch (Exception e) {
            printerr("SIGNATURE UNCHANGED " + function.getEntryPoint() + ": " + e.getMessage());
            return false;
        }
    }

    @Override
    protected void run() throws Exception {
        if (!"PowerPC:BE:32:DECKARD".equals(currentProgram.getLanguageID().toString())) {
            printerr("ABORT: requires PowerPC:BE:32:DECKARD");
            return;
        }
        if (!currentProgram.getName().toUpperCase(Locale.ROOT).contains("DECKARD")) {
            printerr("ABORT: this address-specific script is for the main DECKARD.elf");
            return;
        }

        Memory memory = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        int recoveredInstructions = 0;
        int createdFunctions = 0;
        int renamedFunctions = 0;
        int refinedSignatures = 0;
        int verified = 0;
        int skipped = 0;

        for (Wrapper wrapper : WRAPPERS) {
            monitor.checkCancelled();
            Address entry = toAddr(wrapper.address);
            Address ret = entry.add(4);
            if (!memory.contains(entry) || !memory.contains(ret) ||
                    memory.getBlock(entry) == null || !memory.getBlock(entry).isExecute()) {
                println("SKIP UNMAPPED/NONEXEC " + entry);
                skipped++;
                continue;
            }
            int raw, rawReturn;
            try {
                raw = readBe32(memory, entry);
                rawReturn = readBe32(memory, ret);
            }
            catch (MemoryAccessException e) {
                println("SKIP UNREADABLE " + entry);
                skipped++;
                continue;
            }
            if (raw != wrapper.opcode || rawReturn != BLR) {
                println("SKIP BYTE MISMATCH " + entry + " opcode=" +
                    Integer.toHexString(raw) + " tail=" + Integer.toHexString(rawReturn));
                skipped++;
                continue;
            }
            if (listing.getDefinedDataContaining(entry) != null ||
                    listing.getDefinedDataContaining(ret) != null) {
                println("SKIP DEFINED DATA " + entry);
                skipped++;
                continue;
            }
            Instruction existing = listing.getInstructionContaining(entry);
            Instruction existingReturn = listing.getInstructionContaining(ret);
            if ((existing != null && !entry.equals(existing.getAddress())) ||
                    (existingReturn != null && !ret.equals(existingReturn.getAddress()))) {
                println("SKIP OVERLAPPING INSTRUCTION " + entry);
                skipped++;
                continue;
            }
            Function containing = getFunctionContaining(entry);
            if (containing != null && !entry.equals(containing.getEntryPoint())) {
                println("SKIP PART OF OTHER FUNCTION " + entry +
                    " contained in " + containing.getName());
                skipped++;
                continue;
            }

            if (listing.getInstructionAt(entry) == null) {
                if (!disassemble(entry)) {
                    println("SKIP CANNOT DISASSEMBLE " + entry);
                    skipped++;
                    continue;
                }
                recoveredInstructions++;
            }
            if (listing.getInstructionAt(ret) == null) {
                if (!disassemble(ret)) {
                    println("SKIP CANNOT DISASSEMBLE RETURN " + ret);
                    skipped++;
                    continue;
                }
                recoveredInstructions++;
            }

            Instruction ins = listing.getInstructionAt(entry);
            Instruction returnInsn = listing.getInstructionAt(ret);
            if (ins == null || returnInsn == null ||
                    !wrapper.mnemonic.equals(ins.getMnemonicString().toLowerCase(Locale.ROOT)) ||
                    !"blr".equals(returnInsn.getMnemonicString().toLowerCase(Locale.ROOT))) {
                println("SKIP DECODE MISMATCH " + entry + " wanted=" + wrapper.mnemonic +
                    "/blr found=" + (ins == null ? "null" : ins.getMnemonicString()) +
                    "/" + (returnInsn == null ? "null" : returnInsn.getMnemonicString()));
                skipped++;
                continue;
            }

            Function function = getFunctionAt(entry);
            if (function == null) {
                function = createFunction(entry, wrapper.name);
                if (function == null) {
                    println("SKIP FUNCTION CREATION FAILED " + entry);
                    skipped++;
                    continue;
                }
                createdFunctions++;
            }
            else if (function.getSymbol().getSource() == SourceType.DEFAULT) {
                try {
                    function.setName(wrapper.name, SourceType.ANALYSIS);
                    renamedFunctions++;
                }
                catch (Exception e) {
                    println("PRESERVE NAME " + entry + ": " + e.getMessage());
                }
            }
            if (applyDefaultSignature(function, wrapper)) {
                refinedSignatures++;
            }
            if (listing.getComment(CommentType.PLATE, entry) == null) {
                listing.setComment(entry, CommentType.PLATE,
                    "SCPH-79001 DECKARD verified APU accessor: " +
                    wrapper.mnemonic + " followed by blr. " +
                    "Only PPC register ABI is modeled; APU hardware effects use opaque userops.");
            }
            println("VERIFIED " + entry + " " + ins + " ; " + function.getName() +
                " " + function.getPrototypeString(false, false));
            verified++;
        }

        println("DECKARD APU WRAPPERS verified=" + verified + "/" + WRAPPERS.length +
            " recoveredInstructions=" + recoveredInstructions +
            " createdFunctions=" + createdFunctions +
            " renamedFunctions=" + renamedFunctions +
            " refinedSignatures=" + refinedSignatures + " skipped=" + skipped);
        println("No bytes or SLEIGH processor definitions were modified.");
    }
}
