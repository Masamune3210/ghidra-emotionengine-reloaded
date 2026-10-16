// Apply verified PS3 GXEMU VUART/OPD metadata and audit missing message-sender functions.
// @category PS3.PS2Emulation
// Ghidra 12.1.x; target: ps2_gxemu.elf imported as PowerPC:BE:64:A2ALT.
// Default: apply verified renames, OPD datatype/labels if only default data conflicts.
// No instruction/byte edits, speculative signatures, guessed packet structs or function promotions.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

public class ApplyAuditPs3GxemuVuart10Frames_20261016_v1 extends GhidraScript {
    private static final boolean APPLY_VERIFIED_FUNCTION_NAMES = true;
    private static final boolean APPLY_VERIFIED_OPD_TYPES = true;
    private static final boolean APPLY_VERIFIED_LABELS = true;
    private static final long TOC = 0x00678548L;
    private static final long[] OPD = {
        0x006470A0L, 0x006470B8L, 0x006470E8L, 0x00647100L
    };
    private static final long[] ENTRIES = {
        0x000494A4L, 0x00049544L, 0x000495B8L, 0x00049664L
    };
    private static final String[] ENTRY_NAMES = {
        "Lv1WriteVirtualUart", "Lv1ReadVirtualUart",
        "Lv1VirtualUartParameterDispatch", "Lv1ConfigureVirtualUartIrq"
    };

    private Address at(long a) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(a);
    }

    private boolean callTo(long site, long target) {
        Instruction ins = currentProgram.getListing().getInstructionAt(at(site));
        if (ins == null || !ins.getFlowType().isCall())
            return false;
        for (Address flow : ins.getFlows())
            if (flow.equals(at(target)))
                return true;
        return false;
    }

    private boolean validateDescriptors() throws Exception {
        for (int i = 0; i < OPD.length; ++i) {
            Address a = at(OPD[i]);
            if (!currentProgram.getMemory().contains(a) ||
                !currentProgram.getMemory().contains(a.add(23)))
                return false;
            long entry = currentProgram.getMemory().getLong(a);
            long toc = currentProgram.getMemory().getLong(a.add(8));
            long environment = currentProgram.getMemory().getLong(a.add(16));
            println(String.format("OPD_VERIFY address=%s entry=0x%X toc=0x%X environment=0x%X",
                a, entry, toc, environment));
            if (entry != ENTRIES[i] || toc != TOC || environment != 0)
                return false;
        }
        return true;
    }

    private void addSymbol(long a, String name) throws Exception {
        Address address = at(a);
        Symbol existing = currentProgram.getSymbolTable().getPrimarySymbol(address);
        if (existing != null && existing.getSource() != SourceType.DEFAULT) {
            println("PRESERVE_SYMBOL " + address + " existing=" + existing.getName());
            return;
        }
        try {
            currentProgram.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED);
            println("LABEL " + address + " -> " + name);
        } catch (Exception e) {
            println("LABEL_SKIPPED " + address + " " + e.getMessage());
        }
    }

    private void applyOpdTypes() throws Exception {
        DataType datatype = currentProgram.getDataTypeManager().getDataType(
            "/PS3/PPU/Ppc64FunctionDescriptor24");
        if (datatype == null) {
            StructureDataType model = new StructureDataType(
                new CategoryPath("/PS3/PPU"), "Ppc64FunctionDescriptor24", 0);
            PointerDataType pointer = new PointerDataType(VoidDataType.dataType, 8);
            model.add(pointer, 8, "entry", "Code entry address (verified)");
            model.add(pointer, 8, "toc", "TOC pointer to load into r2 (verified)");
            model.add(pointer, 8, "environment", "Third pointer word; zero in these four entries");
            datatype = currentProgram.getDataTypeManager().addDataType(
                model, DataTypeConflictHandler.DEFAULT_HANDLER);
            println("TYPE_CREATED " + datatype.getPathName() + " size=" + datatype.getLength());
        }
        if (datatype.getLength() != 24) {
            println("TYPE_REFUSED unexpected size " + datatype.getLength());
            return;
        }
        for (int i = 0; i < OPD.length; ++i) {
            Address a = at(OPD[i]);
            try {
                Data data = DataUtilities.createData(currentProgram, a, datatype, 24,
                    DataUtilities.ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
                println("DATA_APPLIED " + a + " " + data.getDataType().getName());
            } catch (Exception e) {
                // Do not clear prior intentional data, user-defined structs or instructions.
                println("DATA_PRESERVED " + a + " existing-data conflict: " + e.getMessage());
            }
            if (APPLY_VERIFIED_LABELS)
                addSymbol(OPD[i], "PpuOpd_" + ENTRY_NAMES[i]);
        }
    }

    private void renameIfVerified(long entry, long callSite, long target, String name) {
        Function f = currentProgram.getFunctionManager().getFunctionAt(at(entry));
        if (f == null || !f.getBody().contains(at(callSite)) ||
            !callTo(callSite, target)) {
            println(String.format("RENAME_REFUSED entry=0x%X call=0x%X target=0x%X",
                entry, callSite, target));
            return;
        }
        if (!f.getName().startsWith("FUN_")) {
            println("PRESERVE_FUNCTION " + f.getEntryPoint() + " " + f.getName());
            return;
        }
        try {
            String old = f.getName();
            f.setName(name, SourceType.USER_DEFINED);
            println("RENAME " + f.getEntryPoint() + " " + old + " -> " + name);
        } catch (Exception e) {
            println("RENAME_SKIPPED " + f.getEntryPoint() + " " + e.getMessage());
        }
    }

    private void printReferences(long a) throws Exception {
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(at(a));
        int count = 0;
        while (it.hasNext()) {
            monitor.checkCancelled();
            Reference ref = it.next();
            if (count < 32)
                println("    REF " + ref.getFromAddress() + " type=" +
                    ref.getReferenceType() + " op=" + ref.getOperandIndex());
            count++;
        }
        println("    REF_COUNT " + count);
    }

    private void scanUnownedCode() throws Exception {
        // Inspect only the gap containing the three observed, unowned port-10
        // writes and their likely surrounding routines.
        long start = 0x0008FD30L, end = 0x00090414L;
        println("FUNCTION_BOUNDARY_AUDIT 0x8FD30..0x90414");
        for (long p = start; p <= end; p += 4) {
            monitor.checkCancelled();
            Address a = at(p);
            Instruction ins = currentProgram.getListing().getInstructionAt(a);
            if (ins == null || ins.getLength() != 4)
                continue;
            int w = currentProgram.getMemory().getInt(a);
            boolean stduR1 = (w & 0xffff0000) == 0xf8210000;
            boolean blr = w == 0x4e800020;
            if (!(stduR1 || blr))
                continue;
            Function owner = currentProgram.getFunctionManager().getFunctionContaining(a);
            println(String.format("BOUNDARY_CANDIDATE %s word=%08X %s owner=%s",
                a, w, ins, owner == null ? "<none>" : owner.getName() +
                "@" + owner.getEntryPoint()));
            if (stduR1) {
                Instruction next = currentProgram.getListing().getInstructionAfter(a);
                Instruction prev = currentProgram.getListing().getInstructionBefore(a);
                println("    PREV=" + (prev == null ? "<none>" : prev.getAddress() +
                    " " + prev));
                println("    NEXT=" + (next == null ? "<none>" : next.getAddress() +
                    " " + next));
                printReferences(p);
            }
        }

        for (long p : new long[]{0x0008FF24L, 0x000900D0L, 0x000903D8L}) {
            Address a = at(p);
            Instruction ins = currentProgram.getListing().getInstructionAt(a);
            println("UNOWNED_WRITE " + a + " ins=" + ins + " owner=" +
                currentProgram.getFunctionManager().getFunctionContaining(a));
        }
    }

    private void tocAudit() throws Exception {
        if (APPLY_VERIFIED_LABELS)
            addSymbol(TOC, "PpuGlobalTocBase");
        // These addresses are derived only if an r2=TOC context is proven:
        // TOC-0x59f0 = 0x672B58; TOC-0x59e8 = 0x672B60;
        // TOC-0x59e0 = 0x672B68. Do not infer pointer contents or types here.
        long[] offsets = {-0x59f0L, -0x59e8L, -0x59e0L, -0x59d0L, -0x59c8L};
        for (long off : offsets) {
            Address a = at(TOC + off);
            MemoryBlock b = currentProgram.getMemory().getBlock(a);
            Data data = currentProgram.getListing().getDataAt(a);
            println(String.format("TOC_SLOT %s signed_offset=%d initialized=%b block=%s data=%s",
                a, off, b != null && b.isInitialized(),
                b == null ? "<none>" : b.getName(),
                data == null ? "<undefined>" : data.getDataType().getName()));
        }
        println("WARNING: r2 context NOT modified. ELF TOC established for 4 OPDs, not necessarily every routine.");
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null ||
            !"PowerPC:BE:64:A2ALT".equals(currentProgram.getLanguageID().toString()) ||
            !currentProgram.getName().contains("ps2_gxemu")) {
            printerr("REFUSE: expected full-address ps2_gxemu / PowerPC:BE:64:A2ALT");
            return;
        }
        println("GXEMU_FRAME_ANALYSIS v1");
        if (!validateDescriptors()) {
            printerr("REFUSE: one or more OPD descriptors differ. No metadata applied.");
            return;
        }
        if (APPLY_VERIFIED_OPD_TYPES)
            applyOpdTypes();
        if (APPLY_VERIFIED_FUNCTION_NAMES) {
            renameIfVerified(0x8FC68, 0x8FCA0, 0x49544, "ReceiveVirtualUartChunk");
            renameIfVerified(0x900FC, 0x901C8, 0x494A4, "SendVirtualUartFrame");
        }
        // Verified 0xFACE + 0x5000 header / 0x70 total outgoing length in
        // SendVirtualUartFrame. Not proof of a native MG command identifier.
        tocAudit();
        scanUnownedCode();
        println("DONE: Verified OPD/TOC and 2 transport names applied where safe.");
        println("No missing functions promoted. No signatures, packet structures, or data bytes changed.");
    }
}
