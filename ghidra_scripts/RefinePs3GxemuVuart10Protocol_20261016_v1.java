// Reconstruct proven PS3 GXEMU virtual UART 10 packet metadata, not native MagicGate crypto.
// @category PS3.PS2Emulation
// Ghidra 12.1.3; ps2_gxemu.elf imported PowerPC:BE:64:A2ALT.
// Conservative and repeatable: validate observed frame constructors and OPDs first.
// Creates datatypes, guarded TOC-local contexts and informative comments; no byte patches.
// Reads and decompiles relevant dispatch/translation functions for the next stage.

import java.math.BigInteger;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class RefinePs3GxemuVuart10Protocol_20261016_v1 extends GhidraScript {
    private static final boolean APPLY = true;
    private static final long TOC = 0x00678548L;
    private static final int MAX_REFS = 40;
    private Address at(long p) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(p);
    }

    private boolean opcode(long address, int word) throws Exception {
        Instruction ins = currentProgram.getListing().getInstructionAt(at(address));
        return ins != null && ins.getLength() == 4 &&
            currentProgram.getMemory().getInt(at(address)) == word;
    }

    private boolean hasCall(long caller, long target) throws Exception {
        Instruction ins = currentProgram.getListing().getInstructionAt(at(caller));
        if (ins == null || !ins.getFlowType().isCall()) return false;
        for (Address to : ins.getFlows()) if (to.equals(at(target))) return true;
        return false;
    }

    private DataType createFramePrefix() throws Exception {
        String path = "/PS3/GXEMU/GxemuVuart10FramePrefixBE";
        DataType existing = currentProgram.getDataTypeManager().getDataType(path);
        if (existing != null) {
            println("PRESERVE_TYPE " + path + " size=" + existing.getLength());
            return existing.getLength() == 0x10 ? existing : null;
        }
        StructureDataType dt = new StructureDataType(
            new CategoryPath("/PS3/GXEMU"), "GxemuVuart10FramePrefixBE", 0x10);
        dt.replaceAtOffset(0x00, DWordDataType.dataType, 4, "sequenceOrTag",
            "Ordinary senders write an incrementing BE32 counter; 0x70-byte constructor writes 0x0000FACE");
        dt.replaceAtOffset(0x04, ByteDataType.dataType, 1, "control4",
            "Observed 0x00 in variable senders and fixed 0x40-byte sender");
        dt.replaceAtOffset(0x05, ByteDataType.dataType, 1, "control5",
            "Observed 0 in variable senders, 1 in fixed 0x40-byte sender");
        dt.replaceAtOffset(0x06, ByteDataType.dataType, 1, "frameClass",
            "Observed 0x50 or 0x90; NOT established as a PS2 MechaCon SCMD");
        dt.replaceAtOffset(0x07, ByteDataType.dataType, 1, "control7",
            "Observed zero in inspected sender constructors");
        dt.replaceAtOffset(0x08, DWordDataType.dataType, 4, "frameLengthField8",
            "Variable senders write payload+0x38 or payload+0x30; fixed sender writes zero");
        dt.replaceAtOffset(0x0C, DWordDataType.dataType, 4, "frameLengthFieldC",
            "Variable senders repeat field8; fixed sender writes 8");
        DataType added = currentProgram.getDataTypeManager().addDataType(
            dt, DataTypeConflictHandler.DEFAULT_HANDLER);
        println("CREATED_TYPE " + added.getPathName() + " size=" + added.getLength());
        return added;
    }

    private DataType createTransferState() throws Exception {
        String path = "/PS3/GXEMU/GxemuVuart10TransferState";
        DataType existing = currentProgram.getDataTypeManager().getDataType(path);
        if (existing != null) {
            println("PRESERVE_TYPE " + path + " size=" + existing.getLength());
            return existing.getLength() == 0x18 ? existing : null;
        }
        StructureDataType dt = new StructureDataType(
            new CategoryPath("/PS3/GXEMU"), "GxemuVuart10TransferState", 0x18);
        PointerDataType opaque = new PointerDataType(VoidDataType.dataType, 8);
        dt.replaceAtOffset(0x00, opaque, 8, "completionFunctionDescriptor",
            "Set from callback argument by 3 UART senders; receive routine invokes callback indirectly");
        dt.replaceAtOffset(0x08, opaque, 8, "dataBuffer",
            "Pointer to framed UART data; receive routine also reads it as destination buffer");
        dt.replaceAtOffset(0x10, DWordDataType.dataType, 4, "requestedBytes",
            "Set to full outgoing packet size in all 3 senders");
        // 0x14..0x17 intentionally unresolved.
        DataType added = currentProgram.getDataTypeManager().addDataType(
            dt, DataTypeConflictHandler.DEFAULT_HANDLER);
        println("CREATED_TYPE " + added.getPathName() + " size=" + added.getLength());
        return added;
    }

    private boolean verifyDescriptor(long opd, long entry) throws Exception {
        return currentProgram.getMemory().contains(at(opd)) &&
            currentProgram.getMemory().contains(at(opd + 23)) &&
            currentProgram.getMemory().getLong(at(opd)) == entry &&
            currentProgram.getMemory().getLong(at(opd+8)) == TOC &&
            currentProgram.getMemory().getLong(at(opd+16)) == 0;
    }

    private boolean writesR2(Function f, Register r2) throws Exception {
        for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(),true)) {
            monitor.checkCancelled();
            for (PcodeOp op : ins.getPcode()) {
                Varnode out = op.getOutput();
                if (out != null && out.isRegister() &&
                    out.getAddress().equals(r2.getAddress())) return true;
            }
        }
        return false;
    }

    private void scopedR2(long entry, long descriptor, Register r2) throws Exception {
        Function f = currentProgram.getFunctionManager().getFunctionAt(at(entry));
        if (f == null || !verifyDescriptor(descriptor, entry)) {
            println(String.format("TOC_REFUSED function=0x%X OPD=0x%X",entry,descriptor));
            return;
        }
        if (writesR2(f, r2)) {
            println("TOC_REFUSED r2 writer in " + f.getName());
            return;
        }
        RegisterValue old = currentProgram.getProgramContext().getRegisterValue(r2, at(entry));
        if (old != null && old.hasValue()) {
            println("TOC_PRESERVED " + f.getEntryPoint() + " existing=" + old.getUnsignedValue());
            return;
        }
        if (APPLY) {
            currentProgram.getProgramContext().setRegisterValue(
                f.getBody().getMinAddress(), f.getBody().getMaxAddress(),
                new RegisterValue(r2,BigInteger.valueOf(TOC)));
        }
        println("TOC_" + (APPLY ? "SET" : "WOULD_SET") + " " +
            f.getName() + "@" + f.getEntryPoint() + " value=0x" + Long.toHexString(TOC));
    }

    private void guardedGlobal(long address, String name, DataType pointedType) throws Exception {
        Address a=at(address);
        Data old=currentProgram.getListing().getDataAt(a);
        println("GLOBAL_BEFORE "+a+" datatype="+(old == null ? "<none>" : old.getDataType()));
        if (APPLY && pointedType != null) {
            try {
                DataType targetPtr = new PointerDataType(pointedType,8);
                DataUtilities.createData(currentProgram,a,targetPtr,8,
                    DataUtilities.ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
                println("GLOBAL_TYPED " + a + " " + targetPtr.getName());
            } catch (Exception ex) {
                println("GLOBAL_TYPE_PRESERVED " + a + " " + ex.getMessage());
            }
        }
        Symbol sym=currentProgram.getSymbolTable().getPrimarySymbol(a);
        if (sym != null && sym.getSource() != SourceType.DEFAULT &&
            sym.getSource() != SourceType.ANALYSIS) {
            println("GLOBAL_NAME_PRESERVED " + a + " " + sym.getName());
            return;
        }
        if (sym != null && !(sym.getName().startsWith("PTR_") ||
            sym.getName().startsWith("DAT_"))) {
            println("GLOBAL_NAME_PRESERVED nonauto " + a + " " + sym.getName());
            return;
        }
        if (APPLY) {
            try {
                currentProgram.getSymbolTable().createLabel(a,name,SourceType.USER_DEFINED);
                println("GLOBAL_LABEL "+a+" -> "+name);
            } catch(Exception e) {
                println("GLOBAL_LABEL_PRESERVED "+a+" "+e.getMessage());
            }
        }
    }

    private void appendPlate(long start, String message) throws Exception {
        Instruction ins=currentProgram.getListing().getInstructionAt(at(start));
        if (ins == null || !APPLY) return;
        String old=ins.getComment(CodeUnit.PLATE_COMMENT);
        if (old == null || old.isEmpty())
            ins.setComment(CodeUnit.PLATE_COMMENT,message);
        else if (!old.contains(message))
            ins.setComment(CodeUnit.PLATE_COMMENT,old+"\n"+message);
    }

    private void refs(long target) throws Exception {
        ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(at(target));
        int count=0;
        while (it.hasNext()) {
            monitor.checkCancelled();
            Reference ref=it.next();
            if (count++ < MAX_REFS) {
                Function owner=currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                println("REF_TO "+at(target)+" from="+ref.getFromAddress()+" type="+
                    ref.getReferenceType()+" owner="+(owner == null ? "<none>" : owner.getName()+"@"+owner.getEntryPoint()));
            }
        }
        println("REF_COUNT "+at(target)+" count="+count);
    }

    private void decompile(long entry, DecompInterface dc) throws Exception {
        Function f=currentProgram.getFunctionManager().getFunctionAt(at(entry));
        if (f==null) {
            println("NO_FUNCTION "+at(entry));
            return;
        }
        println("DECOMP_START "+f.getName()+"@"+f.getEntryPoint());
        DecompileResults result=dc.decompileFunction(f,120,monitor);
        if (result.decompileCompleted() && result.getDecompiledFunction()!=null) {
            String c=result.getDecompiledFunction().getC();
            if (c.length()>12000) {
                println(c.substring(0,12000));
                println("DECOMP_TRUNCATED original_chars="+c.length());
            } else println(c);
        } else println("DECOMP_FAIL "+result.getErrorMessage());
        println("DECOMP_END "+f.getEntryPoint());
    }

    private void printDiagnosticString() throws Exception {
        Address a=at(0x002B1A80L);
        byte[] b=new byte[48];
        try {
            currentProgram.getMemory().getBytes(a,b);
            String s=new String(b,java.nio.charset.StandardCharsets.US_ASCII);
            println("BRIAN_STRING "+a+" "+s.replace("\n","\\n"));
            if (s.contains("REPORT TO BRIAN")) {
                refs(0x002B1A80L);
            }
        } catch(Exception e) {
            println("BRIAN_STRING_UNAVAILABLE "+e.getMessage());
        }
    }

    @Override
    public void run() throws Exception {
        if (currentProgram==null ||
            !"PowerPC:BE:64:A2ALT".equals(currentProgram.getLanguageID().toString()) ||
            !currentProgram.getName().contains("ps2_gxemu")) {
            printerr("REFUSE: only run on the full-address ps2_gxemu PPU database.");
            return;
        }
        println("GXEMU_UART10_PROTOCOL v1 APPLY="+APPLY);
        if (!opcode(0x0008FF1CL,0x3860000A) ||
            !opcode(0x000900C4L,0x3860000A) ||
            !opcode(0x00090194L,0x3860000A) ||
            !opcode(0x000903D0L,0x3860000A) ||
            !hasCall(0x0008FF24L,0x000494A4L) ||
            !hasCall(0x000900D0L,0x000494A4L) ||
            !hasCall(0x000901C8L,0x000494A4L) ||
            !hasCall(0x000903D8L,0x000494A4L)) {
            printerr("REFUSE: one or more expected VUART10 call sites or port arguments differ");
            return;
        }
        DataType header = createFramePrefix();
        DataType state = createTransferState();
        if (header==null || state==null) {
            printerr("TYPE_CONFLICT: unexpected preexisting /PS3/GXEMU datatype; stopping");
            return;
        }
        appendPlate(0x0008FD48L, "Port-10 BE packet, class byte +6=0x50; embedded payload length read BE at input+0x44; total wire length = payload+0x48. This is NOT evidence of native MechaCon SCMD.");
        appendPlate(0x0008FF54L, "Port-10 BE packet, class byte +6=0x90; wire length 0x40, field +0xC=8. Not proven to equal MechaCon SCMD 0x90.");
        appendPlate(0x000900FCL, "Port-10 packet, marker 0x0000FACE; class byte +6=0x50, wire length 0x70; field +0xC=0x60.");
        appendPlate(0x000901FCL, "Port-10 BE packet, class byte +6=0x50; embedded payload length read BE at input+0x3C; total wire length = payload+0x40. This is NOT evidence of native MechaCon SCMD.");

        Register r2=currentProgram.getRegister("r2");
        if (r2==null) throw new IllegalStateException("r2 register missing");
        scopedR2(0x0008FC68L,0x0064F6F8L,r2);
        scopedR2(0x000900FCL,0x0064F758L,r2);

        // Global pointer slots are only retyped if all existing data is default.
        // Do not dereference or materialize pointed-to storage if runtime relocation differs.
        guardedGlobal(0x00672B50L, "gVuart10SequenceCounterPointer",DWordDataType.dataType);
        guardedGlobal(0x00672B58L, "gVuart10TransferStatePointer",state);
        guardedGlobal(0x00672B60L, "gVuart10ReceiveOffsetPointer",QWordDataType.dataType);
        guardedGlobal(0x00672B68L, "gVuart10RemainingBytesPointer",DWordDataType.dataType);

        for(long root:new long[]{0x0008FC68L,0x0008FD48L,0x0008FF54L,
            0x000900FCL,0x000901FCL,0x0024F718L,0x00051528L,0x0024F9A4L}) {
            refs(root);
        }
        printDiagnosticString();
        DecompInterface dc=new DecompInterface();
        dc.toggleCCode(true);
        if (dc.openProgram(currentProgram)) {
            try {
                for(long root:new long[]{0x000494A4L,0x00049544L,
                    0x0008FC68L,0x000900FCL,0x0024F718L,
                    0x00051528L,0x0024F9A4L}) decompile(root,dc);
            } finally {dc.dispose();}
        } else println("DECOMPILER_UNAVAILABLE "+dc.getLastMessage());
        println("DONE. Packet header/transfer types and guarded globals only; not a crypto implementation.");
    }
}
