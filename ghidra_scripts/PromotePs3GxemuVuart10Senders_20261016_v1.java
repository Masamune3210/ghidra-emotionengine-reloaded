// Promote three missing PS3 GXEMU virtual-UART-10 sender functions only after
// verifying instruction boundaries, internal call sites and PowerPC64 OPD tuples.
// @category PS3.PS2Emulation
// For Ghidra 12.1.3 / PowerPC:BE:64:A2ALT. No executable bytes or signatures changed.
// Safe to rerun: preserves preexisting functions, intentional data and names.

import java.math.BigInteger;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class PromotePs3GxemuVuart10Senders_20261016_v1 extends GhidraScript {
    private static final boolean APPLY_FUNCTIONS = true;
    private static final boolean APPLY_OPD_TYPES = true;
    private static final boolean APPLY_SCOPED_R2_CONTEXT = true;
    private static final long TOC = 0x00678548L;

    private static class Sender {
        final long start, finalBlr, writeCall, immediatePort, descriptor;
        final String name, descriptorLabel;
        Sender(long start, long end, long call, long port, long opd, String name, String opdName) {
            this.start=start; this.finalBlr=end; this.writeCall=call;
            this.immediatePort=port; this.descriptor=opd;
            this.name=name; this.descriptorLabel=opdName;
        }
    }

    private static final Sender[] SENDERS = {
        new Sender(0x0008FD48L, 0x0008FF50L, 0x0008FF24L, 0x0008FF1CL,
            0x0064F728L, "SendVirtualUartVariablePacket", "PpuOpd_SendVirtualUartVariablePacket"),
        new Sender(0x0008FF54L, 0x000900F8L, 0x000900D0L, 0x000900C4L,
            0x0064F740L, "SendVirtualUartFixed64BytePacket", "PpuOpd_SendVirtualUartFixed64BytePacket"),
        new Sender(0x000901FCL, 0x00090404L, 0x000903D8L, 0x000903D0L,
            0x0064F770L, "SendVirtualUartVariablePacketAlternate",
            "PpuOpd_SendVirtualUartVariablePacketAlternate")
    };

    private Address at(long off) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
    }

    private boolean instructionIs(long off, int encoding) throws Exception {
        Instruction ins = currentProgram.getListing().getInstructionAt(at(off));
        return ins != null && ins.getLength() == 4 &&
            currentProgram.getMemory().getInt(at(off)) == encoding;
    }

    private boolean calls(long site, long target) throws Exception {
        Instruction ins = currentProgram.getListing().getInstructionAt(at(site));
        if (ins == null || !ins.getFlowType().isCall()) return false;
        for (Address flow : ins.getFlows())
            if (flow.equals(at(target))) return true;
        return false;
    }

    private boolean validate(Sender s) throws Exception {
        boolean good=true;
        if (!instructionIs(s.start-4,0x4E800020) ||
            !instructionIs(s.finalBlr,0x4E800020) ||
            !instructionIs(s.immediatePort,0x3860000A) ||
            !calls(s.writeCall,0x000494A4L)) {
            println(String.format("REFUSE 0x%08X: prologue predecessor/BLR/port 10/call mismatch",s.start));
            return false;
        }
        int prologue=currentProgram.getMemory().getInt(at(s.start));
        if ((prologue & 0xFFFF0000) != 0xF8210000) {
            println(String.format("REFUSE 0x%08X: no stdu r1,negative_frame prologue (0x%08X)",
                s.start,prologue));
            return false;
        }
        if (s.finalBlr < s.start || s.writeCall < s.start || s.writeCall > s.finalBlr ||
            s.immediatePort < s.start || s.immediatePort >= s.writeCall)
            return false;
        int count=0;
        for (long off=s.start;off<=s.finalBlr;off+=4) {
            monitor.checkCancelled();
            Instruction ins=currentProgram.getListing().getInstructionAt(at(off));
            if (ins == null || ins.getLength()!=4) {
                println(String.format("REFUSE 0x%08X: disassembly hole at 0x%08X",s.start,off));
                return false;
            }
            Function owner=currentProgram.getFunctionManager().getFunctionContaining(at(off));
            if (owner != null && !owner.getEntryPoint().equals(at(s.start))) {
                println("REFUSE 0x" + Long.toHexString(s.start) +
                    " overlaps existing function " + owner.getName() + " at " + off);
                return false;
            }
            count++;
        }
        long entry=currentProgram.getMemory().getLong(at(s.descriptor));
        long toc=currentProgram.getMemory().getLong(at(s.descriptor+8));
        long environment=currentProgram.getMemory().getLong(at(s.descriptor+16));
        println(String.format("VERIFY_OPD addr=0x%08X entry=0x%X toc=0x%X env=0x%X",
            s.descriptor,entry,toc,environment));
        if (entry!=s.start || toc!=TOC || environment!=0) {
            println("REFUSE OPD verification for 0x"+Long.toHexString(s.start));
            return false;
        }
        println(String.format("VERIFY_PASS entry=0x%08X end_blr=0x%08X call=0x%08X decoded_instructions=%d",
            s.start,s.finalBlr,s.writeCall,count));
        return true;
    }

    private Function promote(Sender s) throws Exception {
        Function f=currentProgram.getFunctionManager().getFunctionAt(at(s.start));
        if (f==null) {
            if (!APPLY_FUNCTIONS) {
                println("WOULD_CREATE_FUNCTION " + at(s.start));
                return null;
            }
            f=currentProgram.getFunctionManager().createFunction(null,at(s.start),
                new AddressSet(at(s.start),at(s.finalBlr+3)),SourceType.ANALYSIS);
            if (f==null) {
                println("CREATE_FAILED " + at(s.start));
                return null;
            }
            println("CREATED_FUNCTION " + f.getEntryPoint() + " " + f.getName());
        } else {
            println("EXISTING_FUNCTION " + f.getEntryPoint() + " " + f.getName());
            if (!f.getBody().contains(at(s.writeCall))) {
                println("PRESERVE_FUNCTION: body does not contain verified call " + at(s.writeCall));
                return f;
            }
        }
        if (APPLY_FUNCTIONS && f.getName().startsWith("FUN_")) {
            try {
                f.setName(s.name,SourceType.USER_DEFINED);
                println("RENAME " + f.getEntryPoint() + " -> " + s.name);
            } catch (Exception e) {
                println("PRESERVE_NAME "+f.getEntryPoint()+" "+e.getMessage());
            }
        }
        return f;
    }

    private void applyDescriptor(Sender s,DataType type) throws Exception {
        if (type==null || type.getLength()!=24 || !APPLY_OPD_TYPES)
            return;
        try {
            DataUtilities.createData(currentProgram,at(s.descriptor),type,24,
                DataUtilities.ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
            println("OPD_TYPED "+at(s.descriptor)+" "+type.getPathName());
        } catch (Exception e) {
            println("OPD_TYPE_PRESERVED "+at(s.descriptor)+" "+e.getMessage());
        }
        Symbol primary=currentProgram.getSymbolTable().getPrimarySymbol(at(s.descriptor));
        if (primary==null || primary.getSource()==SourceType.DEFAULT) {
            try {
                currentProgram.getSymbolTable().createLabel(at(s.descriptor),
                    s.descriptorLabel,SourceType.USER_DEFINED);
                println("LABEL "+at(s.descriptor)+" -> "+s.descriptorLabel);
            } catch (Exception e) {
                println("LABEL_PRESERVED "+at(s.descriptor)+" "+e.getMessage());
            }
        }
    }

    private boolean writesR2(Function f,Register r2) throws Exception {
        for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(),true)) {
            monitor.checkCancelled();
            for (PcodeOp op : ins.getPcode()) {
                Varnode out=op.getOutput();
                if (out!=null && out.isRegister() &&
                    out.getAddress().equals(r2.getAddress())) {
                    println("R2_WRITER "+ins.getAddress()+" "+ins);
                    return true;
                }
            }
        }
        return false;
    }

    private void scopedToc(Function f,Register r2) throws Exception {
        if (f==null || !APPLY_SCOPED_R2_CONTEXT)
            return;
        if (writesR2(f,r2)) {
            println("R2_CONTEXT_SKIPPED "+f.getEntryPoint()+" r2 writer in function");
            return;
        }
        ProgramContext context=currentProgram.getProgramContext();
        RegisterValue old=context.getRegisterValue(r2,f.getEntryPoint());
        if (old!=null && old.hasValue()) {
            println("R2_CONTEXT_PRESERVED "+f.getEntryPoint()+" existing="+old.getUnsignedValue());
            return;
        }
        RegisterValue value=new RegisterValue(r2,BigInteger.valueOf(TOC));
        try {
            context.setRegisterValue(f.getBody().getMinAddress(),f.getBody().getMaxAddress(),value);
            println("R2_CONTEXT_SET "+f.getEntryPoint()+" body="+f.getBody().getMinAddress()+
                ".."+f.getBody().getMaxAddress()+" value=0x"+Long.toHexString(TOC));
        } catch (Exception e) {
            println("R2_CONTEXT_NOT_SET "+f.getEntryPoint()+" "+e.getMessage());
        }
    }

    private void decompile(Function f,DecompInterface decompiler) throws Exception {
        if (f==null)return;
        println("DECOMP_START "+f.getName()+"@"+f.getEntryPoint());
        DecompileResults result=decompiler.decompileFunction(f,120,monitor);
        if (result.decompileCompleted() && result.getDecompiledFunction()!=null)
            println(result.getDecompiledFunction().getC());
        else
            println("DECOMP_FAILED "+result.getErrorMessage());
        println("DECOMP_END "+f.getEntryPoint());
    }

    @Override
    public void run() throws Exception {
        if (currentProgram==null ||
            !"PowerPC:BE:64:A2ALT".equals(currentProgram.getLanguageID().toString()) ||
            !currentProgram.getName().contains("ps2_gxemu")) {
            printerr("REFUSE: run on ps2_gxemu under PowerPC:BE:64:A2ALT");
            return;
        }
        println("GXEMU_UART10_SENDERS_PROMOTE v1");
        DataType type=currentProgram.getDataTypeManager().getDataType(
            "/PS3/PPU/Ppc64FunctionDescriptor24");
        if (type==null || type.getLength()!=24)
            println("OPD_TYPE_UNAVAILABLE: run ApplyAuditPs3GxemuVuart10Frames_20261016_v1 first");
        Register r2=currentProgram.getRegister("r2");
        if (r2==null) {
            printerr("REFUSE: r2 register unavailable");
            return;
        }
        DecompInterface dec=new DecompInterface();
        dec.toggleCCode(true);
        if (!dec.openProgram(currentProgram)) {
            printerr("Decompiler unavailable: "+dec.getLastMessage());
            return;
        }
        try {
            int passed=0,created=0;
            for (Sender s:SENDERS) {
                monitor.checkCancelled();
                if (!validate(s)) continue;
                passed++;
                Function was=currentProgram.getFunctionManager().getFunctionAt(at(s.start));
                Function f=promote(s);
                if (was==null && f!=null) created++;
                applyDescriptor(s,type);
                scopedToc(f,r2);
                decompile(f,dec);
            }
            // Previously typed wrappers and send/receive functions remain untouched.
            println("SUMMARY verified="+passed+" newly_created="+created+
                " total_candidate_functions="+SENDERS.length);
            println("DONE: verified function bodies, descriptors, names and scoped r2 only;"+
                " no packet struct, signature or executable bytes changed.");
        } finally {
            dec.dispose();
        }
    }
}
