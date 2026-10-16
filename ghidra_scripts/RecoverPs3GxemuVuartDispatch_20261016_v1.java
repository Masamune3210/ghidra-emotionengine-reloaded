// Recover one verified PS3 GXEMU VUART port-10 dispatch function.
// @category PS3.PS2Emulation
// Ghidra 12.1.x; ps2_gxemu.elf / PowerPC:BE:64:A2ALT.
// Conservative: validates ELFv1 descriptor, all disassembly, both UART send
// calls, section boundary, no overlapping functions and no foreign calls into
// the proposed body. Refuses rather than guessing if any check fails.
// Existing signatures, executable bytes and speculative MagicGate labels unchanged.

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;

public class RecoverPs3GxemuVuartDispatch_20261016_v1 extends GhidraScript {
    private static final boolean APPLY = true;
    private static final long START = 0x00250D70L;
    private static final long AFTER = 0x0025109CL;
    private static final long END = AFTER - 1L;
    private static final long OPD = 0x00670530L;
    private static final long TOC = 0x00678548L;
    private static final String NAME = "DispatchVirtualUartPacketTransfers";

    private Address addr(long off) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
    }
    private boolean hasCall(long site, long expectedTarget) {
        Instruction i = currentProgram.getListing().getInstructionAt(addr(site));
        if (i == null || !i.getFlowType().isCall()) return false;
        for (Address a : i.getFlows()) {
            if (a.equals(addr(expectedTarget))) return true;
        }
        return false;
    }
    private boolean isPrologue(long off) throws Exception {
        Instruction i=currentProgram.getListing().getInstructionAt(addr(off));
        if(i==null || i.getLength()!=4) return false;
        int word=currentProgram.getMemory().getInt(addr(off));
        return (word & 0xFFFF0000)==0xF8210000 && (short)word < 0;
    }
    private boolean verifyDescriptor() throws Exception {
        long entry=currentProgram.getMemory().getLong(addr(OPD));
        long toc=currentProgram.getMemory().getLong(addr(OPD + 8));
        long env=currentProgram.getMemory().getLong(addr(OPD + 16));
        boolean ok=entry==START && toc==TOC && env==0;
        println(String.format("DISPATCH_OPD addr=%s entry=0x%X toc=0x%X env=0x%X verified=%b",
            addr(OPD),entry,toc,env,ok));
        return ok;
    }
    private boolean verifyBody() throws Exception {
        MemoryBlock first=currentProgram.getMemory().getBlock(addr(START));
        MemoryBlock last=currentProgram.getMemory().getBlock(addr(END));
        MemoryBlock next=currentProgram.getMemory().getBlock(addr(AFTER));
        println("REGION start="+addr(START)+".."+addr(END)+" block="+
            (first==null?"<none>":first.getName())+" final_block="+
            (last==null?"<none>":last.getName())+" next_block="+
            (next==null?"<none>":next.getName()));
        if(first==null || first!=last || !first.isExecute() ||
            first==next || !isPrologue(START) || !isPrologue(AFTER)) {
            println("VERIFY_FAIL section boundary/prologue mismatch");
            return false;
        }
        if(!hasCall(0x00251044L,0x000901FCL) ||
            !hasCall(0x0025106CL,0x0008FD48L)) {
            println("VERIFY_FAIL expected dispatch UART sender calls missing");
            return false;
        }
        int decoded=0,branches=0,externalRefs=0,externalCalls=0;
        int internalPrologues=0,returns=0;
        int printedExternalRefs=0;
        for(long off=START;off<=END;off+=4) {
            monitor.checkCancelled();
            Address a=addr(off);
            Instruction i=currentProgram.getListing().getInstructionAt(a);
            if(i==null || i.getLength()!=4) {
                println("VERIFY_FAIL instruction hole "+a);
                return false;
            }
            Function owner=currentProgram.getFunctionManager().getFunctionContaining(a);
            if(owner!=null && !owner.getEntryPoint().equals(addr(START))) {
                println("VERIFY_FAIL overlaps "+owner.getName()+" @"+a);
                return false;
            }
            if(off!=START && isPrologue(off)) {
                internalPrologues++;
                println("WARN additional stdu-r1 prologue at "+a);
            }
            if(currentProgram.getMemory().getInt(a)==0x4E800020)returns++;
            if(i.getFlowType().isJump())branches++;
            ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(a);
            while(refs.hasNext()){
                Reference r=refs.next();
                Address src=r.getFromAddress();
                if(src.isMemoryAddress() && src.getAddressSpace().equals(a.getAddressSpace()) &&
                    src.compareTo(addr(START))>=0 && src.compareTo(addr(END))<=0)
                    continue;
                externalRefs++;
                if(printedExternalRefs++<30)
                    println("FOREIGN_REF "+src+" -> "+a+" type="+r.getReferenceType());
                if(off!=START && r.getReferenceType().isCall())
                    externalCalls++;
            }
            decoded++;
        }
        println("VERIFY_BODY instructions="+decoded+" branches="+branches+
            " returns="+returns+" internal_prologues="+internalPrologues+
            " foreign_refs="+externalRefs+" foreign_internal_calls="+externalCalls);
        if(internalPrologues!=0 || externalCalls!=0) {
            println("VERIFY_FAIL possible embedded function; no promotion");
            return false;
        }
        return true;
    }
    private boolean writesR2(Function f,Register r2) throws Exception {
        InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
        while(it.hasNext()){
            monitor.checkCancelled();
            Instruction i=it.next();
            for(PcodeOp p:i.getPcode()){
                Varnode out=p.getOutput();
                if(out!=null && out.isRegister() &&
                    out.getAddress().equals(r2.getAddress())){
                    println("R2_WRITE "+i.getAddress()+" "+i);
                    return true;
                }
            }
        }
        return false;
    }
    private void applyToc(Function f) throws Exception {
        Register r2=currentProgram.getRegister("r2");
        if(r2==null) {
            println("R2_UNAVAILABLE");
            return;
        }
        if(writesR2(f,r2)) {
            println("R2_CONTEXT_PRESERVED real r2 writes; inspect callback paths");
            return;
        }
        RegisterValue old=currentProgram.getProgramContext().getRegisterValue(r2,f.getEntryPoint());
        if(old!=null && old.hasValue()){
            println("R2_CONTEXT_PRESERVED existing="+old.getUnsignedValue());
            return;
        }
        if(APPLY){
            currentProgram.getProgramContext().setRegisterValue(
                f.getBody().getMinAddress(),f.getBody().getMaxAddress(),
                new RegisterValue(r2,BigInteger.valueOf(TOC)));
        }
        println("R2_CONTEXT_"+(APPLY?"SET":"WOULD_SET")+" "+
            f.getEntryPoint()+" toc=0x"+Long.toHexString(TOC));
    }
    private void decompile(Function f) throws Exception {
        DecompInterface decomp=new DecompInterface();
        decomp.toggleCCode(true);
        if(!decomp.openProgram(currentProgram)){
            println("DECOMP_OPEN_FAILED "+decomp.getLastMessage());
            return;
        }
        try{
            println("DECOMP_START "+f.getName()+"@"+f.getEntryPoint());
            DecompileResults r=decomp.decompileFunction(f,180,monitor);
            if(r.decompileCompleted() && r.getDecompiledFunction()!=null){
                String c=r.getDecompiledFunction().getC();
                // Preserve all relevant control flow; report truncation explicitly.
                if(c.length()>40000){
                    println(c.substring(0,40000));
                    println("DECOMP_TRUNCATED original_characters="+c.length());
                }else println(c);
            }else println("DECOMP_FAILED "+r.getErrorMessage());
            println("DECOMP_END "+f.getEntryPoint());
        }finally{decomp.dispose();}
    }
    @Override
    public void run() throws Exception {
        if(currentProgram==null ||
            !"PowerPC:BE:64:A2ALT".equals(currentProgram.getLanguageID().toString()) ||
            !currentProgram.getName().contains("ps2_gxemu")){
            printerr("REFUSE: expected ps2_gxemu / PowerPC:BE:64:A2ALT");
            return;
        }
        println("GXEMU_DISPATCH_RECOVERY_V1 APPLY="+APPLY);
        if(!verifyDescriptor() || !verifyBody()) {
            println("DONE_NO_CHANGES verification failed; send this output");
            return;
        }
        Function f=currentProgram.getFunctionManager().getFunctionAt(addr(START));
        if(f==null){
            if(!APPLY){
                println("WOULD_CREATE_FUNCTION "+addr(START)+".."+addr(END));
                return;
            }
            f=currentProgram.getFunctionManager().createFunction(null,addr(START),
                new AddressSet(addr(START),addr(END)),SourceType.ANALYSIS);
            if(f==null){
                println("CREATE_FAILED no function returned");
                return;
            }
            println("CREATED_FUNCTION "+f.getEntryPoint()+".."+f.getBody().getMaxAddress());
        }else if(!f.getBody().contains(addr(0x251044L)) ||
                 !f.getBody().contains(addr(0x25106CL))){
            println("EXISTING_FUNCTION_INCOMPLETE "+f.getEntryPoint()+" "+f.getName());
            return;
        }else println("EXISTING_FUNCTION "+f.getName()+" @"+f.getEntryPoint());
        if(APPLY && f.getName().startsWith("FUN_")){
            f.setName(NAME,SourceType.USER_DEFINED);
            println("RENAMED "+f.getEntryPoint()+" -> "+NAME);
        }else println("NAME_PRESERVED "+f.getName());
        applyToc(f);
        decompile(f);
        println("DONE verified dispatch region. No signature/packet/crypto assumptions; no executable byte edits.");
    }
}
