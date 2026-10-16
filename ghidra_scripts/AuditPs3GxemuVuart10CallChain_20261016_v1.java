// Read-only follow-up for Sony ps2_gxemu virtual UART port 10.
// @category PS3.PS2Emulation
// Checks the r2-write warning and missing upstream function boundaries without modifying metadata.
// Ghidra 12.1.3, PowerPC:BE:64:A2ALT. Keep all existing user-defined names and types.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AuditPs3GxemuVuart10CallChain_20261016_v1 extends GhidraScript {
    private static final int BEFORE=18, AFTER=14, MAX_DECOMP=14000;
    private Address at(long n) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(n);
    }
    private void dumpSite(long off) throws Exception {
        Address address=at(off);
        Function f=currentProgram.getFunctionManager().getFunctionContaining(address);
        Instruction center=currentProgram.getListing().getInstructionAt(address);
        println("SITE " + address + " function=" + (f==null ? "<none>" :
            f.getName()+"@"+f.getEntryPoint()+" body="+f.getBody().getMinAddress()+
            ".."+f.getBody().getMaxAddress())+" instruction="+center);
        Instruction start=center;
        if (start==null) start=currentProgram.getListing().getInstructionBefore(address);
        if (start==null) return;
        for(int i=0;i<BEFORE;i++){
            Instruction prev=currentProgram.getListing().getInstructionBefore(start.getAddress());
            if(prev==null)break;
            start=prev;
        }
        int n=0;
        for(Instruction it=start;it!=null && n<BEFORE+AFTER+1;
                it=currentProgram.getListing().getInstructionAfter(it.getAddress()),n++) {
            monitor.checkCancelled();
            println("  "+it.getAddress()+" "+it);
            if(it.getAddress().compareTo(address)>0 && n>=BEFORE+AFTER)break;
        }
    }
    private void r2Writes(long functionEntry) throws Exception {
        Function f=currentProgram.getFunctionManager().getFunctionAt(at(functionEntry));
        Register r2=currentProgram.getRegister("r2");
        if(f==null || r2==null) {println("R2_AUDIT_UNAVAILABLE "+at(functionEntry));return;}
        int count=0, direct=0, calls=0;
        println("R2_AUDIT "+f.getName()+"@"+f.getEntryPoint()+" entry_context="+
            currentProgram.getProgramContext().getRegisterValue(r2,f.getEntryPoint()));
        InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
        while(it.hasNext()) {
            monitor.checkCancelled();
            Instruction ins=it.next();
            boolean writes=false;
            for(PcodeOp op:ins.getPcode()){
                Varnode output=op.getOutput();
                if(output!=null && output.isRegister() &&
                    output.getAddress().equals(r2.getAddress())){
                    writes=true;
                    if(count<30)println("  R2_PCODE_WRITER "+ins.getAddress()+" "+
                        ins+" op="+op);
                }
            }
            if(!writes)continue;
            count++;
            if(ins.getFlowType().isCall())calls++;
            else direct++;
        }
        println("R2_AUDIT_SUMMARY entry="+f.getEntryPoint()+
            " writer_instructions="+count+" call_instructions="+calls+
            " noncall_instructions="+direct);
        println("NOTE: P-code writes can include injected call-return/ABI semantics. "+
            "No r2 context was changed.");
    }
    private void opd(long address, long expectedEntry) throws Exception {
        try {
            long code=currentProgram.getMemory().getLong(at(address));
            long toc=currentProgram.getMemory().getLong(at(address+8));
            long env=currentProgram.getMemory().getLong(at(address+16));
            println(String.format("OPD %s entry=0x%X toc=0x%X environment=0x%X match=%s",
                at(address),code,toc,env,(code==expectedEntry && toc==0x678548L && env==0)));
        }catch(Exception e){println("OPD_UNAVAILABLE "+at(address)+" "+e.getMessage());}
    }
    private void refsTo(long off) throws Exception {
        ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(at(off));
        int count=0;
        while(it.hasNext()){
            monitor.checkCancelled();
            Reference ref=it.next();
            if(count<28)println("REF_TO "+at(off)+" from="+ref.getFromAddress()+
                " type="+ref.getReferenceType());
            count++;
        }
        println("REF_COUNT "+at(off)+" "+count);
    }
    private void decompFunction(long entry,DecompInterface dc,Set<Address> seen) throws Exception {
        Function f=currentProgram.getFunctionManager().getFunctionAt(at(entry));
        if(f==null)f=currentProgram.getFunctionManager().getFunctionContaining(at(entry));
        if(f==null){println("NO_DECOMP_FUNCTION "+at(entry));return;}
        if(!seen.add(f.getEntryPoint()))return;
        println("DECOMP_START "+f.getName()+"@"+f.getEntryPoint()+" requested="+at(entry));
        DecompileResults result=dc.decompileFunction(f,90,monitor);
        if(result.decompileCompleted() && result.getDecompiledFunction()!=null) {
            String text=result.getDecompiledFunction().getC();
            println(text.length()<=MAX_DECOMP?text:text.substring(0,MAX_DECOMP));
            if(text.length()>MAX_DECOMP)println("DECOMP_TRUNCATED chars="+text.length());
        }else println("DECOMP_ERROR "+result.getErrorMessage());
        println("DECOMP_END "+f.getEntryPoint());
    }
    @Override
    public void run() throws Exception {
        if(currentProgram==null ||
            !"PowerPC:BE:64:A2ALT".equals(currentProgram.getLanguageID().toString()) ||
            !currentProgram.getName().contains("ps2_gxemu")){
            printerr("REFUSE: expected ps2_gxemu on PowerPC:BE:64:A2ALT");
            return;
        }
        println("GXEMU_VUART10_CALLCHAIN_AUDIT_V1 READ_ONLY");
        r2Writes(0x0008FC68L);
        opd(0x0064F6F8L,0x0008FC68L);
        opd(0x0064F758L,0x000900FCL);
        for(long off:new long[]{0x0004946CL,0x00251044L,0x0025106CL,
            0x0024F9A4L,0x0008FD48L,0x0008FF54L,0x000901FCL}){
            dumpSite(off);
        }
        for(long off:new long[]{0x0024F718L,0x0024F95CL,0x00251044L,0x0025106CL}){
            refsTo(off);
        }
        DecompInterface dc=new DecompInterface();
        dc.toggleCCode(true);
        if(dc.openProgram(currentProgram)){
            try{
                Set<Address> seen=new HashSet<Address>();
                // Intentionally narrow: avoid 227 references to FUN_00051528.
                for(long off:new long[]{0x0024F718L,0x0024F95CL,0x0004946CL,
                    0x00251044L,0x0025106CL})
                    decompFunction(off,dc,seen);
            }finally{dc.dispose();}
        }else println("DECOMPILER_UNAVAILABLE "+dc.getLastMessage());
        println("DONE_READ_ONLY no function promotions, signatures, labels, byte changes, or datatype modifications");
    }
}
