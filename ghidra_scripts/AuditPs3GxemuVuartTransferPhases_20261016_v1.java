// Refine verified GXEMU 16-byte transfer callbacks and audit ambiguous boundaries.
// @category PS3.PS2Emulation
// Ghidra 12.1.x; ps2_gxemu.elf, PowerPC:BE:64:A2ALT.
// Applies only supported generic function names and comments. No signatures,
// parameters, register contexts, instruction bytes, or ambiguous boundaries changed.
// All potentially ambiguous PPC64 ELFv1 TOC and stack-prologue paths are read-only.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;

public class AuditPs3GxemuVuartTransferPhases_20261016_v1 extends GhidraScript {
    private static final boolean APPLY_VERIFIED_METADATA = true;
    private static final long TOC = 0x00678548L;

    private static class Target {
        final long entry, end, opd;
        final String name, evidence;
        Target(long e,long n,long d,String s,String note){
            entry=e;end=n;opd=d;name=s;evidence=note;
        }
    }
    private static final Target[] RECOVERED = {
        new Target(0x0024FD08L,0x0025030BL,0x00670488L,
            "TransferWriteChunk16",
            "GXEMU UART transfer: state 1/6 copies 16 bytes from input to a transfer buffer at +0x40/+0x48, advances cursor by 0x10 and transitions to 2/7 at the transfer limit. Not proof of MagicGate payload."),
        new Target(0x0025030CL,0x002506ABL,0x006704A0L,
            "TransferReadChunk16",
            "GXEMU UART transfer: state 4/9 copies 16 bytes from a transfer buffer at +0x40/+0x48 to the caller buffer, advances cursor by 0x10 and transitions to 5/10 at the transfer limit. Not proof of MagicGate payload."),
        new Target(0x00250978L,0x00250C83L,0x00670500L,
            "AdvanceTransferSegment",
            "GXEMU UART transfer: resets cursor, advances through 0x10-byte segment descriptors and can transition states 5/10 to 6; reads two bytes of caller-supplied segment metadata. Verify its exact descriptor format before typing it.")
    };
    private static final long[][] REFUSED = {
        {0x0025075CL,0x0025085BL,0x006704D0L},
        {0x0025085CL,0x00250977L,0x006704E8L},
        {0x00250C84L,0x00250D6FL,0x00670518L}
    };
    private static final long[] R2_SITES={
        0x0024FD70L,0x00250370L,0x00250BD4L
    };
    private Address at(long x) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(x);
    }
    private boolean opd(long entry,long descriptor)throws Exception{
        long e=currentProgram.getMemory().getLong(at(descriptor));
        long t=currentProgram.getMemory().getLong(at(descriptor+8));
        long v=currentProgram.getMemory().getLong(at(descriptor+16));
        boolean ok=e==entry&&t==TOC&&v==0;
        println(String.format("OPD %08X entry=%08X toc=%08X env=%X verified=%b",
            descriptor,e,t,v,ok));
        return ok;
    }
    private boolean fullyRecovered(Target t)throws Exception{
        if(!opd(t.entry,t.opd))return false;
        Function f=currentProgram.getFunctionManager().getFunctionAt(at(t.entry));
        if(f==null||f.getBody().getMinAddress().getOffset()!=t.entry||
                f.getBody().getMaxAddress().getOffset()!=t.end){
            println("REFUSE_METADATA_BOUNDARY "+at(t.entry)+" current="+
                (f==null?"<none>":f.getName()+"/"+f.getBody()));
            return false;
        }
        for(long x=t.entry;x<=t.end;x+=4){
            monitor.checkCancelled();
            Instruction i=currentProgram.getListing().getInstructionAt(at(x));
            if(i==null||i.getLength()!=4)return false;
        }
        return true;
    }
    private void applyVerified(Target t)throws Exception{
        if(!fullyRecovered(t))return;
        Function f=currentProgram.getFunctionManager().getFunctionAt(at(t.entry));
        if(f.getName().startsWith("FUN_")){
            if(APPLY_VERIFIED_METADATA){
                try{
                    f.setName(t.name,SourceType.USER_DEFINED);
                    println("NAME_APPLIED "+at(t.entry)+" -> "+t.name);
                }catch(Exception e){
                    println("NAME_REFUSED "+at(t.entry)+" "+e.getMessage());
                }
            }else println("NAME_PROPOSED "+at(t.entry)+" -> "+t.name);
        }else println("NAME_PRESERVED "+at(t.entry)+" "+f.getName());
        if(APPLY_VERIFIED_METADATA){
            String previous=f.getComment();
            if(previous==null||previous.isEmpty())f.setComment(t.evidence);
            else if(!previous.contains(t.evidence))f.setComment(previous+"\n"+t.evidence);
        }
        println("TRANSFER_EVIDENCE "+at(t.entry)+" "+t.evidence);
        println("SIGNATURE_PRESERVED "+f.getPrototypeString(false,false));
        println("REGISTER_CONTEXT_PRESERVED "+at(t.entry));
    }
    private String owner(long x){
        Function f=currentProgram.getFunctionManager().getFunctionContaining(at(x));
        return f==null?"<none>":f.getName()+"@"+f.getEntryPoint();
    }
    private boolean internalPrologue(long x)throws Exception{
        Instruction i=currentProgram.getListing().getInstructionAt(at(x));
        if(i==null||i.getLength()!=4)return false;
        int w=currentProgram.getMemory().getInt(at(x));
        return (w&0xFFFF0000)==0xF8210000&&(short)w<0;
    }
    private void refs(long x)throws Exception{
        ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(at(x));
        int n=0;
        while(it.hasNext()){
            monitor.checkCancelled();
            Reference r=it.next();
            if(n<32)println("  REF "+r.getFromAddress()+" -> "+at(x)+
                " "+r.getReferenceType()+" source="+r.getSource());
            n++;
        }
        println("  REF_TOTAL "+at(x)+" "+n);
    }
    private void window(long center,int before,int after)throws Exception{
        println("WINDOW_BEGIN "+at(center));
        for(long x=center-4L*before;x<=center+4L*after;x+=4){
            monitor.checkCancelled();
            Instruction i=currentProgram.getListing().getInstructionAt(at(x));
            println("  "+at(x)+" "+(i==null?"<no instruction>":i.toString())+
                " owner="+owner(x));
        }
        println("WINDOW_END "+at(center));
    }
    private void inspectSkipped(long entry,long end,long descriptor)throws Exception{
        println(String.format("AMBIGUOUS_REGION %08X..%08X descriptor=%08X",entry,end,descriptor));
        if(!opd(entry,descriptor))return;
        Function f=currentProgram.getFunctionManager().getFunctionAt(at(entry));
        println("  ENTRY_OWNER "+owner(entry)+" entry_function="+(f!=null));
        refs(entry);
        int prologues=0,returns=0,foreignInternalRefs=0,externalJumps=0;
        for(long x=entry;x<=end;x+=4){
            monitor.checkCancelled();
            Instruction ins=currentProgram.getListing().getInstructionAt(at(x));
            if(ins==null||ins.getLength()!=4){
                println("  DISASSEMBLY_GAP "+at(x));break;
            }
            if(x!=entry&&internalPrologue(x)){
                prologues++;
                println("  INTERNAL_PROLOGUE "+at(x)+" "+ins);
                refs(x);window(x,7,9);
            }
            if(currentProgram.getMemory().getInt(at(x))==0x4E800020){
                returns++;println("  RETURN "+at(x));
            }
            ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(at(x));
            while(it.hasNext()){
                Reference r=it.next();
                long src=r.getFromAddress().getOffset();
                if(r.getReferenceType().isFlow()&&x!=entry&&
                        (src<entry||src>end)){
                    foreignInternalRefs++;
                    if(foreignInternalRefs<=24)
                        println("  FOREIGN_INTERNAL_FLOW "+r.getFromAddress()+" -> "+at(x)+
                            " "+r.getReferenceType());
                }
            }
            if(ins.getFlowType().isJump()){
                for(Address dest:ins.getFlows()){
                    if(dest.getAddressSpace().equals(at(entry).getAddressSpace())&&
                       (dest.getOffset()<entry||dest.getOffset()>end)){
                        externalJumps++;
                        if(externalJumps<=12)
                            println("  OUTBOUND_JUMP "+at(x)+" -> "+dest);
                    }
                }
            }
        }
        println("  BOUNDARY_SUMMARY prologues="+prologues+
            " returns="+returns+" foreign_internal_flows="+foreignInternalRefs+
            " outbound_jumps="+externalJumps);
    }
    private boolean writesR2(Instruction i,Register r2)throws Exception{
        if(i==null||r2==null)return false;
        for(PcodeOp op:i.getPcode()){
            Varnode v=op.getOutput();
            if(v!=null&&v.isRegister()&&v.getAddress().equals(r2.getAddress()))
                return true;
        }
        return false;
    }
    private void inspectR2(Target t)throws Exception{
        Function f=currentProgram.getFunctionManager().getFunctionAt(at(t.entry));
        if(f==null)return;
        Register r2=currentProgram.getRegister("r2");
        println("TOC_ENTRY "+at(t.entry)+" OPD_TOC="+at(TOC)+
            " context="+(r2==null?"<no r2>":
            currentProgram.getProgramContext().getRegisterValue(r2,at(t.entry))));
        InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
        int count=0;
        while(it.hasNext()){
            monitor.checkCancelled();
            Instruction ins=it.next();
            if(writesR2(ins,r2)){
                count++;
                println("  R2_WRITE "+ins.getAddress()+" "+ins);
                if(count<=12)window(ins.getAddress().getOffset(),5,6);
            }
        }
        println("  R2_WRITE_TOTAL "+at(t.entry)+" "+count);
    }
    private void inspectKnownCalls()throws Exception{
        long[] targets={0x0008FD48L,0x000901FCL,0x0008FF54L,0x00250D70L};
        for(long x:targets){
            println("CROSS_REFERENCE_TARGET "+at(x)+" owner="+owner(x));
            ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(at(x));
            int count=0;
            while(it.hasNext()){
                monitor.checkCancelled();
                Reference r=it.next();
                long src=r.getFromAddress().getOffset();
                if(src>=0x0024E000L&&src<=0x00252000L){
                    if(count<40)println("  XREF "+r.getFromAddress()+" "+r.getReferenceType());
                    count++;
                }
            }
            println("  XREF_IN_TRANSFER_REGION="+count);
        }
    }
    @Override public void run()throws Exception{
        if(currentProgram==null||
          !"PowerPC:BE:64:A2ALT".equals(currentProgram.getLanguageID().toString())||
          !currentProgram.getName().contains("ps2_gxemu")){
            printerr("REFUSE expected ps2_gxemu PowerPC:BE:64:A2ALT");
            return;
        }
        if(!opd(0x00250D70L,0x00670530L)){
            printerr("REFUSE dispatcher descriptor mismatch");return;
        }
        println("GXEMU_TRANSFER_PHASE_AUDIT_V1 apply_verified_metadata="+APPLY_VERIFIED_METADATA);
        for(Target t:RECOVERED){monitor.checkCancelled();applyVerified(t);}
        for(Target t:RECOVERED){monitor.checkCancelled();inspectR2(t);}
        for(long[] r:REFUSED){monitor.checkCancelled();inspectSkipped(r[0],r[1],r[2]);}
        for(long site:R2_SITES){
            println("KNOWN_R2_WRITER "+at(site));window(site,10,8);
        }
        inspectKnownCalls();
        println("DONE: applied only verified names/comments. No signature, datatype, r2 context, ambiguous function or executable byte changes.");
    }
}
