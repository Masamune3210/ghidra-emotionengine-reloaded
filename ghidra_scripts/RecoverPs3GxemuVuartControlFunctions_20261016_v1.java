// Recover PS3 ps2_gxemu UART-10 producer/receiver control functions from
// independently verified ELFv1 PowerPC64 function descriptors.
// @category PS3.PS2Emulation
// Ghidra 12.1.x; language PowerPC:BE:64:A2ALT; ps2_gxemu.elf.
// APPLY=true: existing instructions and bytes are NEVER changed.
// Refuses ambiguous prologues, overlapping functions and foreign calls to
// internal addresses. Full data types/signatures remain as currently resolved.

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DWordDataType;
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
import ghidra.program.model.symbol.Symbol;

public class RecoverPs3GxemuVuartControlFunctions_20261016_v1 extends GhidraScript {
    private static final boolean APPLY=true;
    private static final long TOC=0x00678548L;
    private static class Candidate {
        final long entry,end,opd;
        final String verifiedName;
        Candidate(long a,long b,long d,String n) {
            entry=a;end=b;opd=d;verifiedName=n;
        }
    }
    // Every proposed end is immediately before the next independently
    // verified OPD function entry. No phantom BLR is inserted.
    private static final Candidate[] CANDIDATES={
        new Candidate(0x0024F8F0L,0x0024F903L,0x006703E0L,"SetVuartTransferControlFlag"),
        new Candidate(0x0024F904L,0x0024F90BL,0x006703F8L,"ReturnZero"),
        new Candidate(0x0024F90CL,0x0024F95BL,0x00670410L,"QueueVuartDispatchState4"),
        new Candidate(0x0024FC08L,0x0024FC4BL,0x00670440L,null),
        new Candidate(0x0024FC4CL,0x0024FC9BL,0x00670458L,"QueueVuartDispatchState2"),
        new Candidate(0x0024FC9CL,0x0024FD07L,0x00670470L,null),
        new Candidate(0x0024FD08L,0x0025030BL,0x00670488L,null),
        new Candidate(0x0025030CL,0x002506ABL,0x006704A0L,null),
        new Candidate(0x002506ACL,0x0025075BL,0x006704B8L,null),
        new Candidate(0x0025075CL,0x0025085BL,0x006704D0L,null),
        new Candidate(0x0025085CL,0x00250977L,0x006704E8L,null),
        new Candidate(0x00250978L,0x00250C83L,0x00670500L,null),
        new Candidate(0x00250C84L,0x00250D6FL,0x00670518L,null)
    };
    private Address at(long off){
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
    }
    private int word(long address)throws Exception{
        return currentProgram.getMemory().getInt(at(address));
    }
    private boolean descriptor(Candidate c)throws Exception{
        long entry=currentProgram.getMemory().getLong(at(c.opd));
        long toc=currentProgram.getMemory().getLong(at(c.opd+8));
        long env=currentProgram.getMemory().getLong(at(c.opd+16));
        boolean verified=entry==c.entry&&toc==TOC&&env==0;
        println(String.format("VERIFY_OPD 0x%08X -> 0x%08X toc=0x%X env=0x%X verified=%b",
            c.opd,entry,toc,env,verified));
        return verified;
    }
    private boolean verifyBody(Candidate c)throws Exception{
        if((c.entry&3)!=0||(c.end&3)!=3||c.end<c.entry)return false;
        MemoryBlock b=currentProgram.getMemory().getBlock(at(c.entry));
        if(b==null||!b.isExecute()||currentProgram.getMemory().getBlock(at(c.end))!=b)return false;
        int decoded=0,internalStarts=0,foreignCalls=0,foreignFlows=0;
        int ret=0,externalJumps=0;
        for(long off=c.entry;off<=c.end;off+=4){
            monitor.checkCancelled();
            Address a=at(off);
            Instruction i=currentProgram.getListing().getInstructionAt(a);
            if(i==null||i.getLength()!=4){
                println("REFUSE hole "+a+" in proposed body "+at(c.entry));return false;
            }
            Function f=currentProgram.getFunctionManager().getFunctionContaining(a);
            if(f!=null&&!f.getEntryPoint().equals(at(c.entry))){
                println("REFUSE overlap "+a+" with "+f.getName()+"@"+f.getEntryPoint());
                return false;
            }
            int w=word(off);
            // Additional stack frame prologue is a warning, not always proof
            // of distinct function; REFUSE rather than splitting it by guess.
            if(off!=c.entry && (w&0xFFFF0000)==0xF8210000&&(short)w<0)
                internalStarts++;
            if(w==0x4E800020)ret++;
            ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(a);
            while(refs.hasNext()){
                Reference r=refs.next();
                Address from=r.getFromAddress();
                if(from.getAddressSpace().equals(a.getAddressSpace()) &&
                    from.compareTo(at(c.entry))>=0&&from.compareTo(at(c.end))<=0)
                    continue;
                if(off!=c.entry && r.getReferenceType().isCall())
                    foreignCalls++;
                if(off!=c.entry && r.getReferenceType().isFlow())
                    foreignFlows++;
            }
            if(i.getFlowType().isJump()){
                for(Address dest:i.getFlows()){
                    if(dest.getAddressSpace().equals(a.getAddressSpace())&&
                        (dest.compareTo(at(c.entry))<0||dest.compareTo(at(c.end))>0))
                        externalJumps++;
                }
            }
            decoded++;
        }
        Instruction successor=currentProgram.getListing().getInstructionAt(at(c.end+1));
        if(successor==null){
            println("REFUSE no decoded successor at "+at(c.end+1));return false;
        }
        // An unambiguous next entry must have a valid OPD. The last
        // candidate ends immediately before the known 0x250D70 entry.
        boolean nextOpd=false;
        for(Candidate n:CANDIDATES){
            if(n.entry==c.end+1){nextOpd=descriptorSilent(n);break;}
        }
        if(c.end+1==0x0024F95CL)
            nextOpd=currentProgram.getMemory().getLong(at(0x00670428L))==0x0024F95CL;
        if(c.end+1==0x00250D70L)
            nextOpd=currentProgram.getMemory().getLong(at(0x00670530L))==0x00250D70L;
        if(!nextOpd){
            println("REFUSE no verified successor OPD "+at(c.end+1));return false;
        }
        println(String.format("VERIFY_CODE entry=%s end=%s instructions=%d BLRs=%d "+
            "inner_prologues=%d foreign_calls=%d foreign_jump_entries=%d "+
            "outgoing_jump_targets=%d next_entry=%s",
            at(c.entry),at(c.end),decoded,ret,internalStarts,foreignCalls,
            foreignFlows,externalJumps,successor.getAddress()));
        if(internalStarts!=0||foreignCalls!=0||foreignFlows!=0){
            println("REFUSE ambiguous internal entry in "+at(c.entry));
            return false;
        }
        return true;
    }
    private boolean descriptorSilent(Candidate c)throws Exception{
        return currentProgram.getMemory().getLong(at(c.opd))==c.entry &&
            currentProgram.getMemory().getLong(at(c.opd+8))==TOC &&
            currentProgram.getMemory().getLong(at(c.opd+16))==0;
    }
    private boolean verifiedQueue(Candidate c)throws Exception{
        long store=-1;int state=0;
        if(c.entry==0x0024F90CL){store=0x0024F91CL;state=4;}
        if(c.entry==0x0024FC4CL){store=0x0024FC5CL;state=2;}
        if(store<0)return false;
        // li r0,state; ld r11,-0xDC0(r2); stw r0,0(r11)
        return currentProgram.getMemory().getInt(at(store-0x0C))==(0x38000000|state) &&
            currentProgram.getMemory().getInt(at(store-8))==0xE962F240 &&
            currentProgram.getMemory().getInt(at(store))==0x900B0000;
    }
    private void descriptorData(Candidate c,DataType opdType)throws Exception{
        if(opdType==null||opdType.getLength()!=24)return;
        try {
            if(APPLY) DataUtilities.createData(currentProgram,at(c.opd),opdType,24,
                DataUtilities.ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
            println("OPD_TYPED "+at(c.opd));
        }catch(Exception e){
            println("OPD_TYPE_PRESERVED "+at(c.opd)+" "+e.getMessage());
        }
        Symbol symbol=currentProgram.getSymbolTable().getPrimarySymbol(at(c.opd));
        if((symbol==null || symbol.getSource()==SourceType.DEFAULT)&&APPLY) {
            try {
                currentProgram.getSymbolTable().createLabel(at(c.opd),
                    "PpuOpd_VuartControl_"+Long.toHexString(c.entry),
                    SourceType.USER_DEFINED);
                println("OPD_LABEL "+at(c.opd));
            }catch(Exception e){
                println("OPD_LABEL_PRESERVED "+at(c.opd)+" "+e.getMessage());
            }
        }
    }
    private boolean writesR2(Function f)throws Exception{
        Register r2=currentProgram.getRegister("r2");
        if(r2==null)return true;
        InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
        while(it.hasNext()){
            monitor.checkCancelled();
            Instruction ins=it.next();
            for(PcodeOp op:ins.getPcode()){
                Varnode out=op.getOutput();
                if(out!=null && out.isRegister() &&
                    out.getAddress().equals(r2.getAddress())){
                    println("TOC_CONTEXT_REFUSED R2_WRITER "+ins.getAddress()+" "+ins);
                    return true;
                }
            }
        }
        return false;
    }
    private void scopedToc(Function f)throws Exception{
        Register r2=currentProgram.getRegister("r2");
        if(r2==null||writesR2(f))return;
        RegisterValue old=currentProgram.getProgramContext().getRegisterValue(r2,f.getEntryPoint());
        if(old!=null&&old.hasValue()){
            println("TOC_CONTEXT_PRESERVED "+f.getEntryPoint()+" "+old.getUnsignedValue());
            return;
        }
        if(APPLY)currentProgram.getProgramContext().setRegisterValue(
            f.getBody().getMinAddress(),f.getBody().getMaxAddress(),
            new RegisterValue(r2,BigInteger.valueOf(TOC)));
        println("TOC_CONTEXT_SET "+f.getEntryPoint()+" TOC=0x"+Long.toHexString(TOC));
    }
    private void decompile(Function f,DecompInterface dc)throws Exception{
        if(dc==null)return;
        DecompileResults d=dc.decompileFunction(f,100,monitor);
        println("DECOMP_START "+f.getName()+"@"+f.getEntryPoint());
        if(d.decompileCompleted() && d.getDecompiledFunction()!=null){
            String c=d.getDecompiledFunction().getC();
            println(c.length()>23000?c.substring(0,23000):c);
            if(c.length()>23000)println("DECOMP_TRUNCATED original_chars="+c.length());
        }else println("DECOMP_FAIL "+d.getErrorMessage());
        println("DECOMP_END "+f.getEntryPoint());
    }
    private void labelRuntimeState()throws Exception{
        DataType state=currentProgram.getDataTypeManager().getDataType(
            "/PS3/GXEMU/GxemuVuart10DispatchState");
        if(state==null||state.getLength()!=4)return;
        long from=currentProgram.getMemory().getLong(at(0x00677788L));
        Address target;
        try{target=at(from);}catch(Exception e){
            println("RUNTIME_STATE_ADDR_INVALID "+Long.toHexString(from));return;
        }
        MemoryBlock b=currentProgram.getMemory().getBlock(target);
        println("RUNTIME_STATE_ADDRESS slot=00677788 target="+target+
            " block="+(b==null?"<none>":b.getName()));
        if(b==null||!b.isWrite()||b.isExecute()||
            !currentProgram.getMemory().contains(at(from+3)))return;
        try{
            if(APPLY)DataUtilities.createData(currentProgram,target,state,4,
                DataUtilities.ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
            println("RUNTIME_STATE_TYPED "+target+" "+state.getName());
        }catch(Exception e){
            println("RUNTIME_STATE_TYPE_PRESERVED "+target+" "+e.getMessage());
        }
        Symbol old=currentProgram.getSymbolTable().getPrimarySymbol(target);
        if(old==null||old.getSource()==SourceType.DEFAULT){
            if(APPLY){
                try{
                    currentProgram.getSymbolTable().createLabel(target,
                        "gVuart10DispatchState",SourceType.USER_DEFINED);
                    println("RUNTIME_STATE_LABEL "+target+" -> gVuart10DispatchState");
                }catch(Exception e){
                    println("RUNTIME_STATE_LABEL_PRESERVED "+e.getMessage());
                }
            }
        }
    }
    @Override public void run()throws Exception{
        if(currentProgram==null ||
            !"PowerPC:BE:64:A2ALT".equals(currentProgram.getLanguageID().toString())||
            !currentProgram.getName().contains("ps2_gxemu")){
            printerr("REFUSE: expected ps2_gxemu PowerPC:BE:64:A2ALT");return;
        }
        Function dispatcher=currentProgram.getFunctionManager().getFunctionAt(at(0x250D70L));
        if(dispatcher==null ||
            currentProgram.getMemory().getLong(at(0x670530L))!=0x250D70L ||
            currentProgram.getMemory().getLong(at(0x670538L))!=TOC){
            printerr("REFUSE: existing dispatcher OPD not verified");return;
        }
        println("GXEMU_VUART_CONTROL_RECOVERY_V1 APPLY="+APPLY);
        DataType opd=currentProgram.getDataTypeManager().getDataType(
            "/PS3/PPU/Ppc64FunctionDescriptor24");
        DecompInterface dc=new DecompInterface();
        dc.toggleCCode(true);
        boolean decompAvailable=dc.openProgram(currentProgram);
        if(!decompAvailable){
            println("DECOMPILER_UNAVAILABLE "+dc.getLastMessage()); dc.dispose();
        }
        int passed=0,created=0,skipped=0;
        try {
            for(Candidate c:CANDIDATES){
                monitor.checkCancelled();
                if(!descriptor(c)||!verifyBody(c)){
                    skipped++;println("CANDIDATE_SKIPPED "+at(c.entry));continue;
                }
                passed++;
                Function f=currentProgram.getFunctionManager().getFunctionAt(at(c.entry));
                if(f==null&&APPLY){
                    try {
                        f=currentProgram.getFunctionManager().createFunction(null,
                            at(c.entry),new AddressSet(at(c.entry),at(c.end)),
                            SourceType.ANALYSIS);
                        if(f!=null){created++;println("FUNCTION_CREATED "+f.getEntryPoint()+
                            ".."+f.getBody().getMaxAddress());}
                    }catch(Exception e){
                        println("FUNCTION_CREATE_FAILED "+at(c.entry)+" "+e.getMessage());
                    }
                }
                if(f==null){println("FUNCTION_UNAVAILABLE "+at(c.entry));continue;}
                if(c.verifiedName!=null && f.getName().startsWith("FUN_")){
                    boolean good=c.entry==0x0024F90CL||c.entry==0x0024FC4CL ?
                        verifiedQueue(c):true;
                    if(good&&APPLY){
                        try{
                            f.setName(c.verifiedName,SourceType.USER_DEFINED);
                            println("FUNCTION_RENAMED "+f.getEntryPoint()+" -> "+c.verifiedName);
                        }catch(Exception e){
                            println("FUNCTION_RENAME_PRESERVED "+e.getMessage());
                        }
                    }else println("FUNCTION_RENAME_UNVERIFIED "+at(c.entry));
                }
                descriptorData(c,opd);
                scopedToc(f);
                if(decompAvailable&&(c.entry==0x0024F90CL||c.entry==0x0024FC4CL||
                    c.entry==0x0024FD08L||c.entry==0x0025030CL||
                    c.entry==0x00250978L||c.entry==0x00250C84L))
                    decompile(f,dc);
            }
        }finally{if(decompAvailable)dc.dispose();}
        labelRuntimeState();
        println("SUMMARY candidates="+CANDIDATES.length+
            " verified="+passed+" new_functions="+created+" skipped="+skipped);
        println("DONE: no bytes, signatures, unknown parameters or large ambiguous bodies forced");
    }
}
