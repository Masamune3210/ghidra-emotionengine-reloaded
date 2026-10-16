// Recover three PS3 GXEMU UART control OPD functions that have an ordinary
// PPC64 prologue at entry+8 (two instructions are executed before stack setup).
// @category PS3.PS2Emulation
// Ghidra 12.1.x; ps2_gxemu.elf PowerPC:BE:64:A2ALT.
// Strict verify-first, only new function objects and generic OPD metadata.
// Rejects unreachable instruction islands, foreign internal flows, missing
// entries, out-of-range branches and disassembly/ownership conflicts.
// Never sets r2 context or guesses signatures/names. Decompiled C is printed.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Set;

public class RecoverPs3GxemuDelayedPrologueFunctions_20261016_v1 extends GhidraScript {
    private static final boolean APPLY=true;
    private static final long TOC=0x00678548L;
    private static final long[][] TARGETS={
        {0x0025075CL,0x0025085BL,0x006704D0L,0x0025085CL},
        {0x0025085CL,0x00250977L,0x006704E8L,0x00250978L},
        {0x00250C84L,0x00250D6FL,0x00670518L,0x00250D70L}
    };
    private Address at(long off){
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
    }
    private int word(long off)throws Exception{
        return currentProgram.getMemory().getInt(at(off));
    }
    private boolean descriptor(long off,long entry)throws Exception{
        long e=currentProgram.getMemory().getLong(at(off));
        long toc=currentProgram.getMemory().getLong(at(off+8));
        long env=currentProgram.getMemory().getLong(at(off+16));
        boolean ok=e==entry&&toc==TOC&&env==0;
        println(String.format("OPD %08X entry=%08X toc=%08X env=%X verified=%b",
            off,e,toc,env,ok));
        return ok;
    }
    private boolean prologue(long off)throws Exception{
        int w=word(off);
        return (w&0xFFFF0000)==0xF8210000&&(short)w<0;
    }
    private String dis(long x){
        Instruction i=currentProgram.getListing().getInstructionAt(at(x));
        return i==null?"<no instruction>":i.toString();
    }
    private boolean firstTwoInstructions(long start)throws Exception{
        Instruction a=currentProgram.getListing().getInstructionAt(at(start));
        Instruction b=currentProgram.getListing().getInstructionAt(at(start+4));
        Instruction c=currentProgram.getListing().getInstructionAt(at(start+8));
        if(a==null||b==null||c==null)return false;
        if(a.getLength()!=4||b.getLength()!=4||c.getLength()!=4)return false;
        // The entry begins with a load of an input/global; entry+4 saves LR,
        // and entry+8 allocates the frame. No independent foreign entry at +8.
        return (word(start+4)==0x7C0802A6)&&prologue(start+8)&&
            (a.getMnemonicString().startsWith("lbz")||
             a.getMnemonicString().startsWith("ld"));
    }
    private boolean verify(long[] c)throws Exception{
        long start=c[0],end=c[1],opd=c[2],next=c[3];
        if(!descriptor(opd,start))return false;
        boolean nextOk=false;
        for(long[] other:TARGETS)if(other[0]==next)
            nextOk=descriptor(other[2],next);
        if(next==0x00250D70L)nextOk=descriptor(0x00670530L,next);
        if(!nextOk || end+1!=next || !firstTwoInstructions(start)){
            println("REFUSE entry/successor proof "+at(start));return false;
        }
        MemoryBlock b=currentProgram.getMemory().getBlock(at(start));
        if(b==null||!b.isExecute()||b!=currentProgram.getMemory().getBlock(at(end))){
            println("REFUSE executable block "+at(start));return false;
        }
        Function original=currentProgram.getFunctionManager().getFunctionAt(at(start));
        if(original!=null && (original.getBody().getMinAddress().getOffset()!=start||
            original.getBody().getMaxAddress().getOffset()!=end)){
            println("REFUSE inconsistent preexisting function "+original);return false;
        }
        int instructions=0,prologues=0,ret=0,foreignCalls=0,foreignFlows=0;
        for(long off=start;off<=end;off+=4){
            monitor.checkCancelled();
            Instruction i=currentProgram.getListing().getInstructionAt(at(off));
            if(i==null||i.getLength()!=4){
                println("REFUSE disassembly gap "+at(off));return false;
            }
            Function owning=currentProgram.getFunctionManager().getFunctionContaining(at(off));
            if(owning!=null&&owning!=original){
                println("REFUSE overlap "+at(off)+" with "+owning);return false;
            }
            if(off!=start&&prologue(off)){
                prologues++;
                if(off!=start+8){
                    println("REFUSE extra frame prologue "+at(off));return false;
                }
            }
            if(word(off)==0x4E800020)ret++;
            ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(at(off));
            while(refs.hasNext()){
                Reference r=refs.next();
                if(!r.getFromAddress().getAddressSpace().equals(at(start).getAddressSpace()))
                    continue;
                long from=r.getFromAddress().getOffset();
                if(from>=start&&from<=end)continue;
                if(off!=start&&r.getReferenceType().isCall())foreignCalls++;
                if(off!=start&&r.getReferenceType().isFlow())foreignFlows++;
            }
            if(i.getFlowType().isJump()){
                Address[] dests=i.getFlows();
                if(dests.length==0){
                    println("REFUSE unresolved computed branch "+at(off));return false;
                }
                for(Address dest:dests)if(dest.getAddressSpace().equals(at(start).getAddressSpace()) &&
                   (dest.getOffset()<start||dest.getOffset()>end)){
                    println("REFUSE outgoing jump "+at(off)+" -> "+dest);return false;
                }
            }
            instructions++;
        }
        if(prologues!=1||ret==0||foreignCalls!=0||foreignFlows!=0){
            println("REFUSE structural candidates entry="+at(start)+" frames="+
                prologues+" returns="+ret+" foreign_calls="+foreignCalls+
                " foreign_flows="+foreignFlows);return false;
        }
        // Traverse reachable control-flow from the verified OPD entry. A BLR
        // before end is fine only when later code is reachable via branch.
        ArrayDeque<Long> pending=new ArrayDeque<>();
        Set<Long> visited=new HashSet<>();
        pending.add(start);
        while(!pending.isEmpty()){
            monitor.checkCancelled();
            long off=pending.removeFirst();
            if(off<start||off>end||!visited.add(off))continue;
            Instruction i=currentProgram.getListing().getInstructionAt(at(off));
            if(i==null||i.getLength()!=4)continue;
            Address ft=i.getFallThrough();
            if(ft!=null&&ft.getAddressSpace().equals(at(start).getAddressSpace())&&
               ft.getOffset()>=start&&ft.getOffset()<=end)pending.add(ft.getOffset());
            if(i.getFlowType().isJump()){
                for(Address dest:i.getFlows())if(dest.getAddressSpace().equals(at(start).getAddressSpace())&&
                    dest.getOffset()>=start&&dest.getOffset()<=end)
                    pending.add(dest.getOffset());
            }
        }
        println("REACHABILITY "+at(start)+" reachable="+visited.size()+
            " instructions="+instructions+" returns="+ret);
        if(visited.size()!=instructions){
            int printed=0;
            for(long off=start;off<=end;off+=4)if(!visited.contains(off)){
                if(printed<20)println("UNREACHABLE "+at(off)+" "+dis(off));
                printed++;
            }
            println("REFUSE unreachable instruction islands "+at(start)+" count="+printed);
            return false;
        }
        println("VERIFIED_DELAYED_PROLOGUE "+at(start)+".."+at(end));
        return true;
    }
    private void decompile(Function f,DecompInterface dc)throws Exception{
        DecompileResults r=dc.decompileFunction(f,100,monitor);
        println("DECOMP_START "+f.getName()+"@"+f.getEntryPoint());
        if(r.decompileCompleted()&&r.getDecompiledFunction()!=null){
            String s=r.getDecompiledFunction().getC();
            println(s.length()>22000?s.substring(0,22000):s);
            if(s.length()>22000)println("DECOMP_TRUNCATED original_chars="+s.length());
        }else println("DECOMP_FAILED "+r.getErrorMessage());
        println("DECOMP_END "+f.getEntryPoint());
    }
    @Override public void run()throws Exception{
        if(currentProgram==null||
           !"PowerPC:BE:64:A2ALT".equals(currentProgram.getLanguageID().toString())||
           !currentProgram.getName().contains("ps2_gxemu")){
            printerr("REFUSE expected ps2_gxemu PowerPC:BE:64:A2ALT");return;
        }
        println("GXEMU_DELAYED_PROLOGUE_RECOVERY_V1 APPLY="+APPLY);
        DecompInterface dc=new DecompInterface();
        dc.toggleCCode(true);
        boolean opened=dc.openProgram(currentProgram);
        int checked=0,created=0,refused=0;
        try{
            for(long[] c:TARGETS){
                monitor.checkCancelled();checked++;
                if(!verify(c)){refused++;continue;}
                Function f=currentProgram.getFunctionManager().getFunctionAt(at(c[0]));
                if(f==null&&APPLY){
                    try{
                        f=currentProgram.getFunctionManager().createFunction(null,
                             at(c[0]),new AddressSet(at(c[0]),at(c[1])),
                             SourceType.ANALYSIS);
                        if(f!=null){created++;println("FUNCTION_CREATED "+
                            f.getEntryPoint()+".."+f.getBody().getMaxAddress());}
                    }catch(Exception e){
                        println("FUNCTION_REFUSED "+at(c[0])+" "+e.getMessage());
                    }
                }
                if(f!=null&&opened)decompile(f,dc);
            }
        }finally{dc.dispose();}
        println("SUMMARY checked="+checked+" created="+created+" refused="+refused);
        println("DONE: only independently verified functions created; names, "+
            "signatures, datatypes, TOC contexts, and executable bytes unchanged.");
    }
}
