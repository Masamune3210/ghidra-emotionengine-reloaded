// Trace the PS3 GXEMU UART-10 state producers and missing function boundaries.
// @category PS3.PS2Emulation
// Requires Ghidra 12.1.x, ps2_gxemu.elf, PowerPC:BE:64:A2ALT.
// Applies ONLY verified EOL comments at exact state-2/state-4 stores.
// Function boundaries, function descriptors and all unknown writers: READ-ONLY.
// No names, signatures, datatypes, r2 contexts, functions or bytes changed.

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
import ghidra.program.model.mem.MemoryBlock;

public class TracePs3GxemuVuartDispatchProducers_20261016_v1 extends GhidraScript {
    private static final boolean APPLY_VERIFIED_COMMENTS = true;
    private static final long TOC=0x00678548L;
    private static final long STATE_SLOT=0x00677788L; // r2-0xDC0
    private static final long STATUS_SLOT=0x00677770L; // r2-0xDD8
    private static final long ANALYSIS_START=0x0024E000L;
    private static final long ANALYSIS_END=0x00252000L;
    private static final int MAX_BACK=36;
    private Address at(long n) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(n);
    }
    private int word(Instruction i) throws Exception {
        return currentProgram.getMemory().getInt(i.getAddress());
    }
    private boolean writes(Instruction ins,int register) throws Exception {
        Register r=currentProgram.getRegister("r"+register);
        if(r==null)return true;
        for(PcodeOp op:ins.getPcode()) {
            Varnode out=op.getOutput();
            if(out!=null && out.isRegister() && out.getAddress().equals(r.getAddress()))
                return true;
        }
        return false;
    }
    // Only straight-line PPC. Reject intervening calls/branches/syscalls,
    // earlier register redefinitions and disassembly gaps. Call results
    // LINEAR, never proof of dominance at a CFG merge.
    private Integer previousDefinition(Instruction site,int destReg,boolean wantTocLoad) throws Exception {
        Instruction cursor=site;
        for(int k=0;k<MAX_BACK;k++) {
            monitor.checkCancelled();
            Instruction p=currentProgram.getListing().getInstructionBefore(cursor.getAddress());
            if(p==null||p.getLength()!=4||p.getFallThrough()==null||
                !p.getFallThrough().equals(cursor.getAddress())||
                p.getFlowType().isJump()||p.getFlowType().isCall()||
                p.getFlowType().isTerminal())return null;
            int w=word(p),op=w>>>26,rd=(w>>>21)&31,ra=(w>>>16)&31;
            if(op==17)return null; // sc: conservative side-effect barrier
            if(wantTocLoad && op==58 && rd==destReg && ra==2 &&
                (w&3)==0) {
                return (int)(short)(w&0xFFFC);
            }
            if(!wantTocLoad && op==14 && rd==destReg && ra==0)
                return (int)(short)(w&0xFFFF);
            if(writes(p,destReg))return null;
            cursor=p;
        }
        return null;
    }
    private boolean exactStateWriter(long site,int expectedState) throws Exception {
        Instruction ins=currentProgram.getListing().getInstructionAt(at(site));
        if(ins==null||ins.getLength()!=4)return false;
        int w=word(ins),op=w>>>26,rs=(w>>>21)&31,ra=(w>>>16)&31;
        if(op!=36||(short)w!=0)return false;
        Integer ptr=previousDefinition(ins,ra,true);
        Integer val=previousDefinition(ins,rs,false);
        return ptr!=null&&ptr==-0xDC0&&val!=null&&val==expectedState;
    }
    private void annotate(long site,int state) throws Exception {
        if(!exactStateWriter(site,state)) {
            println(String.format("COMMENT_REFUSED 0x%08X state=%d exact linear proof absent",site,state));
            return;
        }
        println(String.format("CONFIRMED_STATE_WRITE addr=0x%08X state=%d ptr=r2-0xDC0 -> 0x%X",
            site,state,STATE_SLOT));
        if(!APPLY_VERIFIED_COMMENTS)return;
        Instruction ins=currentProgram.getListing().getInstructionAt(at(site));
        String note="GXEMU UART10: stores dispatch state "+state+
            " through pointer from TOC-0xDC0 (slot 0x00677788); local li/ld/stw proven. "+
            "Do not infer native MechaCon S-command from UART dispatch state.";
        String old=ins.getComment(CodeUnit.EOL_COMMENT);
        if(old==null||old.isEmpty())ins.setComment(CodeUnit.EOL_COMMENT,note);
        else if(!old.contains(note))ins.setComment(CodeUnit.EOL_COMMENT,old+"\n"+note);
    }
    private String owner(Address a) {
        Function f=currentProgram.getFunctionManager().getFunctionContaining(a);
        return f==null?"<none>":f.getName()+"@"+f.getEntryPoint();
    }
    private void around(long address,int before,int after) throws Exception {
        Instruction center=currentProgram.getListing().getInstructionAt(at(address));
        if(center==null){println("NO_INSTRUCTION "+at(address));return;}
        Instruction i=center;
        for(int n=0;n<before;n++){
            Instruction p=currentProgram.getListing().getInstructionBefore(i.getAddress());
            if(p==null)break;
            i=p;
        }
        println("CONTEXT_BEGIN "+at(address));
        for(int n=0;i!=null&&n<before+after+1;n++) {
            monitor.checkCancelled();
            println("    "+i.getAddress()+" "+i+" owner="+owner(i.getAddress()));
            i=currentProgram.getListing().getInstructionAfter(i.getAddress());
        }
        println("CONTEXT_END "+at(address));
    }
    private void refs(long address) throws Exception {
        ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(at(address));
        int count=0;
        while(it.hasNext()){
            monitor.checkCancelled();
            Reference r=it.next();
            if(count<24)println("    XREF "+r.getFromAddress()+" -> "+at(address)+" "+r.getReferenceType());
            count++;
        }
        println("    XREF_TOTAL "+at(address)+"="+count);
    }
    private void enumerateWriters() throws Exception {
        InstructionIterator it=currentProgram.getListing().getInstructions(true);
        int candidateStores=0, confirmed=0, unresolved=0;
        println("STATE_WRITER_SCAN "+at(ANALYSIS_START)+".."+at(ANALYSIS_END));
        while(it.hasNext()){
            monitor.checkCancelled();
            Instruction ins=it.next();
            long offset=ins.getAddress().getOffset();
            if(offset<ANALYSIS_START||offset>ANALYSIS_END||ins.getLength()!=4)continue;
            int w=word(ins);
            if((w>>>26)!=36||(short)w!=0)continue; // only stw rS,0(rA)
            candidateStores++;
            int ra=(w>>>16)&31,rs=(w>>>21)&31;
            Integer ptr=previousDefinition(ins,ra,true);
            if(ptr==null|| (ptr!=-0xDC0&&ptr!=-0xDD8))continue;
            Integer value=previousDefinition(ins,rs,false);
            String kind=ptr==-0xDC0?"DISPATCH_STATE":"STATUS";
            if(value==null)unresolved++;else confirmed++;
            println("STATE_OR_STATUS_STORE "+kind+" "+ins.getAddress()+
                " writer="+ins+" immediate="+(value==null?"unresolved":value)+
                " owner="+owner(ins.getAddress())+" evidence=STRAIGHT_LINE");
            around(offset,5,3);
        }
        println("STATE_WRITER_COUNTS stores_visited="+candidateStores+
            " matched_resolved="+confirmed+" matched_unknown_value="+unresolved);
        println("NOTE: these counters omit pointer loads crossing control-flow barriers "+
            "and indirect/out-of-range writers; they are NOT exhaustive.");
    }
    private void candidateDescriptorScan() throws Exception {
        int hits=0, inspected=0;
        // Restricted to the observed contiguous GXEMU OPD cluster. Read-only.
        for(long address=0x006703C0L;address<=0x00670578L;address+=8) {
            monitor.checkCancelled();
            try {
                MemoryBlock b=currentProgram.getMemory().getBlock(at(address));
                if(b==null||!b.isInitialized()||b.isExecute()||
                    !currentProgram.getMemory().contains(at(address+23)))continue;
                inspected++;
                long entry=currentProgram.getMemory().getLong(at(address));
                long toc=currentProgram.getMemory().getLong(at(address+8));
                long env=currentProgram.getMemory().getLong(at(address+16));
                if(entry<0x0024E000L||entry>0x00251100L||
                    toc!=TOC||env!=0)continue;
                hits++;
                Instruction first=currentProgram.getListing().getInstructionAt(at(entry));
                println(String.format("OPD_CANDIDATE address=%s entry=0x%08X TOC=0x%X env=0 "+
                    "defined_function=%s first=%s",at(address),entry,toc,
                    owner(at(entry)),first));
                refs(entry);
                if(hits<16)around(entry,2,5);
            } catch(Exception e) {
                println("OPD_READ_FAILED "+at(address)+" "+e.getMessage());
            }
        }
        println("OPD_SCAN inspected_cells="+inspected+" valid_triples="+hits);
    }
    private void scanBoundaries() throws Exception {
        for(long offset=0x0024F8C0L;offset<=0x0024FD40L;offset+=4) {
            monitor.checkCancelled();
            Instruction i=currentProgram.getListing().getInstructionAt(at(offset));
            if(i==null||i.getLength()!=4)continue;
            int w=word(i);
            boolean start=(w&0xFFFF0000)==0xF8210000&&(short)w<0;
            boolean end=w==0x4E800020;
            if(start||end) {
                println("BOUNDARY_CANDIDATE "+at(offset)+" "+i+
                    " owner="+owner(i.getAddress()));
                if(start)refs(offset);
            }
        }
        for(long site:new long[]{0x0024F8F0L,0x0024F91CL,0x0024F95CL,
            0x0024FC08L,0x0024FC5CL,0x0024FD08L}) {
            around(site,7,11);
        }
    }
    private void callback() throws Exception {
        long[] positions={0x00250EE8L,0x00250EECL,0x00250EF0L,
            0x00250EF4L,0x00250EF8L,0x00250EFCL};
        String[] want={"std r2,0x28(r1)","ld r11,0x10(r9)",
            "mtspr CTR,r0","ld r2,0x8(r9)","bctrl","ld r2,0x28(r1)"};
        boolean ok=true;
        for(int i=0;i<positions.length;i++){
            Instruction ins=currentProgram.getListing().getInstructionAt(at(positions[i]));
            println("DISPATCH_CALLBACK "+at(positions[i])+" "+ins);
            if(ins==null||!want[i].equals(ins.toString()))ok=false;
        }
        println("DISPATCH_CALLBACK_SEQUENCE_VERIFIED="+ok+
            " (no r2 context applied across callback)");
    }
    @Override public void run() throws Exception {
        if(currentProgram==null ||
            !"PowerPC:BE:64:A2ALT".equals(currentProgram.getLanguageID().toString()) ||
            !currentProgram.getName().contains("ps2_gxemu")){
            printerr("REFUSE: expected ps2_gxemu / PowerPC:BE:64:A2ALT");
            return;
        }
        println("GXEMU_STATE_PRODUCER_AUDIT_V1");
        Function dispatcher=currentProgram.getFunctionManager().getFunctionAt(at(0x250D70L));
        if(dispatcher==null ||
            currentProgram.getMemory().getLong(at(0x670530L))!=0x250D70L ||
            currentProgram.getMemory().getLong(at(0x670538L))!=TOC ||
            !dispatcher.getBody().contains(at(0x251044L))) {
            printerr("REFUSE: current dispatcher/OPD evidence differs.");
            return;
        }
        println("DISPATCH_STATE_POINTER_SLOT="+at(STATE_SLOT)+
            " current_data="+currentProgram.getListing().getDataAt(at(STATE_SLOT)));
        println("STATUS_POINTER_SLOT="+at(STATUS_SLOT));
        annotate(0x0024F91CL,4);
        annotate(0x0024FC5CL,2);
        callback();
        enumerateWriters();
        candidateDescriptorScan();
        scanBoundaries();
        println("DONE: verified state 2/4 comments only; function/OPD candidates remain read-only.");
    }
}
