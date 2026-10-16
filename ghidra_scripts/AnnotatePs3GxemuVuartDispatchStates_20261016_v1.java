// PS3 GXEMU VUART10 state-machine metadata and TOC state-writer audit.
// @category PS3.PS2Emulation
// Ghidra 12.1.x: ps2_gxemu.elf PowerPC:BE:64:A2ALT.
// Applies verified enum/OPD/global metadata ONLY, preserving intentional data.
// Does not force r2 context across callback, change signatures or executable bytes.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class AnnotatePs3GxemuVuartDispatchStates_20261016_v1 extends GhidraScript {
    private static final boolean APPLY=true;
    private static final long DISPATCH=0x00250D70L, TOC=0x00678548L, OPD=0x00670530L;
    private static final long DISPATCH_STATE_SLOT=0x00677788L; // r2 - 0xDC0
    private static final long STATUS_SLOT=0x00677770L; // r2 - 0xDD8
    private static final int MAX_TARGET_SITES=45;
    private Address at(long address) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(address);
    }
    private boolean calls(long from,long dest) {
        Instruction ins=currentProgram.getListing().getInstructionAt(at(from));
        if(ins==null || !ins.getFlowType().isCall())return false;
        for(Address a:ins.getFlows())if(a.equals(at(dest)))return true;
        return false;
    }
    private boolean verifyDispatcher() throws Exception {
        Function f=currentProgram.getFunctionManager().getFunctionAt(at(DISPATCH));
        if(f==null || !f.getBody().contains(at(0x00251044L)) ||
            !f.getBody().contains(at(0x0025106CL)))return false;
        if(currentProgram.getMemory().getLong(at(OPD))!=DISPATCH ||
            currentProgram.getMemory().getLong(at(OPD+8))!=TOC ||
            currentProgram.getMemory().getLong(at(OPD+16))!=0)return false;
        if(!calls(0x00251044L,0x000901FCL) ||
            !calls(0x0025106CL,0x0008FD48L))return false;
        println("VERIFY_DISPATCH "+f.getName()+"@"+f.getEntryPoint()+
            " body="+f.getBody().getMinAddress()+".."+f.getBody().getMaxAddress()+
            " both UART senders and 24-byte OPD verified");
        return true;
    }
    private DataType getOrCreateEnum() throws Exception {
        String path="/PS3/GXEMU/GxemuVuart10DispatchState";
        DataType exists=currentProgram.getDataTypeManager().getDataType(path);
        if(exists!=null) {
            println("ENUM_PRESERVED "+exists.getPathName()+" length="+exists.getLength());
            return exists instanceof Enum && exists.getLength()==4?exists:null;
        }
        EnumDataType e=new EnumDataType(new CategoryPath("/PS3/GXEMU"),
            "GxemuVuart10DispatchState",4);
        e.add("Idle",0,"No state-specific action in this dispatch iteration");
        e.add("SendSubtype09",1,"Invokes SendVirtualUartVariablePacketAlternate, byte +0x17=0x09");
        e.add("ProcessResponse",2,"Inspects 32-bit BE field +0x20, sets status and optionally calls a callback");
        e.add("SendSubtype0A",3,"Invokes SendVirtualUartVariablePacket, byte +0x17=0x0A");
        e.add("ProcessResponseLimit",4,"Checks BE64 response +0x40 and clamps values above 0xFFFF to 0x40");
        if(!APPLY) {
            println("WOULD_CREATE_ENUM "+path);
            return e;
        }
        DataType added=currentProgram.getDataTypeManager().addDataType(
            e,DataTypeConflictHandler.DEFAULT_HANDLER);
        println("ENUM_CREATED "+added.getPathName()+" length="+added.getLength());
        return added;
    }
    private void labelIfDefault(long addr,String name) throws Exception {
        Address a=at(addr);
        Symbol sym=currentProgram.getSymbolTable().getPrimarySymbol(a);
        if(sym!=null && sym.getSource()!=SourceType.DEFAULT &&
            sym.getSource()!=SourceType.ANALYSIS) {
            println("PRESERVE_LABEL "+a+" "+sym.getName());
            return;
        }
        if(sym!=null && !(sym.getName().startsWith("DAT_") ||
            sym.getName().startsWith("PTR_"))) {
            println("PRESERVE_LABEL "+a+" "+sym.getName());
            return;
        }
        if(APPLY) {
            try {
                currentProgram.getSymbolTable().createLabel(a,name,SourceType.USER_DEFINED);
                println("LABEL "+a+" -> "+name);
            }catch(Exception ex){
                println("LABEL_REFUSED "+a+" "+ex.getMessage());
            }
        }else println("WOULD_LABEL "+a+" -> "+name);
    }
    private void guardedData(long addr,DataType type,String name) throws Exception {
        Address a=at(addr);
        if(APPLY) {
            try {
                DataUtilities.createData(currentProgram,a,type,type.getLength(),
                    DataUtilities.ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
                println("DATA_TYPED "+a+" -> "+type.getName());
            }catch(Exception ex){
                println("DATA_PRESERVED "+a+" "+ex.getMessage());
            }
        }
        labelIfDefault(addr,name);
    }
    private void appendComment(long address,String message) {
        Instruction ins=currentProgram.getListing().getInstructionAt(at(address));
        if(ins==null || !APPLY)return;
        String old=ins.getComment(CodeUnit.EOL_COMMENT);
        if(old==null || old.isEmpty())
            ins.setComment(CodeUnit.EOL_COMMENT,message);
        else if(!old.contains(message))
            ins.setComment(CodeUnit.EOL_COMMENT,old+"\n"+message);
    }
    private void xrefs(long dest) throws Exception {
        ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(at(dest));
        int n=0;
        while(it.hasNext()) {
            monitor.checkCancelled();
            Reference r=it.next();
            if(n<30)println("XREF "+at(dest)+" from="+r.getFromAddress()+
                " type="+r.getReferenceType());
            n++;
        }
        println("XREF_TOTAL "+at(dest)+" "+n);
    }
    private void dumpAround(Instruction center,int before,int after) throws Exception {
        Instruction cur=center;
        for(int i=0;i<before;i++){
            Instruction p=currentProgram.getListing().getInstructionBefore(cur.getAddress());
            if(p==null)break;
            cur=p;
        }
        int limit=before+after+1;
        for(int n=0;cur!=null && n<limit;n++){
            monitor.checkCancelled();
            Function f=currentProgram.getFunctionManager().getFunctionContaining(cur.getAddress());
            println("    "+cur.getAddress()+" "+cur+
                " owner="+(f==null?"<none>":f.getName()+"@"+f.getEntryPoint()));
            cur=currentProgram.getListing().getInstructionAfter(cur.getAddress());
        }
    }
    private void scanStateSlotLoads() throws Exception {
        // ld rd, -0xdc0(r2): PPC opcode 58, RA=2, DS-immediate -0xdc0.
        // The *loaded* value is a pointer. Its pointed-to value is what
        // the dispatcher compares against states 0..4.
        int count=0, shown=0;
        InstructionIterator it=currentProgram.getListing().getInstructions(true);
        while(it.hasNext()){
            monitor.checkCancelled();
            Instruction ins=it.next();
            if(ins.getLength()!=4)continue;
            int w=currentProgram.getMemory().getInt(ins.getAddress());
            int primary=w>>>26;
            if(primary!=58 || ((w>>>16)&31)!=2 || (w&3)!=0)continue;
            int offset=(short)(w&0xFFFC);
            if(offset!=-0xDC0 && offset!=-0xDD8)continue;
            // These offsets identify the target globals only for code using
            // the verified 0x678548 TOC; print other hits as candidates.
            count++;
            Function f=currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress());
            boolean nearDispatch=ins.getAddress().getOffset()>=0x0024F000L &&
                ins.getAddress().getOffset()<=0x00252000L;
            if(shown++ < MAX_TARGET_SITES) {
                println("TOC_OFFSET_LOAD "+ins.getAddress()+" offset="+offset+
                    " dest_r"+((w>>>21)&31)+" function="+
                    (f==null?"<none>":f.getName()+"@"+f.getEntryPoint())+
                    " in_dispatch_neighborhood="+nearDispatch);
                if(nearDispatch)dumpAround(ins,2,7);
            }
        }
        println("TOC_OFFSET_LOAD_TOTAL "+count+
            " printed="+Math.min(count,MAX_TARGET_SITES));
        println("NOTE: matching r2-relative displacements outside validated OPD scopes "+
            "are NOT definitive references to these globals.");
    }
    private void checkCallbackR2() throws Exception {
        for(long p:new long[]{0x00250EE4L,0x00250EF4L,0x00250F04L}){
            Instruction ins=currentProgram.getListing().getInstructionAt(at(p));
            println("CALLBACK_CONTEXT "+at(p)+" "+ins);
            if(ins!=null)dumpAround(ins,4,7);
        }
        println("NOTE: no function-wide r2 constant assigned; dispatcher has observed r2 writer at 0x250EF4.");
    }
    @Override
    public void run() throws Exception {
        if(currentProgram==null ||
            !"PowerPC:BE:64:A2ALT".equals(currentProgram.getLanguageID().toString()) ||
            !currentProgram.getName().contains("ps2_gxemu")){
            printerr("REFUSE: expected PowerPC:BE:64:A2ALT ps2_gxemu database");
            return;
        }
        println("GXEMU_DISPATCH_STATE_ANALYSIS_V1 APPLY="+APPLY);
        if(!verifyDispatcher()){
            printerr("VERIFY_FAILED: dispatcher not validated; no metadata applied");
            return;
        }
        DataType state=getOrCreateEnum();
        DataType opd=currentProgram.getDataTypeManager().getDataType(
            "/PS3/PPU/Ppc64FunctionDescriptor24");
        if(state!=null) {
            guardedData(DISPATCH_STATE_SLOT,new PointerDataType(state,8),
                "gVuart10DispatchStatePointer");
            guardedData(STATUS_SLOT,new PointerDataType(DWordDataType.dataType,8),
                "gVuart10DispatchStatusPointer");
        }
        if(opd!=null && opd.getLength()==24)
            guardedData(OPD,opd,"PpuOpd_DispatchVirtualUartPacketTransfers");
        appendComment(0x00251044L,"Dispatch state 1: send VUART10 subtype +0x17=0x09 using alternate packet layout; not established as native MagicGate command.");
        appendComment(0x0025106CL,"Dispatch state 3: send VUART10 subtype +0x17=0x0A using other packet layout; not established as native MagicGate command.");
        appendComment(DISPATCH,"Non-returning UART state worker; observed values 0 idle,1 subtype09 send,2 response,3 subtype0A send,4 response-limit. Do not confuse UART frame class with PS2 SCMD.");
        xrefs(DISPATCH);
        xrefs(OPD);
        xrefs(DISPATCH_STATE_SLOT);
        xrefs(STATUS_SLOT);
        checkCallbackR2();
        scanStateSlotLoads();
        println("DONE: state enum and verified metadata; no signatures, executable bytes or r2 context changed.");
    }
}
