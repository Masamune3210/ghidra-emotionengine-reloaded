// PS3 GXEMU: refine verified ELFv1 callback descriptors, guarded address-translation
// name, and inspect the currently unowned VUART-10 upstream dispatch blocks.
// @category PS3.PS2Emulation
// Ghidra 12.1.3; ps2_gxemu.elf, PowerPC:BE:64:A2ALT.
// Every edit is guarded. No executable bytes, instruction boundaries, guessed
// S-command labels or unresolved function parameters are changed.

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;

public class RefinePs3GxemuCallbackAndDispatcher_20261016_v1 extends GhidraScript {
    private static final long TOC=0x00678548L;
    private static final boolean APPLY=true;
    private Address at(long off) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
    }
    private boolean instr(long off,String expected) {
        Instruction ins=currentProgram.getListing().getInstructionAt(at(off));
        return ins!=null && expected.equals(ins.toString());
    }
    private boolean verifyCallback() throws Exception {
        long descriptor=0x0064F6F8L;
        if (currentProgram.getMemory().getLong(at(descriptor))!=0x0008FC68L ||
            currentProgram.getMemory().getLong(at(descriptor+8))!=TOC ||
            currentProgram.getMemory().getLong(at(descriptor+16))!=0)
            return false;
        long[] off={0x8FD10L,0x8FD14L,0x8FD18L,0x8FD1CL,0x8FD20L,0x8FD24L};
        String[] codes={"mtspr CTR,r0","std r2,0x28(r1)","ld r11,0x10(r9)",
            "ld r2,0x8(r9)","bctrl","ld r2,0x28(r1)"};
        for(int i=0;i<off.length;i++) {
            if(!instr(off[i],codes[i])) {
                Instruction actual=currentProgram.getListing().getInstructionAt(at(off[i]));
                println("CALLBACK_VERIFY_FAIL "+at(off[i])+" expected="+codes[i]+
                    " actual="+actual);
                return false;
            }
        }
        println("CALLBACK_VERIFIED save_r2=0008fd14 load_environment_r11=0008fd18"+
            " load_descriptor_toc_r2=0008fd1c call_ctr=0008fd20 restore_r2=0008fd24");
        return true;
    }
    private void refineCallbackType() throws Exception {
        DataType state=currentProgram.getDataTypeManager().getDataType(
            "/PS3/GXEMU/GxemuVuart10TransferState");
        DataType opd=currentProgram.getDataTypeManager().getDataType(
            "/PS3/PPU/Ppc64FunctionDescriptor24");
        if(!(state instanceof Structure) || opd==null || state.getLength()!=24 ||
            opd.getLength()!=24) {
            println("TYPE_NOT_REFINED: expected existing 0x18 state and OPD structures");
            return;
        }
        Structure structure=(Structure)state;
        DataTypeComponent member=structure.getComponentAt(0);
        if(member==null || !(member.getDataType() instanceof Pointer)) {
            println("TYPE_PRESERVED: transfer callback field already nonpointer");
            return;
        }
        Pointer existing=(Pointer)member.getDataType();
        DataType referenced=existing.getDataType();
        if(referenced != null && referenced.isEquivalent(opd)) {
            println("TYPE_ALREADY_REFINED callback->Ppc64FunctionDescriptor24");
            return;
        }
        // Do not clobber a prior deliberate callback type.
        if(referenced!=null && !"void".equals(referenced.getName()) &&
            !"undefined".equals(referenced.getName())) {
            println("TYPE_PRESERVED custom callback type="+referenced.getName());
            return;
        }
        if(APPLY) {
            structure.replaceAtOffset(0,new PointerDataType(opd,8),8,
                "completionFunctionDescriptor",
                "ELFv1 function descriptor: entry at +0, callback r2 TOC at +8, r11 env at +0x10; verified by ReceiveVirtualUartChunk");
        }
        println("TYPE_REFINED /PS3/GXEMU/GxemuVuart10TransferState +0x00 "+
            "Ppc64FunctionDescriptor24 *");
        Instruction call=currentProgram.getListing().getInstructionAt(at(0x8FD20L));
        if(APPLY && call!=null) {
            String msg="PS3 PPC64 indirect callback via OPD: r2 saved 0x8FD14, "+
                "r11=descriptor+0x10, r2=descriptor+8, bctrl, r2 restored 0x8FD24. "+
                "Do not set one r2 value over the temporary TOC switch.";
            String old=call.getComment(CodeUnit.EOL_COMMENT);
            if(old==null || old.isEmpty())call.setComment(CodeUnit.EOL_COMMENT,msg);
            else if(!old.contains(msg))call.setComment(CodeUnit.EOL_COMMENT,old+"\n"+msg);
        }
    }
    private boolean hasCall(long site,long target) {
        Instruction ins=currentProgram.getListing().getInstructionAt(at(site));
        if(ins==null||!ins.getFlowType().isCall())return false;
        for(Address flow:ins.getFlows())if(flow.equals(at(target)))return true;
        return false;
    }
    private void renameAddressTranslator(DecompInterface dc) throws Exception {
        Function f=currentProgram.getFunctionManager().getFunctionAt(at(0x0024F718L));
        if(f==null) {
            println("TRANSLATOR_NOT_FOUND");
            return;
        }
        boolean knownRefs=hasCall(0x0008FC84L,0x0024F718L) &&
            hasCall(0x0008FF00L,0x0024F718L) &&
            hasCall(0x000900ACL,0x0024F718L) &&
            hasCall(0x000903B4L,0x0024F718L);
        DecompileResults dr=dc.decompileFunction(f,60,monitor);
        String c=(dr.decompileCompleted() && dr.getDecompiledFunction()!=null) ?
            dr.getDecompiledFunction().getC() : "";
        boolean verified=knownRefs && c.contains("0xfffffffffffdffff") &&
            c.contains("0x00677720") && c.contains("0x00677728") &&
            c.contains("return param_1");
        println("ADDRESS_TRANSLATOR_VERIFIED="+verified+
            " callers="+knownRefs+" mask="+c.contains("0xfffffffffffdffff")+
            " baseSlots="+(c.contains("0x00677720")&&c.contains("0x00677728")));
        if(!verified)return;
        if(APPLY && f.getName().startsWith("FUN_")) {
            f.setName("TranslateMappedBufferAddress",SourceType.USER_DEFINED);
            println("RENAME 0024F718 -> TranslateMappedBufferAddress");
        }else println("PRESERVE_NAME "+f.getName()+" @ "+f.getEntryPoint());
        Parameter p=f.getParameter(0);
        if(p!=null && p.getDataType().getLength()==8 &&
            p.getName().startsWith("param_") && APPLY) {
            p.setName("candidateAddress",SourceType.USER_DEFINED);
            println("PARAM_NAME 0024F718 param0 -> candidateAddress"+
                " datatype_preserved="+p.getDataType().getName());
        }
        println("GHIDRA_FUNCTION_EDITOR "+
            f.getReturnType().getName()+" "+f.getName()+
            "("+((p==null)?"?":p.getDataType().getName()+" "+p.getName())+")");
    }
    private boolean verifiedOpd(long opd,long entry) throws Exception {
        return currentProgram.getMemory().contains(at(opd)) &&
            currentProgram.getMemory().contains(at(opd+23)) &&
            currentProgram.getMemory().getLong(at(opd))==entry &&
            currentProgram.getMemory().getLong(at(opd+8))==TOC &&
            currentProgram.getMemory().getLong(at(opd+16))==0;
    }
    private boolean r2Written(Function f,Register r2) throws Exception {
        for(Instruction ins:currentProgram.getListing().getInstructions(f.getBody(),true)) {
            monitor.checkCancelled();
            for(PcodeOp op:ins.getPcode()) {
                Varnode out=op.getOutput();
                if(out!=null && out.isRegister() &&
                    out.getAddress().equals(r2.getAddress())) {
                    println("SCOPED_TOC_REFUSED R2_WRITER "+ins.getAddress()+" "+ins);
                    return true;
                }
            }
        }
        return false;
    }
    private void tocForUpstream(long entry,long opd) throws Exception {
        Function f=currentProgram.getFunctionManager().getFunctionAt(at(entry));
        if(f==null||!verifiedOpd(opd,entry)) {
            println(String.format("UPSTREAM_OPD_UNVERIFIED entry=0x%X opd=0x%X",
                entry,opd));
            return;
        }
        Register r2=currentProgram.getRegister("r2");
        if(r2==null || r2Written(f,r2))return;
        RegisterValue old=currentProgram.getProgramContext().getRegisterValue(r2,f.getEntryPoint());
        if(old!=null && old.hasValue()) {
            println("UPSTREAM_TOC_ALREADY "+f.getEntryPoint()+" "+old.getUnsignedValue());
            return;
        }
        if(APPLY) {
            currentProgram.getProgramContext().setRegisterValue(
                f.getBody().getMinAddress(),f.getBody().getMaxAddress(),
                new RegisterValue(r2,BigInteger.valueOf(TOC)));
        }
        println("UPSTREAM_TOC_SET "+f.getEntryPoint()+" r2=0x"+Long.toHexString(TOC)+
            " body="+f.getBody().getMinAddress()+".."+f.getBody().getMaxAddress());
    }
    private int xrefs(long location) throws Exception {
        ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(at(location));
        int n=0;
        while(it.hasNext()){
            monitor.checkCancelled();
            Reference r=it.next();
            if(n<15)println("  XREF "+at(location)+" <- "+r.getFromAddress()+
                " "+r.getReferenceType());
            n++;
        }
        return n;
    }
    private void auditUnownedDispatch() throws Exception {
        long start=0x0024FF00L,end=0x0025109BL;
        println("DISPATCH_AUDIT_RANGE "+at(start)+".."+at(end));
        List<Long> prologues=new ArrayList<Long>();
        List<Long> blrs=new ArrayList<Long>();
        for(long address=start;address+3<=end;address+=4) {
            monitor.checkCancelled();
            Instruction ins=currentProgram.getListing().getInstructionAt(at(address));
            if(ins==null||ins.getLength()!=4)continue;
            int w=currentProgram.getMemory().getInt(at(address));
            if((w&0xFFFF0000)==0xF8210000)
                prologues.add(address);
            if(w==0x4E800020)
                blrs.add(address);
        }
        println("DISPATCH_PROLOGUES "+prologues.size()+" RETURNS "+blrs.size());
        for(long startCandidate:prologues){
            Function owner=currentProgram.getFunctionManager().getFunctionContaining(at(startCandidate));
            println(String.format("  PROLOGUE 0x%08X owner=%s xref_count=%d",startCandidate,
                owner==null?"<none>":owner.getName()+"@"+owner.getEntryPoint(),
                xrefs(startCandidate)));
        }
        for(long branch:new long[]{0x00250DC0L,0x00250ECCL,0x00250EE4L,
            0x00251044L,0x0025106CL,0x0025109CL}) {
            Function f=currentProgram.getFunctionManager().getFunctionContaining(at(branch));
            Instruction ins=currentProgram.getListing().getInstructionAt(at(branch));
            println("DISPATCH_SITE "+at(branch)+" ins="+ins+" owner="+
                (f==null?"<none>":f.getName()+"@"+f.getEntryPoint()));
            if(branch==0x00251044L || branch==0x0025106CL) {
                println("  INCOMING_SITE_REFS="+xrefs(branch));
            }
        }
        for(long last:blrs) {
            if(last>=0x00250D00L)
                println(String.format("  BLR 0x%08X",last));
        }
    }
    private void decompile(DecompInterface dc,long entry) throws Exception {
        Function f=currentProgram.getFunctionManager().getFunctionAt(at(entry));
        if(f==null)return;
        println("DECOMP_START "+f.getName()+"@"+f.getEntryPoint());
        DecompileResults out=dc.decompileFunction(f,90,monitor);
        if(out.decompileCompleted()&&out.getDecompiledFunction()!=null) {
            String c=out.getDecompiledFunction().getC();
            println(c.length()>18000?c.substring(0,18000):c);
            if(c.length()>18000)println("DECOMP_TRUNCATED len="+c.length());
        } else println("DECOMP_FAILED "+out.getErrorMessage());
        println("DECOMP_END "+f.getEntryPoint());
    }
    @Override
    public void run() throws Exception {
        if(currentProgram==null||
            !"PowerPC:BE:64:A2ALT".equals(currentProgram.getLanguageID().toString())||
            !currentProgram.getName().contains("ps2_gxemu")) {
            printerr("REFUSE: requires decrypted ps2_gxemu under PowerPC:BE:64:A2ALT");
            return;
        }
        println("GXEMU_CALLBACK_AND_DISPATCH_V1 APPLY="+APPLY);
        if(verifyCallback())refineCallbackType();
        else println("PRESERVE_CALLBACK_TYPE failed verification");
        DecompInterface dc=new DecompInterface();
        dc.toggleCCode(true);
        if(dc.openProgram(currentProgram)){
            try{
                renameAddressTranslator(dc);
                tocForUpstream(0x0024F95CL,0x00670428L);
                decompile(dc,0x0024F95CL);
            }finally{dc.dispose();}
        }else println("DECOMP_UNAVAILABLE "+dc.getLastMessage());
        auditUnownedDispatch();
        println("DONE: no unverified function promotions or executable bytes changed");
    }
}
