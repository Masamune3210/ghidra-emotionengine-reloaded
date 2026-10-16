// Recover only the established 0x28-byte GXEMU UART transfer cursor layout.
// @category PS3.PS2Emulation
// Ghidra 12.1.x: ps2_gxemu.elf PowerPC:BE:64:A2ALT.
// Depends on RecoverPs3GxemuVuartControlFunctions_20261016_v1.
// Conservative: bytes, function signatures, code, existing user data and
// uncertain descriptor formats are left unchanged. Type layout is derived
// from independent 16-byte copy and segment-advance decompilation.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class DefinePs3GxemuVuartTransferCursor_20261016_v1 extends GhidraScript {
    private static final boolean APPLY=true;
    private static final long TOC=0x00678548L;
    private static final long CURSOR_PTR_SLOT=0x00677768L; // TOC - 0xDE0
    private static final long[][] REQUIRED={
        {0x0024FD08L,0x0025030BL,0x00670488L},
        {0x0025030CL,0x002506ABL,0x006704A0L},
        {0x00250978L,0x00250C83L,0x00670500L}
    };
    private Address at(long x){
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(x);
    }
    private boolean guard()throws Exception{
        if(currentProgram==null||
          !"PowerPC:BE:64:A2ALT".equals(currentProgram.getLanguageID().toString())||
          !currentProgram.getName().contains("ps2_gxemu"))return false;
        for(long[] t:REQUIRED){
            if(currentProgram.getMemory().getLong(at(t[2]))!=t[0]||
               currentProgram.getMemory().getLong(at(t[2]+8))!=TOC||
               currentProgram.getMemory().getLong(at(t[2]+16))!=0)return false;
            Function f=currentProgram.getFunctionManager().getFunctionAt(at(t[0]));
            if(f==null||f.getBody().getMinAddress().getOffset()!=t[0]||
               f.getBody().getMaxAddress().getOffset()!=t[1])return false;
        }
        return true;
    }
    private Structure addCursorType()throws Exception{
        String path="/PS3/GXEMU/GxemuVuartTransferCursor";
        DataType existing=currentProgram.getDataTypeManager().getDataType(path);
        if(existing!=null){
            if(!(existing instanceof Structure)||existing.getLength()!=0x28){
                println("REFUSE existing datatype has different layout: "+existing);
                return null;
            }
            Structure s=(Structure)existing;
            String[] names={"byteOffset","byteLimit","currentSegmentOrdinal",
                            "nextSegmentOrdinal","segmentDescriptorAddress"};
            for(int i=0;i<5;i++){
                ghidra.program.model.data.DataTypeComponent member=s.getComponentAt(i*8);
                if(member==null||member.getOffset()!=i*8||member.getLength()!=8||
                   !member.getDataType().isEquivalent(QWordDataType.dataType)||
                   !names[i].equals(member.getFieldName())){
                    println("REFUSE existing 0x28 structure is not equivalent at offset 0x"+
                            Integer.toHexString(i*8));return null;
                }
            }
            println("CURSOR_DATATYPE_PRESERVED "+path+" size=0x28");
            return s;
        }
        StructureDataType s=new StructureDataType(new CategoryPath("/PS3/GXEMU"),
                                                   "GxemuVuartTransferCursor",0);
        s.add(QWordDataType.dataType,"byteOffset",
              "BE uint64 cursor; incremented by 0x10 for each transferred chunk");
        s.add(QWordDataType.dataType,"byteLimit",
              "BE uint64 limit; state transition when byteOffset >= byteLimit");
        s.add(QWordDataType.dataType,"currentSegmentOrdinal",
              "BE uint64 segment ordinal, written during segment advance and copied to packet header");
        s.add(QWordDataType.dataType,"nextSegmentOrdinal",
              "BE uint64 next ordinal; high word cleared, low word written by segment advance");
        s.add(QWordDataType.dataType,"segmentDescriptorAddress",
              "BE uint64 pointer to a chain of 0x10-byte descriptors; descriptor +4 low two flag bits tested");
        if(s.getLength()!=0x28)throw new IllegalStateException("Unexpected cursor size");
        println("CURSOR_LAYOUT_OBSERVED size=0x28");
        if(!APPLY)return s;
        DataType result=currentProgram.getDataTypeManager().addDataType(s,
                                             DataTypeConflictHandler.KEEP_HANDLER);
        if(!(result instanceof Structure)||result.getLength()!=0x28){
            println("REFUSE created data type mismatch "+result);return null;
        }
        println("CURSOR_DATATYPE_CREATED "+result.getPathName()+" size=0x28");
        return (Structure)result;
    }
    private void placeRuntimeData(Structure cursor)throws Exception{
        long raw=currentProgram.getMemory().getLong(at(CURSOR_PTR_SLOT));
        println(String.format("CURSOR_POINTER_SLOT 0x%08X -> 0x%016X",CURSOR_PTR_SLOT,raw));
        if(raw==0||raw>Long.MAX_VALUE-0x27){
            println("RUNTIME_INSTANCE_REFUSED invalid pointer");return;
        }
        Address target;
        try{target=at(raw);}catch(Exception e){
            println("RUNTIME_INSTANCE_REFUSED address space "+e.getMessage());return;
        }
        MemoryBlock first=currentProgram.getMemory().getBlock(target);
        MemoryBlock last=currentProgram.getMemory().getBlock(at(raw+0x27L));
        if(first==null||first!=last||!first.isWrite()||first.isExecute()){
            println("RUNTIME_INSTANCE_REFUSED no single writable/nonexecutable mapped block for "+
                    target+".."+at(raw+0x27));return;
        }
        Data old=currentProgram.getListing().getDefinedDataAt(target);
        if(old!=null&&!old.getDataType().isEquivalent(cursor)){
            println("RUNTIME_INSTANCE_PRESERVED existing datatype "+old.getDataType());
            return;
        }
        if(old!=null){
            println("RUNTIME_INSTANCE_ALREADY_TYPED "+target);
        }else if(APPLY){
            try{
                DataUtilities.createData(currentProgram,target,cursor,0x28,
                    DataUtilities.ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
                println("RUNTIME_INSTANCE_TYPED "+target+" GxemuVuartTransferCursor");
            }catch(Exception e){
                println("RUNTIME_INSTANCE_TYPE_REFUSED "+target+" "+e.getMessage());
                return;
            }
        }else println("RUNTIME_INSTANCE_PROPOSED "+target);
        Symbol sym=currentProgram.getSymbolTable().getPrimarySymbol(target);
        if(sym==null||sym.getSource()==SourceType.DEFAULT){
            if(APPLY){
                try{
                    currentProgram.getSymbolTable().createLabel(target,
                         "gVuartTransferCursor",SourceType.USER_DEFINED);
                    println("RUNTIME_INSTANCE_LABELED "+target+" -> gVuartTransferCursor");
                }catch(Exception e){
                    println("RUNTIME_INSTANCE_LABEL_REFUSED "+e.getMessage());
                }
            }
        }else println("RUNTIME_INSTANCE_LABEL_PRESERVED "+sym.getName());
    }
    @Override public void run()throws Exception{
        if(!guard()){
            printerr("REFUSE: expected recovered GXEMU cursor functions and matching PPC64 descriptors");
            return;
        }
        println("GXEMU_TRANSFER_CURSOR_V1 APPLY="+APPLY);
        Structure cursor=addCursorType();
        if(cursor==null)return;
        placeRuntimeData(cursor);
        println("DONE: cursor layout only; no unknown descriptor fields, signatures, TOC contexts or bytes changed.");
    }
}
