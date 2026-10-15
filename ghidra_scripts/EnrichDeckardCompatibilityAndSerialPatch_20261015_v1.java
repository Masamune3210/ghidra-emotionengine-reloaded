// Comprehensive metadata pass for SCPH-79001 DECKARD + DPATCH.
// Verifies original firmware bytes AND all 18 ROM parameter records before
// creating any datatypes, functions, globals, labels or comments.
// Does not change firmware bytes, clear existing code/data, or create runtime-only
// branch references. Idempotent; preserves analyst-defined names and types.
//@category PS2.DECKARD
import java.util.Locale;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class EnrichDeckardCompatibilityAndSerialPatch_20261015_v1 extends GhidraScript {
    private static final long BASE_RECORDS = 0x00a0f14cL;
    private static final int COUNT = 18;
    private static final String MARKER = "DECKARD VERIFIED COMPAT/SERIAL: ";
    private static final CategoryPath CATEGORY = new CategoryPath("/DECKARD");

    private static class ParameterRecord {
        final String identifier;
        final int defaultValue;
        final String firmwareName;
        final long namePointer;
        ParameterRecord(String identifier, int defaultValue, String firmwareName,
                        long namePointer) {
            this.identifier = identifier;
            this.defaultValue = defaultValue;
            this.firmwareName = firmwareName;
            this.namePointer = namePointer;
        }
    }

    private static final ParameterRecord[] PARAMETERS = {
        new ParameterRecord("MdecDelayCycle", 500, "PARAM_MDEC_DELAY_CYCLE", 0x00a0ef3cL),
        new ParameterRecord("SpuInterruptDelayLimit", 2000, "PARAM_SPU_INT_DELAY_LIMIT", 0x00a0ef54L),
        new ParameterRecord("SpuInterruptDelayPpcCoefficient", 35, "PARAM_SPU_INT_DELAY_PPC_COEFF", 0x00a0ef70L),
        new ParameterRecord("Spu2InterruptDelayLimit", 2000, "PARAM_SPU2_INT_DELAY_LIMIT", 0x00a0ef90L),
        new ParameterRecord("Spu2InterruptDelayPpcCoefficient", 20, "PARAM_SPU2_INT_DELAY_PPC_COEFF", 0x00a0efacL),
        new ParameterRecord("DmacChannel10InterruptDelay", 0, "PARAM_DMAC_CH10_INT_DELAY", 0x00a0efccL),
        new ParameterRecord("CpuDelay", 1, "PARAM_CPU_DELAY", 0x00a0efe8L),
        new ParameterRecord("SpuDmaWaitLimit", 32, "PARAM_SPU_DMA_WAIT_LIMIT", 0x00a0eff8L),
        new ParameterRecord("GpuDmaWaitLimit", 0, "PARAM_GPU_DMA_WAIT_LIMIT", 0x00a0f014L),
        new ParameterRecord("DmacChannel10InterruptDelayDpc", 0, "PARAM_DMAC_CH10_INT_DELAY_DPC", 0x00a0f030L),
        new ParameterRecord("CpuDelayDpc", 0, "PARAM_CPU_DELAY_DPC", 0x00a0f050L),
        new ParameterRecord("UsbDelayedInterruptEnable", 0, "PARAM_USB_DELAYED_INT_ENABLE", 0x00a0f064L),
        new ParameterRecord("TimerLoadDelay", 0, "PARAM_TIMER_LOAD_DELAY", 0x00a0f084L),
        new ParameterRecord("Sio0DtrSckDelay", 8860, "PARAM_SIO0_DTR_SCK_DELAY", 0x00a0f09cL),
        new ParameterRecord("Sio0DsrSckDelayC", 1772, "PARAM_SIO0_DSR_SCK_DELAY_C", 0x00a0f0b8L),
        new ParameterRecord("Sio0DsrSckDelayM", 1772, "PARAM_SIO0_DSR_SCK_DELAY_M", 0x00a0f0d4L),
        new ParameterRecord("MipsDcacheOn", 1, "PARAM_MIPS_DCACHE_ON", 0x00a0f0f0L),
        new ParameterRecord("CacheFlashChannels", 144, "PARAM_CACHE_FLASH_CHANNELS", 0x00a0f108L)
    };

    private static final long[][] REQUIRED = {
        {0x00a0c7c4L, 0x2c03ffffL},
        {0x00a0c7f0L, 0x2c03ffffL},
        {0x00a0c800L, 0x2b030011L},
        {0x00a0c82cL, 0x7c8b012eL},
        {0x00a0c850L, 0x40beffe4L},
        {0x00a0c860L, 0x4b5f0f10L},
        {0x00a0c864L, 0x9421ffe8L},
        {0x00a0c870L, 0x38000012L},
        {0x00a0c8c0L, 0x38e90a30L},
        {0x00a0c8d4L, 0x81690008L},
        {0x00a0c908L, 0x4bfffee9L},
        {0x00a0c948L, 0x28030011L},
        {0x00a0c95cL, 0x7c83492eL},
        {0x00a0c964L, 0x9421fff8L},
        {0x00a0c970L, 0x4bfffef5L},
        {0x00a0b1b0L, 0x4bfffde1L},
        {0x00a0af90L, 0x70600002L},
        {0x00a0af9cL, 0x396a07a8L},
        {0x00a0afa4L, 0x992b000bL},
        {0x00a0afccL, 0xb069000cL},
        {0x00a0b034L, 0x396a07a8L},
        {0x00a0b084L, 0x3d2000beL},
        {0x00a0b0a8L, 0x39600006L},
        {0xffffd09cL, 0x3c60ffffL},
        {0xffffd1f8L, 0x3c60ffffL},
        {0xffffd2f4L, 0x3c60ffffL},
        {0xffffd3b4L, 0x3c60ffffL},
        {0xffffd494L, 0x3c60ffffL},
        {0xffffd5a4L, 0x3c6000a0L},
        {0xffffd5c8L, 0x48000178L},
        {0xffffd5ecL, 0x70600002L},
        {0xffffd600L, 0x992b000bL},
        {0xffffd620L, 0x7d2c42e6L},
        {0xffffd638L, 0xa00b000cL},
        {0xffffd65cL, 0x812a07a8L},
        {0xffffd66cL, 0x4180fff4L},
        {0xffffd6bcL, 0x3d2000beL},
        {0xffffd6c0L, 0x81690a14L},
        {0xffffd6d0L, 0x7c005840L},
        {0xffffd708L, 0x812a07a8L},
        {0xffffd714L, 0x2800167fL},
        {0xffffd740L, 0x3d6000a1L},
        {0xffffd760L, 0x912bb1b0L},
        {0xffffd770L, 0x9421ff98L},
        {0xffffd7bcL, 0x7c0a402eL},
        {0xffffd7ecL, 0x48a0f005L}
    };

    private static class Target {
        final long address;
        final String name;
        final boolean returnsValue;
        final int parameterCount;
        final boolean firstEnum;
        final boolean callbackSecond;
        Target(long address, String name, boolean returnsValue, int parameterCount,
               boolean firstEnum, boolean callbackSecond) {
            this.address=address; this.name=name; this.returnsValue=returnsValue;
            this.parameterCount=parameterCount; this.firstEnum=firstEnum;
            this.callbackSecond=callbackSecond;
        }
    }

    private static final Target[] FUNCTIONS = {
        new Target(0x00a0c7c4L,"GetCompatibilityParameterValue",true,1,false,false),
        new Target(0x00a0c7f0L,"SetCompatibilityParameterValue",false,2,false,false),
        new Target(0x00a0c864L,"InitializeCompatibilityParameterValues",false,0,false,false),
        new Target(0x00a0c948L,"RegisterCompatibilityParameterCallback",false,2,true,true),
        new Target(0x00a0c964L,"InitializeCompatibilityAndReportReady",true,0,false,false),
        new Target(0x00a0af90L,"UpdateSerialControlState",false,1,false,false),
        new Target(0xffffd5ecL,"UpdateSerialControlStateWithTiming",false,1,false,false),
        new Target(0xffffd770L,"RestoreCompatibilityParameterDefaults",false,0,false,false),
        new Target(0xffffd09cL,"InstallRuntimePatchMode1",false,0,false,false),
        new Target(0xffffd1f8L,"InstallRuntimePatchMode2",false,0,false,false),
        new Target(0xffffd2f4L,"InstallRuntimePatchMode3",false,0,false,false),
        new Target(0xffffd3b4L,"InstallRuntimePatchMode4",false,0,false,false),
        new Target(0xffffd494L,"InstallRuntimePatchMode5",false,0,false,false),
        new Target(0xffffd5a4L,"InstallRuntimePatchMode6",false,0,false,false),
        new Target(0xffffd5c8L,"InstallRuntimePatchMode7",false,0,false,false),
        new Target(0xffffd740L,"WriteRuntimePatchMode7Branch",false,0,false,false)
    };

    private int labels, comments, createdFunctions, namedFunctions;
    private int signatureChanges, typedGlobals, createdDatatypes;
    private int preserved;

    private long read32(long absolute) throws Exception {
        Memory memory=currentProgram.getMemory();
        Address address=toAddr(absolute);
        byte[] bytes=new byte[4];
        if (!memory.contains(address) || memory.getBytes(address,bytes)!=4)
            throw new IllegalStateException("Unreadable "+address);
        return Integer.toUnsignedLong(
            ((bytes[0]&255)<<24)|((bytes[1]&255)<<16)|
            ((bytes[2]&255)<<8)|(bytes[3]&255));
    }

    private String readCString(long absolute) throws Exception {
        Memory memory=currentProgram.getMemory();
        StringBuilder value=new StringBuilder();
        for (int index=0; index<80; index++) {
            Address address=toAddr(absolute+index);
            if (!memory.contains(address)) throw new IllegalStateException("Unmapped string");
            int b=memory.getByte(address)&255;
            if (b==0) return value.toString();
            if (b<32 || b>126) throw new IllegalStateException("Non-ASCII string");
            value.append((char)b);
        }
        throw new IllegalStateException("Unterminated string");
    }

    private boolean validate() throws Exception {
        if (!"PowerPC:BE:32:DECKARD".equals(currentProgram.getLanguageID().toString()) ||
            !"DECKARD.elf".equalsIgnoreCase(currentProgram.getName())) {
            printerr("ABORT: expected combined DECKARD.elf / PowerPC:BE:32:DECKARD");
            return false;
        }
        Memory memory=currentProgram.getMemory();
        MemoryBlock patch=memory.getBlock(toAddr(0xffffd000L));
        if (patch==null || !patch.isInitialized() ||
            patch.getEnd().getOffset()<0xffffd823L) {
            printerr("ABORT: complete DPATCH at 0xFFFFD000..0xFFFFD823 required");
            return false;
        }
        int errors=0;
        for (long[] pair:REQUIRED) {
            long observed;
            try { observed=read32(pair[0]); }
            catch (Exception e) {
                println("INVALID ANCHOR 0x"+Long.toHexString(pair[0])+": "+e.getMessage());
                errors++; continue;
            }
            if (observed!=pair[1]) {
                println(String.format(Locale.ROOT,
                    "MISMATCH 0x%08x expected=0x%08x actual=0x%08x",
                    pair[0],pair[1],observed));
                errors++;
            }
        }
        for (int i=0;i<COUNT;i++) {
            ParameterRecord p=PARAMETERS[i];
            long entry=BASE_RECORDS+i*12L;
            try {
                long id=read32(entry);
                long value=read32(entry+4);
                long name=read32(entry+8);
                if (id!=i || value!=p.defaultValue ||
                    name!=p.namePointer || !p.firmwareName.equals(readCString(name))) {
                    println("BAD PARAM "+i+" id="+id+" value="+value+
                        " nameAddr=0x"+Long.toHexString(name));
                    errors++;
                }
            }
            catch (Exception e) {
                println("BAD PARAM "+i+": "+e.getMessage());
                errors++;
            }
        }
        if (errors!=0) {
            printerr("ABORT: "+errors+" firmware anchors/records failed, nothing applied");
            return false;
        }
        println("PASS: "+REQUIRED.length+" instruction anchors, "+
            COUNT+" parameter IDs/defaults/strings, complete DPATCH.");
        return true;
    }

    private DataType ensureEnum() {
        DataTypeManager manager=currentProgram.getDataTypeManager();
        EnumDataType wanted=new EnumDataType(CATEGORY,
            "DeckardCompatibilityParameterId",4);
        for (int i=0;i<COUNT;i++)
            wanted.add(PARAMETERS[i].identifier,i,PARAMETERS[i].firmwareName);
        DataType previous=manager.getDataType(CATEGORY,wanted.getName());
        if (previous!=null) {
            if (!previous.isEquivalent(wanted)) {
                println("PRESERVE conflicting enum: "+previous.getPathName());
                preserved++; return null;
            }
            return previous;
        }
        createdDatatypes++;
        return manager.addDataType(wanted,DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private DataType ensureCallback(DataType enumType) {
        if (enumType==null) return null;
        DataTypeManager manager=currentProgram.getDataTypeManager();
        FunctionDefinitionDataType wanted=new FunctionDefinitionDataType(
            CATEGORY,"DeckardCompatibilityValueCallback");
        wanted.setReturnType(VoidDataType.dataType);
        wanted.setArguments(
            new ParameterDefinitionImpl("parameterId",enumType,null),
            new ParameterDefinitionImpl("newValue",UnsignedIntegerDataType.dataType,null)
        );
        DataType previous=manager.getDataType(CATEGORY,wanted.getName());
        if (previous!=null) {
            if (!previous.isEquivalent(wanted)) {
                println("PRESERVE conflicting callback type "+previous.getPathName());
                preserved++; return null;
            }
            return previous;
        }
        createdDatatypes++;
        return manager.addDataType(wanted,DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private DataType ensureSerialView() {
        DataTypeManager manager=currentProgram.getDataTypeManager();
        StructureDataType state=new StructureDataType(CATEGORY,
            "DeckardSerialTimingStateView",0,manager);
        DataType u32=UnsignedIntegerDataType.dataType;
        DataType b=ByteDataType.dataType;
        state.add(u32,4,"referenceTicks0","Timebase value at +0x00");
        state.add(u32,4,"referenceTicks1","Additional timebase value at +0x04");
        state.add(b,1,"phaseCode","State-machine byte at +0x08");
        state.add(b,1,"phaseCounter","Transition/counter byte at +0x09");
        state.add(b,1,"lastDataByte","Serial data byte at +0x0A");
        state.add(b,1,"controlFlag","Control flag byte at +0x0B");
        state.add(UnsignedShortDataType.dataType,2,"controlBits",
            "16-bit control mask at +0x0C");
        state.add(b,1,"controlNibble","Extracted bits at +0x0E");
        if (state.getLength()!=15) throw new IllegalStateException("Bad state layout");
        DataType previous=manager.getDataType(CATEGORY,state.getName());
        if (previous!=null) {
            if (!previous.isEquivalent(state)) {
                println("PRESERVE conflicting serial state "+previous.getPathName());
                preserved++; return null;
            }
            return previous;
        }
        createdDatatypes++;
        return manager.addDataType(state,DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private void label(long absolute,String name) {
        Address at=toAddr(absolute);
        if (!currentProgram.getMemory().contains(at)) {
            println("SKIP UNMAPPED LABEL "+at+" "+name);
            preserved++; return;
        }
        for (Symbol symbol:currentProgram.getSymbolTable().getSymbols(at))
            if (name.equals(symbol.getName())) return;
        try {
            currentProgram.getSymbolTable().createLabel(at,name,SourceType.ANALYSIS);
            labels++;
        }
        catch(Exception e) {
            println("PRESERVE SYMBOL "+at+": "+e.getMessage());
            preserved++;
        }
    }

    private void note(long absolute,String detail) {
        Address at=toAddr(absolute);
        Listing listing=currentProgram.getListing();
        String old=listing.getComment(CommentType.PRE,at);
        if (old!=null && old.contains(MARKER)) return;
        listing.setComment(at,CommentType.PRE,
            old==null || old.isEmpty() ? MARKER+detail : old+"\n"+MARKER+detail);
        comments++;
    }

    private void declareIfUndefined(long absolute, DataType datatype,
                                    int length, String description) {
        if (datatype==null) return;
        Address start=toAddr(absolute), end=start.add(length-1);
        if (!currentProgram.getMemory().contains(start) ||
            !currentProgram.getMemory().contains(end)) {
            println("PRESERVE UNMAPPED DATA "+start);
            preserved++; return;
        }
        Listing listing=currentProgram.getListing();
        for (int n=0;n<length;n++) {
            Address at=start.add(n);
            if (listing.getInstructionContaining(at)!=null ||
                listing.getDefinedDataContaining(at)!=null) {
                println("PRESERVE existing data/code "+start+" "+description+
                    " conflictAt="+at);
                preserved++; return;
            }
        }
        try {
            listing.createData(start,datatype);
            typedGlobals++;
            println("TYPED "+start+" "+description);
        }
        catch(Exception e) {
            println("PRESERVE data declaration "+start+": "+e.getMessage());
            preserved++;
        }
    }

    private DataType[] typesFor(Target target,DataType enumType,DataType callbackPtr) {
        DataType u32=UnsignedIntegerDataType.dataType;
        DataType[] a=new DataType[target.parameterCount];
        for (int i=0;i<a.length;i++) {
            if (i==0 && target.firstEnum && enumType!=null) a[i]=enumType;
            else if (i==1 && target.callbackSecond && callbackPtr!=null)
                a[i]=callbackPtr;
            else a[i]=u32;
        }
        return a;
    }

    private String[] namesFor(Target target) {
        if (target.parameterCount==0) return new String[0];
        if (target.callbackSecond) return new String[] {"parameterId","callback"};
        if (target.parameterCount==2) return new String[] {"parameterId","newValue"};
        return new String[] {target.name.contains("Serial") ? "controlWord" : "parameterId"};
    }

    private void function(Target target,DataType enumType,DataType callbackPointer) {
        Address at=toAddr(target.address);
        Listing listing=currentProgram.getListing();
        Function existing=getFunctionAt(at);
        Function containing=getFunctionContaining(at);
        if (existing==null) {
            if (containing!=null) {
                println("PRESERVE FUNCTION "+at+" already contained in "+
                    containing.getName());
                preserved++; return;
            }
            Instruction ins=listing.getInstructionAt(at);
            if (ins==null) {
                println("PRESERVE FUNCTION "+at+": instruction not disassembled");
                preserved++; return;
            }
            existing=createFunction(at,target.name);
            if (existing==null) {
                println("PRESERVE FUNCTION "+at+": creation refused");
                preserved++; return;
            }
            createdFunctions++;
        }
        else if (existing.getName().startsWith("FUN_") &&
                 existing.getSymbol().getSource()!=SourceType.USER_DEFINED) {
            try {
                existing.setName(target.name,SourceType.ANALYSIS);
                namedFunctions++;
            }
            catch (Exception e) {
                println("PRESERVE FUNCTION NAME "+at+": "+e.getMessage());
            }
        }

        if (existing.hasCustomVariableStorage() ||
            existing.getSignatureSource()==SourceType.USER_DEFINED) {
            println("PRESERVE USER SIGNATURE "+at+" "+
                existing.getPrototypeString(false,false));
            preserved++; return;
        }

        DataType wantedReturn=target.returnsValue ?
            UnsignedIntegerDataType.dataType : VoidDataType.dataType;
        DataType[] wantedArgs=typesFor(target,enumType,callbackPointer);
        String[] wantedNames=namesFor(target);

        try {
            if (existing.getParameterCount()==0 &&
                target.parameterCount>0 &&
                existing.getSignatureSource()==SourceType.DEFAULT) {
                Variable[] params=new Variable[target.parameterCount];
                for (int i=0;i<params.length;i++)
                    params[i]=new ParameterImpl(wantedNames[i],wantedArgs[i],currentProgram);
                existing.updateFunction(null,
                    new ReturnParameterImpl(wantedReturn,currentProgram),
                    FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    false,SourceType.ANALYSIS,params);
                signatureChanges++;
            }
            else {
                if (existing.getParameterCount()!=target.parameterCount) {
                    println("PRESERVE PARAMETER COUNT "+at+" "+
                        existing.getParameterCount()+" != "+target.parameterCount);
                    preserved++;
                }
                else {
                    for (int i=0;i<wantedArgs.length;i++) {
                        Parameter p=existing.getParameter(i);
                        if (p==null) continue;
                        if (Undefined.isUndefined(p.getDataType())) {
                            try {
                                p.setDataType(wantedArgs[i],SourceType.ANALYSIS);
                                signatureChanges++;
                            }
                            catch(Exception e) {
                                println("PRESERVE PARAMETER TYPE "+at+" "+e.getMessage());
                            }
                        }
                        if (p.getName()!=null &&
                            p.getName().matches("param_[0-9]+") &&
                            p.getSymbol()!=null &&
                            p.getSymbol().getSource()!=SourceType.USER_DEFINED) {
                            try {
                                p.setName(wantedNames[i],SourceType.ANALYSIS);
                                signatureChanges++;
                            }
                            catch(Exception e) {
                                println("PRESERVE PARAMETER NAME "+at+" "+e.getMessage());
                            }
                        }
                    }
                }
                if (Undefined.isUndefined(existing.getReturnType())) {
                    try {
                        existing.setReturnType(wantedReturn,SourceType.ANALYSIS);
                        signatureChanges++;
                    }
                    catch(Exception e) {
                        println("PRESERVE RETURN TYPE "+at+" "+e.getMessage());
                    }
                }
            }
        }
        catch(Exception e) {
            println("PRESERVE SIGNATURE "+at+": "+e.getMessage());
            preserved++;
        }
        println("FUNCTION "+at+" "+existing.getPrototypeString(false,false));
    }

    @Override
    protected void run() throws Exception {
        if (!validate()) return;

        // Dependency order: enum -> callback definition -> state structure ->
        // storage declarations -> function signatures -> comments.
        DataType parameterId=ensureEnum();
        DataType callback=ensureCallback(parameterId);
        DataType serial=ensureSerialView();
        DataTypeManager manager=currentProgram.getDataTypeManager();
        DataType u32=UnsignedIntegerDataType.dataType;

        DataType callbackPointer=callback==null ? null :
            new PointerDataType(callback,4,manager);

        // .bss compatibility arrays (18 elements, indexed by id*4).
        label(0x00be09e0L,"CompatibilityLiveValues");
        label(0x00be0a28L,"CompatibilityControlWord0");
        label(0x00be0a2cL,"CompatibilityControlWord1");
        label(0x00be0a30L,"CompatibilityBootDefaults");
        label(0x00be0a78L,"CompatibilityCallbackPointers");
        label(0x00be07a8L,"SerialControlTimingState");

        declareIfUndefined(0x00be09e0L,new ArrayDataType(u32,COUNT,4),
            COUNT*4,"compatibility live values[18]");
        declareIfUndefined(0x00be0a28L,u32,4,"compatibility control word 0");
        declareIfUndefined(0x00be0a2cL,u32,4,"compatibility control word 1");
        declareIfUndefined(0x00be0a30L,new ArrayDataType(u32,COUNT,4),
            COUNT*4,"compatibility initialized defaults[18]");
        if (callbackPointer!=null)
            declareIfUndefined(0x00be0a78L,
                new ArrayDataType(callbackPointer,COUNT,4),
                COUNT*4,"compatibility callback pointer[18]");
        if (serial!=null)
            declareIfUndefined(0x00be07a8L,serial,15,
                "serial timing state partial view, 0x0f bytes");

        for (int i=0;i<COUNT;i++) {
            ParameterRecord p=PARAMETERS[i];
            long at=BASE_RECORDS+i*12L;
            label(at,"CompatDefault_"+p.identifier);
            label(p.namePointer,"CompatString_"+p.identifier);
            note(at,"Parameter "+i+" "+p.firmwareName+
                " default="+p.defaultValue+"; data record 12 bytes; "+
                "live value at 0x"+Long.toHexString(0x00be09e0L+i*4L)+
                ", boot default at 0x"+Long.toHexString(0x00be0a30L+i*4L)+
                ", callback at 0x"+Long.toHexString(0x00be0a78L+i*4L)+".");
        }

        for (Target t:FUNCTIONS) function(t,parameterId,callbackPointer);

        note(0x00a0c7c4L,
            "Reads live 32-bit compatibility parameter by 0..17 index "+
            "from 0x00BE09E0. Returns 0 for -1 and out-of-range indices.");
        note(0x00a0c7f0L,
            "Setter for live parameter values at 0x00BE09E0[id]. "+
            "If callback[ id ] at 0x00BE0A78 is nonzero, calls it with "+
            "r3=id, r4=newValue. Special (-1,0) branches to "+
            "0xFFFFD770 to restore defaults. Out-of-range writes skipped.");
        note(0x00a0c860L,
            "Runtime patch redirect: SetCompatibilityParameterValue(-1,0) "+
            "tail-branches into DPATCH default restoration at 0xFFFFD770.");
        note(0x00a0c864L,
            "Base firmware initializer: clears three 18-entry word arrays, "+
            "loads defaults/IDs from 0x00A0F14C, invokes setter 18 times, "+
            "and clears 0x00BE0A28 / 0x00BE0A2C.");
        note(0x00a0c948L,
            "Stores per-ID callback pointers into 0x00BE0A78[parameterId]. "+
            "Valid id range is 0..17; r4 holds callback address.");
        note(0x00a0c964L,
            "Calls compatibility initializer at 0x00A0C864 and returns 1.");
        note(0xffffd770L,
            "DPATCH alternate defaults-restorer called by setter special "+
            "(-1,0). Uses table 0x00A0F14C and invokes setter "+
            "at 0x00A0C7F0 for 18 IDs.");
        note(0x00be09e0L,
            "Mutable compatibility parameter values, uint32_t[18]; "+
            "index 13 is PARAM_SIO0_DTR_SCK_DELAY.");
        note(0x00be0a30L,
            "18 boot defaults staged from record default values "+
            "at 0x00A0F14C, not independent parameter names.");
        note(0x00be0a78L,
            "18 callback function pointers. The setter invokes "+
            "nonzero callbacks through mtLR / blrl.");
        note(0x00be07a8L,
            "Partial serial-state view: tick words at +0/+4, phase at +8, "+
            "counter at +9, data byte at +A, flag at +B, "+
            "control halfword at +C, control bits at +E. "+
            "Only 0x0F bytes declared; do not assume ownership of +F.");
        note(0x00a0af90L,
            "Original serial-control state update reached by call "+
            "at 0x00A0B1B0. DPATCH mode 7 rewrites that call to "+
            "0xFFFFD5EC, adding timebase-based waits.");
        note(0x00a0b1b0L,
            "ROM has relative bl 0x00A0AF90. Mode 7 changes instruction "+
            "to 0x4B5F243D at runtime, relative bl to 0xFFFFD5EC. "+
            "Static bytes and references must remain unchanged.");
        note(0xffffd5ecL,
            "Mode 7 replacement for original serial update. Decodes control "+
            "bits, changes serial phase byte at 0x00BE07B0 and reads timebase. "+
            "Timing gate at 0xFFFFD6C0 loads live parameter 13 "+
            "from 0x00BE0A14 (SIO0_DTR_SCK_DELAY).");
        note(0xffffd620L,
            "Timebase read initializes timing word 0x00BE07A8; "+
            "the control halfword is stored at 0x00BE07B4.");
        note(0xffffd65cL,
            "Waits while elapsed PPC timebase ticks are below 5759; "+
            "state transitions occur after this wait.");
        note(0xffffd6bcL,
            "Only in phase 5 with required flag: reads live "+
            "compatibility parameter 13 from 0x00BE0A14 and waits "+
            "for that many PPC timebase ticks before transition.");
        note(0xffffd708L,
            "Second timebase delay loop uses threshold 5759 ticks "+
            "before returning to the serial state machine.");
        note(0xffffd740L,
            "Installs runtime relative bl to serial timing handler "+
            "0xFFFFD5EC at main code 0x00A0B1B0, icbi and isync.");
        note(0xffffd5c8L,
            "Patch mode 7 dispatcher entry tail-branches into installer "+
            "at 0xFFFFD740.");
        note(0x00a0c8c0L,
            "InitializeCompatibilityParameterValues copies parameter "+
            "name pointers from default table into boot-default bookkeeping? "+
            "VERIFY before refining individual array-element semantics.");

        println("DECKARD COMPAT/SERIAL PASS: enum+callback+stateTypes="+
            createdDatatypes+" newFunctions="+createdFunctions+
            " renamedFunctions="+namedFunctions+
            " signatureChanges="+signatureChanges+" typedGlobals="+typedGlobals+
            " labels="+labels+" comments="+comments+" preserved="+preserved);
        println("All writes were Ghidra metadata. Executable/data bytes unchanged.");
    }
}
