// SCPH-79001 DECKARD combined firmware: compatibility MMIO control,
// parameter 16 MIPS cache callback, boot-time overrides and DPATCH mode 7.
// Verify all 87 original instructions before applying metadata.
// Ghidra Script Manager; no extension rebuild or ELF/DPATCH byte modifications.
//@category PS2.DECKARD
import java.util.Locale;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.UnsignedIntegerDataType;
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

public class RecoverDeckardControlPlaneAndMode7_20261015_v1 extends GhidraScript {
    private static final CategoryPath CATEGORY = new CategoryPath("/DECKARD");
    private static final String PREFIX = "DECKARD CONTROL PLANE: ";
    private static final long MODE7 = 0xffffd5ecL;
    private static final int PATCH_LENGTH = 0x824;

    private static final long[][] EXPECTED = {
        {0x00a04cd4L, 0x9421fff8L},
        {0x00a04ce4L, 0x48007c81L},
        {0x00a04ce8L, 0x2c030000L},
        {0x00a04d04L, 0x48001ee9L},
        {0x00a05d0cL, 0x3800000aL},
        {0x00a05d18L, 0x392a000cL},
        {0x00a05d20L, 0x540005eaL},
        {0x00a05d30L, 0x60000200L},
        {0x00a05d40L, 0x7c00046cL},
        {0x00a05d64L, 0x7c100ba6L},
        {0x00a05da4L, 0x3800000aL},
        {0x00a05db0L, 0x392a0002L},
        {0x00a05db8L, 0x540005eaL},
        {0x00a05dc8L, 0x60000200L},
        {0x00a05dd8L, 0x7c00046cL},
        {0x00a05decL, 0x4e800020L},
        {0x00a05df0L, 0x3d2000beL},
        {0x00a05df4L, 0x80090a20L},
        {0x00a05df8L, 0x2c000000L},
        {0x00a05dfcL, 0x41820008L},
        {0x00a05e00L, 0x4bffff0cL},
        {0x00a05e04L, 0x4bffffa0L},
        {0x00a064c8L, 0x9421ffe8L},
        {0x00a064f0L, 0x546005feL},
        {0x00a065c0L, 0x2c000190L},
        {0x00a06624L, 0x2c0001a0L},
        {0x00a0662cL, 0x2c0001a4L},
        {0x00a06634L, 0x3d2000beL},
        {0x00a06638L, 0x80690400L},
        {0x00a06640L, 0x90890404L},
        {0x00a06644L, 0x480061adL},
        {0x00a0664cL, 0x3d2000beL},
        {0x00a06650L, 0x7c832378L},
        {0x00a06654L, 0x90890400L},
        {0x00a06658L, 0x4800616dL},
        {0x00a0665cL, 0x3d2000beL},
        {0x00a06660L, 0x90690404L},
        {0x00a06b38L, 0x3c8000a0L},
        {0x00a06b3cL, 0x38845df0L},
        {0x00a06b40L, 0x38600010L},
        {0x00a06b44L, 0x48005e05L},
        {0x00a06b48L, 0x38600010L},
        {0x00a06b4cL, 0x4bfff2a5L},
        {0x00a09c0cL, 0x9421ffe8L},
        {0x00a09cc8L, 0x808b0000L},
        {0x00a09cd4L, 0x901f001cL},
        {0x00a09ce0L, 0x38600000L},
        {0x00a09ce4L, 0x48002b0dL},
        {0x00a09cecL, 0x38600006L},
        {0x00a09cf4L, 0x48002afdL},
        {0x00a09cfcL, 0x38600007L},
        {0x00a09d04L, 0x48002aedL},
        {0x00a09d0cL, 0x38600008L},
        {0x00a09d14L, 0x48002addL},
        {0x00a09d1cL, 0x3860000cL},
        {0x00a09d24L, 0x48002acdL},
        {0x00a09d2cL, 0x38600010L},
        {0x00a09d34L, 0x48002abdL},
        {0x00a0c7c4L, 0x2c03ffffL},
        {0x00a0c7f0L, 0x2c03ffffL},
        {0x00a0c820L, 0x3d6000beL},
        {0x00a0c82cL, 0x7c8b012eL},
        {0x00a0c844L, 0x7d2803a6L},
        {0x00a0c848L, 0x4e800021L},
        {0x00a0c860L, 0x4b5f0f10L},
        {0x00a0c948L, 0x28030011L},
        {0x00a0af90L, 0x70600002L},
        {0x00a0b1b0L, 0x4bfffde1L},
        {0xffffd000L, 0x3c80ffffL},
        {0xffffd014L, 0x4e800420L},
        {0xffffd018L, 0xffffd098L},
        {0xffffd098L, 0x4e800020L},
        {0xffffd5c8L, 0x48000178L},
        {0xffffd5ccL, 0x3c0054a3L},
        {0xffffd5e8L, 0x4e800020L},
        {0xffffd5ecL, 0x70600002L},
        {0xffffd620L, 0x7d2c42e6L},
        {0xffffd634L, 0x4e800020L},
        {0xffffd638L, 0xa00b000cL},
        {0xffffd65cL, 0x812a07a8L},
        {0xffffd66cL, 0x4180fff4L},
        {0xffffd6c0L, 0x81690a14L},
        {0xffffd6d0L, 0x7c005840L},
        {0xffffd714L, 0x2800167fL},
        {0xffffd740L, 0x3d6000a1L},
        {0xffffd76cL, 0x4e800020L},
        {0xffffd770L, 0x9421ff98L}
    };

    private static final long[][] PRESET_CALLS = {
        {0x00a09ce0L, 0x00a09ce4L, 0},
        {0x00a09cecL, 0x00a09cf4L, 6},
        {0x00a09cfcL, 0x00a09d04L, 7},
        {0x00a09d0cL, 0x00a09d14L, 8},
        {0x00a09d1cL, 0x00a09d24L, 12},
        {0x00a09d2cL, 0x00a09d34L, 16}
    };

    private int comments, labels, datatypes, dataTyped;
    private int functionsCreated, functionsRenamed, signatureChanges, preserved;

    private long readU32(long address) throws Exception {
        Address at=toAddr(address);
        Memory memory=currentProgram.getMemory();
        byte[] raw=new byte[4];
        if (!memory.contains(at) || memory.getBytes(at,raw)!=4)
            throw new IllegalStateException("Unmapped or unreadable "+at);
        int value=((raw[0]&255)<<24)|((raw[1]&255)<<16)|
            ((raw[2]&255)<<8)|(raw[3]&255);
        return Integer.toUnsignedLong(value);
    }

    private boolean verify() throws Exception {
        if (!"PowerPC:BE:32:DECKARD".equals(currentProgram.getLanguageID().toString()) ||
            !"DECKARD.elf".equalsIgnoreCase(currentProgram.getName())) {
            printerr("ABORT: expected main DECKARD.elf with DECKARD PPC language");
            return false;
        }
        Memory memory=currentProgram.getMemory();
        MemoryBlock patch=memory.getBlock(toAddr(0xffffd000L));
        if (patch==null || !patch.isInitialized() ||
            patch.getEnd().getOffset()<0xffffd823L) {
            printerr("ABORT: complete original DPATCH at 0xFFFFD000..0xFFFFD823 required");
            return false;
        }
        int failures=0;
        for (long[] item:EXPECTED) {
            long actual;
            try { actual=readU32(item[0]); }
            catch(Exception e) {
                println("UNREADABLE "+Long.toHexString(item[0])+": "+e.getMessage());
                failures++; continue;
            }
            if (actual!=item[1]) {
                println(String.format(Locale.ROOT,
                    "WORD MISMATCH %08X expected=%08X actual=%08X",
                    item[0],item[1],actual));
                failures++;
            }
        }
        if (failures!=0) {
            printerr("ABORT: "+failures+" original instruction mismatches. Metadata untouched.");
            return false;
        }
        println("PASS: "+EXPECTED.length+" exact main+DPATCH words; "+
            PATCH_LENGTH+" mapped DPATCH bytes; no mismatches.");
        return true;
    }

    private void note(long address,String content) {
        Address at=toAddr(address);
        Listing list=currentProgram.getListing();
        String old=list.getComment(CommentType.PRE,at);
        if (old!=null && old.contains(PREFIX)) return;
        list.setComment(at,CommentType.PRE,
            old==null || old.isEmpty() ? PREFIX+content :
            old+"\n"+PREFIX+content);
        comments++;
    }

    private void label(long address,String name) {
        Address at=toAddr(address);
        if (!currentProgram.getMemory().contains(at)) {
            println("PRESERVE unmapped label "+at+" "+name);
            preserved++; return;
        }
        for (Symbol symbol:currentProgram.getSymbolTable().getSymbols(at))
            if (name.equals(symbol.getName())) return;
        try {
            currentProgram.getSymbolTable().createLabel(at,name,SourceType.ANALYSIS);
            labels++;
        }
        catch(Exception e) {
            println("PRESERVE label "+at+" "+name+": "+e.getMessage());
            preserved++;
        }
    }

    private DataType ensureMmioEnum() {
        DataTypeManager dtm=currentProgram.getDataTypeManager();
        EnumDataType e=new EnumDataType(CATEGORY,
            "DeckardCompatibilityMmioOffset",2);
        e.add("ParameterIndex",0x01a0);
        e.add("ParameterValue",0x01a4);
        DataType old=dtm.getDataType(CATEGORY,e.getName());
        if (old!=null) {
            if (!old.isEquivalent(e)) {
                println("PRESERVE conflicting enum: "+old.getPathName());
                preserved++; return null;
            }
            return old;
        }
        datatypes++;
        return dtm.addDataType(e,DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private DataType ensureMmioLatch() {
        DataTypeManager dtm=currentProgram.getDataTypeManager();
        StructureDataType s=new StructureDataType(CATEGORY,
            "DeckardCompatibilityMmioLatch",0,dtm);
        s.add(IntegerDataType.dataType,4,"selectedParameterId",
            "Parameter selector written via register offset 0x1A0, including -1 reset sentinel");
        s.add(UnsignedIntegerDataType.dataType,4,"lastValue",
            "Data read at 0x1A0 or written at 0x1A4");
        if (s.getLength()!=8) throw new IllegalStateException("Bad latch structure size");
        DataType old=dtm.getDataType(CATEGORY,s.getName());
        if (old!=null) {
            if (!old.isEquivalent(s)) {
                println("PRESERVE conflicting latch: "+old.getPathName());
                preserved++; return null;
            }
            return old;
        }
        datatypes++;
        return dtm.addDataType(s,DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private void declareIfUndefined(long address,DataType type,int count) {
        if (type==null) return;
        Address first=toAddr(address);
        Address last=first.add(count-1);
        if (!currentProgram.getMemory().contains(first) ||
            !currentProgram.getMemory().contains(last)) {
            println("PRESERVE unmapped data "+first);
            preserved++; return;
        }
        Listing list=currentProgram.getListing();
        for (int i=0;i<count;i++) {
            Address at=first.add(i);
            if (list.getInstructionContaining(at)!=null) {
                println("PRESERVE instruction in data range "+at);
                preserved++; return;
            }
            if (list.getDefinedDataContaining(at)!=null) {
                println("PRESERVE preexisting data at "+at+" ("+
                    list.getDefinedDataContaining(at).getDataType().getName()+")");
                preserved++; return;
            }
        }
        try {
            list.createData(first,type);
            dataTyped++;
        }
        catch(Exception e) {
            println("PRESERVE data at "+first+": "+e.getMessage());
            preserved++;
        }
    }

    private void renameIfDefault(long address,String name,boolean createOnlyIfCode) {
        Address at=toAddr(address);
        Function f=getFunctionAt(at);
        if (f==null && createOnlyIfCode) {
            Function inside=getFunctionContaining(at);
            if (inside==null &&
                currentProgram.getListing().getInstructionAt(at)!=null) {
                f=createFunction(at,name);
                if (f!=null) {
                    functionsCreated++;
                }
            }
        }
        if (f!=null && f.getName().startsWith("FUN_") &&
            f.getSymbol().getSource()!=SourceType.USER_DEFINED) {
            try {
                f.setName(name,SourceType.ANALYSIS);
                functionsRenamed++;
            }
            catch(Exception e) {
                println("PRESERVE function name "+at+": "+e.getMessage());
                preserved++;
            }
        }
        else if (f==null) {
            label(address,name);
            Function inside=getFunctionContaining(at);
            if (inside!=null) {
                println("PRESERVE function boundary "+at+
                    " (inside "+inside.getName()+"); address label only.");
            }
        }
    }

    private void refineReturnVoid(long address) {
        Function f=getFunctionAt(toAddr(address));
        if (f!=null && f.getSignatureSource()!=SourceType.USER_DEFINED &&
            !f.hasCustomVariableStorage() &&
            Undefined.isUndefined(f.getReturnType())) {
            try {
                f.setReturnType(VoidDataType.dataType,SourceType.ANALYSIS);
                signatureChanges++;
            }
            catch(Exception e) {
                println("PRESERVE return at "+f.getEntryPoint()+": "+e.getMessage());
            }
        }
    }

    private void refineCallbackRegistration() {
        Function function=getFunctionAt(toAddr(0x00a0c948L));
        if (function==null || function.getParameterCount()!=2 ||
            function.getSignatureSource()==SourceType.USER_DEFINED ||
            function.hasCustomVariableStorage()) return;
        DataType enumType=currentProgram.getDataTypeManager().getDataType(
            CATEGORY,"DeckardCompatibilityParameterId");
        if (enumType==null || enumType.getLength()!=4) return;
        Parameter p=function.getParameter(0);
        if (p==null || p.getSymbol()==null ||
            p.getSymbol().getSource()==SourceType.USER_DEFINED) return;
        DataType existing=p.getDataType();
        if (!Undefined.isUndefined(existing) &&
            !existing.isEquivalent(UnsignedIntegerDataType.dataType) &&
            !existing.isEquivalent(IntegerDataType.dataType)) return;
        try {
            if (!existing.isEquivalent(enumType)) {
                p.setDataType(enumType,SourceType.ANALYSIS);
                signatureChanges++;
                println("REFINED CALLBACK REGISTRATION "+
                    function.getPrototypeString(false,false));
            }
        }
        catch(Exception e) {
            println("PRESERVE callback index datatype: "+e.getMessage());
            preserved++;
        }
    }

    // Genuine independent code exists at 0xFFFFD5EC, but its caller only
    // exists AFTER the runtime patch at 0x00A0B1B0. Do not split a switch
    // function, remove defined data, or manufacture an original ROM branch.
    private void recoverMode7() throws Exception {
        Address start=toAddr(MODE7);
        Listing list=currentProgram.getListing();
        Function owner=getFunctionContaining(start);
        if (owner!=null && !owner.getEntryPoint().equals(start)) {
            println("PRESERVE MODE7: "+start+" lies in existing function "+
                owner.getName()+". Add label/comment only.");
            label(MODE7,"UpdateSerialControlStateWithTiming");
            note(MODE7,"Distinct entry from runtime-generated bl at 0x00A0B1B0. "+
                "Do not split the surrounding function automatically.");
            preserved++;
            return;
        }
        if (list.getDefinedDataContaining(start)!=null) {
            println("PRESERVE MODE7: existing defined data at "+start);
            preserved++; return;
        }
        Instruction instruction=list.getInstructionAt(start);
        if (instruction==null) {
            Instruction overlap=list.getInstructionContaining(start);
            if (overlap!=null && !overlap.getAddress().equals(start)) {
                println("PRESERVE MODE7: overlapping instruction "+overlap);
                preserved++; return;
            }
            println("RECOVER MODE7: disassembling verified entry "+start);
            if (!disassemble(start)) {
                println("PRESERVE MODE7: disassembler returned false");
            }
        }
        instruction=list.getInstructionAt(start);
        if (instruction==null ||
            !"andi.".equalsIgnoreCase(instruction.getMnemonicString())) {
            println("PRESERVE MODE7: exact instruction mnemonic not recovered at "+start+
                " found="+(instruction==null?"none":instruction.getMnemonicString()));
            preserved++; return;
        }
        if (getFunctionContaining(start)!=null &&
            getFunctionAt(start)==null) {
            println("PRESERVE MODE7: newly discovered code is already part of "+
                getFunctionContaining(start).getName());
            label(MODE7,"UpdateSerialControlStateWithTiming");
            preserved++; return;
        }
        Function function=getFunctionAt(start);
        if (function==null) {
            function=createFunction(start,"UpdateSerialControlStateWithTiming");
            if (function==null) {
                println("PRESERVE MODE7: function creation refused, label only.");
                label(MODE7,"UpdateSerialControlStateWithTiming");
                preserved++; return;
            }
            functionsCreated++;
        }
        if (function.getName().startsWith("FUN_") &&
            function.getSymbol().getSource()!=SourceType.USER_DEFINED) {
            function.setName("UpdateSerialControlStateWithTiming",SourceType.ANALYSIS);
            functionsRenamed++;
        }
        if (!function.hasCustomVariableStorage() &&
            function.getSignatureSource()!=SourceType.USER_DEFINED) {
            if (function.getParameterCount()==0 &&
                function.getSignatureSource()==SourceType.DEFAULT) {
                try {
                    Variable p=new ParameterImpl("controlWord",
                        UnsignedIntegerDataType.dataType,currentProgram);
                    function.updateFunction(null,
                        new ReturnParameterImpl(VoidDataType.dataType,currentProgram),
                        FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                        false,SourceType.ANALYSIS,p);
                    signatureChanges++;
                }
                catch(Exception e) {
                    println("PRESERVE MODE7 signature: "+e.getMessage());
                }
            }
            else {
                if (function.getParameterCount()==1) {
                    Parameter parameter=function.getParameter(0);
                    if (parameter!=null &&
                        Undefined.isUndefined(parameter.getDataType())) {
                        parameter.setDataType(UnsignedIntegerDataType.dataType,SourceType.ANALYSIS);
                        signatureChanges++;
                    }
                }
                refineReturnVoid(MODE7);
            }
        }
        println("MODE7 RECOVERED "+function.getPrototypeString(false,false));
    }

    @Override
    protected void run() throws Exception {
        if (!verify()) return;

        // Dependency order: two new datatypes before declaring memory or signatures.
        ensureMmioEnum();
        DataType latch=ensureMmioLatch();

        label(0x00be0400L,"SelectedCompatibilityParameterId");
        label(0x00be0404L,"CompatibilityParameterValueLatch");
        declareIfUndefined(0x00be0400L,latch,8);

        note(0x00a064c8L,
            "PPC peripheral register write dispatch. The r3 register selector "+
            "is masked with 0x1FF at 0x00A064F0. Two cases, 0x1A0 and 0x1A4, "+
            "bridge accesses to the compatibility parameter API.");
        label(0x00a0664cL,"CompatibilityMmioIndexRegisterWrite");
        label(0x00a06634L,"CompatibilityMmioValueRegisterWrite");
        note(0x00a0664cL,
            "Register offset 0x1A0: save r4 as selected parameter ID "+
            "at 0x00BE0400, call GetCompatibilityParameterValue(r4), "+
            "then store read value at 0x00BE0404. Handles -1 like getter.");
        note(0x00a06634L,
            "Register offset 0x1A4: load previously selected parameter ID "+
            "from 0x00BE0400, store r4 value to 0x00BE0404, and call "+
            "SetCompatibilityParameterValue(id,r4). The (-1,0) pair "+
            "invokes DPATCH restore defaults through the setter.");
        note(0x00be0400L,
            "Signed parameter selector/id latched by register offset 0x1A0. "+
            "Includes special -1 sentinel used by the setter.");
        note(0x00be0404L,
            "Last compatibility parameter read or written. Updated by "+
            "register offsets 0x1A0 (read result) and 0x1A4 (write value).");
        note(0x00a06624L,
            "MMIO register 0x1A0 case selects parameter and reads value. "+
            "Next compare at 0x00A0662C selects register 0x1A4.");

        label(0x00a05df0L,"ApplyMipsDcacheConfiguration");
        label(0x00a05d0cL,"ConfigureMipsDcacheEnabledTlb");
        label(0x00a05da4L,"ConfigureMipsDcacheDisabledTlb");
        note(0x00a06b38L,
            "Initializes callback: r3=16 (PARAM_MIPS_DCACHE_ON), "+
            "r4=0x00A05DF0. Calls RegisterCompatibilityParameterCallback "+
            "at 0x00A0C948 and then immediately calls 0x00A05DF0 "+
            "to apply the current setting.");
        note(0x00a05df0L,
            "Callback registered only for compatibility index 16. It reads "+
            "the mutable live value at 0x00BE0A20, then tail-branches to "+
            "0x00A05D0C when nonzero or 0x00A05DA4 when zero. "+
            "It ignores the incoming callback argument registers.");
        note(0x00a05d0cL,
            "Enable path: updates 10 TLB pairs using tlbrehi/tlbwehi "+
            "and synchronizes with tlbsync. Also changes PPC TLB/SPR "+
            "and MSR state; don't infer literal guest cache bits beyond "+
            "the actual PPC operations.");
        note(0x00a05da4L,
            "Disable path: updates 10 TLB pairs using tlbrehi/tlbwehi "+
            "and tlbsync, then modifies SPR 308. Invoked when "+
            "PARAM_MIPS_DCACHE_ON live value is zero.");
        note(0x00be0a20L,
            "CompatibilityLiveValues[16], PARAM_MIPS_DCACHE_ON (default=1). "+
            "Explicitly consulted by callback 0x00A05DF0.");
        renameIfDefault(0x00a05df0L,"ApplyMipsDcacheConfiguration",true);
        refineReturnVoid(0x00a05df0L);
        refineCallbackRegistration();

        label(0x00a09ce0L,"ApplySixCompatibilityOverrides");
        note(0x00a09c0cL,
            "Peripheral setup routine applies six compatibility parameter "+
            "overrides from a configuration source: IDs 0, 6, 7, 8, 12, "+
            "and 16. This is a call site, not a new default table.");
        for (long[] pair:PRESET_CALLS) {
            int id=(int)pair[2];
            note(pair[0],
                "Loads constant parameter ID "+id+" into PPC r3. "+
                "At 0x"+Long.toHexString(pair[1])+
                " it calls SetCompatibilityParameterValue with r4 "+
                "loaded from the configuration source.");
        }
        note(0x00a04ce4L,
            "Boot/init path calls InitializeCompatibilityAndReportReady "+
            "(0x00A0C964), checks nonzero status, then proceeds with "+
            "remaining hardware initialization.");
        label(0x00a0c844L,"InvokeCompatibilityValueCallback");
        note(0x00a0c844L,
            "Setter uses mtLR r9 / blrl to call callback pointer "+
            "from 0x00BE0A78[id]. First two PPC integer args remain "+
            "id in r3 and newValue in r4.");
        note(0x00a0c860L,
            "Special setter request with parameter ID -1 and value 0 "+
            "branches to DPATCH default restorer at 0xFFFFD770.");

        // The 32 mode slots are a computed-branch switch body. Do not
        // rename them as independently callable functions or split their bodies.
        note(0xffffd014L,
            "bctr switches to one of 32 jump-table destinations at "+
            "0xFFFFD018; modes 1..7 are dispatcher-owned case bodies. "+
            "Preserve Ghidra's encompassing dispatcher function.");
        note(0xffffd5c8L,
            "Mode 7 switch case is a tail branch to in-image installer "+
            "at 0xFFFFD740; it is not a separate callable function.");
        note(0xffffd5ccL,
            "Shared mode-1 post-install path writes instruction 0x54A3F0BE "+
            "to the original ELF site 0x00A097A0, then icbi/isync.");
        note(0xffffd5ecL,
            "Runtime-only serial update target. Patched bl at 0x00A0B1B0 "+
            "is not present in the original ROM; mode 7 installs it. "+
            "The body reads timebase ticks and live parameter 13 "+
            "from 0x00BE0A14 when delaying SIO0 DTR/SCK transitions.");
        note(0x00a0b1b0L,
            "Do not replace ROM instruction 0x4BFFFDE1. Mode 7 "+
            "dynamically installs 0x4B5F243D to call 0xFFFFD5EC.");
        recoverMode7();

        println("DECKARD CONTROL-PLANE SUMMARY datatypes="+datatypes+
            " typedData="+dataTyped+
            " labels="+labels+" comments="+comments+
            " createdFunctions="+functionsCreated+
            " renamedFunctions="+functionsRenamed+
            " signatureChanges="+signatureChanges+
            " preserved="+preserved);
        println("No bytes, existing code/data, or switch-case function bodies cleared.");
    }
}
