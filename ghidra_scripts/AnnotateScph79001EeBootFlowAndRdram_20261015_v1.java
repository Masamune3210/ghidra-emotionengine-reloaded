// Reconstruct the verified SCPH-79001 EE cold-boot chain in its combined Ghidra database.
// Validates every imported segment before updating Ghidra metadata. Optionally fills
// the real, unmodified RDRAM ROM0 module from SCPH-79001.bin or RDRAM.bin.
// Retains all existing instructions, symbols, analyst data and preexisting signatures.
// Emits EE boot-flow DOT and text reports into Downloads; no extension rebuild.
//@category PS2.Boot.MagicGate
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class AnnotateScph79001EeBootFlowAndRdram_20261015_v1 extends GhidraScript {
    private static final String BIOS_SHA = "e76d9c8f4019041fb17f41fff25d57d608c1a3f205c99bda9eb47402c43e8c93";
    private static final String RDRAM_SHA = "e3ae825c718eaaa285cf2a3e000bcc85d2047e50881a2144537410f6398d929d";
    private static final int RDRAM_FILE_OFFSET = 0x41000;
    private static final int RDRAM_SIZE = 0x3154;
    private static final int ROMDIR_COUNT = 105;
    private static final String TAG = "VERIFIED SCPH-79001 EE BOOT: ";

    private static class Section {
        final long address;
        final int size;
        final String name, sha;
        Section(long address, int size, String name, String sha) {
            this.address=address; this.size=size; this.name=name; this.sha=sha;
        }
    }
    private static final Section[] SECTIONS = {
        new Section(0xBFC00000L,0x2780,"RESET","f6a6f7a72ed70bc320b36fd47cba33bb25d14cd6626ce2816bc5f3fb218f708b"),
        new Section(0xBFC02780L,0x06A0,"ROMDIR","44e0cf76068658a9f35277aeea0b8b4dd189d2a75524c2157f5c456c9b9949ba"),
        new Section(0x80000000L,0x173E8,"KERNEL","da56e4697cee326e73f00dbfbd4d805109cea119d88b96addd6fb76a29dcffe9"),
        new Section(0x00082000L,0x0F190,"EELOAD","c94e3da87af7bc5ea90700947096ba9380cbdc4b40296c2253ed7a795f0fbce7")
    };
    // Firmware-evidenced instruction words and syscall table entries, not reconstructed or relocated estimates.
    private static final long[][] REQUIRED_WORDS = {
        {0xBFC00000L,0x401A7800L}, {0xBFC00008L,0x2B410059L},
        {0xBFC0000CL,0x14200005L}, {0xBFC0001CL,0x03400008L},
        {0xBFC00800L,0x3C1A0007L}, {0xBFC00884L,0x3C1A9FC4L},
        {0xBFC00888L,0x375A1000L}, {0xBFC00894L,0x0340F809L},
        {0xBFC0089CL,0x0440002BL}, {0xBFC008B8L,0x3C03BFC0L},
        {0xBFC008C8L,0x00641824L}, {0xBFC008CCL,0x0060F809L},
        {0xBFC008E4L,0x3C088000L}, {0xBFC008E8L,0x35081000L},
        {0xBFC008F4L,0x01000008L},
        {0xBFC00C00L,0x27BDFFD0L}, {0xBFC00C10L,0x0FF0033EL},
        {0xBFC00C44L,0x0FF00364L}, {0xBFC00CF8L,0x0080382DL},
        {0xBFC00D08L,0x3C084553L}, {0xBFC00D10L,0x35084552L},
        {0xBFC00D90L,0x0080482DL},
        {0x80000000L,0x3C1A8001L}, {0x80000018L,0x8F5A5900L},
        {0x80000080L,0x080051D5L}, {0x80000100L,0x080051D5L},
        {0x80000280L,0x0462002AL}, {0x800002F8L,0x8F5A5500L},
        {0x80001000L,0x3C027000L}, {0x80001028L,0x0C00170CL},
        {0x80001030L,0x0C000814L}, {0x800010A0L,0x3C050008L},
        {0x800010B0L,0x0C0014E2L}, {0x800010B8L,0x08001450L},
        {0x80005140L,0x2402004CL}, {0x80005190L,0x27BDFF90L},
        {0x80005298L,0x3C038001L}, {0x80005388L,0x27BDFF80L},
        {0x80005598L,0x27BDFF40L}, {0x80005988L,0x00A0302DL},
        {0x800059A0L,0x27BDFFE0L}, {0x80005C30L,0x27BDFFB0L},
        {0x80015518L,0x80005598L}, {0x800155F0L,0x80005190L},
        {0x800155F4L,0x80005298L}, {0x800156ECL,0x80005988L},
        {0x800156F0L,0x80001564L}, {0x80015920L,0x80000280L},
        {0x00082000L,0x00000000L}, {0x00082008L,0x3C020009L},
        {0x00082060L,0x2403003CL}, {0x00082064L,0x0000000CL},
        {0x0008207CL,0x2403003DL}, {0x00082080L,0x0000000CL},
        {0x0008209CL,0x0C0208E2L}, {0x000820A4L,0x08020C80L},
        {0x00082388L,0x27BDFFA0L}, {0x000823B0L,0x0C020BCCL},
        {0x00082470L,0x0C02089EL}, {0x000824A0L,0x0C02089EL},
        {0x000824D0L,0x0C02089EL}, {0x00082530L,0x0C020AFEL},
        {0x00082BF8L,0x00A0302DL}, {0x00083200L,0x24030004L},
        {0x00083230L,0x24030007L}
    };

    private static class RomdirEntry {
        int index;
        long base, size, extSize, record;
        String name;
        RomdirEntry(int index, long base, long size, long extSize, long record, String name) {
            this.index=index;this.base=base;this.size=size;this.extSize=extSize;
            this.record=record;this.name=name;
        }
    }

    private final List<RomdirEntry> romEntries = new ArrayList<>();
    private int functionsCreated, functionsRenamed, labelsAdded, commentsAdded, typedData, bookmarksAdded, preserved;
    private boolean rdramAvailable;

    private String sha(byte[] bytes) throws Exception {
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        digest.update(bytes);
        StringBuilder result=new StringBuilder(64);
        for (byte b:digest.digest()) result.append(String.format(Locale.ROOT,"%02x",b&255));
        return result.toString();
    }
    private byte[] bytes(long start,int count) throws Exception {
        Memory mem=currentProgram.getMemory();
        byte[] data=new byte[count];
        if (mem.getBytes(toAddr(start),data)!=count)
            throw new IllegalStateException("Incomplete memory at "+toAddr(start));
        return data;
    }
    private long u32(long address) throws Exception {
        byte[] b=bytes(address,4);
        return Integer.toUnsignedLong((b[0]&255)|((b[1]&255)<<8)|((b[2]&255)<<16)|((b[3]&255)<<24));
    }
    private int u16(long address) throws Exception {
        byte[] b=bytes(address,2);
        return (b[0]&255)|((b[1]&255)<<8);
    }

    private boolean validate() throws Exception {
        if (!"r5900:LE:32:default".equals(currentProgram.getLanguageID().toString()) ||
            !"BOOTFLOW_EE_combined_20261015_v1.elf".equals(currentProgram.getName())) {
            printerr("ABORT: expected SCPH-79001 combined EE boot program (R5900)");
            return false;
        }
        for (Section section:SECTIONS) {
            monitor.checkCancelled();
            String observed=sha(bytes(section.address,section.size));
            if (!observed.equalsIgnoreCase(section.sha)) {
                printerr("ABORT "+section.name+" at "+toAddr(section.address)+
                    " SHA256="+observed+" expected="+section.sha);
                return false;
            }
            println("VERIFIED "+section.name+" "+toAddr(section.address)+
                " size=0x"+Integer.toHexString(section.size));
        }
        int errors=0;
        for (long[] pair:REQUIRED_WORDS) {
            long observed=u32(pair[0]);
            if (observed!=pair[1]) {
                println(String.format(Locale.ROOT,
                    "WORD MISMATCH %08x expected=%08x got=%08x",
                    pair[0],pair[1],observed));
                errors++;
            }
        }
        if (errors!=0) {
            printerr("ABORT: "+errors+" boot instruction/table mismatches; database untouched");
            return false;
        }
        println("VERIFIED "+REQUIRED_WORDS.length+" exact instruction/table words");
        return parseRomdir();
    }

    private boolean parseRomdir() throws Exception {
        long offset=0;
        for (int index=0;index<ROMDIR_COUNT;index++) {
            long entryAddress=0xBFC02780L+index*16L;
            byte[] nameBytes=bytes(entryAddress,10);
            int used=0;
            while (used<10 && nameBytes[used]!=0) used++;
            String name=new String(nameBytes,0,used,java.nio.charset.StandardCharsets.US_ASCII);
            long size=u32(entryAddress+12);
            int ext=u16(entryAddress+10);
            if (name.isEmpty() || offset+size>0x400000L)
                throw new IllegalStateException("Invalid ROMDIR entry "+index+" "+name);
            romEntries.add(new RomdirEntry(index,offset,size,ext,entryAddress,name));
            offset+=(size+15)&~15L;
        }
        if (offset!=0x400000L || u32(0xBFC02E1CL)!=0) {
            printerr("ABORT: ROMDIR size or terminating entry mismatched");
            return false;
        }
        boolean haveKernel=false,haveEeLoad=false,haveRdram=false;
        for (RomdirEntry e:romEntries) {
            if (e.name.equals("KERNEL") && e.base==0x392f70L && e.size==0x173e8L) haveKernel=true;
            if (e.name.equals("EELOAD") && e.base==0xd0ff0L && e.size==0xf190L) haveEeLoad=true;
            if (e.name.equals("RDRAM") && e.base==0x41000L && e.size==0x3154L) haveRdram=true;
        }
        if (!haveKernel || !haveEeLoad || !haveRdram) {
            printerr("ABORT: expected KERNEL/EELOAD/RDRAM ROMDIR entries not found");
            return false;
        }
        println("VERIFIED ROMDIR 105 records, aligned total=0x400000, KERNEL/EELOAD/RDRAM positions");
        return true;
    }

    private byte[] sourceRdram() throws Exception {
        Address source=toAddr(0xBFC41000L);
        MemoryBlock existing=currentProgram.getMemory().getBlock(source);
        if (existing!=null && existing.isInitialized() && !existing.isMapped()) {
            byte[] original=bytes(0xBFC41000L,RDRAM_SIZE);
            if (!RDRAM_SHA.equalsIgnoreCase(sha(original)))
                throw new IllegalStateException("Conflicting existing RDRAM bytes; stop without changes");
            rdramAvailable=true;
            println("VERIFIED existing mapped RDRAM code at 0xBFC41000, no new block needed");
            return null;
        }
        if (existing!=null) {
            throw new IllegalStateException("RDRAM address occupied by "+existing.getName()+
                " but not an initialized direct ROM block; preserving it");
        }
        File file=askFile("Select SCPH-79001.bin (4 MiB) or extracted RDRAM.bin", "Use ROM");
        byte[] selected=Files.readAllBytes(file.toPath());
        byte[] candidate;
        if (selected.length==0x400000) {
            if (!BIOS_SHA.equalsIgnoreCase(sha(selected)))
                throw new IllegalStateException("Selected 4 MiB ROM hash mismatch; no changes made");
            candidate=java.util.Arrays.copyOfRange(selected,RDRAM_FILE_OFFSET,
                RDRAM_FILE_OFFSET+RDRAM_SIZE);
        }
        else if (selected.length==RDRAM_SIZE) {
            candidate=selected;
        }
        else {
            throw new IllegalStateException("Expected 4 MiB original ROM or 0x3154-byte RDRAM image");
        }
        if (!RDRAM_SHA.equalsIgnoreCase(sha(candidate)))
            throw new IllegalStateException("RDRAM SHA256 mismatch; no changes made");
        println("VERIFIED external RDRAM module SHA256="+RDRAM_SHA);
        return candidate;
    }

    private void installRdram(byte[] candidate) throws Exception {
        if (candidate!=null) {
            Memory mem=currentProgram.getMemory();
            MemoryBlock block=mem.createInitializedBlock("BIOS_RDRAM_EE",
                toAddr(0xBFC41000L),new ByteArrayInputStream(candidate),
                candidate.length,monitor,false);
            block.setRead(true);
            block.setWrite(false);
            block.setExecute(true);
            rdramAvailable=true;
            println("ADDED initialized RDRAM ROM bytes at 0xBFC41000..0xBFC44153");
        }
        try {
            if (RDRAM_SHA.equalsIgnoreCase(sha(bytes(0x9FC41000L,RDRAM_SIZE)))) {
                println("PASS cached BIOS mirror 0x9FC41000 resolves complete verified RDRAM bytes");
            }
            else {
                println("WARNING cached alias 0x9FC41000 did not match RDRAM bytes; preserve existing alias");
            }
        }
        catch (Exception e) {
            println("WARNING cached RDRAM alias cannot be read: "+e.getMessage());
        }
    }

    private void label(long address,String name) {
        Address at=toAddr(address);
        if (!currentProgram.getMemory().contains(at)) {
            println("UNMAPPED LABEL "+at+" "+name);
            preserved++;return;
        }
        for (Symbol symbol:currentProgram.getSymbolTable().getSymbols(at)) {
            if (symbol.getName().equals(name)) return;
        }
        try {
            currentProgram.getSymbolTable().createLabel(at,name,SourceType.ANALYSIS);
            labelsAdded++;
        }
        catch (Exception ex) {
            println("PRESERVE SYMBOL "+at+" "+name+": "+ex.getMessage());
            preserved++;
        }
    }
    private void note(long address,String text) {
        Address at=toAddr(address);
        if (!currentProgram.getMemory().contains(at)) return;
        String original=getPlateComment(at);
        if (original!=null && original.contains(TAG)) return;
        setPlateComment(at,original==null || original.isEmpty() ? TAG+text :
            original+"\n"+TAG+text);
        commentsAdded++;
    }
    private void mark(long address,String name,String details,boolean function) {
        Address at=toAddr(address);
        if (!currentProgram.getMemory().contains(at)) {
            println("UNMAPPED BOOT ADDRESS "+at+" "+name);
            return;
        }
        if (function) {
            Function fn=getFunctionAt(at);
            Function owner=getFunctionContaining(at);
            if (fn==null && owner!=null) {
                println("PRESERVE FUNCTION BOUNDARY "+at+
                    " inside "+owner.getName()+" (label/comment only)");
            }
            if (fn==null && owner==null) {
                Instruction instruction=currentProgram.getListing().getInstructionAt(at);
                if (instruction==null) {
                    try { disassemble(at); }
                    catch (Exception e) {
                        println("PRESERVE DISASSEMBLY "+at+" "+e.getMessage());
                    }
                }
                if (currentProgram.getListing().getInstructionAt(at)!=null) {
                    try {
                        fn=createFunction(at,name);
                        if (fn!=null) functionsCreated++;
                    }
                    catch (Exception e) {
                        println("PRESERVE FUNCTION "+at+" "+e.getMessage());
                    }
                }
            }
            if (fn!=null && (fn.getName().startsWith("FUN_") ||
                fn.getName().startsWith("sub_")) &&
                fn.getSymbol().getSource()!=SourceType.USER_DEFINED) {
                try {
                    fn.setName(name,SourceType.ANALYSIS);
                    functionsRenamed++;
                }
                catch (Exception e) { preserved++; }
            }
        }
        label(address,name);
        note(address,details);
        if (details.toLowerCase(Locale.ROOT).contains("handoff") ||
            details.toLowerCase(Locale.ROOT).contains("missing") ||
            details.toLowerCase(Locale.ROOT).contains("reset entry")) {
            boolean found=false;
            for (ghidra.program.model.listing.Bookmark bm:
                    currentProgram.getBookmarkManager().getBookmarks(at)) {
                if ("PS2 EE Boot".equals(bm.getCategory()) &&
                    details.equals(bm.getComment())) {found=true;break;}
            }
            if (!found) {
                currentProgram.getBookmarkManager().setBookmark(at,"Analysis","PS2 EE Boot",details);
                bookmarksAdded++;
            }
        }
    }

    private DataType createRomdirType() {
        DataTypeManager dtm=currentProgram.getDataTypeManager();
        CategoryPath category=new CategoryPath("/PS2Boot");
        StructureDataType struct=new StructureDataType(category,"RomDirEntry",0,dtm);
        struct.add(new ArrayDataType(CharDataType.dataType,10,1),"name",null);
        struct.add(UnsignedShortDataType.dataType,"extinfoSize",null);
        struct.add(UnsignedIntegerDataType.dataType,"fileSize",null);
        if (struct.getLength()!=16) throw new IllegalStateException("ROMDIR structure must be 16 bytes");
        DataType previous=dtm.getDataType(category,"RomDirEntry");
        if (previous!=null) {
            if (!previous.isEquivalent(struct)) {
                println("PRESERVE conflicting ROMDIR datatype "+previous.getPathName());
                return null;
            }
            return previous;
        }
        return dtm.addDataType(struct,DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private void typeFreeArray(long address,int count,DataType element,int bytesPerElement) {
        if (element==null)return;
        Listing list=currentProgram.getListing();
        Address start=toAddr(address);
        for (int i=0;i<count*bytesPerElement;i++) {
            Address a=start.add(i);
            if (list.getInstructionContaining(a)!=null ||
                list.getDefinedDataContaining(a)!=null) {
                println("PRESERVE existing markup at "+a+" in array starting "+start);
                preserved++;return;
            }
        }
        try {
            list.createData(start,new ArrayDataType(element,count,bytesPerElement));
            typedData++;
        }
        catch(Exception e) {
            println("PRESERVE data "+start+": "+e.getMessage());
            preserved++;
        }
    }

    private String symbolSafe(String text) {
        if ("-".equals(text))return "Padding";
        return text.replaceAll("[^A-Za-z0-9_]","_");
    }
    private void annotateRomdir() {
        DataType record=createRomdirType();
        typeFreeArray(0xBFC02780L,ROMDIR_COUNT,record,16);
        note(0xBFC02780L,"ROMDIR has 105 records (16 bytes each) followed by one " +
            "zero terminator. File contents start at ROM offset 0; each file is " +
            "16-byte aligned. Offsets are separate from execution-time RAM destinations.");
        for (RomdirEntry e:romEntries) {
            monitor.checkCancelled();
            String key="ROMDIR_"+String.format(Locale.ROOT,"%03d",e.index)+"_"+symbolSafe(e.name);
            label(e.record,key);
            note(e.record, "ROM0 file '"+e.name+"' (#"+e.index+") size=0x"+
                Long.toHexString(e.size)+" extinfo=0x"+Long.toHexString(e.extSize)+
                " ROM offset 0x"+Long.toHexString(e.base)+
                " uncached ROM address 0x"+Long.toHexString(0xBFC00000L+e.base)+
                ". EE and IOP runtime load destinations are separate.");
        }
    }

    private void annotateBoot() {
        mark(0xBFC00000L,"BiosResetCpuDispatch",
            "Cold reset entry. COP0 PRId checked against 0x59; EE goes to 0xBFC00800, IOP goes to 0xBFC02000. Same ROM bytes, different CPUs.",true);
        mark(0xBFC00800L,"InitializeEeFromResetRom",
            "EE reset entry. Sets COP0/TLB, initializes RDRAM through cached ROM call, finds/copies KERNEL using ROMDIR, flushes caches, then transfers to 0x80001000.",true);
        mark(0xBFC00894L,"CallRdramInitialization",
            "EE reset handoff via jalr t8 to 0x9FC41000 (ROMDIR RDRAM at ROM offset 0x41000). Return v0 < 0 enters fail loop at 0xBFC0094C.",false);
        mark(0xBFC008CCL,"CallEeKernelRomCopy",
            "EE reset handoff via jalr to cached ROM alias 0x9FC00C00, which locates KERNEL from the BIOS ROMDIR before copying into EE RAM.",false);
        mark(0xBFC008FCL,"FlushEeResetCaches",
            "EE reset cache synchronization loops run before transferring to kernel.",true);
        mark(0xBFC008F4L,"EnterEeKernelAt80001000",
            "Reset-to-kernel handoff: jr t0, t0=0x80001000, with stack at 0x70003FF0.",false);
        mark(0xBFC0094CL,"StopAfterRdramInitFailure",
            "Fatal RDRAM initialization result (negative v0) causes an infinite branch loop.",false);
        mark(0xBFC00C00L,"FindAndCopyKernelRomImage",
            "Searches ROMDIR, finds KERNEL entry by string, copies its file bytes into uncached EE RAM (A0000000 alias of 80000000), clears remaining memory.",true);
        mark(0xBFC00CF8L,"LocateResetRomdirHeader",
            "Scans for RESET ROMDIR marker and validated 16-byte ROM records; returns ROMDIR location and offsets to caller.",true);
        mark(0xBFC00D90L,"FindRomModuleByName",
            "Searches the ROM directory for caller-supplied filename; KERNEL is supplied at BFC00C3C via 'KERNEL' string BFC01CA8.",true);
        mark(0xBFC01CA8L,"KernelRomModuleName",
            "Literal 'KERNEL' name used by reset-stage ROMDIR search, not an ELF filename.",false);
        if(rdramAvailable) {
            mark(0x9FC41000L,"InitializeRdramController",
                "Verified RDRAM module entry, reached from EE reset at BFC00894 via 9FC cached BIOS alias. Returns status to reset.",true);
            label(0xBFC41000L,"RdramOriginalRomBytes");
        }
        mark(0x80000000L,"EeExceptionVector000",
            "EE kernel general exception vector: saves k1 at 0x80015938, dispatches Cause.ExcCode via pointer table at 0x80015900.",true);
        mark(0x80000080L,"EeExceptionVector080",
            "EE exception vector branches to shared handler at 0x80014754.",true);
        mark(0x80000100L,"EeExceptionVector100",
            "EE exception vector branches to shared handler at 0x80014754.",true);
        mark(0x80000180L,"EeExceptionVector180",
            "EE general exception vector, same table at 0x80015900.",true);
        mark(0x80000200L,"EeInterruptVector200",
            "EE kernel interrupt vector dispatches masked Cause/Status bits via table beginning 0x80015940.",true);
        mark(0x80000280L,"DispatchEeKernelSyscall",
            "MIPS syscall dispatcher indexes a 256-entry table at 0x80015500 using v1. Syscall 0x7C specially dispatches to 0x800147F4.",true);
        mark(0x80001000L,"InitializeEeKernel",
            "RESET-to-KERNEL handoff. Saves RDRAM result, performs kernel hardware/thread/SIF startup, creates EELOAD thread and enters scheduler.",true);
        mark(0x80001028L,"BootInitializeEeTlb",
            "Calls 0x80005C30 for multi-entry EE TLB setup; next calls progress kernel initialization.",false);
        mark(0x80005C30L,"InitializeEeTlbMappings",
            "Kernel startup initializes multiple TLB entries through COP0/TLB operations.",true);
        mark(0x800010B0L,"CreateInitialEeLoadThread",
            "Kernel startup calls 0x80005388 with name 'EELOAD', start address 0x00082000, stack 0x00081000, and argument 0.",false);
        mark(0x80005388L,"CreateInitialEeThread",
            "Boot's thread creation routine, called from 0x800010B0 to create the EELOAD thread.",true);
        mark(0x800010B8L,"StartInitialEeThread",
            "Kernel startup jumps to 0x80005140 with thread identifier in a0; target restores EPC before eret.",false);
        mark(0x80005140L,"EnterInitialEeThread",
            "Starts the newly created boot thread; sets EPC and executes eret to enter EELOAD.",true);
        mark(0x80005190L,"KernelSyscall3CHandler",
            "Kernel syscall 0x3C at table 0x800155F0. EELOAD executes syscall 0x3C during startup, passing runtime layout fields.",true);
        mark(0x80005298L,"KernelSyscall3DHandler",
            "Kernel syscall 0x3D at table 0x800155F4. EELOAD executes syscall 0x3D during startup.",true);
        mark(0x80005598L,"LoadExecPS2",
            "Kernel syscall 0x06 at table[6], executable-load/restart path. Distinct from EELOAD argument parsing and IOP module loading.",true);
        mark(0x80005988L,"ExecOSD",
            "Kernel syscall 0x7B at table[0x7B]; forwards argc/argv to LoadExecPS2 with 'rom0:OSDSYS'.",true);
        mark(0x800059A0L,"LaunchBootBrowser",
            "BootBrowser argument + rom0:OSDSYS path passed to LoadExecPS2, argc=1.",true);
        mark(0x80014754L,"SharedEeExceptionHandler",
            "Shared exception target from kernel vectors 0x80000080 and 0x80000100.",true);
        mark(0x800147F4L,"SpecialEeSyscall7CHandler",
            "Special syscall 0x7C path bypasses the regular syscall pointer table (table slot 0x7C is generic).",true);
        label(0x80015500L,"EeKernelSyscallTable");
        note(0x80015500L,"256 32-bit syscall handler pointers; includes 0x06 LoadExecPS2, 0x3C/0x3D boot layout syscalls and 0x7B ExecOSD. KSEG1 alias pointers are valid.");
        label(0x80015900L,"EeKernelExceptionDispatchTable");
        note(0x80015900L,"14 Cause.ExcCode handler pointers; index 8 goes to syscall dispatcher 0x80000280. 0x80015938 is saved k1, NOT pointer #14.");
        label(0x80015938L,"EeKernelExceptionSavedK1");
        label(0x80015940L,"EeKernelInterruptDispatchTable");
        note(0x80015940L,"Interrupt dispatch pointer region, exact length not yet proven. Do not blanket-define an array.");
        typeFreeArray(0x80015500L,256,Pointer32DataType.dataType,4);
        typeFreeArray(0x80015900L,14,Pointer32DataType.dataType,4);
        mark(0x800162E8L,"EeKernelLoaderName",
            "Literal 'EELOAD' used to name initial EE thread.",false);
        mark(0x800162F0L,"EeKernelOsdsysPath",
            "Literal 'rom0:OSDSYS', passed by ExecOSD/LaunchBootBrowser.",false);
        mark(0x80016300L,"EeKernelBootBrowserArgument",
            "Literal 'BootBrowser' passed with argc=1 to LoadExecPS2.",false);
        mark(0x00082008L,"EeLoadStartup",
            "EELOAD entry code following eight zero bytes at 0x82000. Initializes BSS, performs syscalls 0x3C and 0x3D, then parses boot arguments.",true);
        mark(0x00082064L,"EeLoadSyscall3C",
            "EELOAD invokes kernel syscall 0x3C; verified handler pointer 0x80005190.",false);
        mark(0x00082080L,"EeLoadSyscall3D",
            "EELOAD invokes kernel syscall 0x3D; verified handler pointer 0x80005298.",false);
        mark(0x00082388L,"ParseEeLoadStartupArguments",
            "EELOAD argument and module-load interpreter; checks moduleload/moduleload2 and -m/-k/-x options, then loads executable or defaults.",true);
        mark(0x00082BF8L,"InvokeEeLoadModuleRequest",
            "EELOAD module request wrapper; forwards through common request routine at 0x00082AD0 and the SIF communication code.",true);
        mark(0x00082468L,"ParseEeLoadOptionM",
            "EELOAD parser compares literal '-m ' at 0x00090780.",false);
        mark(0x00082498L,"ParseEeLoadOptionK",
            "EELOAD parser compares literal '-k ' at 0x00090788.",false);
        mark(0x000824C8L,"ParseEeLoadOptionX",
            "EELOAD parser compares literal '-x ' at 0x00090790.",false);
        mark(0x00082530L,"LoadEeStartupExecutable",
            "EELOAD calls module request entry at 0x00082BF8 for the chosen executable path and dispatches BootError/BootIllegal on failures.",false);
        mark(0x00083200L,"EeLoadKernelSyscall04",
            "Thin wrapper: set v1=4 then syscall. Startup jumps here after its main argument handler returns.",false);
        mark(0x00083230L,"EeLoadKernelSyscall07",
            "Thin wrapper: set v1=7 then syscall, used in EELOAD process handoff.",false);
        mark(0x00090700L,"EeLoadDefaultOsdsysPath",
            "Literal 'rom0:OSDSYS'. The default browser path is conditional on EELOAD startup arguments; not every boot necessarily executes OSDSYS.",false);
        mark(0x00090710L,"EeLoadTestmodePath",
            "Literal 'rom0:TESTMODE', alternate EELOAD path.",false);
        mark(0x00090740L,"EeLoadModuleloadToken",
            "EELOAD moduleload command token.",false);
        mark(0x00090750L,"EeLoadModuleload2Token",
            "EELOAD moduleload2 command token.",false);
        mark(0x00090760L,"EeLoadUdnlWithConfig",
            "Literal 'rom0:UDNL rom0:EELOADCNF', a distinct IOP reboot/module-loading path. Do not assume it runs on every boot.",false);
        mark(0x000907A0L,"EeLoadUdnlPrefix",
            "Literal 'rom0:UDNL ' for dynamic IOP-reboot arguments; potential later MagicGate-critical module environment transition.",false);
    }

    private void annotateRomdirSecurityPaths() {
        String signature="MAGICGATE BOOT TRACE: ";
        for (RomdirEntry entry:romEntries) {
            if (entry.name.equals("SECRMAN") || entry.name.equals("MCMAN") ||
                entry.name.equals("MCSERV") || entry.name.equals("SIO2MAN") ||
                entry.name.equals("CDVDMAN") || entry.name.equals("CDVDFSV") ||
                entry.name.equals("IOPBTCONF") || entry.name.equals("IOPBTCON2") ||
                entry.name.equals("EELOAD") || entry.name.equals("PS2LOGO") ||
                entry.name.equals("OSDSYS") || entry.name.equals("UDNL")) {
                Address at=toAddr(entry.record);
                String existing=getPlateComment(at);
                if (existing!=null && existing.contains(signature))continue;
                String extra=signature+"Candidate "+entry.name+": ROMDIR presence does not prove " +
                    "load or authentication on every boot. Resolve using IOPBTCONF/IOPBTCON2 " +
                    "and EELOAD launch/reset paths.";
                setPlateComment(at,existing==null || existing.isEmpty() ? extra :
                    existing+"\n"+extra);
                commentsAdded++;
            }
        }
    }

    private void outputReport() throws Exception {
        File downloads=new File(System.getProperty("user.home"),"Downloads");
        if (!downloads.isDirectory()) {
            println("REPORT not written: Downloads directory missing (will not write to home folder)");
            return;
        }
        String timestamp=Long.toString(System.currentTimeMillis());
        File report=new File(downloads,"EEBootFlow_SCPH79001_20261015_v1_"+timestamp+".txt");
        File dot=new File(downloads,"EEBootFlow_SCPH79001_20261015_v1_"+timestamp+".dot");
        try (PrintWriter out=new PrintWriter(report,"UTF-8")) {
            out.println("SCPH-79001 EE boot flow, Ghidra database="+currentProgram.getName());
            out.println("Language="+currentProgram.getLanguageID());
            out.println("Section SHA checks: 4/4; verified instruction/table words="+REQUIRED_WORDS.length);
            out.println("ROMDIR records="+romEntries.size()+"; RDRAM source present="+rdramAvailable);
            out.println("Functions now="+currentProgram.getFunctionManager().getFunctionCount());
            out.println("Functions created="+functionsCreated+" renamed="+functionsRenamed+
                " labels="+labelsAdded+" comments="+commentsAdded+" typed arrays="+typedData+
                " bookmarks="+bookmarksAdded+" preserved="+preserved);
            out.println();
            out.println("VERIFIED FLOW (addresses are logical Ghidra addresses)");
            out.println("BFC00000 shared reset -> BFC00800 EE path; IOP BFC02000 analyzed separately");
            out.println("BFC00894 jalr -> 9FC41000 RDRAM ROM0 (file offset 0x41000)");
            out.println("BFC008CC jalr -> 9FC00C00 reset ROMDIR/KERNEL lookup/copy");
            out.println("BFC008DC -> BFC008FC cache invalidation; BFC008F4 jr -> 80001000");
            out.println("80001000 -> 80005C30 TLB init -> additional EE kernel initialization");
            out.println("800010B0 -> 80005388 create initial EELOAD thread (image 00082000)");
            out.println("800010B8 -> 80005140 first thread resume (EPC/eret) -> 00082000/00082008");
            out.println("00082064 syscall 3C -> 80005190, 00082080 syscall 3D -> 80005298");
            out.println("00082388 EELOAD argument parsing -> moduleload/moduleload2, UDNL, chosen executable");
            out.println("80015500 syscall[256] -> 80005598 LoadExecPS2, 80005988 ExecOSD");
            out.println("80005988 -> 80005598 rom0:OSDSYS; 800059A0 BootBrowser wrapper");
            out.println();
            out.println("UNRESOLVED: The current combined EE image did not originally include RDRAM,");
            out.println("IOPBOOT, nor all BIOS ROM modules. The IOP image and exact IOP config");
            out.println("must be analyzed separately. SECRMAN presence in ROMDIR is not execution proof.");
            out.println("An RDRAM initializer return value and its hardware effects are not emulator validation.");
            out.println();
            out.println("ROMDIR index / name / ROM offset / size / cached EE ROM entry:");
            for(RomdirEntry e:romEntries) {
                out.printf(Locale.ROOT,"%3d %-10s %06x %06x %08x%n",
                    e.index,e.name,e.base,e.size,0x9fc00000L+e.base);
            }
            out.println();
            out.println("Selected boot/function state:");
            long[] targets={0xBFC00800L,0xBFC00C00L,0xBFC00CF8L,0xBFC00D90L,
                0x9FC41000L,0x80001000L,0x80005140L,0x80005388L,0x80005598L,
                0x80005988L,0x800059A0L,0x80000280L,0x00082008L,0x00082388L};
            for(long target:targets){
                Address a=toAddr(target);
                Function fn=getFunctionContaining(a);
                out.println(a+" function="+(fn==null?"<not defined>":fn.getName()+" @"+fn.getEntryPoint())+
                    " instruction="+currentProgram.getListing().getInstructionAt(a));
                if(fn!=null && fn.getEntryPoint().equals(a)) {
                    int shown=0;
                    for(Instruction ins:currentProgram.getListing().getInstructions(fn.getBody(),true)) {
                        if(ins.getFlowType().isCall()) {
                            out.println("    CALL "+ins.getAddress()+" -> "+
                                java.util.Arrays.toString(ins.getFlows()));
                            if(++shown>=45){out.println("    ... truncated calls");break;}
                        }
                    }
                }
            }
        }
        try (PrintWriter out=new PrintWriter(dot,"UTF-8")) {
            out.println("digraph SCPH79001_EE_Boot {");
            out.println("  rankdir=LR; node [shape=box,fontsize=10];");
            out.println("  reset [label=\"RESET BFC00000\\nCPU dispatch\"];");
            out.println("  ee [label=\"EE RESET BFC00800\"];");
            out.println("  iop [label=\"IOP RESET BFC02000\\nseparate IOP program\",style=dashed];");
            out.println("  rdram [label=\"RDRAM 9FC41000\\nROM0 +41000\"];");
            out.println("  romdir [label=\"ROMDIR BFC02780\\nKERNEL lookup\"];");
            out.println("  kerncopy [label=\"KERNEL ROM copy 9FC00C00\"];");
            out.println("  kernel [label=\"KERNEL 80001000\"];");
            out.println("  thread [label=\"Create boot thread 80005388\"];");
            out.println("  schedule [label=\"Enter thread 80005140\"];");
            out.println("  eeload [label=\"EELOAD 00082008\"];");
            out.println("  opts [label=\"EELOAD argv parser 00082388\"];");
            out.println("  osdsys [label=\"rom0:OSDSYS path\",style=dashed];");
            out.println("  udnl [label=\"rom0:UDNL / EELOADCNF\\nconditional IOP reboot\",style=dashed];");
            out.println("  reset -> ee [label=\"PRId >= 0x59\"]; reset -> iop [label=\"PRId < 0x59\"];");
            out.println("  ee -> rdram [label=\"BFC00894 jalr\"]; ee -> kerncopy [label=\"BFC008CC jalr\"];");
            out.println("  kerncopy -> romdir [label=\"find KERNEL\"]; kerncopy -> kernel [label=\"copied image; BFC008F4 jr\"];");
            out.println("  kernel -> thread [label=\"800010B0\"]; thread -> schedule [label=\"thread id\"];");
            out.println("  schedule -> eeload [label=\"EPC / eret\"]; eeload -> opts [label=\"startup argc/argv\"];");
            out.println("  opts -> osdsys [style=dashed,label=\"default/selected\"]; opts -> udnl [style=dashed,label=\"conditional\"];");
            out.println("}");
        }
        println("BOOT FLOW REPORT "+report.getAbsolutePath());
        println("BOOT FLOW DOT "+dot.getAbsolutePath());
    }

    @Override
    protected void run() throws Exception {
        if(!validate()) return;
        // Check input and any destination conflicts BEFORE metadata modification.
        byte[] rdramBytes=sourceRdram();
        installRdram(rdramBytes);
        annotateRomdir();
        annotateBoot();
        annotateRomdirSecurityPaths();
        outputReport();
        println("EE BOOT METADATA COMPLETE: functionsCreated="+functionsCreated+
            " renamed="+functionsRenamed+" labels="+labelsAdded+
            " comments="+commentsAdded+" pointerTables="+typedData+
            " bookmarks="+bookmarksAdded+" preserved="+preserved);
        println("No executable bytes altered. IOP modules require separate IOP program.");
    }
}