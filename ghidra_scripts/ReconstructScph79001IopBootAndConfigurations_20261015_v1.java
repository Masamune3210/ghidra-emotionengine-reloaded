// Sony SCPH-79001: reconstruct IOP reset, ROM module boot and both IOPBTCON lists.
// Validates all four exact original inputs (RESET, IOPBOOT, IOPBTCONF, IOPBTCON2)
// and ROMDIR; does not synthesize firmware bytes or change existing functions.
// Exports TXT, TSV and DOT reports to the current user's Downloads folder.
//@category PS2.Boot.MagicGate
import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class ReconstructScph79001IopBootAndConfigurations_20261015_v1 extends GhidraScript {
    private static final String PROGRAM = "BOOTFLOW_IOP_combined_20261015_v1.elf";
    private static final String TAG = "VERIFIED SCPH-79001 IOP BOOT: ";
    private static final long ROMDIR_ADDRESS = 0xBFC02780L;
    private static final int ROMDIR_COUNT = 105;

    private static class Segment {
        final long base; final int length; final String name, sha;
        Segment(long b,int l,String n,String s){base=b;length=l;name=n;sha=s;}
    }
    private static final Segment[] SEGMENTS = {
        new Segment(0xBFC00000L,0x2780,"RESET","f6a6f7a72ed70bc320b36fd47cba33bb25d14cd6626ce2816bc5f3fb218f708b"),
        new Segment(0xBFC02780L,0x06A0,"ROMDIR","44e0cf76068658a9f35277aeea0b8b4dd189d2a75524c2157f5c456c9b9949ba"),
        new Segment(0xBFC1EC90L,0x00EA,"IOPBTCONF","9424379b2c4efdd95ee9a9b2b1e786254ffa0a177324e631d5855b589384df75"),
        new Segment(0xBFC1ED80L,0x00C3,"IOPBTCON2","9225c34546e18cf3e947f9b221b01d887dfbb6895b5a15db9a82ede3e220e1e7"),
        new Segment(0xBFC4A000L,0x1160,"IOPBOOT","572e8acd6db6c7854cba1418b3ecfc02f23c3752e1073baa3ccd728a986abc54")
    };
    private static final long[][] OPCODES = {
        {0xBFC00000L, 0x401A7800L},
        {0xBFC00008L, 0x2B410059L},
        {0xBFC0000CL, 0x14200005L},
        {0xBFC00014L, 0x3C1ABFC0L},
        {0xBFC00024L, 0x3C1ABFC0L},
        {0xBFC02000L, 0x10000009L},
        {0xBFC02028L, 0x40087800L},
        {0xBFC02030L, 0x29010010L},
        {0xBFC02034L, 0x14200007L},
        {0xBFC0203CL, 0x3C08BF80L},
        {0xBFC0204CL, 0x11000018L},
        {0xBFC02054L, 0x3C08BFC0L},
        {0xBFC020B0L, 0x3C08BFC0L},
        {0xBFC021B0L, 0x24090CC4L},
        {0xBFC022ECL, 0x40087800L},
        {0xBFC02300L, 0x3C08BF80L},
        {0xBFC02318L, 0x3C090001L},
        {0xBFC02328L, 0x3C090001L},
        {0xBFC02390L, 0x24080006L},
        {0xBFC023FCL, 0x3C04BFC0L},
        {0xBFC02404L, 0x3C06BFC0L},
        {0xBFC0240CL, 0x0FF009A0L},
        {0xBFC02420L, 0x00400008L},
        {0xBFC02458L, 0x3C04BFC0L},
        {0xBFC02468L, 0x0FF009A0L},
        {0xBFC02488L, 0x00400008L},
        {0xBFC02680L, 0x00804021L},
        {0xBFC02690L, 0x3C0D4553L},
        {0xBFC026A0L, 0x2509000CL},
        {0xBFC026ECL, 0x00005021L},
        {0xBFC02754L, 0x25290010L},
        {0xBFC4A000L, 0x40806000L},
        {0xBFC4A018L, 0x0004ED00L},
        {0xBFC4A050L, 0x3C130002L},
        {0xBFC4A0B4L, 0x0FF12B2CL},
        {0xBFC4A0D8L, 0x3C14BFC5L},
        {0xBFC4A0E8L, 0x26220030L},
        {0xBFC4A100L, 0x0FF12B56L},
        {0xBFC4A120L, 0x0FF12B56L},
        {0xBFC4A164L, 0x8FA300A0L},
        {0xBFC4A204L, 0x8FA500A0L},
        {0xBFC4A214L, 0x14620007L},
        {0xBFC4A224L, 0x0FF12923L},
        {0xBFC4A234L, 0x14620010L},
        {0xBFC4A248L, 0x0FF1293CL},
        {0xBFC4A278L, 0x1062000AL},
        {0xBFC4A280L, 0x0FF12B56L},
        {0xBFC4A330L, 0x8E440000L},
        {0xBFC4A334L, 0x0FF12980L},
        {0xBFC4A384L, 0x0FF129FCL},
        {0xBFC4A38CL, 0x0FF12BB4L},
        {0xBFC4A39CL, 0x0040F809L},
        {0xBFC4A3ACL, 0x0FF12980L},
        {0xBFC4A404L, 0x0FF12BB4L},
        {0xBFC4A414L, 0xAE62000CL},
        {0xBFC4A44CL, 0x0040F809L},
        {0xBFC4A48CL, 0x8C850000L},
        {0xBFC4A4F0L, 0x10800003L},
        {0xBFC4A578L, 0x10800003L},
        {0xBFC4A5C8L, 0x14800004L},
        {0xBFC4A600L, 0x00804021L},
        {0xBFC4A610L, 0x24020162L},
        {0xBFC4A61CL, 0x85030014L},
        {0xBFC4A66CL, 0x24027001L},
        {0xBFC4A6F8L, 0x8D02001CL},
        {0xBFC4A7F0L, 0x27BDFFE8L},
        {0xBFC4A918L, 0x27BDFFE0L},
        {0xBFC4A998L, 0x27BDFFE8L},
        {0xBFC4A9FCL, 0x27BDFFD0L},
        {0xBFC4ACB0L, 0x00803821L},
        {0xBFC4AD58L, 0x27BDFFF0L},
        {0xBFC4AED0L, 0x40086000L}
    };
    private static class RomFile {
        final String name; final long offset,length,romdirEntry;
        RomFile(String n,long o,long l,long e){name=n;offset=o;length=l;romdirEntry=e;}
    }
    private final List<RomFile> files = new ArrayList<>();
    private final List<String> primary = new ArrayList<>();
    private final List<String> alternate = new ArrayList<>();
    private int labels, comments, functionsCreated, renamed, preserved, bookmarks,typed;

    private byte[] read(long address,int length) throws Exception {
        byte[] result=new byte[length];
        if(currentProgram.getMemory().getBytes(toAddr(address),result)!=length)
            throw new IllegalStateException("Missing bytes at "+toAddr(address));
        return result;
    }
    private long getU32(long address) throws Exception {
        byte[] b=read(address,4);
        return Integer.toUnsignedLong((b[0]&255)|((b[1]&255)<<8)|((b[2]&255)<<16)|((b[3]&255)<<24));
    }
    private int getU16(long address) throws Exception {
        byte[] b=read(address,2);return (b[0]&255)|((b[1]&255)<<8);
    }
    private String hash(byte[] data) throws Exception {
        byte[] sum=MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder sb=new StringBuilder();
        for(byte b:sum)sb.append(String.format(Locale.ROOT,"%02x",b&255));
        return sb.toString();
    }
    private String ascii(long address,int size) throws Exception {
        return new String(read(address,size),StandardCharsets.US_ASCII);
    }
    private boolean verify() throws Exception {
        if(!PROGRAM.equals(currentProgram.getName())) {
            printerr("ABORT expected "+PROGRAM+", got "+currentProgram.getName());return false;
        }
        if(currentProgram.getLanguage().isBigEndian() ||
           !currentProgram.getLanguage().getProcessor().toString().startsWith("MIPS")) {
            printerr("ABORT: this is an IOP little-endian MIPS32 program; not R5900 EE/DECKARD");
            return false;
        }
        for(Segment s:SEGMENTS) {
            monitor.checkCancelled();
            String actual=hash(read(s.base,s.length));
            if(!s.sha.equals(actual)) {
                printerr("ABORT "+s.name+" at "+toAddr(s.base)+" sha="+actual+" expected="+s.sha);
                return false;
            }
            println("PASS "+s.name+" length="+s.length+" SHA256="+actual);
        }
        int failures=0;
        for(long[] pair:OPCODES) {
            long actual=getU32(pair[0]);
            if(actual!=pair[1]) {
                println(String.format(Locale.ROOT,"WRONG WORD %08x expected=%08x found=%08x",
                    pair[0],pair[1],actual));
                failures++;
            }
        }
        if(failures>0) {printerr("ABORT: "+failures+" opcode mismatches");return false;}
        parseRomdir();
        parseConfig(0xBFC1EC90L,0xEA,primary,"IOPBTCONF");
        parseConfig(0xBFC1ED80L,0xC3,alternate,"IOPBTCON2");
        if(primary.size()!=29 || alternate.size()!=24)
            throw new IllegalStateException("Configuration module counts differ from verified source");
        println("PASS "+OPCODES.length+" original words, 105 ROMDIR entries, 29+24 config rows");
        return true;
    }
    private void parseRomdir() throws Exception {
        long offset=0;
        for(int i=0;i<ROMDIR_COUNT;i++) {
            long at=ROMDIR_ADDRESS+16L*i;
            byte[] nameBytes=read(at,10);
            int end=0;while(end<10 && nameBytes[end]!=0)end++;
            String name=new String(nameBytes,0,end,StandardCharsets.US_ASCII);
            long length=getU32(at+12);
            if(name.length()==0 || offset+length>0x400000L)
                throw new IllegalStateException("Unexpected ROMDIR entry "+i);
            files.add(new RomFile(name,offset,length,at));
            offset=(offset+length+15L)&~15L;
        }
        if(offset!=0x400000L)throw new IllegalStateException("Unexpected 4 MiB ROMDIR extent");
        for(RomFile f:files) {
            if(f.name.equals("IOPBOOT") && (f.offset!=0x4A000L || f.length!=0x1160L))
                throw new IllegalStateException("IOPBOOT source offset mismatch");
            if(f.name.equals("SECRMAN") && f.offset!=0x5C340L)
                throw new IllegalStateException("SECRMAN ROM position mismatch");
        }
    }
    private void parseConfig(long base,int size,List<String> dest,String title) throws Exception {
        String raw=ascii(base,size);
        if(!raw.startsWith("@800\n"))throw new IllegalStateException(title+" does not begin @800");
        String[] lines=raw.split("\n",-1);
        for(int i=1;i<lines.length;i++) {
            if(lines[i].isEmpty())continue;
            if(!lines[i].matches("[A-Z0-9_]+"))
                throw new IllegalStateException(title+" invalid line "+(i+1)+": "+lines[i]);
            dest.add(lines[i]);
        }
    }
    private void note(long address,String content) {
        if(!currentProgram.getMemory().contains(toAddr(address)))return;
        String before=getPlateComment(toAddr(address));
        String full=TAG+content;
        if(before!=null && before.contains(full))return;
        setPlateComment(toAddr(address),before==null||before.isEmpty()?full:before+"\n"+full);
        comments++;
    }
    private void label(long address,String name) {
        Address at=toAddr(address);
        if(!currentProgram.getMemory().contains(at))return;
        for(Symbol existing:currentProgram.getSymbolTable().getSymbols(at))
            if(name.equals(existing.getName()))return;
        try {currentProgram.getSymbolTable().createLabel(at,name,SourceType.ANALYSIS);labels++;}
        catch(Exception e){println("PRESERVE SYMBOL "+at+" "+e.getMessage());preserved++;}
    }
    private void mark(long address,String name,String content,boolean function) throws Exception {
        Address at=toAddr(address);
        if(!currentProgram.getMemory().contains(at)) {
            println("UNMAPPED "+name+" "+at);preserved++;return;
        }
        if(function) {
            Function f=getFunctionAt(at);
            Function owner=getFunctionContaining(at);
            if(f==null&&owner==null) {
                if(currentProgram.getListing().getDefinedDataContaining(at)==null) {
                    if(currentProgram.getListing().getInstructionAt(at)==null)disassemble(at);
                    if(currentProgram.getListing().getInstructionAt(at)!=null) {
                        try {f=createFunction(at,name);if(f!=null)functionsCreated++;}
                        catch(Exception e) {println("PRESERVE FUNCTION "+at+" "+e.getMessage());preserved++;}
                    }
                }
            }
            if(f==null&&owner!=null) {
                println("PRESERVE FUNCTION BOUNDARY "+at+" inside "+owner.getName());preserved++;
            }
            if(f!=null && (f.getName().startsWith("FUN_")||f.getName().startsWith("sub_")) &&
                f.getSymbol().getSource()!=SourceType.USER_DEFINED) {
                try {f.setName(name,SourceType.ANALYSIS);renamed++;}
                catch(Exception e) {println("PRESERVE FUNCTION NAME "+at+" "+e.getMessage());preserved++;}
            }
        }
        label(address,name);
        note(address,content);
    }
    private RomFile getRom(String module){
        for(RomFile f:files)if(module.equals(f.name))return f;
        return null;
    }
    private void annotateConfig(long base,List<String> modules,String title) {
        label(base,"Rom0_"+title);
        note(base,"Boot configuration (ASCII @800), "+modules.size()+" ordered module names. "+
            "IOPBOOT selects a configuration at runtime. The presence of a module here "+
            "does not establish that the selected configuration was executed.");
        int offset=5;
        for(int i=0;i<modules.size();i++) {
            String module=modules.get(i);
            long location=base+offset;
            RomFile f=getRom(module);
            label(location,title+"_"+String.format(Locale.ROOT,"%02d",i+1)+"_"+module);
            String where=f==null?"NOT FOUND in ROMDIR":"ROM offset 0x"+Long.toHexString(f.offset)+
                ", 0x"+Long.toHexString(f.length)+" source bytes";
            note(location,"Module position "+(i+1)+"/"+modules.size()+": "+module+"; "+where+
                ". A boot list is not proof of successful module initialization or authentication.");
            offset+=module.length()+1;
        }
    }
    private void annotateSecurityCandidates() {
        for(String module:new String[]{"SECRMAN","MCMAN","SIO2MAN","CDVDMAN","CDVDFSV",
                "SIFCMD","LOADFILE","EESYNC","SIFINIT","REBOOT","MODLOAD","LOADCORE","SYSMEM"}) {
            RomFile rf=getRom(module);
            if(rf!=null) {
                label(rf.romdirEntry,"ROMDIR_"+module);
                boolean inDefault=primary.contains(module),inAlternate=alternate.contains(module);
                note(rf.romdirEntry,"ROM module "+module+" at offset 0x"+Long.toHexString(rf.offset)+
                    "; IOPBTCONF="+inDefault+", IOPBTCON2="+inAlternate+
                    ". Loading an IRX and invoking MagicGate authentication are distinct events.");
            }
        }
    }
    private void annotateCode() throws Exception {
        mark(0xBFC00000L,"BiosResetCpuDispatch",
            "Common EE+IOP reset vector: COP0 PRId < 0x59 selects IOP branch 0xBFC02000; " +
            "the EE branch enters 0xBFC00800 in the other database.",true);
        mark(0xBFC02000L,"InitializeIopFromResetRom",
            "IOP reset: selects hardware initialization sequences using PRId and "+
            "0xBF801450, clears CPU state/cache, and resolves a ROM module by name.",true);
        mark(0xBFC02054L,"IopResetHardwareVariantA",
            "IOP reset chooses register initialization list near 0xBFC024E4.",false);
        mark(0xBFC020B0L,"IopResetHardwareVariantB",
            "Alternative initial register list near 0xBFC0259C; variant depends on hardware state.",false);
        mark(0xBFC023FCL,"IopResetLookupPrimaryBootModule",
            "Finds named ROM module TBIN using the ROMDIR scanner at 0xBFC02680; "+
            "if found, jumps into its entry. This branch does not necessarily invoke IOPBOOT.",false);
        mark(0xBFC02458L,"IopResetLookupIopbootModule",
            "Finds the named ROM module IOPBOOT using the ROMDIR scanner at 0xBFC02680; "+
            "jumps into returned entry and clears the remaining argument registers.",false);
        mark(0xBFC02680L,"FindResetRomModuleByName",
            "Scans ROMDIR records for a 10-character name and aligned ROM contents; called "+
            "from IOP reset for TBIN / IOPBOOT.",true);
        label(0xBFC024B4L,"IopResetIopbootRomName");
        note(0xBFC024B4L,"ASCII IOPBOOT ROM module name used by the reset ROMDIR lookup.");
        label(0xBFC024C4L,"IopResetTbinRomName");
        note(0xBFC024C4L,"ASCII TBIN ROM module name used by an alternative reset path.");
        mark(0xBFC4A000L,"IopBootMain",
            "IOPBOOT entry: establishes GP/stack, builds a module list using an IOPBTCON* " +
            "ROM file, loads and links SYSMEM and LOADCORE, and transfers execution through returned entrypoints.",true);
        mark(0xBFC4A0E8L,"IopBootBuildVariantConfigName",
            "Constructs configuration name by replacing the final byte of literal IOPBTCONF " +
            "with ASCII '0'+incoming config selector. Tries the requested variant, then "+
            "falls back to IOPBTCONF. Runtime selector not established solely by file presence.",false);
        mark(0xBFC4A100L,"IopBootFindSelectedConfiguration",
            "Looks up the numeric-suffix IOPBTCON* filename via ROMDIR helper at 0xBFC4AD58.",false);
        mark(0xBFC4A120L,"IopBootFallbackDefaultConfig",
            "Second ROMDIR lookup when numeric-variant configuration is unavailable.",false);
        mark(0xBFC4A204L,"IopBootParseConfigurationDirective",
            "Parses boot configuration: '@' numeric directive, '!' directive, '#'-prefixed special name "+
            "or regular module name. Do not treat configuration text as instruction bytes.",false);
        mark(0xBFC4A330L,"IopBootBeginCoreModuleLoad",
            "Processes first two ROM config entries using module type classification "+
            "and section-copy helpers; resolves entrypoints for startup.",false);
        mark(0xBFC4A39CL,"IopBootInvokeFirstModuleEntry",
            "Indirect jalr to the first resolved module entry (SYSMEM in both supplied configurations). " +
            "Runtime address depends on loader relocation.",false);
        mark(0xBFC4A404L,"IopBootPrepareSecondModuleEntry",
            "Loads the second configured module (LOADCORE in both supplied configurations) "+
            "and prepares entry call.",false);
        mark(0xBFC4A44CL,"IopBootTransferToLoadcore",
            "Indirect transfer through a loaded module entrypoint with boot context at 0x00020000; " +
            "subsequent module loading is handled by LOADCORE, not by reinterpreting ROMDIR list as calls.",false);
        mark(0xBFC4A4F0L,"CompareBootConfigText",
            "Bounded ASCII compare helper, used by IOPBOOT while resolving directives.",true);
        mark(0xBFC4A578L,"CopyIopBootString",
            "String copy helper used for boot configuration file names.",true);
        mark(0xBFC4A5C8L,"LengthOfIopBootString",
            "String length helper used when positioning boot-config data.",true);
        mark(0xBFC4A600L,"InspectIopBootModuleFormat",
            "Recognizes older IRX and ELF-style IOP module formats from header fields " +
            "and returns a module-format category/loader descriptor. No MagicGate validation here.",true);
        mark(0xBFC4A7F0L,"LoadIopBootExecutableSections",
            "Copies mapped segments and clears BSS according to decoded module format.",true);
        mark(0xBFC4ACB0L,"LocateIopBootRomDirectory",
            "Finds ROMDIR base/contents for IOPBOOT's module resolver.",true);
        mark(0xBFC4AD58L,"FindIopBootRomFile",
            "Searches ROMDIR for an exact requested file and returns location/size metadata.",true);
        mark(0xBFC4AED0L,"IopBootCriticalTransferStub",
            "Transitions through privileged cache/CP0 register manipulation before an " +
            "indirect module-entry call.",true);
        label(0xBFC4B154L,"IopBootDefaultConfigurationName");
        note(0xBFC4B154L,"Literal 'IOPBTCONF' used to generate variant name IOPBTCON0..9; " +
            "the actual selected variant depends on incoming IOPBOOT arguments and runtime state.");
    }
    private void addBootDatatypes() throws Exception {
        DataTypeManager dtm=currentProgram.getDataTypeManager();
        CategoryPath category=new CategoryPath("/PS2Boot");
        StructureDataType romdir=new StructureDataType(category,"IopBootRomdirRecord",0,dtm);
        romdir.add(new ArrayDataType(CharDataType.dataType,10,1),"name",null);
        romdir.add(UnsignedShortDataType.dataType,"extinfoLength",null);
        romdir.add(UnsignedIntegerDataType.dataType,"fileLength",null);
        if(romdir.getLength()!=16)throw new IllegalStateException("ROMDIR layout failed");
        DataType rt=dtm.getDataType(category,romdir.getName());
        if(rt==null)rt=dtm.addDataType(romdir,DataTypeConflictHandler.DEFAULT_HANDLER);
        else if(!rt.isEquivalent(romdir)) {
            println("PRESERVE conflicting ROMDIR record type "+rt.getPathName());
            rt=null;preserved++;
        }
        if(rt!=null) {
            boolean occupied=false;
            Address start=toAddr(ROMDIR_ADDRESS);
            Listing listing=currentProgram.getListing();
            for(int i=0;i<ROMDIR_COUNT*16;i++) {
                Address at=start.add(i);
                if(listing.getInstructionContaining(at)!=null ||
                    listing.getDefinedDataContaining(at)!=null) {occupied=true;break;}
            }
            if(!occupied) {
                try {
                    listing.createData(start,new ArrayDataType(rt,ROMDIR_COUNT,16));
                    typed++;
                }catch(Exception e){println("PRESERVE ROMDIR type: "+e.getMessage());preserved++;}
            } else {println("PRESERVE existing ROMDIR markup");preserved++;}
        }
        // Runtime IOP RAM 0x20000 is intentionally not mapped by the boot-only
        // ELF. Define its partial header view without creating fabricated RAM.
        StructureDataType context=new StructureDataType(category,"IopBootContextHeaderView",0,dtm);
        DataType u32=UnsignedIntegerDataType.dataType;
        context.add(u32,"bootArgument0",null);
        context.add(u32,"bootArgument1",null);
        context.add(u32,"optionalConfigurationPointer",null);
        context.add(u32,"firstModuleEntryPoint",null);
        context.add(u32,"optionalRomBase",null);
        context.add(u32,"optionalRomSize",null);
        context.add(u32,"configuredModuleCount",null);
        context.add(u32,"loadArenaCursor",null);
        if(context.getLength()!=0x20)throw new IllegalStateException("IOPBOOT header size mismatch");
        DataType existing=dtm.getDataType(category,context.getName());
        if(existing==null)dtm.addDataType(context,DataTypeConflictHandler.DEFAULT_HANDLER);
        else if(!existing.isEquivalent(context)) {
            println("PRESERVE conflicting IOPBOOT context type "+existing.getPathName());preserved++;
        }
    }

    private void typeConfigsIfEmpty() throws Exception {
        Listing list=currentProgram.getListing();
        for(Segment s:SEGMENTS) {
            if(!s.name.startsWith("IOPBTCON"))continue;
            Address start=toAddr(s.base);
            boolean occupied=false;
            for(int i=0;i<s.length;i++) {
                Address at=start.add(i);
                if(list.getInstructionContaining(at)!=null ||list.getDefinedDataContaining(at)!=null) {
                    occupied=true;break;
                }
            }
            if(occupied) {println("PRESERVE existing config markup at "+start);preserved++;continue;}
            try {
                DataType charArray=new ArrayDataType(CharDataType.dataType,s.length,1);
                list.createData(start,charArray);typed++;
            }catch(Exception e){println("PRESERVE type "+start+" "+e.getMessage());preserved++;}
        }
    }
    private void output() throws Exception {
        File directory=new File(System.getProperty("user.home"),"Downloads");
        if(!directory.isDirectory()) {println("REPORT unavailable: Downloads missing");return;}
        String tag=Long.toString(System.currentTimeMillis());
        File report=new File(directory,"IopBootFlow_SCPH79001_20261015_v1_"+tag+".txt");
        File tsv=new File(directory,"IopBootModules_SCPH79001_20261015_v1_"+tag+".tsv");
        File dot=new File(directory,"IopBootFlow_SCPH79001_20261015_v1_"+tag+".dot");
        try(PrintWriter o=new PrintWriter(report,"UTF-8")) {
            o.println("SCPH-79001 IOP boot and MagicGate preconditions; Ghidra="+currentProgram.getName());
            o.println("Five verified ROM segments; "+OPCODES.length+" exact instructions; ROMDIR=105 entries");
            o.println("Function changes created="+functionsCreated+" renamed="+renamed+
               " labels="+labels+" comments="+comments+" typedConfigs="+typed+" preserved="+preserved);
            o.println("CHECK: RESET BFC00000 -> IOP BFC02000 (CPU PRId <0x59)");
            o.println("CHECK: reset path resolves TBIN or IOPBOOT by ROMDIR name, hardware dependent");
            o.println("CHECK: IOPBOOT BFC4A000 -> variant IOPBTCON* / default IOPBTCONF fallback");
            o.println("CHECK: both configurations load SYSMEM then LOADCORE first");
            o.println("CHECK: IOPBOOT transfers to loaded core modules through indirect entries");
            o.println("MAGICGATE: SECRMAN is configured in both; SIO2MAN/MCMAN only in IOPBTCON2");
            o.println("WARNING: module list != runtime completion; authentication is later and unproven");
            o.println("UNRESOLVED: actual boot configuration selector, module relocation destinations,");
            o.println("LOADCORE exports/import binding, invocation of SECRMAN functions, and PCSX2 behavior.");
            o.println();
            for(int config=0;config<2;config++) {
                List<String> list=config==0?primary:alternate;
                o.println((config==0?"IOPBTCONF":"IOPBTCON2")+" ["+list.size()+"]:");
                for(int i=0;i<list.size();i++) {
                    RomFile f=getRom(list.get(i));
                    o.printf(Locale.ROOT,"  %02d %-10s ROM=%s%n",i+1,list.get(i),
                        f==null?"unresolved":String.format(Locale.ROOT,"0x%06X size=0x%X",f.offset,f.length));
                }
            }
            o.println();
            o.println("IOPBOOT helper state and source entrypoints:");
            for(long a:new long[]{0xBFC02000L,0xBFC02680L,0xBFC4A000L,0xBFC4A4F0L,
                    0xBFC4A578L,0xBFC4A5C8L,0xBFC4A600L,0xBFC4A7F0L,
                    0xBFC4ACB0L,0xBFC4AD58L,0xBFC4AED0L}) {
                Function f=getFunctionContaining(toAddr(a));
                o.println(toAddr(a)+" function="+(f==null?"none":f.getName()+" @"+f.getEntryPoint())+
                    " instruction="+currentProgram.getListing().getInstructionAt(toAddr(a)));
            }
        }
        try(PrintWriter o=new PrintWriter(tsv,"UTF-8")) {
            o.println("Configuration\tOrder\tModule\tROMOffset\tROMSize\tInOtherConfiguration");
            for(int t=0;t<2;t++) {
                List<String> list=t==0?primary:alternate;
                List<String> other=t==0?alternate:primary;
                String config=t==0?"IOPBTCONF":"IOPBTCON2";
                for(int i=0;i<list.size();i++) {
                    String name=list.get(i);RomFile rf=getRom(name);
                    o.printf(Locale.ROOT,"%s\t%d\t%s\t%s\t%s\t%b%n",config,i+1,name,
                        rf==null?"UNKNOWN":String.format(Locale.ROOT,"0x%06X",rf.offset),
                        rf==null?"UNKNOWN":String.format(Locale.ROOT,"0x%X",rf.length),
                        other.contains(name));
                }
            }
        }
        try(PrintWriter o=new PrintWriter(dot,"UTF-8")) {
            o.println("digraph SCPH79001_IOP_Boot {");
            o.println("rankdir=LR; node [shape=box,fontsize=10];");
            o.println("reset [label=\"Reset BFC00000\\nIOP branch BFC02000\"];");
            o.println("lookup [label=\"RESET ROMDIR lookup\\nBFC02680\"];");
            o.println("tbin [label=\"TBIN alternate branch\",style=dashed];");
            o.println("boot [label=\"IOPBOOT BFC4A000\"];");
            o.println("config [label=\"IOPBTCONF (29 entries)\"];");
            o.println("config2 [label=\"IOPBTCON2 (24 entries)\"];");
            o.println("sysmem [label=\"SYSMEM (first)\"];");
            o.println("loadcore [label=\"LOADCORE (second)\"];");
            o.println("secr [label=\"SECRMAN (both configurations)\"];");
            o.println("card [label=\"SIO2MAN / MCMAN\\nIOPBTCON2 only\"];");
            o.println("reset -> lookup; lookup -> boot; lookup -> tbin [style=dashed];");
            o.println("boot -> config [style=dashed,label=\"fallback/default\"];");
            o.println("boot -> config2 [style=dashed,label=\"selected variant\"];");
            o.println("config -> sysmem; config2 -> sysmem; sysmem -> loadcore;");
            o.println("loadcore -> secr [style=dashed,label=\"configured, not auth\"];");
            o.println("config2 -> card [style=dashed,label=\"configured, not auth\"];");
            o.println("}");
        }
        println("IOP BOOT REPORT "+report.getAbsolutePath());
        println("IOP MODULE TSV "+tsv.getAbsolutePath());
        println("IOP BOOT GRAPH "+dot.getAbsolutePath());
    }
    @Override
    protected void run() throws Exception {
        if(!verify())return;
        annotateConfig(0xBFC1EC90L,primary,"IOPBTCONF");
        annotateConfig(0xBFC1ED80L,alternate,"IOPBTCON2");
        annotateSecurityCandidates();
        addBootDatatypes();
        annotateCode();
        typeConfigsIfEmpty();
        output();
        println("IOP BOOT COMPLETE functionsCreated="+functionsCreated+" renamed="+renamed+
            " labels="+labels+" comments="+comments+" typed="+typed+" preserved="+preserved);
        println("Firmware bytes unchanged. SECRMAN initialization is NOT MagicGate authentication.");
    }
}