// Restore and cross-check ROM0 SYSMEM / LOADCORE export metadata in the EXISTING Ghidra programs.
// SHA-256 guards are sourced from the byte-identical SCPH-39001 and SCPH-79001 original IRX files.
// Does not import binaries, clear markup, rewrite ROM bytes, or invent runtime relocation bases.
// Run once in SYSMEM.bin, once in LOADCORE.bin. Reports are written to Downloads.
//@category PS2.Boot.MagicGate
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.*;
import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;

public class RecoverExistingIopBootLibraryMetadata_20261015_v1 extends GhidraScript {
    private static final String SYSMEM_SHA = "1b03e6ffd2042c2545cf1a78ab937b6b57ccda037783e7ad52467bb9f5556054";
    private static final String LOADCORE_SHA = "b7eef224d6473362d49f9e890d89c3bbeb0d243c56f6961bdb4e772ba5b1632b";
    private static final String TAG = "ROM0 VERIFIED BOOT IMPORT/EXPORT: ";
    private int labels, functionRenames, functionsCreated, comments, refsAdded, types, preserved, bookmarks;
    private PrintWriter report;
    private boolean loadcore;

    // These ordinals are documented in PS2SDK sysmem.h / loadcore.h, and each
    // table/target offset is independently checked against the original ROM0 IRX.
    // Empty entries are deliberately unresolved, not filled with guesses.
    private static final String[] SYSMEM_NAMES = {
        null,null,null,"GetSysmemInternalData","AllocSysMemory","FreeSysMemory",
        "QueryMemSize","QueryMaxFreeMemSize","QueryTotalFreeMemSize",
        "QueryBlockTopAddress","QueryBlockSize",null,null,null,"Kprintf","KprintfSet"
    };
    private static final int[] SYSMEM_TARGETS = {
        0x60,0xd8,0x58,0x460,0x2ec,0x33c,0x204,0x230,
        0x294,0x3a4,0x40c,0x58,0x58,0x58,0xb90,0xbdc
    };
    private static final String[] LOADCORE_NAMES = {
        null,null,null,"GetLoadcoreInternalData","FlushIcache","FlushDcache",
        "RegisterLibraryEntries","ReleaseLibraryEntries","LinkLibraryEntries",
        "UnLinkLibraryEntries","RegisterNonAutoLinkEntries","QueryLibraryEntryTable",
        "QueryBootMode","RegisterBootMode","LockLibraryClient","UnLockLibraryClient",
        "RegisterModule","ReleaseModule",null,null,"AddRebootNotifyHandler",
        "SetCacheCtrl","ProbeExecutableObject","LoadExecutableObject","SearchModuleCBByAddr"
    };
    private static final int[] LOADCORE_TARGETS = {
        0x0,0x5dc,0x1bdc,0xe04,0x1910,0x1a14,0x898,0xab8,
        0xc00,0xcbc,0xa58,0xb94,0x640,0x5e4,0xe14,0xe28,
        0x740,0x7bc,0x1bdc,0x1bdc,0x69c,0x1b18,0x1260,0x1450,0x828
    };

    private Address a(long value) { return toAddr(value); }
    private long word(long address) throws Exception {
        byte[] buf = new byte[4];
        if (currentProgram.getMemory().getBytes(a(address), buf) != buf.length)
            throw new IllegalStateException("Unmapped word at " + a(address));
        return Integer.toUnsignedLong((buf[0]&255) | ((buf[1]&255)<<8) |
                ((buf[2]&255)<<16) | ((buf[3]&255)<<24));
    }
    private String ascii(long at, int len) throws Exception {
        byte[] b = new byte[len];
        if (currentProgram.getMemory().getBytes(a(at), b) != len)
            throw new IllegalStateException("Unmapped name at " + a(at));
        return new String(b, StandardCharsets.US_ASCII).replace("\u0000", "").trim();
    }
    private boolean check() throws Exception {
        String sha = currentProgram.getExecutableSHA256();
        String name = currentProgram.getName();
        if (!"MIPS:LE:32:default".equals(currentProgram.getLanguageID().toString()) ||
            !"Executable and Linking Format (ELF)".equals(currentProgram.getExecutableFormat())) {
            printerr("ABORT: expected existing ELF little-endian MIPS32 IOP program"); return false;
        }
        loadcore = "LOADCORE.bin".equalsIgnoreCase(name);
        if (!loadcore && !"SYSMEM.bin".equalsIgnoreCase(name)) {
            printerr("ABORT: only existing SYSMEM.bin / LOADCORE.bin databases supported"); return false;
        }
        if (sha == null || !sha.equalsIgnoreCase(loadcore ? LOADCORE_SHA : SYSMEM_SHA)) {
            printerr("ABORT: executable hash mismatch. " + name + " SHA256=" + sha);
            return false;
        }
        String lib = loadcore ? "loadcore" : "sysmem";
        int start = loadcore ? 0x1b60 : 0;
        if (word(start)!=0x41c00000L || ascii(start+12,8).equals(lib)==false) {
            printerr("ABORT: expected verified " + lib + " export header missing"); return false;
        }
        if (loadcore) {
            if (word(0)!=0x40806000L || word(0x1bf0)!=0x41e00000L ||
                !ascii(0x1bfc,8).equals("sysmem")) {
                printerr("ABORT: LOADCORE entry or sysmem import header differs");return false;
            }
            for (int k=0;k<3;k++) {
                long slot = 0x1c04 + k*8;
                if (word(slot)!=0x03e00008L || word(slot+4)!=(0x24000004L+k)) {
                    printerr("ABORT: LOADCORE sysmem import stub mismatch at " + a(slot));return false;
                }
            }
        } else if (word(0x60)!=0x27bdffe8L) {
            printerr("ABORT: SYSMEM expected module entry bytes absent");return false;
        }
        final int[] targets = loadcore ? LOADCORE_TARGETS : SYSMEM_TARGETS;
        for (int i=0;i<targets.length;i++) {
            monitor.checkCancelled();
            long address = start + 20L + 4L*i;
            // Normally these are unrelocated offsets. An existing Ghidra import may
            // have applied a module base. Check the relocation record instead of
            // assuming a different byte means another firmware image.
            long actual = word(address);
            if (actual != Integer.toUnsignedLong(targets[i])) {
                boolean relocation = false;
                for (Relocation r:currentProgram.getRelocationTable().getRelocations(a(address))) {
                    if (r.getType() == 2) { relocation=true;break; }
                }
                if (!relocation) {
                    printerr("ABORT: export ordinal " + i + " differs without R_MIPS_32 evidence");
                    return false;
                }
            }
        }
        if (word(start+20L+targets.length*4L)!=0) {
            printerr("ABORT: expected export table terminator absent");return false;
        }
        println("PASS " + name + " executable SHA256=" + sha + " exports="+targets.length);
        return true;
    }
    private void record(String text) { println(text);if(report!=null)report.println(text); }
    private void note(long address,String description) {
        if(!currentProgram.getMemory().contains(a(address)))return;
        String old=getPlateComment(a(address));
        String addition=TAG+description;
        if(old!=null&&old.contains(addition))return;
        setPlateComment(a(address),old==null||old.isEmpty()?addition:old+"\n"+addition);
        comments++;
    }
    private void label(long address,String name) {
        Address at=a(address);
        if(!currentProgram.getMemory().contains(at)) {record("UNMAPPED "+at+" "+name);return;}
        for(Symbol s:currentProgram.getSymbolTable().getSymbols(at))
            if(s.getName().equals(name))return;
        try {currentProgram.getSymbolTable().createLabel(at,name,SourceType.ANALYSIS); labels++;}
        catch(Exception x) {preserved++;record("PRESERVE symbol "+name+" @"+at+" "+x.getMessage());}
    }
    private void nameFunction(long at,String name) {
        Address address=a(at);
        if(!currentProgram.getMemory().contains(address))return;
        Function f=getFunctionAt(address);
        if(f==null && getFunctionContaining(address)==null &&
            currentProgram.getListing().getInstructionAt(address)!=null) {
            try {f=createFunction(address,name);if(f!=null)functionsCreated++;}
            catch(Exception e) {preserved++;record("PRESERVE function @"+address+": "+e.getMessage());}
        }
        if(f!=null && !f.getName().equals(name) &&
            (f.getName().startsWith("FUN_") || f.getName().startsWith("sub_")) &&
            f.getSymbol().getSource()!=SourceType.USER_DEFINED) {
            try {f.setName(name,SourceType.ANALYSIS);functionRenames++;}
            catch(Exception e){preserved++;}
        }
        label(at,name);
    }
    private DataType libHeader() {
        DataTypeManager manager=currentProgram.getDataTypeManager();
        CategoryPath path=new CategoryPath("/PS2/IOP/BootTrace");
        StructureDataType def=new StructureDataType(path,"IopLibraryHeader",0,manager);
        def.add(UnsignedIntegerDataType.dataType,"magic",null);
        def.add(UnsignedIntegerDataType.dataType,"linkPointer",null);
        def.add(UnsignedShortDataType.dataType,"version",null);
        def.add(UnsignedShortDataType.dataType,"flags",null);
        def.add(new ArrayDataType(CharDataType.dataType,8,1),"name",null);
        if(def.getLength()!=20)throw new IllegalStateException("Invalid IopLibraryHeader size");
        DataType existing=manager.getDataType(path,"IopLibraryHeader");
        if(existing!=null) {
            if(!existing.isEquivalent(def))record("PRESERVE conflicting existing datatype "+existing.getPathName());
            return existing.isEquivalent(def)?existing:null;
        }
        types++;return manager.addDataType(def,DataTypeConflictHandler.DEFAULT_HANDLER);
    }
    private void typeHeaderIfFree(long pos,DataType dt) {
        if(dt==null)return;
        Listing l=currentProgram.getListing();
        for(long i=pos;i<pos+20;i++) {
            if(l.getInstructionContaining(a(i))!=null || l.getDefinedDataContaining(a(i))!=null) {
                preserved++;record("PRESERVE existing library header markup @"+a(pos));return;
            }
        }
        try {l.createData(a(pos),dt);types++;}
        catch(Exception e){preserved++;record("PRESERVE header datatype @"+a(pos)+" "+e.getMessage());}
    }
    private boolean hasReference(long src,long dest) {
        for(Reference r:currentProgram.getReferenceManager().getReferencesFrom(a(src)))
            if(r.getToAddress().equals(a(dest)))return true;
        return false;
    }
    private void reference(long src,long dest) {
        if(src==dest||hasReference(src,dest))return;
        if(!currentProgram.getMemory().contains(a(src)) ||
            !currentProgram.getMemory().contains(a(dest)))return;
        try {
            currentProgram.getReferenceManager().addMemoryReference(a(src),a(dest),RefType.DATA,SourceType.ANALYSIS,0);
            refsAdded++;
        } catch(Exception e) {preserved++;record("PRESERVE reference "+a(src)+" -> "+a(dest)+" " +e.getMessage());}
    }
    private boolean hasReloc(long address) {
        for(Relocation r:currentProgram.getRelocationTable().getRelocations(a(address)))
            if(r.getType()==2)return true;
        return false;
    }
    private void bookmark(long address,String note) {
        for(Bookmark b:currentProgram.getBookmarkManager().getBookmarks(a(address)))
            if("PS2 Boot MagicGate".equals(b.getCategory())&&note.equals(b.getComment()))return;
        currentProgram.getBookmarkManager().setBookmark(a(address),"Analysis","PS2 Boot MagicGate",note);
        bookmarks++;
    }
    private void recoverExports(DataType header) throws Exception {
        String lib=loadcore?"loadcore":"sysmem";
        int[] targets=loadcore?LOADCORE_TARGETS:SYSMEM_TARGETS;
        String[] names=loadcore?LOADCORE_NAMES:SYSMEM_NAMES;
        int start=loadcore?0x1b60:0x0;
        typeHeaderIfFree(start,header);
        label(start,"IopExportTable_"+lib);
        note(start,"ROM0 "+lib+" v1.01: "+targets.length+" export entries; " +
            "module-relative addresses (not runtime load addresses).");
        for(int i=0;i<targets.length;i++) {
            monitor.checkCancelled();
            int target=targets[i];long slot=start+20+4L*i;
            String n=names[i];
            label(slot,"IopExport_"+lib+"_Ordinal_"+String.format(Locale.ROOT,"%02d",i));
            String desc=lib+" export ordinal "+i+" -> .text+0x"+Integer.toHexString(target)+
                (n==null?" (semantics unresolved)":" ("+n+")");
            if(loadcore && i==0) {
                desc+="; first cell is zero because module entry is .text+0x0, " +
                    "with source R_MIPS_32 relocation. This is NOT the table terminator.";
                if(hasReloc(slot))record("PASS R_MIPS_32 at LOADCORE first export ordinal @"+a(slot));
                else record("NOTE no Ghidra relocation row at first export slot; byte identity and source ELF independently confirm it");
                bookmark(slot,"LOADCORE export ordinal zero is relocated module entry, not terminator");
            }
            note(slot,desc);
            if(n!=null)nameFunction(target,n);
            else if(loadcore&&i==0)nameFunction(target,"LoadcoreModuleEntry");
            if(currentProgram.getMemory().contains(a(target)))reference(slot,target);
            record(String.format(Locale.ROOT,"EXPORT %-8s ordinal=%02d slot=%08x target=%08x %s",lib,i,slot,target,n==null?"(unresolved)":n));
        }
    }
    private void recoverLoadcoreImports(DataType header) throws Exception {
        typeHeaderIfFree(0x1bf0,header);
        label(0x1bf0,"IopImportTable_sysmem");
        note(0x1bf0,"LOADCORE imports sysmem v1.01 ordinals 4,5,6; binding occurs in IOP RAM at runtime, not within this separate Ghidra program.");
        final int[] ordinal={4,5,6};
        final int[] targets={0x2ec,0x33c,0x204};
        for(int i=0;i<3;i++) {
            long stub=0x1c04L+i*8L;
            String method=SYSMEM_NAMES[ordinal[i]];
            label(stub,"IopImport_sysmem_Ordinal_"+String.format(Locale.ROOT,"%02d",ordinal[i]));
            String context="LOADCORE sysmem ordinal "+ordinal[i]+" ("+method+") " +
                "resolves to existing SYSMEM.bin function .text+0x"+Integer.toHexString(targets[i]);
            note(stub,context);
            bookmark(stub,context);
            int count=0;
            for(Reference ref:currentProgram.getReferenceManager().getReferencesTo(a(stub))) {
                if(!ref.getReferenceType().isCall())continue;
                long call=ref.getFromAddress().getOffset();
                note(call,"Call to "+method+" through LOADCORE's sysmem import ordinal " +ordinal[i]+"; target in the separate SYSMEM Ghidra program at 0x"+Integer.toHexString(targets[i])+".");
                count++;
            }
            record("IMPORT sysmem ordinal "+ordinal[i]+" -> SYSMEM.bin:0x"+Integer.toHexString(targets[i])+" "+method+"; Ghidra call sites="+count);
        }
        bookmark(0,"LOADCORE entry 0x0 initializes module loader before later configured modules, including SECRMAN. Boot registration is not evidence of MagicGate authentication.");
        note(0,"LOADCORE module entry; resolves SYSMEM imports, then boot-time module/library initialization. Do not assign fixed runtime IOP RAM placement from this unrelocated ELF.");
    }
    private void openReport() throws Exception {
        File downloads=new File(System.getProperty("user.home"),"Downloads");
        if(!downloads.isDirectory()) {record("REPORT not written: Downloads folder not found");return;}
        File file=new File(downloads,"IopExistingBootMetadata_"+(loadcore?"LOADCORE":"SYSMEM")+"_20261015_v1_"+System.currentTimeMillis()+".txt");
        report=new PrintWriter(file,"UTF-8");
        println("REPORT "+file.getAbsolutePath());
    }
    @Override protected void run() throws Exception {
        if(!check())return;
        openReport();
        try {
            record("Existing Ghidra program="+currentProgram.getName()+" SHA256="+currentProgram.getExecutableSHA256());
            record("Ghidra function count BEFORE="+currentProgram.getFunctionManager().getFunctionCount());
            DataType header=libHeader();
            recoverExports(header);
            if(loadcore) {
                recoverLoadcoreImports(header);
                note(0x30,"Bootstrap body reached by the module entry at .text+0x0; uses the IOPBOOT-provided context and SYSMEM allocator/free/size imports before setting up loader facilities.");
            } else {
                label(0xc80,"SysmemBootManagerState");
                note(0xc80,"GetSysmemInternalData (.text+0x460) returns this IOP RAM state address. Its exact structure must be verified; the version-specific BSS range does not justify applying all fields of a newer PS2SDK struct.");
            }
            record("SUMMARY functionRenames="+functionRenames+" functionsCreated="+functionsCreated+
                " labels="+labels+" comments="+comments+" references="+refsAdded+
                " datatypes+applications="+types+" bookmarks="+bookmarks+" preserved="+preserved);
            record("Ghidra function count AFTER="+currentProgram.getFunctionManager().getFunctionCount());
            record("No imported program bytes, user-defined signatures, or existing markup cleared.");
            record("SECRMAN configured for boot is not proof of actual MagicGate authentication.");
        } finally {
            if(report!=null){report.close();report=null;}
        }
    }
}