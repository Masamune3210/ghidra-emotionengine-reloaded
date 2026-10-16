// Dragon MechaCon 6.12, ROM-verified indirect callback resolution and focused
// ingress/egress decompilation. Runs against the EXISTING analyzed ARM program.
// Does not assume any internal 0x70/0x80/0x90 state equals an external SCMD.
// Preserves existing user names/signatures/instructions and all firmware bytes.
// Reports saved under Downloads, never the home directory.
//@category PS2.MechaCon.MagicGate

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import java.io.File;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public class TraceDragon612ControllerCallbacks_20261016_v2 extends GhidraScript {
    private static final String ROM_SHA =
        "18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b";
    private static final long TABLE = 0x38680L;
    private static final int COUNT = 18;
    private static final long[] CALLBACKS = {
        0x2a66dL,0x2a66fL,0x2a9d5L,0x2aa9dL,0x2ab65L,0x2afc9L,
        0x2b071L,0x2b119L,0x2b205L,0x2b2adL,0x2a66dL,0x2b43dL,
        0x2b491L,0x2b841L,0x2b843L,0x2b9e9L,0x2ba3dL,0x2b2adL
    };
    private static final String TAG = "DRAGON612_INDIRECT_FLOW: ";
    private int labelsAdded, namesChanged, refsAdded, commentsAdded, typedArrays, preserved;

    private Address addr(long a) {return toAddr(a);}
    private int u8(long a) throws Exception { return currentProgram.getMemory().getByte(addr(a)) & 0xff; }
    private int u16(long a) throws Exception {return u8(a) | u8(a+1)<<8;}
    private long u32(long a) throws Exception {
        return Integer.toUnsignedLong(u8(a) | u8(a+1)<<8 | u8(a+2)<<16 | u8(a+3)<<24);
    }
    private void expect16(long at,int word) throws Exception {
        if(u16(at)!=word) throw new IllegalStateException(String.format(Locale.ROOT,
            "Thumb instruction mismatch %08X expected=%04X actual=%04X",at,word,u16(at)));
    }
    private void expect32(long at,long value) throws Exception {
        if(u32(at)!=value) throw new IllegalStateException(String.format(Locale.ROOT,
            "ROM pointer mismatch %08X expected=%08X actual=%08X",at,value,u32(at)));
    }
    private void verify() throws Exception {
        if(!"ARM".equalsIgnoreCase(currentProgram.getLanguage().getProcessor().toString()) ||
                currentProgram.getLanguage().isBigEndian())
            throw new IllegalStateException("Expected existing little endian ARM Dragon program");
        MessageDigest dig=MessageDigest.getInstance("SHA-256");
        for(long p=0;p<0x44000L;p++) {
            if((p&0x3fff)==0) monitor.checkCancelled();
            dig.update(currentProgram.getMemory().getByte(addr(p)));
        }
        StringBuilder hex=new StringBuilder();
        for(byte b:dig.digest()) hex.append(String.format(Locale.ROOT,"%02x",b&255));
        if(!hex.toString().equals(ROM_SHA)) throw new IllegalStateException(
            "Unexpected MechaCon ROM SHA256="+hex);
        for(int i=0;i<COUNT;i++) expect32(TABLE+i*4L,CALLBACKS[i]);
        expect32(0x2a658L,0x02000488L); // selector byte
        expect32(0x2a65cL,TABLE);        // callback array literal
        expect32(0x2a660L,0x02000480L); // flags after callback
        expect32(0x2a668L,0x0200048cL); // status fields
        expect16(0x2a604L,0xb580); // push r7,lr
        expect16(0x2a608L,0x7800); // ldrb r0,[r0]
        expect16(0x2a60aL,0x0080); // shift index by two
        expect16(0x2a60eL,0x580f); // ldr r7,[r1,r0]
        expect16(0x2a610L,0xf00b); expect16(0x2a612L,0xf925); // bl bx-r7 thunk
        expect16(0x3585eL,0x4738); // bx r7
        expect16(0x29af2L,0xf000); expect16(0x29af4L,0xfd87); // caller -> dispatcher
        expect16(0x151c2L,0xf000); expect16(0x151c4L,0xfe05); // other dispatcher BL
        expect32(0x2baf8L,0x036000a0L);
        expect32(0x2bc74L,0x036000a0L);
        expect32(0x29e30L,0x03005000L);
        expect32(0x29e34L,0x03808000L);
        expect32(0x2bafcL,0x0200048cL);
        expect32(0x2bc78L,0x0200048cL);
        expect32(0x2bc7cL,0x02000496L);
        println("VERIFIED Dragon 6.12 SHA256 "+ROM_SHA);
        println("VERIFIED all 18 Thumb callback words, dispatcher and call-site opcodes");
        println("VERIFIED MMIO pointer literals 0x036000A0, 0x03005000, 0x03808000");
    }
    private void label(long pos, String name) {
        Address a=addr(pos);
        if(!currentProgram.getMemory().contains(a)) {preserved++;return;}
        for(Symbol s:currentProgram.getSymbolTable().getSymbols(a))
            if(name.equals(s.getName())) return;
        try {currentProgram.getSymbolTable().createLabel(a,name,SourceType.ANALYSIS);labelsAdded++;}
        catch(Exception e) {println("PRESERVE label "+a+" "+name+" "+e.getMessage());preserved++;}
    }
    private void note(long pos, String message) {
        Address a=addr(pos);
        if(!currentProgram.getMemory().contains(a))return;
        String old=getPlateComment(a);
        if(old!=null&&old.contains(TAG+message))return;
        setPlateComment(a,(old==null||old.isEmpty()?"":old+"\n")+TAG+message);
        commentsAdded++;
    }
    private void function(long pos, String name, String explanation) {
        Address a=addr(pos);
        Function f=getFunctionAt(a);
        if(f!=null && f.getSymbol().getSource()!=SourceType.USER_DEFINED &&
                (f.getName().startsWith("FUN_")||f.getName().startsWith("sub_"))) {
            try {f.setName(name,SourceType.ANALYSIS);namesChanged++;}
            catch(Exception ex){preserved++;}
        }
        // Not creating functions: existing Ghidra boundaries remain authoritative.
        label(pos,name);
        note(pos,explanation);
    }
    private boolean hasRef(long source, long destination) {
        for(Reference ref:currentProgram.getReferenceManager().getReferencesFrom(addr(source)))
            if(ref.getToAddress().equals(addr(destination)))return true;
        return false;
    }
    private void reference(long source,long target,RefType refType) {
        if(hasRef(source,target)) return;
        try {
            currentProgram.getReferenceManager().addMemoryReference(
                addr(source),addr(target),refType,SourceType.ANALYSIS,0);
            refsAdded++;
        } catch(Exception e) {
            println("PRESERVE reference "+addr(source)+" -> "+addr(target)+" "+e.getMessage());
            preserved++;
        }
    }
    private void declareTableIfFree() {
        Listing list=currentProgram.getListing();
        for(int i=0;i<COUNT*4;i++) {
            Address at=addr(TABLE+i);
            if(list.getInstructionContaining(at)!=null || list.getDefinedDataContaining(at)!=null) {
                println("PRESERVE preexisting callback table markup at "+at);
                preserved++; return;
            }
        }
        try {
            list.createData(addr(TABLE),new ArrayDataType(DWordDataType.dataType,COUNT,4));
            typedArrays++;
        } catch(Exception ex) {
            println("PRESERVE callback array datatype: "+ex.getMessage()); preserved++;
        }
    }
    private void annotate() {
        label(TABLE,"ControllerCallbackTable18_ThumbPointers");
        note(TABLE,"18 raw 32-bit callback addresses with ARM Thumb LSB=1. Selector at RAM " +
            "0x02000488 selects one table entry; the dispatcher branches via BX R7. " +
            "These entries are NOT the external MechaCon SCMD 0x80..0x97 table.");
        declareTableIfFree();
        for(int i=0;i<COUNT;i++) {
            long slot=TABLE+i*4L,target=CALLBACKS[i]&~1L;
            label(slot,String.format(Locale.ROOT,"ControllerCallbackSlot_%02d",i));
            note(slot,String.format(Locale.ROOT,"callback index %d -> Thumb function 0x%08X " +
                "(raw address 0x%08X, Thumb bit 1).",i,target,CALLBACKS[i]));
            reference(slot,target,RefType.DATA);
        }
        function(0x2a604L,"DispatchControllerCallbackByIndex",
            "Read callback index from RAM 0x02000488, calculate index*4, fetch " +
            "Thumb function pointer from 0x00038680, execute via 0x3585E BX R7 thunk.");
        function(0x3585eL,"BranchToR7",
            "Instruction BX R7 (0x4738), tail transfers to selected Thumb callback.");
        function(0x2bac4L,"TryStartControllerTransfer",
            "Reads peripheral control/status at 0x036000A1, on ready clears " +
            "controller flag at 0x02000480 and writes 0x20/status/2 to " +
            "0x036000A4/0x036000A8/0x036000A5. Actual peripheral identity not established.");
        function(0x2bc24L,"TrySendControllerByte",
            "Checks 0x036000A1 bits; writes 0x20 and next byte from RAM " +
            "0x02000496 through controller 0x036000A0+4/+8/+5. Existing argument type preserved.");
        function(0x29e0cL,"TriggerControllerCommand",
            "Writes input byte to peripheral 0x03005004, updates flags in " +
            "0x03005000, and writes 0x00010000 to 0x03808004. " +
            "An internal peripheral command, not identified as SCMD.");
        note(0x29af2L,"Verified Thumb BL from polling loop to 0x2A604; callback selection happens per loop iteration.");
        note(0x151c2L,"Verified Thumb BL to 0x15DD0, independent RAM-state dispatcher; " +
            "Ghidra earlier lacked a reference to 0x15DD0.");
        note(0x2a65cL,"ROM literal 0x00038680, address of the verified 18-entry Thumb callback table.");
        note(0x2baf8L,"ROM pointer to peripheral MMIO base 0x036000A0 (not SRAM).");
        note(0x2bc74L,"ROM pointer to same MMIO 0x036000A0.");
        note(0x29e30L,"ROM pointer to peripheral MMIO base 0x03005000.");
        note(0x29e34L,"ROM pointer to peripheral MMIO base 0x03808000.");
        label(0x02000488L,"ControllerCallbackIndex");
        label(0x0200048cL,"ControllerTransferByte");
        label(0x02000496L,"ControllerPendingByte");
        note(0x02000488L,"Index into table 0x38680; same RAM area as existing " +
            "state byte at 0x02000489. No externally sourced command relationship established.");
        reference(0x29af2L,0x2a604L,RefType.UNCONDITIONAL_CALL);
        reference(0x2a610L,0x3585eL,RefType.UNCONDITIONAL_CALL);
        reference(0x151c2L,0x15dd0L,RefType.UNCONDITIONAL_CALL);
    }
    private void report(PrintWriter out) throws Exception {
        out.println("Dragon 6.12, ROM SHA256="+ROM_SHA);
        out.println("Verified 18-entry Thumb indirect callback table 0x38680-0x386C7");
        out.println("Caller 0x29AF2 -> selector dispatcher 0x2A604; 0x2A60E loads R7; 0x3585E BX R7");
        out.println("Selector RAM=0x02000488; substate RAM=0x02000489");
        for(int i=0;i<COUNT;i++) {
            monitor.checkCancelled();
            long target=CALLBACKS[i]&~1L;
            Function f=getFunctionAt(addr(target));
            Function owner=f!=null?f:getFunctionContaining(addr(target));
            out.printf(Locale.ROOT,"slot=%02d raw=%08X thumb_entry=%08X function=%s%n",
                i,CALLBACKS[i],target,owner==null?"<undefined>":owner.getName()+"@"+owner.getEntryPoint());
        }
        out.println("CALLEE XREFS:");
        for(long target:new long[]{0x2a604,0x2afc8,0x2b070,0x15dd0}) {
            out.println(String.format(Locale.ROOT,"target %08x",target));
            for(Reference r:currentProgram.getReferenceManager().getReferencesTo(addr(target)))
                out.println("  "+r.getFromAddress()+" "+r.getReferenceType());
        }
        out.println("Controller MMIO evidence (ROM literal, value):");
        for(long location:new long[]{0x2baf8,0x2bc74,0x29e30,0x29e34})
            out.printf(Locale.ROOT,"  %08x -> %08x%n",location,u32(location));
        out.println("RAM addresses: selector 02000488, substate 02000489, transfer 0200048c, pending 02000496");
        out.println("No authentication SCMD or cryptographic handler identity proven.");
        out.println("Metadata: functionRenames="+namesChanged+" labels="+labelsAdded+
            " comments="+commentsAdded+" references="+refsAdded+
            " typedTables="+typedArrays+" preserved="+preserved);
    }
    private void decomp(PrintWriter out) {
        // New roots and ingress candidates, not a repeat of v1's eight decompilations.
        long[] roots={0x29af2,0x2a604,0x2a66e,0x151c2,0x12614,0x12694,
            0x12760,0x30380,0x16f94,0x2ea18,0x2ea88,0x31b84,0x374f8};
        Set<Address> done=new HashSet<>();
        DecompInterface dc=new DecompInterface();
        if(!dc.openProgram(currentProgram)) {
            out.println("Decompiler could not open program");dc.dispose();return;
        }
        try {
            for(long p:roots) {
                if(monitor.isCancelled())break;
                Function f=getFunctionContaining(addr(p));
                if(f==null || !done.add(f.getEntryPoint())) {
                    out.println(String.format(Locale.ROOT,"SKIP %08x: no distinct Ghidra function",p));
                    continue;
                }
                out.printf(Locale.ROOT,"%n===== %s @%s [requested %08x] =====%n",
                    f.getName(),f.getEntryPoint(),p);
                try {
                    DecompileResults dr=dc.decompileFunction(f,12,monitor);
                    if(dr!=null && dr.decompileCompleted() && dr.getDecompiledFunction()!=null) {
                        String c=dr.getDecompiledFunction().getC();
                        if(c.length()>25000) {
                            out.println(c.substring(0,25000));
                            out.println("TRUNCATED to 25000 chars");
                        } else out.println(c);
                    } else out.println("NOT DECOMPILED "+(dr==null?"null result":dr.getErrorMessage()));
                } catch(Exception ex) {out.println("Decompiler error: "+ex.getMessage());}
            }
        } finally {dc.dispose();}
    }
    @Override
    protected void run() throws Exception {
        verify();
        annotate();
        File downloads=new File(System.getProperty("user.home"),"Downloads");
        if(!downloads.isDirectory()) {
            printerr("Downloads folder not available; metadata kept, reports not emitted");return;
        }
        String stamp=Long.toString(System.currentTimeMillis());
        File audit=new File(downloads,"Dragon612_ControllerCallbackAudit_20261016_v2_"+stamp+".txt");
        File c=new File(downloads,"Dragon612_CommandIngressCandidates_20261016_v2_"+stamp+".txt");
        try(PrintWriter w=new PrintWriter(audit,"UTF-8")){report(w);}
        try(PrintWriter w=new PrintWriter(c,"UTF-8")){decomp(w);}
        println("DRAGON CALLBACK AUDIT "+audit.getAbsolutePath());
        println("DRAGON INGRESS CANDIDATES "+c.getAbsolutePath());
        println("DONE 18 callback slots; renames="+namesChanged+" labels="+labelsAdded+
            " comments="+commentsAdded+" references="+refsAdded+
            " typedTables="+typedArrays+" preserved="+preserved);
        println("No firmware bytes, existing function bodies, or signatures changed. No SCMD inferred.");
    }
}