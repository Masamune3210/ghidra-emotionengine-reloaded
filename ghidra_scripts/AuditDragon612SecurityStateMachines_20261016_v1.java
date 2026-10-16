// Dragon MechaCon 6.12 ARMv4T firmware: verify and document protocol-state
// discriminators without misidentifying them as SECRMAN/MagicGate commands.
// Run on the user's ALREADY ANALYZED Dragon_MechaCon_6_12_ARMv4T_Ghidra_20261015_v2.elf program.
// No reimport, function-body clearing, firmware modifications, or signature rewrites.
// Adds guarded labels/comments and optional BCD table data; writes a full report,
// decoded CMP-immediate candidate table, and selected decompilations to Downloads.
//@category PS2.MechaCon.MagicGate

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.listing.Bookmark;
import java.io.File;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class AuditDragon612SecurityStateMachines_20261016_v1 extends GhidraScript {
    private static final String EXPECTED_SHA =
        "18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b";
    private static final long ROM_SIZE = 0x44000L;
    private static final String TAG = "DRAGON612_VERIFIED: ";
    private int labels, comments, functions, dataItems, bookmarks, preserved;

    private Address a(long v) { return toAddr(v); }
    private int u8(long address) throws Exception {
        return currentProgram.getMemory().getByte(a(address)) & 255;
    }
    private int u16(long address) throws Exception {
        return u8(address) | (u8(address + 1) << 8);
    }
    private long u32(long address) throws Exception {
        return Integer.toUnsignedLong(u8(address) | (u8(address + 1) << 8) |
            (u8(address + 2) << 16) | (u8(address + 3) << 24));
    }
    private String sha() throws Exception {
        MessageDigest dig = MessageDigest.getInstance("SHA-256");
        for (long i = 0; i < ROM_SIZE; i++) {
            if ((i & 0x1fff) == 0) monitor.checkCancelled();
            dig.update(currentProgram.getMemory().getByte(a(i)));
        }
        StringBuilder s = new StringBuilder();
        for (byte b : dig.digest()) s.append(String.format(Locale.ROOT, "%02x", b & 255));
        return s.toString();
    }
    private void expect16(long address, int word) throws Exception {
        if (u16(address) != word)
            throw new IllegalStateException(String.format(Locale.ROOT,
                "ARM/Thumb anchor mismatch @%08x: expected=%04x got=%04x",
                address, word, u16(address)));
    }
    private void expect32(long address, long word) throws Exception {
        if (u32(address) != word)
            throw new IllegalStateException(String.format(Locale.ROOT,
                "ROM pointer mismatch @%08x expected=%08x got=%08x",
                address, word, u32(address)));
    }
    private void verify() throws Exception {
        if (!"ARM".equalsIgnoreCase(currentProgram.getLanguage().getProcessor().toString()) ||
                currentProgram.getLanguage().isBigEndian())
            throw new IllegalStateException("Expected little-endian ARM MechaCon program");
        if (currentProgram.getMemory().getBlock(a(0)) == null ||
                currentProgram.getMemory().getBlock(a(0x43fff)) == null)
            throw new IllegalStateException("The complete mapped 0x44000-byte ROM is required");
        String got = sha();
        if (!EXPECTED_SHA.equals(got))
            throw new IllegalStateException("ROM fingerprint mismatch: " + got);
        // Function entry opcodes and the direct CMP immediate sequences.
        expect16(0x15dd0, 0xb500); expect16(0x15dd4, 0x78c0);
        expect16(0x15dd6, 0x2890); expect16(0x15dda, 0x2891);
        expect16(0x15dde, 0x2892); expect16(0x15de2, 0x2893);
        expect16(0x2afc8, 0xb500); expect16(0x2afcc, 0x7840);
        expect16(0x2afce, 0x2870); expect16(0x2afd2, 0x2871);
        expect16(0x2afd6, 0x2872); expect16(0x2afda, 0x2873);
        expect16(0x2b070, 0xb500); expect16(0x2b074, 0x7840);
        expect16(0x2b076, 0x2880); expect16(0x2b07a, 0x2881);
        expect16(0x2b07e, 0x2882); expect16(0x2b082, 0x2883);
        // The LDR PC literal values prove the RAM base of each state byte.
        expect32(0x15ebc, 0x02000274L);
        expect32(0x2b068, 0x02000488L);
        expect32(0x2b110, 0x02000488L);
        expect32(0x25f04, 0x00038438L);
        for (int n = 0; n < 100; n++) {
            int bcd = (n / 10) * 16 + (n % 10);
            if (u8(0x38438L + n) != bcd)
                throw new IllegalStateException("BCD table mismatch at entry " + n);
        }
        println("VERIFIED Dragon 6.12 ROM SHA-256=" + got);
        println("VERIFIED three four-state dispatchers with RAM pointer literals");
        println("VERIFIED packed-BCD table 100/100 at 0x38438 (NOT a command table)");
    }
    private void label(long addr, String newName) {
        Address at = a(addr);
        if (!currentProgram.getMemory().contains(at)) {
            println("PRESERVE unmapped label " + newName + " @ " + at);
            preserved++; return;
        }
        for (Symbol s : currentProgram.getSymbolTable().getSymbols(at)) {
            if (s.getName().equals(newName)) return;
        }
        try {
            currentProgram.getSymbolTable().createLabel(at, newName, SourceType.ANALYSIS);
            labels++;
        } catch (Exception ex) {
            println("PRESERVE existing symbol at " + at + ": " + ex.getMessage());
            preserved++;
        }
    }
    private void note(long addr, String message) {
        Address at = a(addr);
        if (!currentProgram.getMemory().contains(at)) return;
        String before = getPlateComment(at);
        if (before != null && before.contains(TAG + message)) return;
        setPlateComment(at, (before == null || before.isEmpty()) ? TAG + message :
            before + "\n" + TAG + message);
        comments++;
    }
    private void mark(long address, String proposedName, String evidence) {
        Address at = a(address);
        Function f = getFunctionAt(at);
        if (f != null && (f.getName().startsWith("FUN_") ||
                f.getName().startsWith("sub_")) &&
                f.getSymbol().getSource() != SourceType.USER_DEFINED) {
            try { f.setName(proposedName, SourceType.ANALYSIS); functions++; }
            catch (Exception ex) { preserved++; }
        }
        // If Ghidra has placed the entry inside a larger function, do not
        // split that function or rewrite its control flow.
        if (f == null && getFunctionContaining(at) != null) {
            println("PRESERVE existing function boundary at " + at);
            preserved++;
        }
        label(address, proposedName);
        note(address, evidence);
    }
    private void bookmark(long address, String text) {
        Address at = a(address);
        for (Bookmark bm : currentProgram.getBookmarkManager().getBookmarks(at)) {
            if ("Dragon 6.12 Protocol".equals(bm.getCategory()) &&
                    text.equals(bm.getComment())) return;
        }
        currentProgram.getBookmarkManager().setBookmark(at, "Analysis",
            "Dragon 6.12 Protocol", text);
        bookmarks++;
    }
    private void typeBcd() throws Exception {
        Address start = a(0x38438L);
        Listing listing = currentProgram.getListing();
        for (int i = 0; i < 100; i++) {
            Address p = start.add(i);
            if (listing.getInstructionContaining(p) != null ||
                    listing.getDefinedDataContaining(p) != null) {
                println("PRESERVE BCD table existing markup at " + p);
                preserved++;
                return;
            }
        }
        try {
            listing.createData(start, new ArrayDataType(ByteDataType.dataType, 100, 1));
            dataItems++;
        } catch (Exception ex) {
            println("PRESERVE BCD data type: " + ex.getMessage());
            preserved++;
        }
    }
    private void typeStateByte(long address) {
        Address at = a(address);
        Listing listing = currentProgram.getListing();
        if (listing.getInstructionContaining(at) != null ||
                listing.getDefinedDataContaining(at) != null) {
            println("PRESERVE state-byte markup at " + at);
            preserved++; return;
        }
        try {
            listing.createData(at, ByteDataType.dataType);
            dataItems++;
        } catch (Exception ex) {
            println("PRESERVE state-byte datatype at " + at + ": " + ex.getMessage());
            preserved++;
        }
    }
    private void annotate() throws Exception {
        mark(0x15dd0L, "DispatchState90To93",
            "Thumb dispatcher checks internal byte [0x02000274 + 3] against 0x90..0x93. " +
            "Separate RAM base 0x02000274. Meaning of these state values and any " +
            "relationship to CDVD SCMD/MagicGate NOT established.");
        mark(0x2afc8L, "DispatchState70To73",
            "Thumb dispatcher checks internal byte [0x02000488 + 1] against 0x70..0x73. " +
            "Shares state RAM with DispatchState80To83, not with DispatchState90To93.");
        mark(0x2b070L, "DispatchState80To83",
            "Thumb dispatcher checks internal byte [0x02000488 + 1] against 0x80..0x83. " +
            "It is NOT proven to implement mechacon authentication SCMD 0x80..0x83.");
        label(0x02000277L, "StateByte_02000277");
        note(0x02000277L,
            "State byte read by Thumb function 0x15DD0, values 0x90..0x93. " +
            "Indirect memory operand uses base pointer literal 0x15EBC (0x02000274), offset +3.");
        typeStateByte(0x02000277L);
        label(0x02000489L, "StateByte_02000489");
        note(0x02000489L,
            "Shared state byte read by Thumb functions 0x2AFC8 and 0x2B070, " +
            "values 0x70..0x73 and 0x80..0x83, respectively. " +
            "Base pointer 0x02000488; offset +1. Command identity not established.");
        typeStateByte(0x02000489L);
        label(0x38438L, "PackedBcd00To99_Lookup");
        note(0x38438L,
            "Verified 100-byte table of packed BCD values 0x00..0x99, " +
            "in numerical order for decimal indices 0..99. Bytes 0x80..0x97 " +
            "here are *not* the MagicGate command sequence. " +
            "One code literal reference is 0x25F04.");
        typeBcd();
        bookmark(0x15dd0L, "Candidate protocol state dispatcher, not an identified SCMD handler");
        bookmark(0x2b070L, "Candidate protocol state dispatcher, not an identified SCMD handler");
        bookmark(0x38438L, "Verified packed BCD lookup, do not misidentify as SCMD table");
        note(0x151c2L,
            "Verified Thumb BL from 0x151C2 to 0x15DD0. " +
            "This establishes an inbound call to DispatchState90To93. " +
            "Caller logic must be traced before assigning security semantics.");
    }
    private void emitReferences(PrintWriter out, long dest) {
        Address target = a(dest);
        out.println("\nREFERENCES TO " + target);
        int count = 0;
        for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(target)) {
            Function caller = getFunctionContaining(ref.getFromAddress());
            out.println("  from " + ref.getFromAddress() + " " + ref.getReferenceType() +
                " in " + (caller == null ? "<no function>" :
                    caller.getName() + " @" + caller.getEntryPoint()));
            if (++count == 200) { out.println("  ...truncated 200"); break; }
        }
        out.println("  referenceCountShown=" + count);
    }
    private long constantOperand(Instruction ins) {
        if (!ins.getMnemonicString().toLowerCase(Locale.ROOT).startsWith("cmp"))
            return -1;
        if (ins.getNumOperands() < 2) return -1;
        for (Object object : ins.getOpObjects(1)) {
            if (object instanceof Scalar) return ((Scalar) object).getUnsignedValue();
        }
        return -1;
    }
    private int emitComparisons(PrintWriter out, PrintWriter tsv) throws Exception {
        int found = 0;
        for (Instruction ins : currentProgram.getListing().getInstructions(true)) {
            long addr = ins.getAddress().getOffset();
            if (addr >= 0x37800L || addr > 0xffffffffL) continue;
            if ((found & 511) == 0) monitor.checkCancelled();
            long v = constantOperand(ins);
            if (v < 0x70 || v > 0x97) continue;
            Function fn = getFunctionContaining(ins.getAddress());
            String name = fn == null ? "<unknown>" : fn.getName();
            tsv.printf(Locale.ROOT,"%08x\t%02x\t%s\t%s%n",
                addr, v, name, ins.toString().replace('\t',' '));
            out.printf(Locale.ROOT, "  0x%08X CMP 0x%02X in %s: %s%n",
                addr,v,name,ins.toString());
            found++;
        }
        out.println("CMP candidates (decoded instructions, immediate 0x70..0x97): " + found);
        out.println("CMP values alone are NOT evidence of SCMD/MagicGate support.");
        return found;
    }
    private void decompileTargets(PrintWriter out) {
        long[] targetStarts = {0x15dd0L,0x2afc8L,0x2b070L,0x1610cL,
            0x24dc8L,0x2bac4L,0x2bc24L,0x29e0cL};
        Set<Address> seen = new HashSet<>();
        DecompInterface interface_ = new DecompInterface();
        if (!interface_.openProgram(currentProgram)) {
            out.println("Decompiler failed to open program");
            interface_.dispose(); return;
        }
        try {
            for (long offset : targetStarts) {
                if (monitor.isCancelled()) break;
                Address start = a(offset);
                Function function = getFunctionContaining(start);
                if (function == null || !seen.add(function.getEntryPoint())) {
                    out.println("\nSKIP decompilation @"+start+" (no unique function)");
                    continue;
                }
                out.println("\n===== " + function.getName() + " @"+
                    function.getEntryPoint() + " (requested " + start + ") =====");
                try {
                    DecompileResults result = interface_.decompileFunction(function, 12, monitor);
                    if (result != null && result.decompileCompleted() &&
                            result.getDecompiledFunction() != null) {
                        String c = result.getDecompiledFunction().getC();
                        if (c.length() > 50000) {
                            out.println(c.substring(0,50000));
                            out.println("... decompiled text truncated at 50000 characters");
                        } else out.println(c);
                    } else {
                        out.println("NOT DECOMPILED: " +
                            (result == null ? "no result" : result.getErrorMessage()));
                    }
                } catch (Exception ex) {
                    out.println("Decompiler error: " + ex.getMessage());
                }
            }
        } finally { interface_.dispose(); }
    }
    @Override
    protected void run() throws Exception {
        // Complete validation happens before modifying metadata.
        verify();
        annotate();
        File downloads = new File(System.getProperty("user.home"), "Downloads");
        if (!downloads.isDirectory()) {
            printerr("No Downloads directory; metadata applied, report not written");
            return;
        }
        String stamp = String.valueOf(System.currentTimeMillis());
        File report = new File(downloads,
            "Dragon612_SecurityStateAudit_20261016_v1_" + stamp + ".txt");
        File tsv = new File(downloads,
            "Dragon612_CmpImmediateCandidates_20261016_v1_" + stamp + ".tsv");
        File cfile = new File(downloads,
            "Dragon612_ProtocolDecomp_20261016_v1_" + stamp + ".txt");
        int candidates;
        try (PrintWriter out = new PrintWriter(report,"UTF-8");
                PrintWriter candidatesOut = new PrintWriter(tsv,"UTF-8")) {
            out.println("Dragon MechaCon 6.12, exact ROM SHA=" + EXPECTED_SHA);
            out.println("Language=" + currentProgram.getLanguageID() +
                " Functions=" + currentProgram.getFunctionManager().getFunctionCount());
            out.println("Verified Thumb state dispatchers:");
            out.println("  0x15DD0: CMP 90,91,92,93; source RAM 0x02000277");
            out.println("  0x2AFC8: CMP 70,71,72,73; source RAM 0x02000489");
            out.println("  0x2B070: CMP 80,81,82,83; source RAM 0x02000489");
            out.println("  0x38438: BCD table [100] (negative control, not SCMD)");
            out.println("None of these state values proves a MechaCon SCMD opcode.");
            for (long location : new long[]{0x15dd0L,0x2afc8L,0x2b070L,
                    0x02000277L,0x02000489L,0x38438L})
                emitReferences(out,location);
            out.println("\nDECODED CMP IMMEDIATE EVIDENCE");
            candidatesOut.println("address\tvalue_hex\tcontaining_function\tinstruction");
            candidates = emitComparisons(out,candidatesOut);
            out.println("\nMETA changes: functionRenames=" + functions +
                " labels=" + labels + " comments=" + comments +
                " typedData=" + dataItems + " bookmarks=" + bookmarks +
                " preserved=" + preserved);
            out.println("No ROM bytes, function signatures, or existing function bodies modified.");
            out.println("Further work: trace command ingress, MechaCon hardware register writes,");
            out.println("challenge data buffers and status result path before comparing with");
            out.println("PCSX2 CDVD SCMD cases 0x80..0x97 and memory-card authentication.");
        }
        try (PrintWriter out = new PrintWriter(cfile, "UTF-8")) {
            out.println("Dragon 6.12 selected firmware decompilations (auditable evidence)");
            out.println("These functions are NOT yet asserted to be MagicGate routines.");
            decompileTargets(out);
        }
        println("REPORT " + report.getAbsolutePath());
        println("CMP CANDIDATES " + tsv.getAbsolutePath() + " count="+candidates);
        println("SELECTED DECOMP " + cfile.getAbsolutePath());
        println("DRAGON 6.12 COMPLETE: renamedFunctions="+functions+
            " labels="+labels+" comments="+comments+" typedData="+dataItems+
            " bookmarks="+bookmarks+" preserved="+preserved);
        println("No security handlers inferred solely from matching SCMD numeric values.");
    }
}