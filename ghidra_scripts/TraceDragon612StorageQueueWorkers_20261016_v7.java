// Read-only Dragon 6.12 addressable-storage queue and readback verification trace.
//@category PS2.MechaCon.MagicGate
// Run inside the existing, analyzed Dragon 6.12 ARM/Thumb Ghidra program.
// Outputs TWO timestamped reports into the current Windows user's Downloads/1 directory.
// Does not create functions, rename symbols, alter signatures, modify bytes, or write database metadata.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.BufferedWriter;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class TraceDragon612StorageQueueWorkers_20261016_v7 extends GhidraScript {
    private static final int ROM_SIZE = 0x44000;
    private static final String EXPECTED_SHA256 = "18371ba394e6339d861cfe19db7db7c9e44c8067114888421ee4a35feaaeba1b";
    private static final long CALLBACK_TABLE = 0x38680L;
    private static final long[] CALLBACK_POINTERS = {
        0x0002a66dL, 0x0002a66fL, 0x0002a9d5L, 0x0002aa9dL,
        0x0002ab65L, 0x0002afc9L, 0x0002b071L, 0x0002b119L,
        0x0002b205L, 0x0002b2adL, 0x0002a66dL, 0x0002b43dL,
        0x0002b491L, 0x0002b841L, 0x0002b843L, 0x0002b9e9L,
        0x0002ba3dL, 0x0002b2adL
    };
    private static final long[] ROOTS = {
        0x00008464L, // read-buffer operation
        0x00008658L, // queue a write at a 16-bit location
        0x000086d0L, // queue, wait, then verify returned bytes
        0x000087d0L, // related storage queue operation
        0x000088f0L, // readback helper
        0x0000364cL, // reads 0xE3 and 0xE8 locations
        0x00014270L, // writes 0xC0 then transformed data
        0x00003558L, // eight-byte block transforms
        0x00002f6cL  // separate hardware-backed transform helper
    };
    private static final long[] XREF_TARGETS = {
        0x00008464L, 0x00008658L, 0x000086d0L, 0x000087d0L,
        0x000088f0L, 0x0000364cL, 0x00014270L, 0x00003558L
    };
    private static final long[] STORAGE_POINTER_LITERALS = {
        0x000086c0L, 0x000086c4L, 0x000086c8L, 0x000086ccL,
        0x000087bcL, 0x000087c0L, 0x000087c4L, 0x000087c8L,
        0x000087ccL, 0x00003040L
    };

    private final Map<Long, Function> decompileTargets = new LinkedHashMap<>();
    private Memory mem;
    private Listing listing;
    private ReferenceManager refs;

    @Override
    protected void run() throws Exception {
        mem = currentProgram.getMemory();
        listing = currentProgram.getListing();
        refs = currentProgram.getReferenceManager();
        Path downloads = Paths.get(System.getProperty("user.home"), "Downloads", "1");
        Files.createDirectories(downloads);
        String suffix = Long.toString(System.currentTimeMillis());
        Path indexPath = downloads.resolve("Dragon612_StorageQueueWorkers_20261016_v7_" + suffix + ".txt");
        Path bodiesPath = downloads.resolve("Dragon612_StorageQueueBodies_20261016_v7_" + suffix + ".txt");
        byte[] rom = new byte[ROM_SIZE];
        int got;
        try {
            got = mem.getBytes(toAddr(0), rom);
        } catch (Exception e) {
            printerr("ROM memory read failed; no analysis applied: " + e);
            return;
        }
        if (got != ROM_SIZE) {
            printerr("ROM memory length mismatch: got " + got + ", expected " + ROM_SIZE + "; no analysis applied.");
            return;
        }
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        String digest = hex(sha.digest(rom));
        if (!EXPECTED_SHA256.equalsIgnoreCase(digest)) {
            printerr("Dragon 6.12 ROM SHA-256 mismatch " + digest + " expected " + EXPECTED_SHA256 + "; no analysis applied.");
            return;
        }
        for (int i = 0; i < CALLBACK_POINTERS.length; i++) {
            long word = unsigned32(mem.getInt(toAddr(CALLBACK_TABLE + 4L * i)));
            if (word != CALLBACK_POINTERS[i]) {
                printerr(String.format("Callback table mismatch at %08X: got %08X expected %08X; no analysis applied.", CALLBACK_TABLE + 4L * i, word, CALLBACK_POINTERS[i]));
                return;
            }
        }
        println("VERIFIED Dragon 6.12 ROM SHA256 " + digest + "; 18 Thumb callback pointers exact");
        try (PrintWriter index = writer(indexPath); PrintWriter bodies = writer(bodiesPath)) {
            index.println("DRAGON 6.12 ADDRESSABLE STORAGE QUEUE AUDIT v7 (READ ONLY)");
            index.println("SHA256 " + digest + " ROM bytes=0x44000; 18 callback words exact");
            index.println("Aim: resolve queue worker and readback for addressable offsets C0/E3/E8. Larger-than-byte offsets disprove simple SCMD mapping.");
            index.println("All offsets in this report are ROM addresses unless explicitly prefixed RAM/MMIO.");
            index.println();
            dumpRootInstructionWindows(index);
            dumpXrefs(index);
            dumpStoragePointerConsumers(index, rom);
            dumpDecompilations(bodies);
            index.println("\nNEXT EVIDENCE REQUIRED: identify backing region and queue worker, not command opcodes; investigate transform hardware separately.");
            index.println("Metadata changes: NONE; program contents and existing annotations preserved.");
        }
        println("DRAGON EDGE AUDIT " + indexPath);
        println("DRAGON CALLBACK BODIES " + bodiesPath);
        println("DONE read-only; unique function bodies requested=" + decompileTargets.size());
    }

    private void dumpCallbacks(PrintWriter out) {
        out.println("===== VERIFIED CALLBACK SLOTS (NO NEW FUNCTION CREATION) =====");
        Set<Long> distinct = new LinkedHashSet<>();
        for (int i = 0; i < CALLBACK_POINTERS.length; i++) {
            long raw = CALLBACK_POINTERS[i];
            long entry = raw & ~1L;
            distinct.add(entry);
            Function at = listing.getFunctionAt(toAddr(entry));
            Function owner = listing.getFunctionContaining(toAddr(entry));
            Instruction ins = listing.getInstructionAt(toAddr(entry));
            out.printf(Locale.ROOT, "slot=%02d table=%08X raw=%08X thumbEntry=%08X at=%s containing=%s instruction=%s%n",
                    i, CALLBACK_TABLE + 4L * i, raw, entry, functionName(at), functionName(owner), inst(ins));
            if (at != null) decompileTargets.putIfAbsent(at.getEntryPoint().getOffset(), at);
            else if (owner != null) decompileTargets.putIfAbsent(owner.getEntryPoint().getOffset(), owner);
        }
        out.println("distinct entry addresses=" + distinct.size() + "; duplicate slots are NOT new handlers");
        out.println();
    }

    private void dumpRootInstructionWindows(PrintWriter out) {
        out.println("===== ROOTS AND CALL-SITE INSTRUCTION WINDOWS =====");
        for (long offset : ROOTS) {
            Address a = toAddr(offset);
            Function exact = listing.getFunctionAt(a);
            Function owner = listing.getFunctionContaining(a);
            out.printf(Locale.ROOT, "\nROOT %08X exact=%s owner=%s%n", offset, functionName(exact), functionName(owner));
            if (owner != null) decompileTargets.putIfAbsent(owner.getEntryPoint().getOffset(), owner);
            dumpWindow(out, a, 7, 12);
        }
        out.println();
    }

    private void dumpXrefs(PrintWriter out) {
        out.println("===== TWO-HOP REFERENCES TO STORAGE QUEUE AND READBACK FUNCTIONS =====");
        for (long target : XREF_TARGETS) {
            out.printf(Locale.ROOT, "\nTARGET %08X %s%n", target, functionName(listing.getFunctionContaining(toAddr(target))));
            ReferenceIterator it = refs.getReferencesTo(toAddr(target));
            int count = 0;
            Set<Long> seenCallers = new LinkedHashSet<>();
            while (it.hasNext() && count < 20) {
                Reference r = it.next();
                Address from = r.getFromAddress();
                Function owner = listing.getFunctionContaining(from);
                out.printf(Locale.ROOT, "  FROM %s type=%s owner=%s instr=%s%n",
                        from, r.getReferenceType(), functionName(owner), inst(listing.getInstructionAt(from)));
                if (owner != null) {
                    if (decompileTargets.size() < 28) decompileTargets.putIfAbsent(owner.getEntryPoint().getOffset(), owner);
                    seenCallers.add(owner.getEntryPoint().getOffset());
                }
                count++;
            }
            if (count == 0) out.println("  no Ghidra references to exact entry; may be indirect or unanalyzed");
            for (long caller : seenCallers) {
                ReferenceIterator higher = refs.getReferencesTo(toAddr(caller));
                int n = 0;
                while (higher.hasNext() && n < 12) {
                    Reference r = higher.next();
                    Function f = listing.getFunctionContaining(r.getFromAddress());
                    out.printf(Locale.ROOT, "    UPSTREAM %s type=%s owner=%s%n", r.getFromAddress(), r.getReferenceType(), functionName(f));
                    n++;
                }
            }
        }
        out.println();
    }


    private void dumpStoragePointerConsumers(PrintWriter out, byte[] rom) {
        out.println("===== STORAGE POINTER LITERALS AND EXACT-ADDRESS CONSUMERS =====");
        out.println("ROM data equality and Ghidra code xrefs are separate evidence levels.");
        Set<Long> seenValues = new LinkedHashSet<>();
        for (long poolAt : STORAGE_POINTER_LITERALS) {
            if (monitor.isCancelled()) break;
            long value = unsigned32(mem.getInt(toAddr(poolAt)));
            out.printf(Locale.ROOT, "\nQUEUE_LITERAL %08X = %08X%n", poolAt, value);
            if (value < 0x02000000L || value >= 0x04000000L) {
                out.println("  outside RAM/MMIO candidate range; do not chase");
                continue;
            }
            if (!seenValues.add(value)) {
                out.println("  already inspected duplicate pointer value");
                continue;
            }
            int hits = 0;
            for (int at = 0; at + 4 <= rom.length; at += 4) {
                if (monitor.isCancelled()) break;
                long candidate = ((long)rom[at] & 0xff) |
                    (((long)rom[at+1] & 0xff) << 8) |
                    (((long)rom[at+2] & 0xff) << 16) |
                    (((long)rom[at+3] & 0xff) << 24);
                if (candidate != value) continue;
                if (++hits > 40) { out.println("  truncated after 40 occurrences"); break; }
                ReferenceIterator iter = refs.getReferencesTo(toAddr(at));
                int refsCount = 0;
                while (iter.hasNext() && refsCount < 12) {
                    Reference ref = iter.next();
                    Address use = ref.getFromAddress();
                    Function owner = listing.getFunctionContaining(use);
                    out.printf(Locale.ROOT, "  POOL %08X USE %s type=%s owner=%s instruction=%s%n",
                        at, use, ref.getReferenceType(), functionName(owner),
                        inst(listing.getInstructionAt(use)));
                    if (owner != null && decompileTargets.size() < 28)
                        decompileTargets.putIfAbsent(owner.getEntryPoint().getOffset(), owner);
                    refsCount++;
                }
                if (refsCount == 0) out.printf(Locale.ROOT, "  POOL %08X (no Ghidra xref)%n", at);
            }
            out.println("  matching literal occurrences=" + hits);
        }
        out.println("No pointer literal by itself proves dynamic access or device identity.");
        out.println();
    }

    private void dumpRamAndMmioLiterals(PrintWriter out, byte[] rom) {
        out.println("===== ROM LITTLE-ENDIAN RAM/MMIO POINTER LITERALS =====");
        out.println("Include 0x020002xx / 0x020004xx regions because code may load a base pointer then use byte offsets; literals alone DO NOT prove a read/write.");
        int matches = 0;
        for (int at = 0; at + 4 <= ROM_SIZE; at += 4) {
            long val = ((long)rom[at] & 0xff) | (((long)rom[at + 1] & 0xff) << 8) |
                       (((long)rom[at + 2] & 0xff) << 16) | (((long)rom[at + 3] & 0xff) << 24);
            boolean ramRegion = (val >= 0x02000200L && val <= 0x020002ffL) ||
                                (val >= 0x02000400L && val <= 0x020004ffL);
            boolean mmio = val == 0x036000a0L || val == 0x03005000L || val == 0x03808000L;
            if (!ramRegion && !mmio) continue;
            matches++;
            out.printf(Locale.ROOT, "LITERAL %08X -> %08X%s%n", at, val, mmio ? " MMIO" : " RAM");
            ReferenceIterator it = refs.getReferencesTo(toAddr(at));
            int n = 0;
            while (it.hasNext() && n < 20) {
                Reference r = it.next();
                Function f = listing.getFunctionContaining(r.getFromAddress());
                out.printf(Locale.ROOT, "  CODE_REF %s type=%s owner=%s instr=%s%n",
                        r.getFromAddress(), r.getReferenceType(), functionName(f), inst(listing.getInstructionAt(r.getFromAddress())));
                if (f != null && decompileTargets.size() < 100) {
                    decompileTargets.putIfAbsent(f.getEntryPoint().getOffset(), f);
                }
                n++;
            }
            if (n == 0) out.println("  no Ghidra xref (possibly missing literal-pool references)");
        }
        out.println("literal matches=" + matches);
        out.println("Target fields: selector RAM 02000488; substate 02000489; transfer 0200048C; pending 02000496; separate 90-state RAM 02000277.");
        out.println();
    }

    private void dumpUnresolvedCallbackWindows(PrintWriter out) {
        out.println("===== CALLBACK ENTRIES WITH NO FUNCTION START =====");
        Set<Long> seen = new LinkedHashSet<>();
        for (long word : CALLBACK_POINTERS) {
            long entry = word & ~1L;
            if (!seen.add(entry)) continue;
            if (listing.getFunctionAt(toAddr(entry)) != null) continue;
            out.printf(Locale.ROOT, "\nUNRESOLVED ENTRY %08X owner=%s%n", entry, functionName(listing.getFunctionContaining(toAddr(entry))));
            dumpWindow(out, toAddr(entry), 5, 14);
        }
        out.println("No functions were auto-created: these entry points may share bodies, jump into a neighboring function, or need ARM/Thumb context review.");
    }

    private void dumpDecompilations(PrintWriter out) {
        out.println("DRAGON 6.12 STORAGE QUEUE FUNCTION BODIES v7; read-only snapshot");
        out.println("SHA256 " + EXPECTED_SHA256);
        out.println("Includes write/read queue, readback verifier and bounded storage-pointer users.");
        out.println("Decompiled C is diagnostic only; addresses C0/E3/E8 are not verified SCMDs.");
        DecompInterface ifc = new DecompInterface();
        ifc.setSimplificationStyle("decompile");
        if (!ifc.openProgram(currentProgram)) {
            out.println("DECOMPILER FAILED TO OPEN PROGRAM: " + ifc.getLastMessage());
            ifc.dispose();
            return;
        }
        int done = 0;
        for (Map.Entry<Long, Function> e : decompileTargets.entrySet()) {
            if (monitor.isCancelled() || done >= 28) break;
            Function f = e.getValue();
            if (f.isExternal()) continue;
            out.printf(Locale.ROOT, "\n===== %s @%s =====%n", f.getName(), f.getEntryPoint());
            out.println("signature: " + f.getPrototypeString(false, false));
            try {
                DecompileResults res = ifc.decompileFunction(f, 25, monitor);
                if (!res.decompileCompleted() || res.getDecompiledFunction() == null) {
                    out.println("DECOMPILATION INCOMPLETE: " + res.getErrorMessage());
                } else {
                    String c = res.getDecompiledFunction().getC();
                    if (c.length() > 32000) {
                        out.print(c.substring(0, 32000));
                        out.println("\n[TRUNCATED after 32000 characters: use Ghidra for full body]");
                    } else {
                        out.println(c);
                    }
                }
            } catch (Exception ex) {
                out.println("DECOMPILATION EXCEPTION: " + ex);
            }
            done++;
        }
        ifc.dispose();
        out.println("\nDecompilations attempted=" + done + "; total selected=" + decompileTargets.size());
    }

    private void dumpWindow(PrintWriter out, Address center, int before, int after) {
        Instruction cur = listing.getInstructionAt(center);
        if (cur == null) cur = listing.getInstructionContaining(center);
        if (cur == null) {
            out.println("  No instruction at address (possibly data or unrecognized Thumb entry)");
            return;
        }
        Instruction first = cur;
        for (int i = 0; i < before; i++) {
            Instruction prev = listing.getInstructionBefore(first.getAddress());
            if (prev == null || prev.getAddress().getOffset() + 32 < first.getAddress().getOffset()) break;
            first = prev;
        }
        int max = before + after + 1;
        Instruction it = first;
        for (int i = 0; i < max && it != null; i++) {
            out.printf(Locale.ROOT, "  %s %s%s%n", it.getAddress(), inst(it),
                    it.getAddress().equals(cur.getAddress()) ? "   <== target" : "");
            Instruction next = listing.getInstructionAfter(it.getAddress());
            if (next == null || it.getAddress().getOffset() + 32 < next.getAddress().getOffset()) break;
            it = next;
        }
    }

    private String functionName(Function f) {
        return f == null ? "<none>" : f.getName() + "@" + f.getEntryPoint();
    }

    private String inst(Instruction i) {
        return i == null ? "<not an instruction>" : i.toString();
    }

    private PrintWriter writer(Path path) throws Exception {
        return new PrintWriter(new BufferedWriter(Files.newBufferedWriter(path)));
    }

    private static long unsigned32(int n) { return n & 0xffffffffL; }

    private static String hex(byte[] bytes) {
        StringBuilder b = new StringBuilder();
        for (byte v : bytes) b.append(String.format(Locale.ROOT, "%02x", v & 0xff));
        return b.toString();
    }
}