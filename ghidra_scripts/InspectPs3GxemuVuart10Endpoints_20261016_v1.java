// Analyze verified virtual UART port-10 call sites in ps2_gxemu.
// @category PS3.PS2Emulation
// Read-only: no labels, signatures, data types, function promotions or byte changes.
// Intended for PowerPC:BE:64:A2ALT on Ghidra 12.1.x.
// Send the complete script output to follow the virtual UART transport into MechaCon.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class InspectPs3GxemuVuart10Endpoints_20261016_v1 extends GhidraScript {
    private static final long[] PORT10_CALLS = {
        0x0008FCA0L, // known read, from FUN_0008FC68
        0x0008FF24L, // write, owner unresolved
        0x000900D0L, // write, owner unresolved
        0x000901C8L, // write, from FUN_000900FC
        0x000903D8L  // write, owner unresolved
    };
    private static final long[] EXPECTED_TARGETS = {
        0x00049544L, 0x000494A4L, 0x000494A4L,
        0x000494A4L, 0x000494A4L
    };
    private static final long[] DESCRIPTORS = {
        0x006470A0L, 0x006470B8L, 0x006470E8L, 0x00647100L
    };
    private static final long[] DESCRIPTOR_TARGETS = {
        0x000494A4L, 0x00049544L, 0x000495B8L, 0x00049664L
    };
    private static final int CONTEXT_BEFORE = 22;
    private static final int CONTEXT_AFTER = 12;

    private Address addr(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private void printInstruction(Instruction ins) throws Exception {
        byte[] b = ins.getBytes();
        StringBuilder h = new StringBuilder();
        for (byte v : b)
            h.append(String.format("%02X", v & 255));
        println("    " + ins.getAddress() + " [" + h + "] " + ins);
    }

    private void context(Address target) throws Exception {
        Instruction at = currentProgram.getListing().getInstructionAt(target);
        if (at == null) {
            println("CONTEXT_MISSING " + target);
            return;
        }
        ArrayList<Instruction> before = new ArrayList<Instruction>();
        Instruction it = at;
        for (int i = 0; i < CONTEXT_BEFORE; i++) {
            it = currentProgram.getListing().getInstructionBefore(it.getAddress());
            if (it == null)
                break;
            before.add(0, it);
        }
        println("CONTEXT_START " + target);
        for (Instruction ins : before)
            printInstruction(ins);
        printInstruction(at);
        it = at;
        for (int i = 0; i < CONTEXT_AFTER; i++) {
            it = currentProgram.getListing().getInstructionAfter(it.getAddress());
            if (it == null)
                break;
            printInstruction(it);
        }
        println("CONTEXT_END " + target);
    }

    private void refsTo(Address target) throws Exception {
        ReferenceIterator iterator = currentProgram.getReferenceManager().getReferencesTo(target);
        int count = 0;
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Reference ref = iterator.next();
            count++;
            if (count <= 75)
                println("  REF_TO " + target + " FROM " + ref.getFromAddress() +
                    " TYPE " + ref.getReferenceType());
        }
        println("REF_TO_COUNT " + target + " " + count);
    }

    private void describeFunction(Address a, DecompInterface decompiler, Set<Address> decompiled) throws Exception {
        Function containing = currentProgram.getFunctionManager().getFunctionContaining(a);
        Function before = currentProgram.getFunctionManager().getFunctionBefore(a);
        Function after = currentProgram.getFunctionManager().getFunctionAfter(a);
        println("OWNER_FOR " + a + " = " + (containing == null ? "<none>" :
            containing.getName() + " entry=" + containing.getEntryPoint() +
            " body=" + containing.getBody().getMinAddress() + ".." +
            containing.getBody().getMaxAddress()));
        println("  NEIGHBORS preceding=" + (before == null ? "<none>" :
            before.getName() + "@" + before.getEntryPoint()) +
            " following=" + (after == null ? "<none>" :
            after.getName() + "@" + after.getEntryPoint()));
        if (containing == null || !decompiled.add(containing.getEntryPoint()))
            return;
        println("DECOMPILE_START " + containing.getName() + "@" + containing.getEntryPoint());
        DecompileResults result = decompiler.decompileFunction(containing, 120, monitor);
        if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
            println("DECOMPILE_FAILED " + result.getErrorMessage());
        } else {
            println(result.getDecompiledFunction().getC());
        }
        println("DECOMPILE_END " + containing.getEntryPoint());
    }

    private void descriptor(long a, long expectedEntry) throws Exception {
        Address at = addr(a);
        try {
            long entry = currentProgram.getMemory().getLong(at);
            long toc = currentProgram.getMemory().getLong(at.add(8));
            long third = currentProgram.getMemory().getLong(at.add(16));
            boolean matches = (entry == expectedEntry && toc == 0x00678548L);
            MemoryBlock block = currentProgram.getMemory().getBlock(at);
            println(String.format("PPC64_DESCRIPTOR %s entry=0x%016X toc=0x%016X third=0x%016X match=%b block=%s",
                at, entry, toc, third, matches,
                block == null ? "<none>" : block.getName()));
            println("  DATA_TYPE " + (currentProgram.getListing().getDataAt(at) == null ?
                "<not defined>" : currentProgram.getListing().getDataAt(at).getDataType()));
            refsTo(at);
        } catch (Exception e) {
            println("DESCRIPTOR_READ_FAILED " + at + " " + e.getMessage());
        }
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null ||
            !"PowerPC:BE:64:A2ALT".equals(currentProgram.getLanguageID().toString()) ||
            !currentProgram.getName().contains("ps2_gxemu")) {
            printerr("REFUSE: requires ps2_gxemu imported using PowerPC:BE:64:A2ALT");
            return;
        }
        println("PS3_GXEMU_VUART10_ENDPOINTS read-only v1");
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        if (!decompiler.openProgram(currentProgram)) {
            printerr("DecompInterface.openProgram failed: " + decompiler.getLastMessage());
            return;
        }
        try {
            Set<Address> visited = new HashSet<Address>();
            for (int i = 0; i < PORT10_CALLS.length; i++) {
                monitor.checkCancelled();
                Address call = addr(PORT10_CALLS[i]);
                Instruction ins = currentProgram.getListing().getInstructionAt(call);
                boolean verified = false;
                if (ins != null && ins.getFlowType().isCall()) {
                    for (Address flow : ins.getFlows()) {
                        if (flow.equals(addr(EXPECTED_TARGETS[i]))) {
                            verified = true;
                            break;
                        }
                    }
                }
                println(String.format("PORT10_CANDIDATE call=%s expected=%08X verified_target=%b ins=%s",
                    call, EXPECTED_TARGETS[i], verified,
                    ins == null ? "<none>" : ins.toString()));
                if (!verified)
                    continue;
                describeFunction(call, decompiler, visited);
                context(call);
            }
            println("---- EXTRA ORPHANED LV1 READ SITE ----");
            describeFunction(addr(0x00049748L), decompiler, visited);
            context(addr(0x00049748L));
            println("---- VUART WRAPPER FUNCTION DESCRIPTORS ----");
            for (int i = 0; i < DESCRIPTORS.length; i++)
                descriptor(DESCRIPTORS[i], DESCRIPTOR_TARGETS[i]);
            println("---- KNOWN CODE ROOTS AND IMMEDIATE XREFS ----");
            for (long root : new long[] {0x0008FC68L, 0x000900FCL, 0x000494A4L,
                                          0x00049544L, 0x000495B8L, 0x00049664L}) {
                Address target = addr(root);
                println("CODE_ROOT " + target);
                refsTo(target);
            }
            println("DONE. No names, function boundaries, datatypes, comments, bytes or signatures modified.");
        } finally {
            decompiler.dispose();
        }
    }
}
