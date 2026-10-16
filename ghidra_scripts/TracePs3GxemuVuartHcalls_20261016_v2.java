// Identify directly encoded PS3 LV1 VUART hypercall selectors in ps2_gxemu.
// @category PS3.PS2Emulation
// For Ghidra 12.1.x, PowerPC:BE:64:A2ALT; no executable bytes are changed.
// Only contiguous, straight-line r11 immediate definitions are considered.
// This is a targeted FOLLOW-UP to InspectAnnotatePs3GxemuPpu64_20261016_v2.java.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.Map;
import java.util.TreeMap;

public class TracePs3GxemuVuartHcalls_20261016_v2 extends GhidraScript {
    private static final boolean APPLY = true;
    private static final int MAX_LOOKBACK = 16;
    private static final String TAG = "PS3 VUART: ";

    private static String vuartName(long id) {
        switch ((int) id) {
            case 162: return "lv1_read_virtual_uart";
            case 163: return "lv1_write_virtual_uart";
            case 164: return "lv1_set_virtual_uart_param";
            case 165: return "lv1_get_virtual_uart_param";
            case 166: return "lv1_configure_virtual_uart_irq";
            default: return null;
        }
    }

    private static boolean writesRegister(Instruction ins, Address registerAddress) {
        for (PcodeOp op : ins.getPcode()) {
            Varnode output = op.getOutput();
            if (output != null && output.isRegister() && output.getAddress().equals(registerAddress)) {
                return true;
            }
        }
        return false;
    }

    // Resolve LI (addi rN,r0,imm) and LIS (addis rN,r0,imm),
    // optionally followed by ORI rN,rN,imm. No other register writers
    // or non-fall-through predecessor instructions are traversed.
    private Long precedingConstant(Instruction syscall, int registerNumber, Address regAddress) throws Exception {
        Instruction next = syscall;
        Integer orLow = null;
        for (int n = 0; n < MAX_LOOKBACK; n++) {
            monitor.checkCancelled();
            Instruction prev = currentProgram.getListing().getInstructionBefore(next.getAddress());
            if (prev == null || prev.getFallThrough() == null ||
                !prev.getFallThrough().equals(next.getAddress()) ||
                prev.getFlowType().isJump() || prev.getFlowType().isCall() ||
                prev.getFlowType().isTerminal()) {
                return null;
            }
            if (prev.getLength() != 4) {
                return null;
            }
            int word = currentProgram.getMemory().getInt(prev.getAddress());
            int opcode = word >>> 26;
            if (opcode == 17) {
                return null; // a prior sc may change r3/r11 before this call
            }
            int rdOrRs = (word >>> 21) & 31;
            int ra = (word >>> 16) & 31;
            int imm = word & 0xffff;
            // ori rN,rN,imm: accumulate before the base immediate.
            if (opcode == 24 && rdOrRs == registerNumber && ra == registerNumber) {
                if (orLow != null) {
                    return null;
                }
                orLow = imm;
                next = prev;
                continue;
            }
            // addi/addis rN,r0,imm are the raw PPC encodings of li/lis.
            if ((opcode == 14 || opcode == 15) && rdOrRs == registerNumber && ra == 0) {
                long value = opcode == 14 ? (long)(short) imm :
                    (((long)(short) imm) << 16);
                if (orLow != null) {
                    value |= (long) orLow;
                }
                return value;
            }
            if (writesRegister(prev, regAddress)) {
                return null; // unmodelled definition: never guess
            }
            next = prev;
        }
        return null;
    }

    private static void appendEol(Instruction ins, String message) {
        String old = ins.getComment(CodeUnit.EOL_COMMENT);
        String newPart = TAG + message;
        if (old == null || old.isEmpty()) {
            ins.setComment(CodeUnit.EOL_COMMENT, newPart);
        } else if (!old.contains(newPart)) {
            ins.setComment(CodeUnit.EOL_COMMENT, old + "\n" + newPart);
        }
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null ||
            !"PowerPC:BE:64:A2ALT".equals(currentProgram.getLanguageID().toString()) ||
            !currentProgram.getName().contains("ps2_gxemu")) {
            printerr("REFUSE: run only on the full-address PowerPC:BE:64:A2ALT ps2_gxemu program.");
            return;
        }
        Register r11 = currentProgram.getRegister("r11");
        Register r3 = currentProgram.getRegister("r3");
        if (r11 == null || r3 == null) {
            printerr("REFUSE: r11/r3 registers unavailable.");
            return;
        }

        Map<Long, Integer> counts = new TreeMap<Long, Integer>();
        int sc1Total = 0, resolved = 0, vuartTotal = 0, localPort10 = 0;
        InstructionIterator iterator = currentProgram.getListing().getInstructions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction sc = iterator.next();
            if (sc.getLength() != 4) {
                continue;
            }
            int w = currentProgram.getMemory().getInt(sc.getAddress());
            if (w != 0x44000022) {
                continue; // exactly sc 1, not sc 0 or another encoding
            }
            sc1Total++;
            Long callId = precedingConstant(sc, 11, r11.getAddress());
            if (callId == null) {
                continue;
            }
            resolved++;
            counts.put(callId, counts.containsKey(callId) ? counts.get(callId) + 1 : 1);
            String identity = vuartName(callId);
            if (identity == null) {
                continue;
            }
            vuartTotal++;
            boolean takesPort = callId >= 162 && callId <= 165;
            Long port = takesPort ? precedingConstant(sc, 3, r3.getAddress()) : null;
            boolean port10 = takesPort && port != null && port.longValue() == 10;
            if (port10) localPort10++;

            Function owner = currentProgram.getFunctionManager().getFunctionContaining(sc.getAddress());
            String ownerName = owner == null ? "<no function>" :
                owner.getName() + "@" + owner.getEntryPoint();
            println(String.format(
                "VUART_HCALL site=%s id=%d identity=%s owner=%s local_r3=%s%s",
                sc.getAddress(), callId, identity, ownerName,
                !takesPort ? "not-a-port-argument" : (port == null ? "unknown" : String.format("0x%X", port)),
                port10 ? " PORT10_LINEAR_CANDIDATE" : ""));

            if (APPLY) {
                String note = identity + " (r11=" + callId + " from straight-line li/lis[+ori]); " +
                    "r3 " + (takesPort ? ("port=" + (port == null ? "unresolved" : String.format("0x%X", port))) : "is IRQ-bitmap address, not VUART port") +
                    ". Hypervisor call only; guest MagicGate handler not identified.";
                appendEol(sc, note);
                currentProgram.getBookmarkManager().setBookmark(sc.getAddress(),
                    BookmarkType.ANALYSIS, "PS3 VUART Hypercall", note);
            }
        }

        println("SC1_TOTAL=" + sc1Total +
            " R11_LOCAL_IMMEDIATE=" + resolved +
            " R11_UNRESOLVED=" + (sc1Total - resolved) +
            " VUART_162_166=" + vuartTotal +
            " VUART_PORT10_LINEAR_CANDIDATES=" + localPort10);
        println("R11_IMMEDIATE_ID_HISTOGRAM:");
        for (Map.Entry<Long, Integer> count : counts.entrySet()) {
            println(String.format("  id=%d (0x%X) sites=%d%s", count.getKey(),
                count.getKey(), count.getValue(),
                vuartName(count.getKey()) == null ? "" : " " + vuartName(count.getKey())));
        }
        println("NOTE: linear local r3=10 is a lead, not proof all control-flow paths use port 10.");
        println("NOTE: unknown r11 values, memory-loaded selectors and caller-supplied ports remain unresolved.");
        println("DONE: only comments/bookmarks at evidenced VUART call sites; no renames, signatures or byte changes.");
    }
}
