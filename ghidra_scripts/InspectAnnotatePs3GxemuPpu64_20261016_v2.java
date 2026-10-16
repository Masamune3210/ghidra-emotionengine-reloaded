// Ghidra script: audit the ps2_gxemu 64-bit PPU import and apply verified annotations.
// @category PS3.PS2Emulation
// Works on a Ghidra 12.1.x PowerPC:BE:64:A2ALT import.
// Adds only evidence-based comments/bookmarks. Does not patch bytes or guess signatures.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class InspectAnnotatePs3GxemuPpu64_20261016_v2 extends GhidraScript {
    private static final boolean APPLY = true;
    private static final String TAG = "PS3 LV1: ";

    private static void annotate(Instruction ins, String message) {
        String old = ins.getComment(CodeUnit.EOL_COMMENT);
        if (old == null || old.isEmpty()) {
            ins.setComment(CodeUnit.EOL_COMMENT, TAG + message);
        } else if (!old.contains(TAG + message)) {
            ins.setComment(CodeUnit.EOL_COMMENT, old + "\n" + TAG + message);
        }
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            printerr("No active program");
            return;
        }
        String lang = currentProgram.getLanguageID().toString();
        String name = currentProgram.getName();
        if (!"PowerPC:BE:64:A2ALT".equals(lang) || !name.contains("ps2_gxemu")) {
            printerr("REFUSE: expected ps2_gxemu on PowerPC:BE:64:A2ALT; found " + name + ", " + lang);
            return;
        }

        println("PS3_GXEMU_PPU_AUDIT program=" + name + " language=" + lang + " APPLY=" + APPLY);
        println("FUNCTIONS=" + currentProgram.getFunctionManager().getFunctionCount());
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        int above4GiB = 0;
        for (MemoryBlock b : blocks) {
            long hi = b.getEnd().getOffset();
            if (Long.compareUnsigned(hi, 0x100000000L) >= 0) {
                above4GiB++;
            }
            println(String.format("BLOCK %s %s..%s size=0x%X R=%b W=%b X=%b initialized=%b",
                b.getName(), b.getStart(), b.getEnd(), b.getSize(),
                b.isRead(), b.isWrite(), b.isExecute(), b.isInitialized()));
        }
        println("BLOCKS_ABOVE_4G=" + above4GiB);

        int entryCount = 0;
        int entrySelfLoops = 0;
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            monitor.checkCancelled();
            Symbol sym = symbols.next();
            if (!"entry".equals(sym.getName()) || sym.isExternal())
                continue;
            entryCount++;
            Address addr = sym.getAddress();
            Instruction ins = currentProgram.getListing().getInstructionAt(addr);
            println("ENTRY " + addr + " instruction=" + (ins == null ? "none" : ins.toString()));
            if (ins == null)
                continue;
            boolean self = false;
            for (Address flow : ins.getFlows()) {
                if (flow.equals(addr)) {
                    self = true;
                    break;
                }
            }
            if (self) {
                entrySelfLoops++;
                if (APPLY) {
                    annotate(ins, "ELF entry begins with a direct self-branch. May be a parked/holding stub; not evidence that other mapped code is unreachable.");
                    currentProgram.getBookmarkManager().setBookmark(addr, BookmarkType.ANALYSIS,
                        "PS3 GXEMU Entry", "Verified direct entry self-branch; inspect alternate initialization references before renaming");
                }
            }
        }
        println("ENTRY_SYMBOLS=" + entryCount + " DIRECT_SELF_BRANCHES=" + entrySelfLoops);

        int instructionCount = 0;
        int lv1CallCount = 0;
        InstructionIterator iter = currentProgram.getListing().getInstructions(true);
        while (iter.hasNext()) {
            monitor.checkCancelled();
            Instruction ins = iter.next();
            instructionCount++;
            if (ins.getLength() != 4)
                continue;
            byte[] bytes = ins.getBytes();
            if (bytes.length != 4 || (bytes[0] & 0xff) != 0x44 || (bytes[1] & 0xff) != 0x00 ||
                (bytes[2] & 0xff) != 0x00 || (bytes[3] & 0xff) != 0x22)
                continue;
            lv1CallCount++;
            println("LV1_SC1 " + ins.getAddress() + " disassembly=" + ins);
            if (APPLY) {
                String detail = "PowerPC sc with LEV=1 (opcode 0x44000022); candidate LV1 hypervisor call. Resolve r11 call number and surrounding argument registers separately.";
                annotate(ins, detail);
                currentProgram.getBookmarkManager().setBookmark(ins.getAddress(), BookmarkType.ANALYSIS,
                    "PS3 LV1 Calls", detail);
            }
        }
        println("INSTRUCTIONS=" + instructionCount + " LV1_SC1_SITES=" + lv1CallCount);
        println("NOTE: No TOC, function descriptor, crypto, or MagicGate names inferred solely from the instruction signature.");
        println("DONE: Only verified self-branch and sc/LEV=1 annotations applied, no data/code byte changes.");
    }
}
