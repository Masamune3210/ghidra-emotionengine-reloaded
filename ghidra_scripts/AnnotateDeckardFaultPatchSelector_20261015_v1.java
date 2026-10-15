// Annotate the verified PPC exception gate for DECKARD runtime patch modes.
// SCPH-79001 DECKARD.elf + DPATCH, PowerPC:BE:32:DECKARD.
// Metadata only: no byte changes, no new functions, no guessed processor semantics.
//@category PS2.DECKARD
import java.util.Locale;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class AnnotateDeckardFaultPatchSelector_20261015_v1 extends GhidraScript {
    private static final long[][] REQUIRED = {
        {0x00a01138L, 0x0060021cL}, // amfpc r3
        {0x00a0113cL, 0x546300feL}, // clrlwi r3,r3,3
        {0x00a01140L, 0x3c801fc0L}, // lis r4,0x1fc0
        {0x00a01144L, 0x60840000L}, // ori r4,r4,0
        {0x00a01148L, 0x7c032040L}, // cmplw r3,r4
        {0x00a0114cL, 0x41a00058L}, // blt fallback
        {0x00a01150L, 0x7c7d0aa6L}, // mfspr r3,61 = DEAR
        {0x00a01154L, 0x54648414L}, // rlwinm r4,r3,16,16,10
        {0x00a01158L, 0x28040200L}, // cmplwi r4,0x200
        {0x00a0115cL, 0x40a20048L}, // bne fallback
        {0x00a01160L, 0x7cfa02a6L}, // mfsrr0 r7
        {0x00a01164L, 0x38e70004L}, // addi r7,r7,4
        {0x00a01168L, 0x7cfa03a6L}, // mtsrr0 r7
        {0x00a0116cL, 0x546306feL}, // clrlwi r3,r3,27 (DEAR & 0x1f)
        {0x00a01170L, 0x4bffd003L}, // bla 0xffffd000
        {0x00a011a0L, 0x4c000064L}, // rfi
        {0x00a011a4L, 0x38201100L}, // fallback handler
        {0xffffd000L, 0x3c80ffffL}  // patch dispatcher mapped
    };

    private static int readBe32(Memory m, Address a) throws Exception {
        byte[] bytes = new byte[4];
        if (m.getBytes(a, bytes) != 4) {
            throw new IllegalStateException("Unable to read four bytes at " + a);
        }
        return ((bytes[0] & 255) << 24) |
               ((bytes[1] & 255) << 16) |
               ((bytes[2] & 255) << 8) |
               (bytes[3] & 255);
    }

    private int addedComments = 0;
    private int createdLabels = 0;

    private void addComment(long absolute, String detail) {
        Address address = toAddr(absolute);
        Listing list = currentProgram.getListing();
        String prefix = "DECKARD PATCH-FAULT GATE: ";
        String existing = list.getComment(CommentType.PRE, address);
        if (existing != null && existing.contains(prefix)) {
            println("PRESERVE existing gate annotation at " + address);
            return;
        }
        list.setComment(address, CommentType.PRE,
            (existing == null || existing.isEmpty()) ?
            prefix + detail : existing + "\n" + prefix + detail);
        addedComments++;
    }

    private void addCodeLabel(long absolute, String name) {
        Address address = toAddr(absolute);
        if (currentProgram.getListing().getInstructionAt(address) == null) {
            println("PRESERVE non-instruction address " + address + ": " + name);
            return;
        }
        for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(address)) {
            if (name.equals(symbol.getName())) {
                return;
            }
        }
        try {
            // Creates an additional address label; does not rename functions.
            currentProgram.getSymbolTable().createLabel(
                address, name, SourceType.ANALYSIS);
            createdLabels++;
        }
        catch (Exception e) {
            println("PRESERVE labels at " + address + ": " + e.getMessage());
        }
    }

    @Override
    protected void run() throws Exception {
        if (!"PowerPC:BE:32:DECKARD".equals(currentProgram.getLanguageID().toString()) ||
            !"DECKARD.elf".equalsIgnoreCase(currentProgram.getName())) {
            printerr("ABORT: requires combined DECKARD.elf, PowerPC:BE:32:DECKARD");
            return;
        }
        Memory mem = currentProgram.getMemory();
        int mismatches = 0;
        for (long[] pair : REQUIRED) {
            Address at = toAddr(pair[0]);
            if (!mem.contains(at)) {
                println("MISSING " + at);
                mismatches++;
                continue;
            }
            long actual = Integer.toUnsignedLong(readBe32(mem, at));
            if (actual != pair[1]) {
                println(String.format(Locale.ROOT,
                    "MISMATCH %08x expected %08x got %08x",
                    pair[0], pair[1], actual));
                mismatches++;
            }
        }
        if (mismatches > 0) {
            printerr("ABORT: " + mismatches + " opcode mismatches; no metadata changed.");
            return;
        }

        println("PASS: 18 main/DPATCH instruction words match the original SCPH-79001 image.");
        Instruction exceptionCall =
            currentProgram.getListing().getInstructionAt(toAddr(0x00a01170L));
        println("EXCEPTION CALL " + toAddr(0x00a01170L) +
            ": " + (exceptionCall == null ? "not disassembled" : exceptionCall));

        addCodeLabel(0x00a01138L, "CheckMipsRomPatchContext");
        addCodeLabel(0x00a01150L, "CheckDataExceptionPatchAddress");
        addCodeLabel(0x00a01160L, "SkipFaultingPpcInstructionForPatch");
        addCodeLabel(0x00a0116cL, "DispatchPatchModeFromDear");

        addComment(0x00a01138L,
            "amfpc reads emulated MIPS PC. clrlwi r3,r3,3 computes " +
            "(MipsPc & 0x1FFFFFFF). Unsigned compare against 0x1FC00000; " +
            "values below this boot-ROM range branch to 0x00A011A4.");
        addComment(0x00a01150L,
            "mfspr r3,61 reads DEAR (Data Exception Address Register). " +
            "rlwinm r4,r3,16,16,10 followed by cmplwi r4,0x200 is equivalent to " +
            "(DEAR & 0xFFFFFFE0) == 0x02000000; other fault addresses " +
            "branch to 0x00A011A4.");
        addComment(0x00a01160L,
            "Successful patch fault: SRR0 += 4. This skips the PPC instruction " +
            "that faulted before the saved context is restored and rfi executes.");
        addComment(0x00a0116cL,
            "r3 = DEAR & 31, then absolute bla 0xFFFFD000. " +
            "DPATCH selects via its 32-entry pointer table. " +
            "Mode 0 and 8..31 do nothing; 1..7 select code-patch handlers.");
        addComment(0x00a011a4L,
            "Alternate exception path reached if normalized MIPS PC is below " +
            "0x1FC00000 or DEAR is outside 0x02000000..0x0200001F. " +
            "Not the DPATCH dispatch path; do not treat as a normal function return.");

        println("DECKARD FAULT GATE annotated comments=" + addedComments +
            " newLabels=" + createdLabels + " mismatches=" + mismatches);
        println("All executable bytes and existing functions/signatures preserved.");
    }
}
