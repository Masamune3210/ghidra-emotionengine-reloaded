// Read-only Ghidra script, run in freshly imported 3_DECKARD.elf or 5_DPATCH.bin
// after installing PowerPC:BE:32:DECKARD and running auto analysis.
//@category PS2.DECKARD
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import java.util.Locale;

public class AuditDeckardApuDecode_20261015_v1 extends GhidraScript {
    private static class Row {
        final long address; final int word; final String mnemonic;
        Row(long address, int word, String mnemonic) {
            this.address=address; this.word=word; this.mnemonic=mnemonic;
        }
    }
    private static final Row[] MAIN = {
        new Row(0x00a03198L, 0x000323cc, "amtgte"),
        new Row(0x00a031a0L, 0x006303dc, "amfgte"),
        new Row(0x00a031a8L, 0x0003238c, "amtgp"),
        new Row(0x00a031b0L, 0x0063039c, "amfgp"),
        new Row(0x00a031d8L, 0x0003020c, "amtpc"),
        new Row(0x00a031e0L, 0x0060021c, "amfpc"),
        new Row(0x00a031e8L, 0x0003024c, "amtcc"),
        new Row(0x00a031f0L, 0x0060025c, "amfcc"),
        new Row(0x00a03540L, 0x03be000c, "aexec"),
    };
    private static final Row[] PATCH = {
        new Row(0xffffd198L, 0x0003020c, "amtpc"),
        new Row(0xffffd178L, 0x0063039c, "amfgp"),
        new Row(0xffffd1d0L, 0x0380049c, "amfop"),
    };
    @Override
    protected void run() throws Exception {
        String language=currentProgram.getLanguageID().toString();
        if (!"PowerPC:BE:32:DECKARD".equals(language)) {
            printerr("FAIL expected PowerPC:BE:32:DECKARD, found "+language);
            return;
        }
        Memory m=currentProgram.getMemory();
        Row[] rows=currentProgram.getName().contains("DPATCH") ? PATCH : MAIN;
        int good=0, missing=0, badBytes=0, badDecode=0;
        for (Row r:rows) {
            monitor.checkCancelled();
            Address a=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(r.address);
            if (!m.contains(a)) { println("UNMAPPED "+a); missing++; continue; }
            byte[] bytes=new byte[4];
            if (m.getBytes(a,bytes)!=4) { println("UNREADABLE "+a);missing++;continue; }
            int word=((bytes[0]&255)<<24)|((bytes[1]&255)<<16)|((bytes[2]&255)<<8)|(bytes[3]&255);
            if (word!=r.word) {println("BYTES MISMATCH "+a+" expected "+Integer.toHexString(r.word)+" actual "+Integer.toHexString(word));badBytes++;continue;}
            Instruction ins=currentProgram.getListing().getInstructionAt(a);
            if (ins==null || !r.mnemonic.equals(ins.getMnemonicString().toLowerCase(Locale.ROOT))) {
                println("NOT DECODED "+a+" expected "+r.mnemonic+" observed "+(ins==null?"no instruction":ins.getMnemonicString())); badDecode++;
            } else {println("PASS "+a+" "+ins);good++;}
        }
        println("DECKARD APU AUDIT good="+good+" unmapped="+missing+" wrongBytes="+badBytes+" notDecoded="+badDecode);
        println("Read-only. For missing instructions, disassemble only known executable regions before rechecking.");
    }
}
