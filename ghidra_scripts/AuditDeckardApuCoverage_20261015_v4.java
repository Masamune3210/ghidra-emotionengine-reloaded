// Read-only full-text APU opcode coverage audit for Sony DECKARD firmware.
// Inspect recognized and unmatched OP=0 words; never disassemble or retype data.
//@category PS2.DECKARD
import java.util.Locale;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class AuditDeckardApuCoverage_20261015_v4 extends GhidraScript {
    private static final class Op {
        final String name;
        final int xop;
        final boolean zeroD, zeroA, zeroB;
        int matches, decoded, data, missing, wrongMnemonic;
        Op(String name, int xop, boolean zeroD, boolean zeroA, boolean zeroB) {
            this.name=name; this.xop=xop; this.zeroD=zeroD;
            this.zeroA=zeroA; this.zeroB=zeroB;
        }
        boolean matches(int word) {
            if (word == 0 || (word >>> 26) != 0 || (word & 1) != 0 ||
                    ((word >>> 1) & 1023) != xop) return false;
            int d=(word >>> 21) & 31;
            int a=(word >>> 16) & 31;
            int b=(word >>> 11) & 31;
            return (!zeroD || d == 0) && (!zeroA || a == 0) &&
                   (!zeroB || b == 0);
        }
    }

    // Generated from data/languages/deckard_apu.sinc, using exact OP/XOP
    // and zeroed unused GPR selector fields, not fuzzy mnemonic matching.
    private static final Op[] OPCODES = {
        new Op("aexec", 0x6, false, false, true),
        new Op("aexeci", 0x26, false, false, true),
        new Op("aexecn", 0x46, false, false, true),
        new Op("amtpc", 0x106, true, false, true),
        new Op("amfpc", 0x10e, false, true, true),
        new Op("amtcc", 0x126, true, false, true),
        new Op("amfcc", 0x12e, false, true, true),
        new Op("amthi", 0x146, true, false, true),
        new Op("amfhi", 0x14e, false, true, true),
        new Op("amtlo", 0x166, true, false, true),
        new Op("amflo", 0x16e, false, true, true),
        new Op("aunk0", 0x186, true, true, true),
        new Op("amtgp", 0x1c6, true, false, false),
        new Op("amfgp", 0x1ce, false, false, true),
        new Op("amtgte", 0x1e6, true, false, false),
        new Op("amfgte", 0x1ee, false, false, true),
        new Op("amf04", 0x20e, false, true, true),
        new Op("amf05", 0x22e, false, true, true),
        new Op("amfop", 0x24e, false, true, true),
        new Op("amfrd", 0x26e, false, true, true),
        new Op("amf04_u", 0x28e, false, true, true),
        new Op("amf05_u", 0x2ae, false, true, true),
        new Op("amf06_u", 0x2ce, false, true, true),
        new Op("amf07_u", 0x2ee, false, true, true),
        new Op("amf08_u", 0x30e, false, true, true),
        new Op("amf09_u", 0x32e, false, true, true),
        new Op("amf0A_u", 0x34e, false, true, true),
        new Op("amf0B_u", 0x36e, false, true, true),
        new Op("amf0C_u", 0x38e, false, true, true),
        new Op("amf0D_u", 0x3ae, false, true, true),
        new Op("amf0E_u", 0x3ce, false, true, true),
        new Op("amf0F_u", 0x3ee, false, true, true)
    };

    private static int readBe32(Memory memory, Address at) throws Exception {
        byte[] b = new byte[4];
        if (memory.getBytes(at, b) != 4)
            throw new IllegalArgumentException("Short read " + at);
        return ((b[0] & 255) << 24) | ((b[1] & 255) << 16) |
               ((b[2] & 255) << 8) | (b[3] & 255);
    }

    @Override
    protected void run() throws Exception {
        if (!"PowerPC:BE:32:DECKARD".equals(currentProgram.getLanguageID().toString())) {
            printerr("ABORT: this script requires PowerPC:BE:32:DECKARD");
            return;
        }
        String programName=currentProgram.getName().toUpperCase(Locale.ROOT);
        boolean patch=programName.contains("DPATCH");
        if (!patch && !programName.contains("DECKARD")) {
            printerr("ABORT: expected DECKARD.elf or DPATCH.bin");
            return;
        }
        Memory memory=currentProgram.getMemory();
        Listing listing=currentProgram.getListing();
        long lo, hi;
        if (!patch) {
            MemoryBlock text=memory.getBlock(".text");
            if (text == null || !text.isInitialized()) {
                printerr("ABORT: main ELF has no initialized .text block");
                return;
            }
            lo=text.getStart().getOffset();
            hi=text.getEnd().getOffset();
        } else {
            lo=0xffffd000L;
            hi=0xffffd823L;
        }
        if (hi < lo || (hi - lo) > 0x200000L) {
            printerr("ABORT: unreasonable scan range");
            return;
        }
        int primary0=0, documented=0, undecoded=0, unclassified=0;
        int alreadyDecoded=0, definedData=0, incorrectMnemonic=0;
        int printedMisses=0, printedUnknown=0;
        println("DECKARD APU COVERAGE scan=" + (patch ? "DPATCH" : "DECKARD .text") +
                " range=0x" + Long.toHexString(lo) +
                "..0x" + Long.toHexString(hi) + " language=" + currentProgram.getLanguageID());
        for (long pos=lo; pos+3<=hi; pos+=4) {
            monitor.checkCancelled();
            Address at=toAddr(pos);
            MemoryBlock block=memory.getBlock(at);
            if (block == null || !block.isInitialized()) continue;
            int word;
            try { word=readBe32(memory, at); }
            catch (Exception e) { continue; }
            if (word == 0 || (word >>> 26) != 0) continue;
            primary0++;
            Op matched=null;
            for (Op op:OPCODES) {
                if (op.matches(word)) { matched=op; break; }
            }
            Instruction ins=listing.getInstructionAt(at);
            if (matched==null) {
                unclassified++;
                // The opcode-0 test includes pointers and other embedded data.
                // Only surface potential gaps if Ghidra currently sees executable code.
                if (ins!=null && printedUnknown++ < 24) {
                    println("UNCLASSIFIED-INSTRUCTION " + at + " word=0x" +
                        String.format("%08x",word) + " decoded=" + ins.getMnemonicString());
                }
                continue;
            }
            documented++;
            matched.matches++;
            if (ins!=null) {
                if (matched.name.equals(ins.getMnemonicString().toLowerCase(Locale.ROOT))) {
                    matched.decoded++; alreadyDecoded++;
                } else {
                    matched.wrongMnemonic++; incorrectMnemonic++;
                    if (printedMisses++ < 48) {
                        println("MNEMONIC-MISMATCH " + at + " word=0x" +
                            String.format("%08x",word) + " expected=" + matched.name +
                            " actual=" + ins.getMnemonicString());
                    }
                }
                continue;
            }
            Data datum=listing.getDefinedDataContaining(at);
            if (datum != null) {
                matched.data++; definedData++;
                continue;
            }
            matched.missing++; undecoded++;
            if (printedMisses++ < 48) {
                String containing=currentProgram.getFunctionManager().getFunctionContaining(at)!=null ?
                    currentProgram.getFunctionManager().getFunctionContaining(at).getName() :
                    "<no containing function>";
                println("NOT-DISASSEMBLED " + at + " word=0x" +
                    String.format("%08x",word) + " expected=" + matched.name +
                    " in=" + containing);
            }
        }
        println("DECKARD APU SUMMARY primary0Nonzero=" + primary0 +
            " documentedMatches=" + documented +
            " decoded=" + alreadyDecoded +
            " notDisassembled=" + undecoded +
            " definedData=" + definedData +
            " wrongMnemonic=" + incorrectMnemonic +
            " unclassifiedCandidateWords=" + unclassified);
        for (Op op:OPCODES) {
            if (op.matches>0) {
                println(String.format(Locale.ROOT,
                    "APU %-12s matches=%3d decoded=%3d missing=%3d data=%3d wrong=%3d",
                    op.name,op.matches,op.decoded,op.missing,op.data,op.wrongMnemonic));
            }
        }
        println("Read-only. Not-disassembled and unclassified candidate bytes are not automatically SLEIGH failures.");
    }
}
