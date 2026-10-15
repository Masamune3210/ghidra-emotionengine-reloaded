// Refine only unresolved types/names in existing, exactly verified DECKARD APU wrappers.
// Target: SCPH-79001 DECKARD.elf, PowerPC:BE:32:DECKARD.
// No rebuild or extension reinstall required: run directly from Ghidra Script Manager.
//@category PS2.DECKARD
import java.util.Locale;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;

public class RefineDeckardApuWrapperSignatures_20261015_v3 extends GhidraScript {
    private static final int BLR = 0x4e800020;

    private static final class Target {
        final long address;
        final int opcode;
        final String mnemonic;
        final String name;
        final boolean returnsValue;
        final String[] args;
        Target(long address, int opcode, String mnemonic, String name,
               boolean returnsValue, String... args) {
            this.address = address;
            this.opcode = opcode;
            this.mnemonic = mnemonic;
            this.name = name;
            this.returnsValue = returnsValue;
            this.args = args;
        }
    }

    private static final Target[] TARGETS = {
        new Target(0x00a03198L, 0x000323cc, "amtgte", "ApuWriteGteRegister",
                   false, "registerIndex", "value"),
        new Target(0x00a031d8L, 0x0003020c, "amtpc", "ApuWriteMipsProgramCounter",
                   false, "mipsPc"),
        new Target(0x00a031e0L, 0x0060021c, "amfpc", "ApuReadMipsProgramCounter",
                   true),
        new Target(0x00a031e8L, 0x0003024c, "amtcc", "ApuWriteMipsCycleCounter",
                   false, "cycles"),
        new Target(0x00a031f0L, 0x0060025c, "amfcc", "ApuReadMipsCycleCounter",
                   true)
    };

    private static int be32(Memory m, Address a) throws Exception {
        byte[] b = new byte[4];
        if (m.getBytes(a, b) != 4) throw new IllegalStateException("Unreadable " + a);
        return ((b[0] & 255) << 24) | ((b[1] & 255) << 16) |
               ((b[2] & 255) << 8) | (b[3] & 255);
    }

    @Override
    protected void run() throws Exception {
        if (!"PowerPC:BE:32:DECKARD".equals(currentProgram.getLanguageID().toString()) ||
            !"DECKARD.elf".equalsIgnoreCase(currentProgram.getName())) {
            printerr("ABORT: requires main DECKARD.elf under PowerPC:BE:32:DECKARD");
            return;
        }

        Memory memory = currentProgram.getMemory();
        DataType u32 = UnsignedIntegerDataType.dataType;
        int signatures = 0, returns = 0, types = 0, names = 0, skipped = 0;
        for (Target target : TARGETS) {
            monitor.checkCancelled();
            Address at = toAddr(target.address);
            Function function = getFunctionAt(at);
            Instruction op = currentProgram.getListing().getInstructionAt(at);
            Instruction ret = currentProgram.getListing().getInstructionAt(at.add(4));
            if (function == null || !target.name.equals(function.getName()) ||
                op == null || ret == null ||
                !target.mnemonic.equals(op.getMnemonicString().toLowerCase(Locale.ROOT)) ||
                !"blr".equals(ret.getMnemonicString().toLowerCase(Locale.ROOT)) ||
                be32(memory, at) != target.opcode ||
                be32(memory, at.add(4)) != BLR) {
                println("SKIP UNVERIFIED " + at);
                skipped++;
                continue;
            }
            if (function.hasCustomVariableStorage() ||
                function.getSignatureSource() == SourceType.USER_DEFINED ||
                function.getParameterCount() != target.args.length) {
                println("PRESERVE SIGNATURE " + at + " source=" +
                    function.getSignatureSource() + " args=" + function.getParameterCount());
                skipped++;
                continue;
            }
            boolean changed = false;
            DataType wanted = target.returnsValue ? u32 : VoidDataType.dataType;
            if (Undefined.isUndefined(function.getReturnType())) {
                try {
                    function.setReturnType(wanted, SourceType.ANALYSIS);
                    returns++;
                    changed = true;
                }
                catch (Exception e) {
                    println("PRESERVE RETURN " + at + " " + e.getMessage());
                }
            }
            else if (!function.getReturnType().isEquivalent(wanted)) {
                println("PRESERVE KNOWN RETURN " + at + " " + function.getReturnType().getName());
            }

            for (int i = 0; i < target.args.length; i++) {
                Parameter p = function.getParameter(i);
                if (p == null) continue;
                if (Undefined.isUndefined(p.getDataType())) {
                    try {
                        p.setDataType(u32, SourceType.ANALYSIS);
                        types++;
                        changed = true;
                    }
                    catch (Exception e) {
                        println("PRESERVE PARAM TYPE " + at + " [" + i + "] " + e.getMessage());
                    }
                }
                String name = p.getName();
                if ((name == null || name.matches("param_[0-9]+")) &&
                    p.getSymbol() != null &&
                    p.getSymbol().getSource() != SourceType.USER_DEFINED) {
                    try {
                        p.setName(target.args[i], SourceType.ANALYSIS);
                        names++;
                        changed = true;
                    }
                    catch (Exception e) {
                        println("PRESERVE PARAM NAME " + at + " [" + i + "] " + e.getMessage());
                    }
                }
            }
            if (changed) signatures++;
            println((changed ? "REFINED " : "PRESERVED ") + at + " " +
                function.getPrototypeString(false, false));
        }
        println("DECKARD SIGNATURE REFINEMENT updatedFunctions=" + signatures +
            " returns=" + returns + " parameterTypes=" + types +
            " parameterNames=" + names + " skipped=" + skipped);
        println("Idempotent: concrete types, custom storage, and user-defined signatures preserved.");
    }
}
