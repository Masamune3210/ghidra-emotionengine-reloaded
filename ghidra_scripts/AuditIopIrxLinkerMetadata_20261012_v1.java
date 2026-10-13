// Read-only audit of source-validated Sony IOP IRX linker boundaries and GP.
//@category ghidra-emotionengine

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

/**
 * Reports verified linker pseudo-labels without creating fictitious RAM.
 * Run after importing a fresh IOP IRX with the updated extension.
 */
public class AuditIopIrxLinkerMetadata_20261012_v1 extends GhidraScript {
    private int passed, failed;

    private void check(boolean okay, String message) {
        if (okay) {
            passed++;
            println("PASS " + message);
        } else {
            failed++;
            println("FAIL " + message);
        }
    }

    private Address address(long value) {
        if (value < 0) return null;
        try {
            return currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(value);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private void boundary(Options options, String symbol) {
        long value = options.getLong("Linker " + symbol + " (ELF value)", -1);
        boolean valid = value >= 0;
        println("BOUNDARY " + symbol + " = " +
                (valid ? "0x" + Long.toHexString(value) : "NOT VERIFIED"));
        if (!valid) return;
        Address at = address(value);
        boolean mapped = at != null && currentProgram.getMemory().getBlock(at) != null;
        check(mapped, symbol + " corresponds to mapped section boundary");
        if (mapped) {
            boolean found = false;
            for (Symbol candidate : currentProgram.getSymbolTable().getSymbols(at)) {
                if (candidate.getName().equals(symbol)) found = true;
            }
            check(found, symbol + " is a Ghidra label at the verified boundary");
        }
    }

    @Override
    public void run() throws Exception {
        Options options = currentProgram.getOptions("PS2 IOP IRX");
        long end = options.getLong("Linker end (ELF value)", -1);
        long gp = options.getLong("Linker GP (ELF value)", -1);
        check(end >= 0, "end/_end verified against PT_LOAD end");
        if (end >= 0) {
            Address exclusive = address(end);
            check(exclusive != null &&
                    currentProgram.getMemory().getBlock(exclusive) == null,
                    "end at 0x" + Long.toHexString(end) +
                    " is exclusive: no fabricated memory block");
        }
        check(gp >= 0, "_gp verified against .iopmod");
        if (gp >= 0) {
            println("SOURCE GP = 0x" + Long.toHexString(gp));
            Address gpAddress = address(gp);
            println("GP is a register value; address " + gpAddress +
                    " must not be fabricated just to hold a label");
        }
        boundary(options, "etext");
        boundary(options, "_etext");
        boundary(options, "edata");
        boundary(options, "_edata");
        boundary(options, "_fbss");

        String entryString = options.getString("Entry (ELF value)", "");
        try {
            if (entryString.startsWith("0x") && gp >= 0) {
                long entry = Long.parseUnsignedLong(entryString.substring(2), 16);
                Address entryAddress = address(entry);
                Register gpRegister = currentProgram.getRegister("gp");
                RegisterValue value = entryAddress == null || gpRegister == null ? null :
                        currentProgram.getProgramContext()
                                .getRegisterValue(gpRegister, entryAddress);
                check(value != null && value.hasValue() &&
                        value.getUnsignedValue().longValue() == gp,
                        "MIPS GP context at module entry " + entryString +
                        " is 0x" + Long.toHexString(gp));
            } else {
                println("GP entry-context check unavailable: entry=" + entryString);
            }
        } catch (RuntimeException e) {
            check(false, "GP context inspection failed: " + e.getMessage());
        }
        println("IRX LINKER AUDIT: passed=" + passed +
                " failed=" + failed + " (read-only)");
    }
}
