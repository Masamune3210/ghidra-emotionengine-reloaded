// Read-only audit of source-validated Sony IOP IRX linker boundaries and GP.
//@category ghidra-emotionengine

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

/**
 * Reports verified linker pseudo-labels without creating fictitious RAM.
 * Run after importing a fresh IOP IRX with the updated extension.
 */
public class AuditIopIrxLinkerMetadata_20261012_v2 extends GhidraScript {
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

    private long verifiedEntry(Options options) {
        long sourceVerified = options.getLong(
                "Verified module entry (ELF value)", -1);
        if (sourceVerified >= 0) return sourceVerified;
        // Compatibility with previously imported IRX databases.
        String earlier = options.getString("Entry (ELF value)", "");
        if (earlier.startsWith("0x")) {
            try {
                return Long.parseUnsignedLong(earlier.substring(2), 16);
            } catch (NumberFormatException e) {
                println("Unparseable earlier module entry option: " + earlier);
            }
        }
        return -1;
    }

    private void checkGpContext(Options options, long gpValue) throws Exception {
        if (gpValue < 0) return; // GP verification has already failed.
        Register gp = currentProgram.getRegister("gp");
        if (gp == null) {
            check(false, "MIPS gp register is available");
            return;
        }
        long entry = verifiedEntry(options);
        if (entry >= 0) {
            Address at = address(entry);
            RegisterValue value = at == null ? null :
                    currentProgram.getProgramContext().getRegisterValue(gp, at);
            check(value != null && value.hasValue() &&
                    value.getUnsignedValue().longValue() == gpValue,
                    "MIPS GP context at independently verified module entry 0x" +
                    Long.toHexString(entry) + " is 0x" +
                    Long.toHexString(gpValue));
            return;
        }

        // Databases imported before the entry option was persisted can still
        // prove that the source GP was stored on executable code. This is
        // intentionally weaker than verifying it at the actual entry point.
        println("Verified entry option absent; auditing existing executable " +
                "GP context ranges instead");
        AddressRangeIterator ranges = currentProgram.getProgramContext()
                .getRegisterValueAddressRanges(gp);
        boolean found = false;
        while (ranges.hasNext()) {
            monitor.checkCanceled();
            AddressRange range = ranges.next();
            Address at = range.getMinAddress();
            MemoryBlock block = currentProgram.getMemory().getBlock(at);
            if (block == null || !block.isExecute()) continue;
            RegisterValue value = currentProgram.getProgramContext()
                    .getRegisterValue(gp, at);
            if (value != null && value.hasValue() &&
                    value.getUnsignedValue().longValue() == gpValue) {
                found = true;
                println("MATCH GP=0x" + Long.toHexString(gpValue) +
                        " at executable context range " + range);
            }
        }
        check(found, "source GP value is preserved on executable register " +
                "context (module entry not independently recorded)");
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

        checkGpContext(options, gp);
        println("IRX LINKER AUDIT: passed=" + passed +
                " failed=" + failed + " (read-only)");
    }
}
