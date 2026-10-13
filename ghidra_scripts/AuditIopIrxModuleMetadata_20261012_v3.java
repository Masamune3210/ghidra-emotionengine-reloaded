// Read-only source-backed Sony IOP module audit, including stripped IRX binaries.
//@category ghidra-emotionengine

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.symbol.Symbol;

public class AuditIopIrxModuleMetadata_20261012_v3 extends GhidraScript {
    private int passed, failed;
    private void check(boolean good, String what) {
        if (good) { passed++; println("PASS " + what); }
        else { failed++; println("FAIL " + what); }
    }
    private Address address(long offset) {
        try {
            return currentProgram.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(offset);
        } catch (RuntimeException e) { return null; }
    }
    @Override
    public void run() throws Exception {
        Options o = currentProgram.getOptions("PS2 IOP IRX");
        long moduleGp = o.getLong("Verified module GP (ELF value)", -1);
        long linkerGp = o.getLong("Linker GP (ELF value)", -1);
        long entry = o.getLong("Verified module entry (ELF value)", -1);
        long gp = moduleGp >= 0 ? moduleGp : linkerGp;
        if (linkerGp >= 0 && moduleGp >= 0) {
            check(linkerGp == moduleGp, "reserved _gp agrees with source module GP");
        }
        println("MODULE GP " + (gp < 0 ? "not verified" : "0x" + Long.toHexString(gp)));
        println("ENTRY " + (entry < 0 ? "not verified" : "0x" + Long.toHexString(entry)));
        if (gp >= 0 && entry >= 0) {
            Address at = address(entry);
            Register reg = currentProgram.getRegister("gp");
            RegisterValue value = at == null || reg == null ? null :
                    currentProgram.getProgramContext().getRegisterValue(reg, at);
            check(value != null && value.hasValue() &&
                    value.getUnsignedValue().longValue() == gp,
                    "MIPS gp register context at verified module entry");
        } else {
            println("GP entry-context assertion skipped: source entry/GP not both verified");
        }
        long end = o.getLong("Linker end (ELF value)", -1);
        if (end >= 0) {
            Address at = address(end);
            check(at != null && currentProgram.getMemory().getBlock(at) == null,
                    "exclusive end does not fabricate a memory block");
        }
        String[] names = {"etext", "_etext", "edata", "_edata", "_fbss"};
        for (String name : names) {
            long v = o.getLong("Linker " + name + " (ELF value)", -1);
            if (v < 0) continue; // Optional; stripped modules have no linker labels.
            Address at = address(v);
            boolean found = false;
            if (at != null && currentProgram.getMemory().getBlock(at) != null) {
                for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(at)) {
                    if (name.equals(symbol.getName())) found = true;
                }
            }
            check(found, name + " at verified mapped ELF boundary");
        }
        int total = o.getInt("Relocations recorded", -1);
        if (total >= 0) {
            int applied = o.getInt("Relocations applied", 0);
            int partial = o.getInt("Relocations partial", 0);
            int failure = o.getInt("Relocations failed", 0);
            int unsupported = o.getInt("Relocations unsupported", 0);
            int skipped = o.getInt("Relocations skipped", 0);
            int unknown = o.getInt("Relocations unknown", 0);
            println("RELOCATIONS total=" + total + " applied=" + applied +
                    " partial=" + partial + " failed=" + failure +
                    " unsupported=" + unsupported + " skipped=" + skipped +
                    " unknown=" + unknown);
            check(total == applied + partial + failure + unsupported + skipped + unknown,
                    "relocation status counts are complete");
            check(failure == 0 && unsupported == 0,
                    "no failed or unsupported relocations");
        }
        println("IOP TABLES imports=" + o.getInt("Import tables recognized", -1) +
                " exports=" + o.getInt("Export tables recognized", -1));
        println("IRX MODULE AUDIT: passed=" + passed +
                " failed=" + failed + " (read-only)");
    }
}
