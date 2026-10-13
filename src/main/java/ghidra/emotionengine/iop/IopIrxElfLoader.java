package ghidra.emotionengine.iop;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Map;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.classfinder.ExtensionPointProperties;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Restricts the native Ghidra ELF loader's language decision to IOP IRX/SRX
 * binaries. The R5900 ELF path and its EE memory mirrors are unaffected.
 *
 * No claim of relocated IRX runtime placement is made: .rel.* must be audited
 * separately, especially for Sony ET_IRX files (not standard ET_REL).
 */
@ExtensionPointProperties(priority = 2)
public class IopIrxElfLoader extends ElfLoader {
    private static final CategoryPath TYPES = new CategoryPath("/PS2/IOP");
    private static final String OPT = "PS2 IOP IRX";
    private static final int MAX_SECTION_BYTES = 16 * 1024 * 1024;

    @Override
    public String getName() {
        return "PlayStation 2 IOP IRX (ELF)";
    }

    @Override
    public LoaderTier getTier() {
        // Only Sony IOP types pass findSupportedLoadSpecs; prioritize those over
        // the generic ELF loader without touching ordinary EE/MIPS imports.
        return LoaderTier.SPECIALIZED_TARGET_LOADER;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        if (provider.length() < 52 ||
            !IopIrxFormat.isIopElf(provider.readBytes(0, 52))) {
            return Collections.emptyList();
        }
        return Collections.singletonList(new LoadSpec(this, 0,
            new LanguageCompilerSpecPair("MIPS:LE:32:default", "default"), true));
    }

    @Override
    public void load(Program program, Loader.ImporterSettings settings)
            throws IOException, CancelledException {
        super.load(program, settings);
        // Preserve ELF format identity for Ghidra analyzers that check
        // ElfLoader.isElf(program), despite this loader's distinct UI name.
        program.setExecutableFormat(ElfLoader.ELF_NAME);
        if (!IopIrxFormat.isIopElf(settings.provider().readBytes(0, 52))) {
            return;
        }
        processIop(program, settings.provider(), settings.monitor(), settings.log());
    }

    private static void processIop(Program program, ByteProvider provider,
            TaskMonitor monitor, MessageLog log) throws CancelledException {
        DataType modType = moduleType(program);
        DataType libraryType = libraryType(program);
        try {
            ElfHeader elf = new ElfHeader(provider, null);
            boolean hasRelocations = false;
            for (ElfSectionHeader section : elf.getSections()) {
                monitor.checkCancelled();
                String name = section.getNameAsString();
                if (name == null) {
                    continue;
                }
                if (name.startsWith(".rel")) {
                    hasRelocations = true;
                }
                if (!".iopmod".equals(name)) {
                    continue;
                }
                long size = section.getSize();
                if (size < 27 || size > 4096) {
                    log.appendMsg("IOP IRX: .iopmod has implausible size: " + size);
                    continue;
                }
                byte[] data = provider.readBytes(section.getOffset(), size);
                IopIrxFormat.Module mod = IopIrxFormat.readModule(data);
                if (mod == null) {
                    log.appendMsg("IOP IRX: .iopmod failed validation");
                    continue;
                }
                program.getOptions(OPT).setString("Module name", mod.name);
                program.getOptions(OPT).setString("Module version", version(mod.version));
                program.getOptions(OPT).setString("Entry (ELF value)", hex(mod.entry));
                program.getOptions(OPT).setString("GP (ELF value)", hex(mod.gp));
                program.getOptions(OPT).setString("ModuleInfo (ELF value)", hex(mod.moduleInfo));
                program.getOptions(OPT).setString("Text size", hex(mod.textSize));
                program.getOptions(OPT).setString("Data size", hex(mod.dataSize));
                program.getOptions(OPT).setString("BSS size", hex(mod.bssSize));
                MemoryBlock iopmod = program.getMemory().getBlock(".iopmod");
                if (iopmod != null && iopmod.isInitialized() && iopmod.getSize() >= 26) {
                    makeData(program, iopmod.getStart(), modType);
                    comment(program, iopmod.getStart(),
                        "IOP module " + mod.name + " v" + version(mod.version) +
                        "; entry=" + hex(mod.entry) + "; gp=" + hex(mod.gp));
                }
                labelIfMapped(program, mod.entry, "IOP_ModuleEntry_" + safe(mod.name), true);
                // The module's GP is a *register value*, not necessarily
                // mapped RAM; do not try to label an address just because it
                // has the same number as the GP register's contents.
                program.getOptions(OPT).setLong("Module GP register value", mod.gp);
                log.appendMsg("IOP IRX module: " + mod.name + " v" + version(mod.version));
            }
            program.getOptions(OPT).setBoolean("ELF relocation sections present", hasRelocations);
            int total = 0, applied = 0, failed = 0, unsupported = 0, skipped = 0;
            int partial = 0, unknown = 0;
            Iterator<Relocation> relocations = program.getRelocationTable().getRelocations();
            while (relocations.hasNext()) {
                monitor.checkCancelled();
                Relocation.Status status = relocations.next().getStatus();
                total++;
                switch (status) {
                    case APPLIED:
                    case APPLIED_OTHER: applied++; break;
                    case FAILURE: failed++; break;
                    case UNSUPPORTED: unsupported++; break;
                    case SKIPPED: skipped++; break;
                    case PARTIAL: partial++; break;
                    case UNKNOWN: unknown++; break;
                }
            }
            program.getOptions(OPT).setInt("Relocations recorded", total);
            program.getOptions(OPT).setInt("Relocations applied", applied);
            program.getOptions(OPT).setInt("Relocations failed", failed);
            program.getOptions(OPT).setInt("Relocations unsupported", unsupported);
            program.getOptions(OPT).setInt("Relocations skipped", skipped);
            program.getOptions(OPT).setInt("Relocations partial", partial);
            program.getOptions(OPT).setInt("Relocations unknown", unknown);
            log.appendMsg("IOP IRX relocations: recorded=" + total + ", applied=" +
                applied + ", failed=" + failed + ", unsupported=" + unsupported +
                ", skipped=" + skipped + ", partial=" + partial + ", unknown=" + unknown);
            if (hasRelocations) {
                log.appendMsg("IOP IRX: Sony ET_IRX is not ET_REL; verify relocated " +
                    "instructions and data even when Ghidra reports applied relocations.");
            }
        }
        catch (IOException | ElfException | RuntimeException e) {
            log.appendMsg("IOP IRX module metadata: " + e.getMessage());
        }

        // Generic ELF processing rejects SHN_HIPROC linker pseudo-symbols.
        // Preserve only values independently corroborated by this IRX's ELF
        // sections/PT_LOAD and .iopmod, without making unmapped fake blocks.
        try {
            IopIrxLinkerSymbols symbols = IopIrxLinkerSymbols.inspect(provider);
            if (symbols != null) applyLinkerSymbols(program, symbols, log);
        }
        catch (IOException | RuntimeException e) {
            log.appendMsg("IOP IRX linker pseudo-symbol audit: " + e.getMessage());
        }

        int imports = 0;
        int exports = 0;
        Memory memory = program.getMemory();
        for (MemoryBlock block : memory.getBlocks()) {
            monitor.checkCancelled();
            String name = block.getName();
            if (!block.isLoaded() || !block.isInitialized() ||
                !(".text".equals(name) || ".rodata".equals(name) || ".data".equals(name)) ||
                block.getSize() > MAX_SECTION_BYTES || block.getSize() < 24) {
                continue;
            }
            byte[] bytes = new byte[(int) block.getSize()];
            try {
                if (memory.getBytes(block.getStart(), bytes) != bytes.length) {
                    continue;
                }
            }
            catch (Exception e) {
                log.appendMsg("IOP IRX: cannot inspect " + name + ": " + e.getMessage());
                continue;
            }
            for (int pos = 0; pos <= bytes.length - 24; pos += 4) {
                if ((pos & 0x3fff) == 0) {
                    monitor.checkCancelled();
                }
                IopIrxFormat.Library lib = IopIrxFormat.readLibrary(bytes, pos);
                if (lib == null) {
                    continue;
                }
                Address address = block.getStart().add(pos);
                String prefix = lib.imported ? "IOP_Import_" : "IOP_Export_";
                String tableName = prefix + safe(lib.name) + "_" + Long.toHexString(address.getOffset());
                createLabel(program, address, tableName);
                makeData(program, address, libraryType);
                comment(program, address, (lib.imported ? "IOP import " : "IOP export ") +
                    lib.name + " v" + version(lib.version) +
                    ", mode=" + lib.mode + ", entries=" + lib.values.length);
                for (int i = 0; i < lib.values.length; i++) {
                    Address slot = address.add(20L + (lib.imported ? 8L : 4L) * i);
                    if (lib.imported) {
                        int ordinal = lib.values[i];
                        createLabel(program, slot, "IOP_Import_" + safe(lib.name) +
                            "_ord_" + ordinal + "_" + Long.toHexString(slot.getOffset()));
                        comment(program, slot, "IOP import " + lib.name + " ordinal " + ordinal);
                    }
                    else {
                        long functionAddress = Integer.toUnsignedLong(lib.values[i]);
                        Address target = program.getAddressFactory().getDefaultAddressSpace()
                            .getAddress(functionAddress);
                        MemoryBlock targetBlock = memory.getBlock(target);
                        if (targetBlock != null && targetBlock.isExecute()) {
                            createLabel(program, target, "IOP_Export_" + safe(lib.name) +
                                "_ord_" + i + "_" + Long.toHexString(target.getOffset()));
                            program.getReferenceManager().addMemoryReference(
                                slot, target, RefType.DATA, SourceType.IMPORTED, 0);
                        }
                    }
                }
                if (lib.imported) {
                    imports++;
                }
                else {
                    exports++;
                }
                pos += ((lib.byteLength + 3) & ~3) - 4;
            }
        }
        program.getOptions(OPT).setInt("Import tables recognized", imports);
        program.getOptions(OPT).setInt("Export tables recognized", exports);
        log.appendMsg("IOP IRX: " + imports + " import and " + exports +
            " export tables recognized (unresolved imports are not falsely linked)");
    }

    private static void applyLinkerSymbols(Program program,
            IopIrxLinkerSymbols symbols, MessageLog log) {
        var options = program.getOptions(OPT);
        for (Map.Entry<String, Long> symbol : symbols.verified().entrySet()) {
            String name = symbol.getKey();
            long value = symbol.getValue();
            options.setLong("Linker " + name + " (ELF value)", value);
            if ("etext".equals(name) || "_etext".equals(name) ||
                    "edata".equals(name) || "_edata".equals(name) ||
                    "_fbss".equals(name)) {
                // These are section boundaries which coincide with the start
                // of another section and therefore may be mapped safely.
                labelBoundaryIfMapped(program, value, name);
            }
        }
        if (symbols.verified("end", symbols.imageEnd()) ||
                symbols.verified("_end", symbols.imageEnd())) {
            options.setLong(IopIrxLinkerSymbols.END_VALUE, symbols.imageEnd());
            log.appendMsg("IOP IRX: end/_end = 0x" +
                    Long.toHexString(symbols.imageEnd()) +
                    " (exclusive PT_LOAD boundary; no memory label created)");
        }
        if (symbols.verified("_gp", symbols.moduleGp()) && symbols.moduleGp() != 0) {
            options.setLong(IopIrxLinkerSymbols.GP_VALUE, symbols.moduleGp());
            // Setting GP at the entry instruction seeds the MIPS address
            // analyzer's GP assumption without forcing that constant over
            // the full text region, where the register may be modified.
            // _gp is NOT a memory location; it must not become a RAM label.
            long entry = symbols.moduleEntry();
            try {
                if (entry >= 0) {
                    Address address = program.getAddressFactory()
                            .getDefaultAddressSpace().getAddress(entry);
                    MemoryBlock block = program.getMemory().getBlock(address);
                    Register gp = program.getRegister("gp");
                    if (block != null && block.isExecute() && gp != null) {
                        RegisterValue old = program.getProgramContext()
                                .getRegisterValue(gp, address);
                        if (old == null || !old.hasValue()) {
                            program.getProgramContext().setValue(gp, address, address,
                                    BigInteger.valueOf(symbols.moduleGp()));
                            log.appendMsg("IOP IRX: MIPS gp initialized at entry " +
                                    address + " to module _gp=0x" +
                                    Long.toHexString(symbols.moduleGp()));
                        } else if (old.getUnsignedValue().longValue() != symbols.moduleGp()) {
                            log.appendMsg("IOP IRX: existing GP context differs from " +
                                    "source _gp; preserved existing value");
                        }
                    }
                }
            }
            catch (ContextChangeException | RuntimeException e) {
                log.appendMsg("IOP IRX: GP context was not applied: " + e.getMessage());
            }
            log.appendMsg("IOP IRX: _gp=0x" +
                    Long.toHexString(symbols.moduleGp()) +
                    " verified against .iopmod (register value, not mapped data)");
        }
        for (Map.Entry<String, Long> entry : symbols.observed().entrySet()) {
            if (!symbols.verified(entry.getKey(), entry.getValue())) {
                log.appendMsg("IOP IRX: reserved linker symbol " + entry.getKey() +
                        "=0x" + Long.toHexString(entry.getValue()) +
                        " failed section/module verification; left unresolved");
            }
        }
        log.appendMsg("IOP IRX: verified " + symbols.verified().size() +
                " reserved ELF linker symbols");
    }

    private static String hex(long n) {
        return "0x" + Long.toHexString(n);
    }

    private static String version(int v) {
        return ((v >>> 8) & 255) + "." + String.format("%02d", v & 255);
    }

    private static String safe(String s) {
        return s.replaceAll("[^A-Za-z0-9_]", "_");
    }

    private static void labelBoundaryIfMapped(Program program, long offset,
            String name) {
        try {
            Address address = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(offset);
            MemoryBlock block = program.getMemory().getBlock(address);
            // _fbss, edata and _edata can mark uninitialized .sbss/.bss.
            if (block != null && block.isLoaded()) {
                createLabel(program, address, name);
            }
        } catch (RuntimeException ignored) {
            // Section boundary is recorded numerically in program options.
        }
    }

    private static void labelIfMapped(Program program, long offset,
            String name, boolean executable) {
        if (offset == 0) {
            return;
        }
        try {
            Address address = program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(offset);
            MemoryBlock block = program.getMemory().getBlock(address);
            if (block != null && block.isInitialized() && (!executable || block.isExecute())) {
                createLabel(program, address, name);
            }
        }
        catch (Exception ignored) {
            // Unrelocated section-relative ELF values may not map to the program.
        }
    }

    private static void createLabel(Program program, Address address, String name) {
        try {
            program.getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
        }
        catch (Exception ignored) {
            // Preserve existing symbols and analysis.
        }
    }

    private static void comment(Program program, Address address, String description) {
        Listing listing = program.getListing();
        if (listing.getComment(CommentType.PLATE, address) == null) {
            listing.setComment(address, CommentType.PLATE, description);
        }
    }

    private static void makeData(Program program, Address address, DataType dt) {
        Listing listing = program.getListing();
        if (listing.getCodeUnitContaining(address) == null ||
            listing.getCodeUnitContaining(address) instanceof ghidra.program.model.listing.Data &&
            !((ghidra.program.model.listing.Data) listing.getCodeUnitContaining(address)).isDefined()) {
            try {
                listing.createData(address, dt);
            }
            catch (Exception ignored) {
                // Never clear existing instructions/data to force a header declaration.
            }
        }
    }

    private static DataType moduleType(Program p) {
        StructureDataType s = new StructureDataType(TYPES, "IopModuleHeader", 0);
        s.add(DWordDataType.dataType, "moduleInfo", null);
        s.add(DWordDataType.dataType, "entry", null);
        s.add(DWordDataType.dataType, "gp", null);
        s.add(DWordDataType.dataType, "textSize", null);
        s.add(DWordDataType.dataType, "dataSize", null);
        s.add(DWordDataType.dataType, "bssSize", null);
        s.add(WordDataType.dataType, "version", null);
        return p.getDataTypeManager().addDataType(s, DataTypeConflictHandler.KEEP_HANDLER);
    }

    private static DataType libraryType(Program p) {
        StructureDataType s = new StructureDataType(TYPES, "IopLibraryTableHeader", 0);
        s.add(DWordDataType.dataType, "magic", null);
        s.add(DWordDataType.dataType, "next", null);
        s.add(WordDataType.dataType, "version", null);
        s.add(WordDataType.dataType, "mode", null);
        s.add(new ArrayDataType(CharDataType.dataType, 8, 1), "name", null);
        return p.getDataTypeManager().addDataType(s, DataTypeConflictHandler.KEEP_HANDLER);
    }
}
