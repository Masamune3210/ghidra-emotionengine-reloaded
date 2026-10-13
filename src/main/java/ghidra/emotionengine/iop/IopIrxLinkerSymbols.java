package ghidra.emotionengine.iop;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import ghidra.app.util.bin.ByteProvider;

/**
 * Conservative ELF32/LE symbol and range inspection for Sony IOP IRX/ERX.
 *
 * A handful of old MIPS linkers emit linker boundary symbols with shndx
 * 0xff1f (SHN_HIPROC). Generic ELF symbol placement cannot map them.
 * This reader records their original values and verifies them against actual
 * section, PT_LOAD and .iopmod geometry before any metadata is applied.
 * It neither patches source bytes nor invents mapped memory.
 */
public final class IopIrxLinkerSymbols {
    public static final String OPTIONS = "PS2 IOP IRX";
    public static final String END_VALUE = "Linker end (ELF value)";
    public static final String GP_VALUE = "Linker GP (ELF value)";
    public static final int SHN_HIPROC = 0xff1f;
    private static final Set<String> KNOWN = Set.of(
            "etext", "_etext", "edata", "_edata", "_fbss", "end", "_end", "_gp");
    private static final int MAX_TABLE_BYTES = 0x100000;

    private final Map<String, Long> verified;
    private final Map<String, Long> observed;
    private final long imageEnd;
    private final long moduleGp;

    private IopIrxLinkerSymbols(Map<String, Long> verified,
            Map<String, Long> observed, long imageEnd, long moduleGp) {
        this.verified = Collections.unmodifiableMap(new HashMap<>(verified));
        this.observed = Collections.unmodifiableMap(new HashMap<>(observed));
        this.imageEnd = imageEnd;
        this.moduleGp = moduleGp;
    }

    public Map<String, Long> verified() { return verified; }
    public Map<String, Long> observed() { return observed; }
    public boolean verified(String name, long value) {
        return verified.getOrDefault(name, -1L) == value;
    }
    public long imageEnd() { return imageEnd; }
    public long moduleGp() { return moduleGp; }

    private static int u16(byte[] b, int offset) {
        return (b[offset] & 0xff) | ((b[offset + 1] & 0xff) << 8);
    }

    private static long u32(byte[] b, int offset) {
        return Integer.toUnsignedLong((b[offset] & 0xff) |
                ((b[offset + 1] & 0xff) << 8) |
                ((b[offset + 2] & 0xff) << 16) |
                (b[offset + 3] << 24));
    }

    private static byte[] read(ByteProvider provider, long offset, long size)
            throws IOException {
        if (offset < 0 || size < 0 || size > MAX_TABLE_BYTES ||
                offset > provider.length() ||
                size > provider.length() - offset) {
            throw new IOException("Invalid IOP ELF table extent");
        }
        return provider.readBytes(offset, size);
    }

    private static String cstring(byte[] bytes, long offset) {
        if (offset < 0 || offset >= bytes.length) return "";
        StringBuilder s = new StringBuilder(64);
        for (int i = (int) offset; i < bytes.length && s.length() < 256; i++) {
            int c = bytes[i] & 0xff;
            if (c == 0) return s.toString();
            if (c < 32 || c > 126) return "";
            s.append((char) c);
        }
        return "";
    }

    private static final class Section {
        final long nameOffset, type, address, fileOffset, fileSize, link;
        final long entrySize;
        String name = "";

        Section(byte[] sh) {
            nameOffset = u32(sh, 0);
            type = u32(sh, 4);
            address = u32(sh, 12);
            fileOffset = u32(sh, 16);
            fileSize = u32(sh, 20);
            link = u32(sh, 24);
            entrySize = u32(sh, 36);
        }
    }

    /**
     * Returns null for non-IOP ELFs. Corrupt ELF geometry throws IOException.
     * No symbol is considered verified solely because its name matches.
     */
    public static IopIrxLinkerSymbols inspect(ByteProvider provider) throws IOException {
        if (provider.length() < 52) return null;
        byte[] header = read(provider, 0, 52);
        if (!IopIrxFormat.isIopElf(header)) return null;

        long phoff = u32(header, 28), shoff = u32(header, 32);
        int phent = u16(header, 42), phnum = u16(header, 44);
        int shent = u16(header, 46), shnum = u16(header, 48);
        int namesIndex = u16(header, 50);
        if (phent < 32 || phnum == 0 || phnum > 128 ||
                shent < 40 || shnum == 0 || shnum > 4096 ||
                namesIndex >= shnum) {
            throw new IOException("Malformed IOP ELF table dimensions");
        }
        long end = -1;
        for (int i = 0; i < phnum; i++) {
            byte[] ph = read(provider, phoff + (long) i * phent, 32);
            if (u32(ph, 0) != 1) continue; // PT_LOAD
            long vaddr = u32(ph, 8);
            long memsize = u32(ph, 20);
            if (memsize > 0 && vaddr + memsize <= 0x100000000L) {
                end = Math.max(end, vaddr + memsize);
            }
        }

        Section[] sections = new Section[shnum];
        for (int i = 0; i < shnum; i++) {
            sections[i] = new Section(read(provider,
                    shoff + (long) i * shent, 40));
        }
        Section shNames = sections[namesIndex];
        byte[] nameBytes = read(provider, shNames.fileOffset, shNames.fileSize);
        Map<String, Section> byName = new HashMap<>();
        for (Section section : sections) {
            section.name = cstring(nameBytes, section.nameOffset);
            if (!section.name.isEmpty()) byName.putIfAbsent(section.name, section);
        }
        long gp = -1;
        Section iopmod = byName.get(".iopmod");
        if (iopmod != null && iopmod.fileSize >= 12) {
            byte[] module = read(provider, iopmod.fileOffset, 12);
            gp = u32(module, 8);
        }

        Map<String, Long> observed = new HashMap<>();
        for (Section sec : sections) {
            if (sec.type != 2 || sec.entrySize < 16 || sec.fileSize > MAX_TABLE_BYTES ||
                    sec.link >= sections.length) continue; // SHT_SYMTAB
            Section strings = sections[(int) sec.link];
            if (strings.type != 3) continue; // SHT_STRTAB
            byte[] strtab = read(provider, strings.fileOffset, strings.fileSize);
            byte[] symbols = read(provider, sec.fileOffset, sec.fileSize);
            for (int i = 0; i + 16 <= symbols.length; i += (int) sec.entrySize) {
                if (u16(symbols, i + 14) != SHN_HIPROC) continue;
                String name = cstring(strtab, u32(symbols, i));
                if (KNOWN.contains(name)) {
                    observed.putIfAbsent(name, u32(symbols, i + 4));
                }
            }
        }

        Map<String, Long> verified = new HashMap<>();
        Section text = byName.get(".text");
        Section data = byName.get(".data");
        Section sbss = byName.get(".sbss");
        Section bss = byName.get(".bss");
        long textEnd = text == null ? -1 : text.address + text.fileSize;
        long dataEnd = data == null ? -1 : data.address + data.fileSize;
        long smallBss = sbss != null ? sbss.address : bss != null ? bss.address : -1;
        for (Map.Entry<String, Long> e : observed.entrySet()) {
            String name = e.getKey();
            long actual = e.getValue();
            long expected;
            switch (name) {
                case "etext":
                case "_etext": expected = textEnd; break;
                case "edata":
                case "_edata": expected = dataEnd; break;
                case "_fbss": expected = smallBss; break;
                case "end":
                case "_end": expected = end; break;
                case "_gp": expected = gp; break;
                default: continue;
            }
            if (expected >= 0 && actual == expected) {
                verified.put(name, actual);
            }
        }
        return new IopIrxLinkerSymbols(verified, observed, end, gp);
    }
}
