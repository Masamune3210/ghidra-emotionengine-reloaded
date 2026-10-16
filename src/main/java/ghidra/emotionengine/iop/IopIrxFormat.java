package ghidra.emotionengine.iop;

import java.util.ArrayList;
import java.util.List;

/**
 * Byte-level PS2 IOP IRX format checks. No Ghidra types are needed, allowing
 * malformed-file and table-layout tests without importing a program.
 */
public final class IopIrxFormat {
    public static final int IMPORT_MAGIC = 0x41e00000;
    public static final int EXPORT_MAGIC = 0x41c00000;
    private static final int MAX_ENTRIES = 1024;

    private IopIrxFormat() {}

    private static int u16(byte[] b, int p) {
        return (b[p] & 255) | ((b[p + 1] & 255) << 8);
    }

    private static int u32(byte[] b, int p) {
        return u16(b, p) | (u16(b, p + 2) << 16);
    }

    // Sony IOP relocatables use 0xff80/0xff81. The 0xff90/0xff91
    // relocatable types belong to the Emotion Engine, not the IOP.
    private static final int ET_SCE_IOPRELEXEC = 0xff80;
    private static final int ET_SCE_IOPRELEXEC2 = 0xff81;
    private static final int EF_MIPS_MACH_MASK = 0x00ff0000;
    private static final int E_MIPS_MACH_5900 = 0x00920000;

    /** Recognize only IOP relocatables, never R5900/EE executables. */
    public static boolean isIopElf(byte[] h) {
        if (h == null || h.length < 52 || h[0] != 0x7f ||
            h[1] != 'E' || h[2] != 'L' || h[3] != 'F' ||
            h[4] != 1 || h[5] != 1 || h[6] != 1) {
            return false;
        }
        int type = u16(h, 16);
        int machine = u16(h, 18);
        int flags = u32(h, 36);
        return (type == ET_SCE_IOPRELEXEC || type == ET_SCE_IOPRELEXEC2) &&
            (machine == 8 || machine == 10) &&
            (flags & EF_MIPS_MACH_MASK) != E_MIPS_MACH_5900;
    }

    public static final class Module {
        public final long moduleInfo, entry, gp, textSize, dataSize, bssSize;
        public final int version;
        public final String name;

        private Module(byte[] b, String name) {
            moduleInfo = Integer.toUnsignedLong(u32(b, 0));
            entry = Integer.toUnsignedLong(u32(b, 4));
            gp = Integer.toUnsignedLong(u32(b, 8));
            textSize = Integer.toUnsignedLong(u32(b, 12));
            dataSize = Integer.toUnsignedLong(u32(b, 16));
            bssSize = Integer.toUnsignedLong(u32(b, 20));
            version = u16(b, 24);
            this.name = name;
        }
    }

    /** Fixed 0x1a-byte .iopmod fields, followed by a NUL-terminated name. */
    public static Module readModule(byte[] b) {
        if (b == null || b.length < 27) {
            return null;
        }
        int end = 26;
        while (end < b.length && end < 154 && b[end] != 0) {
            int c = b[end] & 255;
            if (c < 32 || c > 126) {
                return null;
            }
            end++;
        }
        if (end == 26 || end == b.length || end == 154 || b[end] != 0) {
            return null;
        }
        return new Module(b, new String(b, 26, end - 26, java.nio.charset.StandardCharsets.US_ASCII));
    }

    public static final class Library {
        public final boolean imported;
        public final int version, mode, byteLength;
        public final String name;
        /** For imports: the ordinal; for exports: the 32-bit function address. */
        public final int[] values;

        private Library(boolean imported, String name, int version, int mode,
                int byteLength, List<Integer> items) {
            this.imported = imported;
            this.name = name;
            this.version = version;
            this.mode = mode;
            this.byteLength = byteLength;
            values = new int[items.size()];
            for (int i = 0; i < items.size(); i++) {
                values[i] = items.get(i);
            }
        }
    }

    /**
     * Tables: magic, next, u16 version, u16 mode, char name[8], then:
     * imports = { jr ra, addiu/ori zero,zero,ordinal } pairs, ended by {0,0};
     * exports = pointer words terminated by zero.
     */
    public static Library readLibrary(byte[] b, int start) {
        return readLibrary(b, start, false);
    }

    /**
     * The first export can point to offset zero in a Sony relocatable module.
     * On disk that entry is zero and carries an R_MIPS_32 relocation, just
     * like the later nonzero entries. A plain zero is otherwise the export
     * terminator. Callers may permit a leading zero ONLY after independently
     * verifying the R_MIPS_32 relocation at that exact first export slot.
     *
     * Do not enable this for import stubs; their {0,0} terminator is strict.
     */
    public static Library readLibrary(byte[] b, int start,
            boolean allowRelocatedZeroFirstExport) {
        if (b == null || start < 0 || (start & 3) != 0 ||
                (long) start + 24 > b.length) {
            return null;
        }
        int magic = u32(b, start);
        if (magic != IMPORT_MAGIC && magic != EXPORT_MAGIC) {
            return null;
        }
        int nameEnd = start + 12;
        while (nameEnd < start + 20 && b[nameEnd] != 0) {
            int c = b[nameEnd] & 255;
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) {
                return null;
            }
            nameEnd++;
        }
        if (nameEnd == start + 12) {
            return null;
        }
        for (int i = nameEnd + 1; i < start + 20; i++) {
            if (b[i] != 0) {
                return null;
            }
        }
        String name = new String(b, start + 12, nameEnd - start - 12,
            java.nio.charset.StandardCharsets.US_ASCII);
        boolean imported = magic == IMPORT_MAGIC;
        List<Integer> values = new ArrayList<>();
        int at = start + 20;
        for (int i = 0; i < MAX_ENTRIES; i++) {
            if ((long) at + (imported ? 8 : 4) > b.length) {
                return null;
            }
            int first = u32(b, at);
            if (first == 0 && !imported && values.isEmpty() &&
                    allowRelocatedZeroFirstExport) {
                // Require a subsequent aligned nonzero target. This avoids
                // accepting a vacant table even if the caller is mistaken.
                if ((long) at + 8 > b.length) {
                    return null;
                }
                int next = u32(b, at + 4);
                if (next == 0 || (next & 3) != 0) {
                    return null;
                }
                values.add(0);
                at += 4;
                continue;
            }
            if (first == 0) {
                if (imported && u32(b, at + 4) != 0) {
                    return null;
                }
                if (values.isEmpty()) {
                    return null;
                }
                return new Library(imported, name, u16(b, start + 8),
                    u16(b, start + 10), at + (imported ? 8 : 4) - start, values);
            }
            if (imported) {
                int second = u32(b, at + 4);
                if (first != 0x03e00008 ||
                    ((second & 0xffff0000) != 0x24000000 &&
                     (second & 0xffff0000) != 0x34000000)) {
                    return null;
                }
                values.add(second & 0xffff);
                at += 8;
            }
            else {
                values.add(first);
                at += 4;
            }
        }
        return null;
    }
}
