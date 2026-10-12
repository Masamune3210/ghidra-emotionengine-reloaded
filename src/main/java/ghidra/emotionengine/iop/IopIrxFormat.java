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

    /** ET_IRX, ET_IRX2 and ET_ERX2 are Sony ELF types, not ET_REL. */
    public static boolean isIopElf(byte[] h) {
        if (h == null || h.length < 52 || h[0] != 0x7f ||
            h[1] != 'E' || h[2] != 'L' || h[3] != 'F' ||
            h[4] != 1 || h[5] != 1 || h[6] != 1) {
            return false;
        }
        int type = u16(h, 16);
        int machine = u16(h, 18);
        return (type == 0xff80 || type == 0xff81 || type == 0xff91) &&
            (machine == 8 || machine == 10);
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
