package ghidra.emotionengine.iop;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;

import org.junit.Test;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.emotionengine.symboltable.Ccc2SymbolImporter;

public class IopIrxLinkerSymbolsTest {
    private static void u16(byte[] b, int p, int n) {
        b[p] = (byte) n;
        b[p + 1] = (byte) (n >>> 8);
    }
    private static void u32(byte[] b, int p, long n) {
        for (int i = 0; i < 4; i++) b[p + i] = (byte) (n >>> (8 * i));
    }
    private static String stringTable(String[] values) {
        StringBuilder result = new StringBuilder("\0");
        for (String value : values) result.append(value).append('\0');
        return result.toString();
    }
    private static void section(byte[] elf, int index, int nameOffset,
            int type, long addr, int off, int size, int link, int entrySize) {
        int p = 0x400 + index * 40;
        u32(elf, p, nameOffset);
        u32(elf, p + 4, type);
        u32(elf, p + 8, index == 2 ? 6 : index == 3 ? 2 :
                index == 4 || index == 5 || index == 6 ? 3 : 0);
        u32(elf, p + 12, addr);
        u32(elf, p + 16, off);
        u32(elf, p + 20, size);
        u32(elf, p + 24, link);
        u32(elf, p + 36, entrySize);
    }
    private static byte[] fixture() {
        byte[] elf = new byte[0x700];
        elf[0] = 0x7f; elf[1] = 'E'; elf[2] = 'L'; elf[3] = 'F';
        elf[4] = 1; elf[5] = 1; elf[6] = 1;
        u16(elf, 16, 0xff80); u16(elf, 18, 8);
        u32(elf, 20, 1); u32(elf, 24, 0x10);
        u32(elf, 28, 0x34); u32(elf, 32, 0x400);
        u16(elf, 40, 52); u16(elf, 42, 32); u16(elf, 44, 1);
        u16(elf, 46, 40); u16(elf, 48, 10); u16(elf, 50, 9);

        // One loadable segment occupies the ELF VMA interval [0,0x98).
        u32(elf, 0x34, 1); u32(elf, 0x38, 0xa0);
        u32(elf, 0x3c, 0); u32(elf, 0x44, 0x80);
        u32(elf, 0x48, 0x98);

        u32(elf, 0x80, 0xffffffffL); u32(elf, 0x84, 0x10);
        u32(elf, 0x88, 0x8080); // entry and GP from .iopmod

        String shnames = stringTable(new String[] {
                ".iopmod", ".text", ".rodata", ".data",
                ".sbss", ".bss", ".strtab", ".symtab", ".shstrtab"});
        byte[] sh = shnames.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(sh, 0, elf, 0x140, sh.length);
        String strnames = stringTable(new String[] {
                "etext", "_etext", "edata", "_edata", "_fbss",
                "end", "_end", "_gp"});
        byte[] str = strnames.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(str, 0, elf, 0x1c0, str.length);

        section(elf, 1, shnames.indexOf(".iopmod"), 0x70000080, 0, 0x80, 27, 0, 0);
        section(elf, 2, shnames.indexOf(".text"), 1, 0, 0xa0, 0x40, 0, 0);
        section(elf, 3, shnames.indexOf(".rodata"), 1, 0x40, 0xe0, 0x20, 0, 0);
        section(elf, 4, shnames.indexOf(".data"), 1, 0x60, 0x100, 0x20, 0, 0);
        section(elf, 5, shnames.indexOf(".sbss"), 8, 0x80, 0, 8, 0, 0);
        section(elf, 6, shnames.indexOf(".bss"), 8, 0x90, 0, 8, 0, 0);
        section(elf, 7, shnames.indexOf(".strtab"), 3, 0, 0x1c0, str.length, 0, 0);
        section(elf, 8, shnames.indexOf(".symtab"), 2, 0, 0x240, 9 * 16, 7, 16);
        section(elf, 9, shnames.indexOf(".shstrtab"), 3, 0, 0x140, sh.length, 0, 0);

        String[] names = {"etext", "_etext", "edata", "_edata",
                "_fbss", "end", "_end", "_gp"};
        long[] values = {0x40, 0x40, 0x80, 0x80, 0x80, 0x98, 0x98, 0x8080};
        for (int i = 0; i < names.length; i++) {
            int p = 0x240 + (i + 1) * 16;
            u32(elf, p, strnames.indexOf(names[i]));
            u32(elf, p + 4, values[i]);
            u16(elf, p + 14, 0xff1f);
        }
        return elf;
    }

    @Test
    public void recognizesAllEightReservedLinkerSymbolsWithoutMakingEndOrGpMapped()
            throws Exception {
        IopIrxLinkerSymbols result =
                IopIrxLinkerSymbols.inspect(new ByteArrayProvider(fixture()));
        assertNotNull(result);
        assertEquals(8, result.verified().size());
        assertEquals(0x98, result.imageEnd());
        assertEquals(0x8080, result.moduleGp());
        assertEquals(0x10, result.moduleEntry());
        assertTrue(result.verified("etext", 0x40));
        assertTrue(result.verified("_fbss", 0x80));
        assertTrue(result.verified("end", 0x98));
        assertTrue(result.verified("_end", 0x98));
        assertTrue(result.verified("_gp", 0x8080));
    }

    @Test
    public void refusesMismatchingSpecialSymbolsAndUnverifiedEntry() throws Exception {
        byte[] corrupted = fixture();
        u32(corrupted, 0x240 + 8 * 16 + 4, 0x9090);
        u32(corrupted, 0x240 + 6 * 16 + 4, 0x90);
        u32(corrupted, 0x84, 0x14);
        IopIrxLinkerSymbols result =
                IopIrxLinkerSymbols.inspect(new ByteArrayProvider(corrupted));
        assertFalse(result.verified("_gp", 0x9090));
        assertFalse(result.verified("end", 0x90));
        assertEquals(-1, result.moduleEntry());
        assertTrue(result.verified("_end", 0x98));
        assertEquals(6, result.verified().size());
    }

    @Test
    public void rejectsNonIopElfs() throws Exception {
        byte[] notIop = fixture();
        u16(notIop, 16, 2);
        assertNull(IopIrxLinkerSymbols.inspect(new ByteArrayProvider(notIop)));
    }
}
