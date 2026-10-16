package ghidra.emotionengine.iop;

import static org.junit.Assert.*;

import org.junit.Test;

public class IopIrxFormatTest {
    private static void word(byte[] b, int p, int value) {
        for (int i = 0; i < 4; i++) {
            b[p + i] = (byte) (value >>> (i * 8));
        }
    }

    @Test
    public void recognizesOnlyLittleEndian32BitIopElfs() {
        byte[] h = new byte[52];
        h[0] = 0x7f; h[1] = 'E'; h[2] = 'L'; h[3] = 'F';
        h[4] = 1; h[5] = 1; h[6] = 1; h[16] = (byte) 0x80; h[17] = (byte) 0xff;
        h[18] = 8;
        assertTrue(IopIrxFormat.isIopElf(h));
        h[16] = 2;
        assertFalse(IopIrxFormat.isIopElf(h));
        h[16] = (byte) 0x80;
        h[5] = 2;
        assertFalse(IopIrxFormat.isIopElf(h));
        h[5] = 1;
        h[4] = 2;
        assertFalse(IopIrxFormat.isIopElf(h));
    }

    @Test
    public void iopAndEeRelocatableTypesAreDisjoint() {
        byte[] h = new byte[52];
        h[0] = 0x7f; h[1] = 'E'; h[2] = 'L'; h[3] = 'F';
        h[4] = 1; h[5] = 1; h[6] = 1; h[18] = 8;

        // Both Sony IOP relocatable types must be accepted.
        h[16] = (byte) 0x80; h[17] = (byte) 0xff;
        assertTrue(IopIrxFormat.isIopElf(h));
        h[16] = (byte) 0x81;
        assertTrue(IopIrxFormat.isIopElf(h));

        // Neither Sony EE relocatable type is an IOP program.
        h[16] = (byte) 0x90;
        assertFalse(IopIrxFormat.isIopElf(h));
        h[16] = (byte) 0x91;
        assertFalse(IopIrxFormat.isIopElf(h));

        // Even a contradictory IOP type + explicit R5900 machine flag must
        // not be offered for import as an IOP module.
        h[16] = (byte) 0x80;
        word(h, 36, 0x20924001); // EE/R5900 e_flags
        assertFalse(IopIrxFormat.isIopElf(h));
        h[16] = (byte) 0x81;
        assertFalse(IopIrxFormat.isIopElf(h));

        // Other machine flags are not accidentally treated as R5900.
        word(h, 36, 0x20000000);
        assertTrue(IopIrxFormat.isIopElf(h));
        h[18] = 10;
        assertTrue(IopIrxFormat.isIopElf(h));
        h[18] = 9;
        assertFalse(IopIrxFormat.isIopElf(h));
    }

    @Test
    public void decodesIopModuleHeader() {
        byte[] b = new byte[40];
        word(b, 4, 0x1234);
        word(b, 8, 0x4000);
        word(b, 12, 0x2000);
        b[24] = 2; b[25] = 1;
        byte[] name = "secrman".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(name, 0, b, 26, name.length);
        IopIrxFormat.Module mod = IopIrxFormat.readModule(b);
        assertNotNull(mod);
        assertEquals("secrman", mod.name);
        assertEquals(0x1234L, mod.entry);
        assertEquals(0x4000L, mod.gp);
        assertEquals(0x102, mod.version);
        b[26] = 1;
        assertNull(IopIrxFormat.readModule(b));
    }

    @Test
    public void relocatedZeroFirstExportRequiresExplicitEvidence() {
        byte[] b = new byte[64];
        word(b, 0, IopIrxFormat.EXPORT_MAGIC);
        b[8] = 1; b[9] = 1;
        System.arraycopy("loadcore".getBytes(), 0, b, 12, 8);
        // Ordinal zero points to module image offset 0. In the source IRX
        // this cell has an R_MIPS_32 relocation; the loader verifies it.
        word(b, 20, 0);
        word(b, 24, 0x5dc);
        word(b, 28, 0x1bdc);
        word(b, 32, 0);

        assertNull("Without relocation evidence, zero remains a terminator",
            IopIrxFormat.readLibrary(b, 0));
        IopIrxFormat.Library exp = IopIrxFormat.readLibrary(b, 0, true);
        assertNotNull(exp);
        assertFalse(exp.imported);
        assertEquals("loadcore", exp.name);
        assertArrayEquals(new int[]{0, 0x5dc, 0x1bdc}, exp.values);
        assertEquals(36, exp.byteLength);

        // A zero followed by another zero is not a valid export table.
        word(b, 24, 0);
        assertNull(IopIrxFormat.readLibrary(b, 0, true));
        // Unaligned second pointer is not a valid MIPS instruction entry.
        word(b, 24, 0x5dd);
        assertNull(IopIrxFormat.readLibrary(b, 0, true));
    }

    @Test
    public void importTerminatorIsNeverPromotedByExportException() {
        byte[] b = new byte[48];
        word(b, 0, IopIrxFormat.IMPORT_MAGIC);
        System.arraycopy("sysmem".getBytes(), 0, b, 12, 6);
        word(b, 20, 0);
        word(b, 24, 0x5dc);
        assertNull(IopIrxFormat.readLibrary(b, 0, true));
    }

    @Test
    public void validatesImportAndExportTerminators() {
        byte[] b = new byte[128];
        word(b, 0, IopIrxFormat.IMPORT_MAGIC);
        b[8] = 1; b[9] = 1;
        System.arraycopy("sysmem".getBytes(), 0, b, 12, 6);
        word(b, 20, 0x03e00008);
        word(b, 24, 0x24000004);
        IopIrxFormat.Library imp = IopIrxFormat.readLibrary(b, 0);
        assertNotNull(imp);
        assertTrue(imp.imported);
        assertEquals(4, imp.values[0]);
        assertEquals(36, imp.byteLength);
        word(b, 24, 0x24010004);
        assertNull(IopIrxFormat.readLibrary(b, 0));

        word(b, 64, IopIrxFormat.EXPORT_MAGIC);
        System.arraycopy("loadcore".getBytes(), 0, b, 76, 8);
        word(b, 84, 0x1000);
        IopIrxFormat.Library exp = IopIrxFormat.readLibrary(b, 64);
        assertNotNull(exp);
        assertFalse(exp.imported);
        assertEquals(0x1000, exp.values[0]);
        assertEquals(28, exp.byteLength);
    }
}
