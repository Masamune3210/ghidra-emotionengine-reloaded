package ghidra.emotionengine.symboltable;

import static org.junit.Assert.*;

import java.io.File;
import java.nio.file.Files;
import java.util.Collections;
import java.util.Set;

import org.junit.Test;

import com.google.gson.JsonParser;
import com.google.gson.JsonObject;

public class CccIopLegacyUnsignedRangesTest {
    private static File specimen(boolean irx, String... names) throws Exception {
        byte[] header = new byte[52];
        header[0] = 0x7f;
        header[1] = 'E'; header[2] = 'L'; header[3] = 'F';
        header[4] = 1; header[5] = 1; header[6] = 1;
        header[16] = irx ? (byte) 0x80 : 2;
        header[17] = irx ? (byte) 0xff : 0;
        header[18] = 8;
        File file = File.createTempFile("ccc_iop_legacy_stabs_", ".elf");
        file.deleteOnExit();
        try (java.io.OutputStream out = Files.newOutputStream(file.toPath())) {
            out.write(header);
            for (String name : names) {
                out.write(0);
                out.write(name.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                out.write(0);
            }
        }
        return file;
    }

    @Test
    public void recognizesExactLegacyStabsUnsignedRangeOnlyInsideIopElf()
            throws Exception {
        String unsigned = "unsigned int:t4=r4;0;-1;";
        String longer = "long unsigned int:t5=r5;0;-1;";
        File iop = specimen(true, unsigned, longer, "other:t1=r1;0;-1;");
        try {
            assertEquals(Set.of("unsigned int", "long unsigned int"),
                    CccIopLegacyUnsignedRanges.find(iop));
        } finally {
            assertTrue(iop.delete());
        }

        File nonIop = specimen(false, unsigned, longer);
        try {
            assertTrue(CccIopLegacyUnsignedRanges.find(nonIop).isEmpty());
        } finally {
            assertTrue(nonIop.delete());
        }
    }

    @Test
    public void rejectsSimilarButDifferentRanges() {
        assertEquals("unsigned int", CccIopLegacyUnsignedRanges.recognizedName(
                "unsigned int:t4=r4;0;-1;"));
        assertNull(CccIopLegacyUnsignedRanges.recognizedName(
                "unsigned int:t4=r4;0;4294967295;"));
        assertNull(CccIopLegacyUnsignedRanges.recognizedName(
                "unsigned int:t4=r4;0;18446744073709551615;"));
        assertNull(CccIopLegacyUnsignedRanges.recognizedName(
                "unsigned int:t4=r4;0;-1;extra"));
    }

    @Test
    public void correctsOnlyCccLegacy128BitClassWithSourceProvenance() {
        JsonObject suspicious = JsonParser.parseString(
                "{\"descriptor\":\"builtin\",\"class\":\"128-bit integer\"}")
                .getAsJsonObject();
        JsonObject real = JsonParser.parseString(
                "{\"descriptor\":\"builtin\",\"class\":\"128-bit unsigned integer\"}")
                .getAsJsonObject();
        Set<String> proven = Set.of("unsigned int", "long unsigned int");
        assertTrue(Ccc2SymbolImporter.shouldCorrectLegacyIopUnsigned(
                "unsigned int", suspicious, proven, 14));
        assertTrue(Ccc2SymbolImporter.shouldCorrectLegacyIopUnsigned(
                "long unsigned int", suspicious, proven, 13));
        assertFalse(Ccc2SymbolImporter.shouldCorrectLegacyIopUnsigned(
                "unsigned int", suspicious, proven, 15));
        assertFalse(Ccc2SymbolImporter.shouldCorrectLegacyIopUnsigned(
                "uint128_t", suspicious, proven, 14));
        assertFalse(Ccc2SymbolImporter.shouldCorrectLegacyIopUnsigned(
                "unsigned int", real, proven, 14));
        assertFalse(Ccc2SymbolImporter.shouldCorrectLegacyIopUnsigned(
                "unsigned int", suspicious, Collections.emptySet(), 14));
    }
}
