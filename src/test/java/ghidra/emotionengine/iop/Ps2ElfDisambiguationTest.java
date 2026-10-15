package ghidra.emotionengine.iop;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Test;

/**
 * Regression checks for the EE opinion's ELF e_flags matcher versus the
 * IOP-specific ELF loader. Opinions cannot inspect e_type, so the IOP loader
 * must also reject any header carrying an R5900 machine variant.
 */
public class Ps2ElfDisambiguationTest {
    private static final Path EE_OPINION = Path.of("data/languages/r5900.opinion");

    private static String r5900FlagPattern() throws IOException {
        String xml = Files.readString(EE_OPINION);
        Matcher m = Pattern.compile(
            "processor=\\\"MIPS-R5900\\\"[\\s\\S]*?secondary\\s*=\\s*\\\"([^\\\"]+)\\\"")
            .matcher(xml);
        assertTrue("missing R5900 secondary opinion", m.find());
        String bits = m.group(1).replaceAll("\\s", "");
        assertTrue("expected binary e_flags opinion", bits.startsWith("0b"));
        bits = bits.substring(2);
        assertEquals("ELF32 e_flags must have 32 bits", 32, bits.length());
        return bits;
    }

    private static boolean opinionMatches(String bits, int flags) {
        for (int bit = 0; bit < 32; bit++) {
            char expected = bits.charAt(bit);
            if (expected != '.' && (expected - '0') != ((flags >>> (31 - bit)) & 1)) {
                return false;
            }
        }
        return true;
    }

    private static byte[] header(int type, int flags) {
        byte[] h = new byte[52];
        h[0] = 0x7f; h[1] = 'E'; h[2] = 'L'; h[3] = 'F';
        h[4] = 1; h[5] = 1; h[6] = 1; h[18] = 8;
        h[16] = (byte) type; h[17] = (byte) (type >>> 8);
        for (int i = 0; i < 4; i++) {
            h[36 + i] = (byte) (flags >>> (8 * i));
        }
        return h;
    }

    @Test
    public void eeOpinionRequiresR5900MachineFlag() throws IOException {
        String bits = r5900FlagPattern();
        assertTrue(opinionMatches(bits, 0x20924001)); // PS2 EE
        assertFalse(opinionMatches(bits, 0x20004001)); // MIPS III, no R5900 flag
        assertFalse(opinionMatches(bits, 0x20914001)); // other machine variant
        assertFalse(opinionMatches(bits, 0x00000000)); // MIPS I
    }

    @Test
    public void noIopHeaderAlsoMatchesR5900Opinion() throws IOException {
        String bits = r5900FlagPattern();
        int[] types = { 0xff80, 0xff81, 0xff90, 0xff91 };
        int[] flags = { 0, 0x20000000, 0x20924001, 0x20920000, 0x20004001 };
        for (int type : types) {
            for (int f : flags) {
                assertFalse("type=0x" + Integer.toHexString(type) +
                    " flags=0x" + Integer.toHexString(f),
                    IopIrxFormat.isIopElf(header(type, f)) && opinionMatches(bits, f));
            }
        }
    }
}
