package ghidra.emotionengine.symboltable;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.emotionengine.iop.IopIrxFormat;

/**
 * Identifies a legacy STABS ambiguity in old PS2 IOP toolchains.
 *
 * CCC 2.1 (JSON v14) classifies a STABS range "0;-1" as an unqualified
 * 128-bit integer. In this IOP compiler's debug strings, however,
 * "unsigned int:tN=rN;0;-1;" and "long unsigned int:tN=rN;0;-1;"
 * describe 32-bit unsigned integer aliases. Preserve the CCC result
 * unless the source IRX/ERX contains an exact matching declaration.
 *
 * Only examines printable NUL/control-delimited strings from an IOP ELF.
 * Never writes to the input file and does not require Ghidra analysis.
 */
final class CccIopLegacyUnsignedRanges {
    private static final Pattern DECLARATION = Pattern.compile(
            "^(unsigned int|long unsigned int):t[0-9]+=r[0-9]+;0;-1;$");

    private CccIopLegacyUnsignedRanges() {}

    static String recognizedName(String token) {
        Matcher match = DECLARATION.matcher(token);
        return match.matches() ? match.group(1) : null;
    }

    static Set<String> find(File file) throws IOException {
        try (BufferedInputStream input =
                     new BufferedInputStream(new FileInputStream(file))) {
            byte[] header = input.readNBytes(52);
            if (!IopIrxFormat.isIopElf(header)) {
                return Collections.emptySet();
            }
            Set<String> names = new HashSet<>();
            StringBuilder token = new StringBuilder(128);
            int value;
            while ((value = input.read()) != -1) {
                if (value >= 32 && value <= 126 && token.length() < 256) {
                    token.append((char) value);
                    continue;
                }
                if (token.length() > 0) {
                    String recognized = recognizedName(token.toString());
                    if (recognized != null) names.add(recognized);
                }
                token.setLength(0);
                if (names.size() == 2) break;
            }
            if (token.length() > 0) {
                String recognized = recognizedName(token.toString());
                if (recognized != null) names.add(recognized);
            }
            return Collections.unmodifiableSet(names);
        }
    }
}
