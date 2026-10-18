package ghidra.emotionengine.symboltable;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Guard against applying pre-link CCC .mdebug addresses when the ELF loader
 * already imported the corresponding linked function name elsewhere.
 */
public class Ccc2FunctionAddressGuardTest {
    @Test
    public void preservesAnExactLinkedSymbolEvenWithOtherSameNamedFunctions() {
        assertFalse(Ccc2SymbolImporter.conflictingImportedFunctionAddress(true, true));
        assertFalse(Ccc2SymbolImporter.conflictingImportedFunctionAddress(true, false));
    }

    @Test
    public void rejectsCccAddressContradictedByTheLinkedElf() {
        assertTrue(Ccc2SymbolImporter.conflictingImportedFunctionAddress(false, true));
    }

    @Test
    public void preservesCccOnlyAndStrippedElfFunctions() {
        assertFalse(Ccc2SymbolImporter.conflictingImportedFunctionAddress(false, false));
    }
}
