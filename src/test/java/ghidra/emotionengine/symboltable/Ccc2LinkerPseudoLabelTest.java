package ghidra.emotionengine.symboltable;

import static org.junit.Assert.*;

import org.junit.Test;

public class Ccc2LinkerPseudoLabelTest {
    @Test
    public void onlyValidatedUnmappedBoundaryAndGpNamesAreAccepted() {
        long end = 0x18a8;
        long gp = 0x97d0;
        assertTrue(Ccc2SymbolImporter.isVerifiedLinkerPseudoLabel(
                "end", end, end, gp));
        assertTrue(Ccc2SymbolImporter.isVerifiedLinkerPseudoLabel(
                "_end", end, end, gp));
        assertTrue(Ccc2SymbolImporter.isVerifiedLinkerPseudoLabel(
                "_gp", gp, end, gp));
        assertFalse(Ccc2SymbolImporter.isVerifiedLinkerPseudoLabel(
                "_gp", 0x9ff0, end, gp));
        assertFalse(Ccc2SymbolImporter.isVerifiedLinkerPseudoLabel(
                "end", 0x18a4, end, gp));
        assertFalse(Ccc2SymbolImporter.isVerifiedLinkerPseudoLabel(
                "arbitrary", end, end, gp));
    }

    @Test
    public void refusesUnverifiedOrMissingMetadata() {
        assertFalse(Ccc2SymbolImporter.isVerifiedLinkerPseudoLabel(
                "end", 0x18a8, -1, -1));
        assertFalse(Ccc2SymbolImporter.isVerifiedLinkerPseudoLabel(
                "_gp", 0x97d0, -1, -1));
        assertFalse(Ccc2SymbolImporter.isVerifiedLinkerPseudoLabel(
                "end", -1, -1, -1));
    }
}
