package ghidra.emotionengine.symboltable;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedInteger16DataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;

/**
 * Regression checks for CCC v14 32-bit fields referring to 16-byte integer
 * types, and for overlap accounting before Ghidra can shift components.
 */
public class Ccc2BitfieldLayoutTest {

    private static DataTypeComponent named(StructureDataType structure, String name) {
        for (DataTypeComponent component : structure.getDefinedComponents()) {
            if (name.equals(component.getFieldName())) return component;
        }
        fail("Missing component: " + name);
        return null;
    }

    @Test
    public void two32BitFieldsFitInEightByteStructureWithoutWideningBaseType()
            throws Exception {
        StructureDataType structure = new StructureDataType("CccPair", 8);
        structure.insertBitFieldAt(0, 8, 0, UnsignedInteger16DataType.dataType,
                32, "attr", "");
        structure.insertBitFieldAt(0, 8, 32, UnsignedInteger16DataType.dataType,
                32, "option", "");

        assertEquals(8, structure.getLength());
        assertEquals(2, structure.getDefinedComponents().length);
        DataTypeComponent attr = named(structure, "attr");
        DataTypeComponent option = named(structure, "option");
        assertTrue(attr.isBitFieldComponent());
        assertTrue(option.isBitFieldComponent());
        assertEquals(32, ((BitFieldDataType) attr.getDataType()).getBitSize());
        assertEquals(32, ((BitFieldDataType) option.getDataType()).getBitSize());
        assertEquals(16, ((BitFieldDataType) attr.getDataType())
                .getBaseDataType().getLength());
        assertEquals(16, ((BitFieldDataType) option.getDataType())
                .getBaseDataType().getLength());
        assertEquals(0, Ccc2SymbolImporter.componentFirstBit(attr, false));
        assertEquals(32, Ccc2SymbolImporter.componentFirstBit(option, false));
        assertNull(Ccc2SymbolImporter.conflictingMember(structure, 64, 96));
        assertNotNull(Ccc2SymbolImporter.conflictingMember(structure, 16, 24));
        assertNotNull(Ccc2SymbolImporter.conflictingMember(structure, 32, 64));
    }

    @Test
    public void unionBitfieldIsNotExpandedToFullUnderlyingType() throws Exception {
        UnionDataType union = new UnionDataType("CccUnion");
        DataTypeComponent member = union.addBitField(
                UnsignedInteger16DataType.dataType, 32, "flags", "");
        assertTrue(member.isBitFieldComponent());
        assertEquals(32, ((BitFieldDataType) member.getDataType()).getBitSize());
        assertEquals(16, ((BitFieldDataType) member.getDataType())
                .getBaseDataType().getLength());
        assertEquals(4, union.getLength());
    }

    @Test
    public void ordinaryMemberAfterBitfieldRegionRemainsAtOriginalOffset()
            throws Exception {
        StructureDataType structure = new StructureDataType("CccTrailing", 12);
        structure.replaceAtOffset(8, UnsignedIntegerDataType.dataType, 4,
                "trailing", "");
        structure.insertBitFieldAt(0, 8, 0, UnsignedInteger16DataType.dataType,
                32, "attr", "");
        structure.insertBitFieldAt(0, 8, 32, UnsignedInteger16DataType.dataType,
                32, "option", "");

        assertEquals(12, structure.getLength());
        assertEquals(8, named(structure, "trailing").getOffset());
        assertEquals(0, Ccc2SymbolImporter.componentFirstBit(
                named(structure, "attr"), false));
        assertEquals(32, Ccc2SymbolImporter.componentFirstBit(
                named(structure, "option"), false));
        assertNotNull(Ccc2SymbolImporter.conflictingMember(structure, 64, 96));
        assertNull(Ccc2SymbolImporter.conflictingMember(structure, 96, 128));
    }
}
