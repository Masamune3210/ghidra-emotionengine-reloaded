package ghidra.emotionengine.symboltable;

import static org.junit.Assert.*;


import org.junit.Test;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.UnsignedIntegerDataType;

/** Regression for multi-hop STABS aliases such as u_int:t44=4 and uint:t48=4. */
public class Ccc2TypedefAliasTest {

    @Test
    public void retainsNamedAliasesWhenTargetIsAlreadyATypedef() {
        DataType root = Ccc2SymbolImporter.preserveNamedAlias(
                UnsignedIntegerDataType.dataType, "unsigned int", "builtin", true);
        DataType alias = Ccc2SymbolImporter.preserveNamedAlias(
                root, "u_int", "type_name", true);
        DataType second = Ccc2SymbolImporter.preserveNamedAlias(
                root, "uint", "type_name", true);

        assertTrue(root instanceof TypeDef);
        assertTrue(alias instanceof TypeDef);
        assertTrue(second instanceof TypeDef);
        assertEquals("unsigned int", root.getName());
        assertEquals("u_int", alias.getName());
        assertEquals("uint", second.getName());
        assertEquals(4, alias.getLength());
        assertEquals(4, second.getLength());
        assertEquals("unsigned int", ((TypeDef) alias).getDataType().getName());

        assertSame(root, Ccc2SymbolImporter.preserveNamedAlias(
                root, "unsigned int", "type_name", true));
        assertSame(root, Ccc2SymbolImporter.preserveNamedAlias(
                root, "u_int", "type_name", false));
        assertSame(root, Ccc2SymbolImporter.preserveNamedAlias(
                root, "", "type_name", true));
    }

    @Test
    public void distinctAliasesRetainNamesAndFourByteWidths() {
        DataType unsignedInt = Ccc2SymbolImporter.preserveNamedAlias(
                UnsignedIntegerDataType.dataType, "unsigned int", "builtin", true);
        DataType unsignedLong = Ccc2SymbolImporter.preserveNamedAlias(
                UnsignedIntegerDataType.dataType, "long unsigned int", "builtin", true);
        DataType uInt = Ccc2SymbolImporter.preserveNamedAlias(
                unsignedInt, "u_int", "type_name", true);
        DataType uint = Ccc2SymbolImporter.preserveNamedAlias(
                unsignedInt, "uint", "type_name", true);
        DataType uLong = Ccc2SymbolImporter.preserveNamedAlias(
                unsignedLong, "u_long", "type_name", true);

        assertEquals("u_int", uInt.getName());
        assertEquals("uint", uint.getName());
        assertEquals("u_long", uLong.getName());
        assertEquals("unsigned int", ((TypeDef) uInt).getDataType().getName());
        assertEquals("long unsigned int", ((TypeDef) uLong).getDataType().getName());
        assertEquals(4, uInt.getLength());
        assertEquals(4, uint.getLength());
        assertEquals(4, uLong.getLength());
    }

    @Test
    public void explicitAliasToStructureIsNotMistakenForStructureDefinition() {
        StructureDataType structure = new StructureDataType("_example", 8);
        DataType alias = Ccc2SymbolImporter.preserveNamedAlias(
                structure, "ExampleAlias", "type_name", true);
        assertTrue(alias instanceof TypeDef);
        assertEquals(8, alias.getLength());
        assertEquals("ExampleAlias", alias.getName());
        assertSame(structure, Ccc2SymbolImporter.preserveNamedAlias(
                structure, "_example", "type_name", true));
        assertSame(structure, Ccc2SymbolImporter.preserveNamedAlias(
                structure, "ExampleAlias", "struct", true));
    }
}
