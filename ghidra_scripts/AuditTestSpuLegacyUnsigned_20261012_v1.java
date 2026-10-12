// Read-only TESTSPU datatype audit for GCC/STABS 0;-1 unsigned ranges.
//@category ghidra-emotionengine

import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;

public class AuditTestSpuLegacyUnsigned_20261012_v1 extends GhidraScript {
    private int passes;
    private int failures;

    private DataType datatype(String name) {
        Iterator<DataType> types = currentProgram.getDataTypeManager().getAllDataTypes();
        while (types.hasNext()) {
            monitor.checkCanceled();
            DataType current = types.next();
            if (name.equals(current.getName())) return current;
        }
        return null;
    }

    private void check(boolean condition, String description) {
        if (condition) {
            passes++;
            println("PASS " + description);
        } else {
            failures++;
            println("FAIL " + description);
        }
    }

    private void typeWidth(String name, int expectedBytes) {
        DataType type = datatype(name);
        check(type != null && type.getLength() == expectedBytes,
                name + " expected=" + expectedBytes +
                " actual=" + (type == null ? "MISSING" : type.getLength()));
    }

    private Structure structure(String name, int expectedBytes) {
        DataType type = datatype(name);
        check(type instanceof Structure && type.getLength() == expectedBytes,
                name + " expected size=0x" + Integer.toHexString(expectedBytes) +
                " actual=" + (type == null ? "MISSING" : type.getLength()));
        return type instanceof Structure ? (Structure) type : null;
    }

    private DataTypeComponent field(Structure structure, String name,
            int offset, int expectedBytes, boolean expectedBitfield) {
        DataTypeComponent result = null;
        if (structure != null) {
            for (DataTypeComponent component : structure.getDefinedComponents()) {
                if (name.equals(component.getFieldName())) {
                    result = component;
                    break;
                }
            }
        }
        check(result != null && result.getOffset() == offset &&
                result.getLength() == expectedBytes &&
                result.isBitFieldComponent() == expectedBitfield,
                (structure == null ? "<missing structure>" : structure.getName()) +
                "." + name + " offset=0x" + Integer.toHexString(offset) +
                " bytes=" + expectedBytes + " bitfield=" + expectedBitfield);
        return result;
    }

    private void bitfield(Structure structure, String name, int offset,
            int width, int bitOffset) {
        DataTypeComponent member = field(structure, name, offset,
                (width + bitOffset + 7) / 8, true);
        check(member != null && member.getDataType() instanceof BitFieldDataType &&
                ((BitFieldDataType) member.getDataType()).getBitSize() == width &&
                ((BitFieldDataType) member.getDataType()).getBitOffset() == bitOffset,
                "bitfield " + name + " width=" + width +
                " offsetWithinByte=" + bitOffset);
    }

    @Override
    public void run() throws Exception {
        // The exact declarations occur in TESTSPU.bin's original .mdebug.
        typeWidth("unsigned int", 4);
        typeWidth("long unsigned int", 4);
        typeWidth("u_int", 4);
        typeWidth("u_long", 4);

        Structure libinfo = structure("_libinfo", 0x14);
        DataTypeComponent dummy = field(libinfo, "dummy", 0, 8, false);
        check(dummy != null && dummy.getDataType() instanceof Array &&
                ((Array) dummy.getDataType()).getNumElements() == 2 &&
                ((Array) dummy.getDataType()).getDataType().getLength() == 4,
                "_libinfo.dummy must have two 4-byte array elements");
        field(libinfo, "version", 8, 2, false);
        field(libinfo, "dummy2", 10, 2, false);
        field(libinfo, "name", 12, 8, false);

        Structure caller = structure("_libcaller", 0x14);
        field(caller, "magic", 0, 4, false);
        field(caller, "client", 4, 4, false);

        Structure flagParam = structure("EventFlagParam", 0xc);
        field(flagParam, "attr", 0, 4, false);
        field(flagParam, "option", 4, 4, false);
        field(flagParam, "initPattern", 8, 4, false);

        Structure cmd = structure("sceSifCmdHdr", 0x10);
        bitfield(cmd, "psize", 0, 8, 0);
        bitfield(cmd, "dsize", 1, 24, 0);
        field(cmd, "daddr", 4, 4, false);
        field(cmd, "fcode", 8, 4, false);
        field(cmd, "opt", 12, 4, false);

        println("TESTSPU STABS AUDIT: passed=" + passes +
                " failed=" + failures + " (read-only)");
    }
}
