// Read-only datatype audit for CCC 2.x imports, including already-imported programs.
//@category ghidra-emotionengine

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;

public class AuditCccBitfieldLayouts_20261012_v1 extends GhidraScript {
    private static final class Span {
        final String name;
        final long start, end;

        Span(String name, long start, long end) {
            this.name = name;
            this.start = start;
            this.end = end;
        }
    }

    @Override
    public void run() throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        boolean bigEndian = dtm.getDataOrganization().isBigEndian();
        int composites = 0;
        int bitfields = 0;
        int suspectWidths = 0;
        int layoutIssues = 0;

        Iterator<DataType> types = dtm.getAllDataTypes();
        while (types.hasNext()) {
            monitor.checkCanceled();
            DataType dt = types.next();
            if (!(dt instanceof Composite)) continue;
            Composite composite = (Composite) dt;
            DataTypeComponent[] components = composite.getDefinedComponents();
            boolean hasBitfields = false;
            for (DataTypeComponent part : components) {
                if (part.isBitFieldComponent()) {
                    hasBitfields = true;
                    break;
                }
            }
            if (!hasBitfields) continue;

            composites++;
            println("COMPOSITE " + dt.getCategoryPath() + "/" + dt.getName() +
                    " length=0x" + Integer.toHexString(dt.getLength()) +
                    (dt instanceof Union ? " (union)" : " (structure)"));
            List<Span> spans = new ArrayList<>();
            for (DataTypeComponent component : components) {
                DataType fieldType = component.getDataType();
                String name = component.getFieldName() == null
                        ? "<unnamed>" : component.getFieldName();
                long start = (long) component.getOffset() * 8;
                int bits = component.getLength() * 8;
                if (component.isBitFieldComponent()) {
                    BitFieldDataType bf = (BitFieldDataType) fieldType;
                    bits = bf.getBitSize();
                    start = Structure.BitOffsetComparator.getNormalizedBitfieldOffset(
                            component.getOffset(), component.getLength(),
                            bits, bf.getBitOffset(), bigEndian);
                    int baseBytes = bf.getBaseDataType().getLength();
                    bitfields++;
                    println("  BITFIELD " + name + " bitStart=" + start +
                            " bits=" + bits + " byteOffset=0x" +
                            Integer.toHexString(component.getOffset()) +
                            " base=" + bf.getBaseDataType().getName() +
                            " baseBytes=" + baseBytes);
                    if (baseBytes >= 8 && bits <= 32) {
                        suspectWidths++;
                        println("    CHECK: wide underlying type relative to field width");
                    }
                }
                if (bits <= 0) continue;
                long end = start + bits;
                if (start < 0 || end > (long) dt.getLength() * 8) {
                    layoutIssues++;
                    println("    ISSUE: component extends beyond composite length: " +
                            name + " bits [" + start + ", " + end + ")");
                }
                if (dt instanceof Structure) {
                    for (Span previous : spans) {
                        if (start < previous.end && previous.start < end) {
                            layoutIssues++;
                            println("    ISSUE: overlapping structure members " +
                                    previous.name + " and " + name +
                                    " at bit " + Math.max(start, previous.start));
                        }
                    }
                    spans.add(new Span(name, start, end));
                }
            }
        }
        println("CCC BITFIELD AUDIT: composites=" + composites +
                " bitfields=" + bitfields +
                " wideBaseTypeCandidates=" + suspectWidths +
                " layoutIssues=" + layoutIssues +
                " (read-only; includes any non-CCC datatypes in this program)");
    }
}
