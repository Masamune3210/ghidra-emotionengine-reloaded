package ghidra.emotionengine.symboltable;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Map;
import java.util.LinkedHashMap;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.emotionengine.iop.IopIrxLinkerSymbols;
import ghidra.app.util.exporter.ExporterException;
import ghidra.app.util.exporter.OriginalFileExporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.Platform;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * Imports CCC 2.x's flat symbol database (JSON schema 13 through 15).
 *
 * Deliberately independent of the obsolete CCC v1 / STABS AST. Missing or
 * ambiguous symbol types are left unapplied, never replaced with invented
 * declarations. All addresses and indices come from an untrusted ELF parser.
 */
public class Ccc2SymbolImporter extends FlatProgramAPI {
    private static final String TAG = "CCC 2.x";
    private final Program program;
    private final StabsImporter.ImportOptions options;
    private final TaskMonitor monitor;
    private final MessageLog log;
    private JsonObject database;
    private JsonArray definitions;
    private DataType[] types;
    private final Set<Integer> activeTypes = new HashSet<>();
    private final Set<Integer> completedTypes = new HashSet<>();
    private int appliedTypes, appliedFunctions, appliedGlobals, appliedLabels, skipped;
    private int anonymousTypeCounter;
    private int schemaVersion;
    private int placedBitfields, narrowedBitfieldWindows;
    private int correctedLegacyUnsignedTypes, restoredOrdinaryFields;
    private Set<String> legacyIopUnsignedNames = java.util.Collections.emptySet();
    private final Set<Integer> correctedLegacyUnsignedIndices = new HashSet<>();
    private int verifiedBitfields, layoutWarnings;
    private int retainedLinkerSentinels;
    private final Map<String, Integer> skipReasons = new LinkedHashMap<>();

    public Ccc2SymbolImporter(Program program, StabsImporter.ImportOptions options,
            TaskMonitor monitor, MessageLog log) {
        super(program, monitor);
        this.program = program;
        this.options = options;
        this.monitor = monitor;
        this.log = log;
    }

    private static JsonArray array(JsonObject obj, String key) {
        return obj != null && obj.has(key) && obj.get(key).isJsonArray()
                ? obj.getAsJsonArray(key) : new JsonArray();
    }

    private static JsonObject object(JsonObject obj, String key) {
        return obj != null && obj.has(key) && obj.get(key).isJsonObject()
                ? obj.getAsJsonObject(key) : null;
    }

    private static String string(JsonObject obj, String key) {
        if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) return "";
        try { return obj.get(key).getAsString(); }
        catch (RuntimeException e) { return ""; }
    }

    private static int number(JsonObject obj, String key, int fallback) {
        if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) return fallback;
        try { return obj.get(key).getAsInt(); }
        catch (RuntimeException e) { return fallback; }
    }

    private static long unsignedAddress(JsonObject obj, String key) {
        if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) return -1;
        try {
            long value = obj.get(key).getAsLong();
            return value >= 0 && value <= 0xffffffffL ? value : -1;
        } catch (RuntimeException e) { return -1; }
    }

    private Address mappedAddress(JsonObject obj) {
        long offset = unsignedAddress(obj, "address");
        if (offset < 0) return null;
        try {
            Address a = toAddr(offset);
            MemoryBlock block = program.getMemory().getBlock(a);
            return block == null ? null : a;
        } catch (RuntimeException e) { return null; }
    }

    private void warning(String message) {
        log.appendMsg(TAG, message);
    }

    private void skip(String reason, String detail) {
        skipped++;
        int count = skipReasons.merge(reason, 1, Integer::sum);
        // Most categories only need representative failures. Unmapped labels
        // are few and often linker sentinels: show enough to identify each.
        int detailLimit = "unmapped labels".equals(reason) ? 16 : 2;
        if (count <= detailLimit && detail != null && !detail.isBlank()) {
            warning("Skipped [" + reason + "]: " + detail);
        }
    }

    private void logSkipBreakdown() {
        for (Map.Entry<String, Integer> entry : skipReasons.entrySet()) {
            warning("Skip reason: " + entry.getKey() + " = " + entry.getValue());
        }
    }

    public boolean doImport() {
        try {
            if (options.onlyRunOnce &&
                    program.getOptions("CCC 2.x Symbols").getBoolean("Imported", false)) {
                warning("Already imported; clear the 'Imported' program option to reapply.");
                return true;
            }
            byte[] json = loadJson();
            if (json == null || monitor.isCancelled()) return false;
            JsonElement parsed = JsonParser.parseString(new String(json, StandardCharsets.UTF_8));
            if (!parsed.isJsonObject()) throw new IllegalArgumentException("JSON root is not an object");
            database = parsed.getAsJsonObject();
            String format = string(database, "format");
            int version = number(database, "version", -1);
            if (!"CCC Symbol Database".equals(format) || version < 13 || version > 15) {
                throw new IllegalArgumentException("Unsupported CCC symbol database format/version: "
                        + format + " v" + version + " (requires v13-v15)");
            }
            schemaVersion = version;
            definitions = array(database, "data_types");
            types = new DataType[definitions.size()];
            monitor.setMessage("CCC 2.x - Importing types");
            prepareCompositeTypes();
            for (int i = 0; i < types.length && !monitor.isCancelled(); i++) {
                try { resolveType(i); }
                catch (RuntimeException e) { skip("type resolution", "#" + i + ": " + e); }
            }
            for (int i = 0; i < types.length && !monitor.isCancelled(); i++) {
                if (types[i] == null) continue;
                if (!options.importBuiltins && definitions.get(i).isJsonObject() &&
                        "builtin".equals(string(object(definitions.get(i).getAsJsonObject(), "type"), "descriptor"))) {
                    continue;
                }
                try {
                    DataType resolved = program.getDataTypeManager().addDataType(
                            types[i], DataTypeConflictHandler.DEFAULT_HANDLER);
                    types[i] = resolved;
                    appliedTypes++;
                } catch (RuntimeException e) { skip("datatype registration", "#" + i + ": " + e); }
            }
            if (monitor.isCancelled()) return false;
            monitor.setMessage("CCC 2.x - Importing functions");
            if (options.importFunctions) importFunctions();
            if (monitor.isCancelled()) return false;
            monitor.setMessage("CCC 2.x - Importing globals and labels");
            if (options.importGlobals) importGlobals();
            importLabels();
            if (monitor.isCancelled()) return false;
            program.getOptions("CCC 2.x Symbols").setBoolean("Imported", true);
            logSkipBreakdown();
            warning("Legacy IOP unsigned types corrected=" + correctedLegacyUnsignedTypes +
                    " false bitfields restored as ordinary fields=" + restoredOrdinaryFields);
            warning("Bitfields placed=" + placedBitfields +
                    " verifiedPositions=" + verifiedBitfields +
                    " narrowedStorageWindows=" + narrowedBitfieldWindows +
                    " structureLayoutWarnings=" + layoutWarnings);
            if (retainedLinkerSentinels != 0) warning(
                    "Linker pseudo-labels retained as verified ELF metadata=" +
                    retainedLinkerSentinels + " (no artificial memory created)");
            warning("Imported types=" + appliedTypes + " functions=" + appliedFunctions
                    + " globals=" + appliedGlobals + " labels=" + appliedLabels
                    + " skipped=" + skipped + " (JSON v" + version + ")");
            return true;
        } catch (Exception e) {
            log.appendException(e);
            warning("Import failed: " + e.getMessage());
            return false;
        }
    }

    private byte[] loadJson() throws IOException, InterruptedException, ExporterException {
        if (!options.overrideJsonPath.isBlank()) {
            if (!options.overrideElfPath.isBlank()) {
                inspectLegacyIopRanges(new File(options.overrideElfPath));
            }
            return Files.readAllBytes(new File(options.overrideJsonPath).toPath());
        }
        File elf = null;
        boolean temporary = options.overrideElfPath.isBlank();
        try {
            if (temporary) {
                elf = File.createTempFile("ccc2_input_", ".elf");
                new OriginalFileExporter().export(elf, program, null, monitor);
            } else {
                elf = new File(options.overrideElfPath);
            }
            inspectLegacyIopRanges(elf);
            File tool = Application.getOSFile("stdump" +
                    Platform.CURRENT_PLATFORM.getExecutableExtension());
            if (tool == null || !tool.isFile()) {
                warning("CCC 2.x stdump executable missing. Install CCC v2.x "
                        + "in the extension's platform os directory.");
                return null;
            }
            File stderr = File.createTempFile("ccc2_stderr_", ".log");
            Process process = null;
            try {
                ProcessBuilder builder = new ProcessBuilder(
                        tool.getAbsolutePath(), "json", elf.getAbsolutePath());
                builder.redirectError(stderr);
                process = builder.start();
                byte[] output;
                try (InputStream input = process.getInputStream()) {
                    output = input.readAllBytes();
                }
                int exit = process.waitFor();
                for (String line : Files.readAllLines(stderr.toPath())) {
                    warning(line.replaceAll("\\x1b\\[[0-9;]*m", ""));
                }
                if (exit != 0) {
                    warning("stdump exited with status " + exit);
                    return null;
                }
                return output;
            } finally {
                if (process != null && process.isAlive()) process.destroyForcibly();
                Files.deleteIfExists(stderr.toPath());
            }
        } finally {
            if (temporary && elf != null) Files.deleteIfExists(elf.toPath());
        }
    }

    private void inspectLegacyIopRanges(File elf) {
        try {
            legacyIopUnsignedNames = CccIopLegacyUnsignedRanges.find(elf);
            if (!legacyIopUnsignedNames.isEmpty()) {
                warning("Legacy IOP STABS unsigned 0;-1 declarations detected: " +
                        legacyIopUnsignedNames);
            }
        } catch (IOException e) {
            warning("Unable to inspect IOP STABS signatures; no compatibility " +
                    "correction will be applied: " + e.getMessage());
        }
    }

    // Allocate composites first so pointers and self-references can resolve.
    private void prepareCompositeTypes() {
        for (int i = 0; i < definitions.size(); i++) {
            if (!definitions.get(i).isJsonObject()) continue;
            JsonObject symbol = definitions.get(i).getAsJsonObject();
            JsonObject node = object(symbol, "type");
            String kind = string(node, "descriptor");
            String name = safeTypeName(string(symbol, "name"), i);
            int size = number(node, "size_bytes", number(symbol, "size", 0));
            try {
                if ("struct".equals(kind) || "structure".equals(kind)) {
                    types[i] = new StructureDataType(name, Math.max(0, Math.min(size, 0x100000)), program.getDataTypeManager());
                } else if ("union".equals(kind)) {
                    types[i] = new UnionDataType(name);
                } else if ("enum".equals(kind)) {
                    types[i] = new EnumDataType(name, size == 1 || size == 2 || size == 8 ? size : 4);
                }
            } catch (RuntimeException e) { skip("composite allocation", "#" + i + ": " + e); }
        }
    }

    private static String safeTypeName(String name, int index) {
        return name.isBlank() ? "ccc2_anonymous_" + index : name;
    }

    private DataType resolveType(int index) {
        if (index < 0 || index >= types.length) return null;
        DataType result = types[index];
        if (completedTypes.contains(index) || activeTypes.contains(index)) return result;
        if (!definitions.get(index).isJsonObject()) return result;
        activeTypes.add(index);
        try {
            JsonObject item = definitions.get(index).getAsJsonObject();
            JsonObject node = object(item, "type");
            if (node == null) return result;
            String name = safeTypeName(string(item, "name"), index);
            if (result instanceof StructureDataType) {
                fillStructure((StructureDataType) result, node);
            } else if (result instanceof UnionDataType) {
                fillUnion((UnionDataType) result, node);
            } else if (result instanceof EnumDataType) {
                fillEnum((EnumDataType) result, node);
            } else if (result == null) {
                if (shouldCorrectLegacyIopUnsigned(name, node,
                        legacyIopUnsignedNames, schemaVersion)) {
                    // CCC 2.1 maps a traditional GCC/STABS 0;-1 range to
                    // int128. The original source ELF proves this named
                    // integer alias belongs to a 32-bit IOP toolchain.
                    result = UnsignedIntegerDataType.dataType;
                    correctedLegacyUnsignedIndices.add(index);
                    correctedLegacyUnsignedTypes++;
                } else {
                    result = resolveNode(node);
                }
                // A type_name referring to a typedef must keep its own alias,
                // rather than silently reuse the referenced typedef's name.
                // This also preserves named references to composite types.
                result = preserveNamedAlias(result, string(item, "name"),
                        string(node, "descriptor"), options.importTypedefs);
                types[index] = result;
            }
            return result;
        } finally {
            activeTypes.remove(index);
            completedTypes.add(index);
        }
    }

    /**
     * Keep the name of an explicit CCC alias, even when its target was itself
     * already represented as a typedef. Raw composite declarations retain
     * their native Ghidra data type rather than acquiring a second wrapper.
     */
    static DataType preserveNamedAlias(DataType target, String name, String descriptor,
            boolean enabled) {
        if (!enabled || target == null || name == null || name.isBlank() ||
                name.equals(target.getName())) {
            return target;
        }
        boolean isReference = "type_name".equals(descriptor);
        if (!isReference && (target instanceof TypedefDataType ||
                target instanceof Structure || target instanceof Union ||
                target instanceof ghidra.program.model.data.Enum)) {
            return target;
        }
        return new TypedefDataType(name, target);
    }

    static boolean shouldCorrectLegacyIopUnsigned(String name, JsonObject node,
            Set<String> names, int version) {
        return version <= 14 && names.contains(name) &&
                "builtin".equals(string(node, "descriptor")) &&
                "128-bit integer".equals(string(node, "class"));
    }

    private boolean refersToCorrectedLegacyUnsigned(JsonObject node) {
        Set<Integer> visited = new HashSet<>();
        for (int i = 0; i < 64 && node != null; i++) {
            if (!"type_name".equals(string(node, "descriptor"))) return false;
            int index = number(node, "data_type", -1);
            if (correctedLegacyUnsignedIndices.contains(index)) return true;
            if (index < 0 || index >= definitions.size() || !visited.add(index) ||
                    !definitions.get(index).isJsonObject()) return false;
            node = object(definitions.get(index).getAsJsonObject(), "type");
        }
        return false;
    }

    private DataType resolveNode(JsonObject node) {
        if (node == null) return null;
        String kind = string(node, "descriptor");
        switch (kind) {
            case "type_name": {
                int reference = number(node, "data_type", -1);
                // CCC may emit -1 for unresolved cross-references.
                return resolveType(reference);
            }
            case "builtin": return builtin(string(node, "class"));
            case "pointer":
            case "reference": {
                DataType value = resolveNode(object(node, "value_type"));
                if (value == null) return null;
                return new PointerDataType(value);
            }
            case "array": {
                DataType value = resolveNode(object(node, "element_type"));
                int count = number(node, "element_count", -1);
                if (value == null || value.getLength() <= 0 || count <= 0 ||
                        count > 0x100000 || (long) count * value.getLength() > 0x1000000L) return null;
                return new ArrayDataType(value, count, value.getLength());
            }
            case "bitfield": return resolveNode(object(node, "underlying_type"));
            case "struct":
            case "structure": {
                int length = number(node, "size_bytes", -1);
                if (length < 0 || length > 0x100000) return null;
                StructureDataType structure = new StructureDataType(
                        safeTypeName(string(node, "name"), ++anonymousTypeCounter), length,
                        program.getDataTypeManager());
                fillStructure(structure, node);
                return structure;
            }
            case "union": {
                UnionDataType union = new UnionDataType(
                        safeTypeName(string(node, "name"), ++anonymousTypeCounter));
                fillUnion(union, node);
                return union;
            }
            case "enum": {
                int length = number(node, "size_bytes", 4);
                EnumDataType enumeration = new EnumDataType(
                        safeTypeName(string(node, "name"), ++anonymousTypeCounter),
                        length == 1 || length == 2 || length == 8 ? length : 4);
                fillEnum(enumeration, node);
                return enumeration;
            }
            case "function": {
                DataType returnType = resolveNode(object(node, "return_type"));
                // An absent return type is not evidence that the function returns void.
                if (returnType == null) return null;
                FunctionDefinitionDataType signature = new FunctionDefinitionDataType(
                        "ccc2_function_type_" + (++anonymousTypeCounter));
                signature.setReturnType(returnType);
                if (node.has("parameters")) {
                    List<ParameterDefinition> definitions = new ArrayList<>();
                    for (JsonElement element : array(node, "parameters")) {
                        if (!element.isJsonObject()) return null;
                        JsonObject arg = element.getAsJsonObject();
                        DataType argType = resolveNode(arg);
                        if (argType == null || argType instanceof VoidDataType) return null;
                        String argName = string(arg, "name");
                        if (argName.isBlank()) argName = "param_" + definitions.size();
                        definitions.add(new ParameterDefinitionImpl(argName, argType, null));
                    }
                    signature.setArguments(definitions.toArray(new ParameterDefinition[0]));
                }
                return signature;
            }
            default: return null;
        }
    }

    static DataType builtin(String value) {
        switch (value) {
            case "void": return VoidDataType.dataType;
            case "8-bit unsigned integer": return UnsignedCharDataType.dataType;
            case "8-bit signed integer":
            case "8-bit integer": return CharDataType.dataType;
            case "8-bit boolean": return BooleanDataType.dataType;
            case "16-bit unsigned integer": return UnsignedShortDataType.dataType;
            case "16-bit signed integer": return ShortDataType.dataType;
            case "32-bit unsigned integer": return UnsignedIntegerDataType.dataType;
            case "32-bit signed integer": return IntegerDataType.dataType;
            case "32-bit floating point": return FloatDataType.dataType;
            case "64-bit unsigned integer": return UnsignedLongDataType.dataType;
            case "64-bit signed integer": return LongDataType.dataType;
            case "64-bit floating point": return DoubleDataType.dataType;
            case "128-bit unsigned integer": return UnsignedInteger16DataType.dataType;
            case "128-bit signed integer": return Integer16DataType.dataType;
            case "128-bit integer": return Integer16DataType.dataType;
            case "128-bit floating point": return Float16DataType.dataType;
            default: return null;
        }
    }

    /**
     * Trace CCC type_name references through the original database for useful
     * diagnostics, including unsupported builtins and reference cycles.
     * This is deliberately read-only and never guesses a missing datatype.
     */
    private String describeTypeReferenceChain(JsonObject node) {
        StringBuilder path = new StringBuilder();
        Set<Integer> visited = new HashSet<>();
        for (int depth = 0; depth < 16 && node != null; depth++) {
            String descriptor = string(node, "descriptor");
            if (depth != 0) path.append(" -> ");
            path.append(descriptor);
            if ("builtin".equals(descriptor)) {
                path.append("(").append(string(node, "class")).append(")");
                break;
            }
            if (!"type_name".equals(descriptor)) {
                path.append("(size=").append(number(node, "size_bytes", -1)).append(")");
                break;
            }
            int index = number(node, "data_type", -1);
            path.append("[").append(index).append("]");
            if (index < 0 || index >= definitions.size() ||
                    !definitions.get(index).isJsonObject()) {
                path.append("(invalid index)");
                break;
            }
            if (!visited.add(index)) {
                path.append("(cycle)");
                break;
            }
            JsonObject entry = definitions.get(index).getAsJsonObject();
            String name = string(entry, "name");
            if (!name.isBlank()) path.append("(").append(name).append(")");
            node = object(entry, "type");
            if (node == null) path.append(" -> missing type");
        }
        return path.toString();
    }

    private static final class ExpectedBitfield {
        final String name;
        final long startBit;
        final int width;

        ExpectedBitfield(String name, long startBit, int width) {
            this.name = name;
            this.startBit = startBit;
            this.width = width;
        }
    }

    private void reportLayoutWarning(String structureName, String detail) {
        layoutWarnings++;
        if (layoutWarnings <= 12) {
            warning("Structure layout warning [" + structureName + "]: " + detail);
        }
    }

    static long componentFirstBit(DataTypeComponent component, boolean bigEndian) {
        if (component.isBitFieldComponent()) {
            BitFieldDataType bf = (BitFieldDataType) component.getDataType();
            return Structure.BitOffsetComparator.getNormalizedBitfieldOffset(
                    component.getOffset(), component.getLength(),
                    bf.getBitSize(), bf.getBitOffset(), bigEndian);
        }
        return (long) component.getOffset() * 8;
    }

    static String conflictingMember(Structure structure, long firstBit, long lastBitExclusive) {
        boolean bigEndian = structure.getDataOrganization().isBigEndian();
        for (DataTypeComponent member : structure.getDefinedComponents()) {
            long existingStart = componentFirstBit(member, bigEndian);
            long existingWidth = member.isBitFieldComponent()
                    ? ((BitFieldDataType) member.getDataType()).getBitSize()
                    : (long) member.getLength() * 8;
            if (existingWidth > 0 && firstBit < existingStart + existingWidth &&
                    existingStart < lastBitExclusive) {
                return (member.getFieldName() == null ? "<unnamed>" : member.getFieldName()) +
                        " at bit " + existingStart;
            }
        }
        return null;
    }

    private void auditStructureFields(Structure structure,
            List<ExpectedBitfield> expected, int sourceLength) {
        if (sourceLength >= 0 && !(sourceLength == 0 && structure.isNotYetDefined())
                && sourceLength != structure.getLength()) {
            reportLayoutWarning(structure.getName(), "size changed from " +
                    sourceLength + " to " + structure.getLength());
        }
        boolean bigEndian = program.getDataTypeManager().getDataOrganization().isBigEndian();
        for (ExpectedBitfield field : expected) {
            boolean matched = false;
            for (DataTypeComponent component : structure.getDefinedComponents()) {
                if (!component.isBitFieldComponent() ||
                        !field.name.equals(component.getFieldName())) continue;
                BitFieldDataType actual = (BitFieldDataType) component.getDataType();
                if (actual.getBitSize() == field.width &&
                        componentFirstBit(component, bigEndian) == field.startBit) {
                    matched = true;
                    break;
                }
            }
            if (matched) {
                verifiedBitfields++;
            } else {
                reportLayoutWarning(structure.getName(), "missing/moved bitfield " +
                        field.name + " expected bit=" + field.startBit +
                        " width=" + field.width);
            }
        }
    }

    private void fillStructure(Structure structure, JsonObject node) {
        List<ExpectedBitfield> expected = new ArrayList<>();
        int sourceLength = number(node, "size_bytes", -1);
        for (JsonElement element : array(node, "base_classes")) {
            if (element.isJsonObject()) {
                applyStructureField(structure, element.getAsJsonObject(), "base", expected);
            }
        }
        for (JsonElement element : array(node, "fields")) {
            if (element.isJsonObject()) {
                applyStructureField(structure, element.getAsJsonObject(), "field", expected);
            }
        }
        auditStructureFields(structure, expected, sourceLength);
    }

    private void applyStructureField(Structure structure, JsonObject field, String prefix,
            List<ExpectedBitfield> expected) {
        int offset = number(field, "offset_bytes", -1);
        if (offset < 0) {
            // Static C++ members have no instance offset.
            if (!"static".equals(string(field, "storage_class"))) {
                skip("structure field has no usable offset",
                        safeFieldName(field, prefix, offset));
            }
            return;
        }
        JsonObject fieldType = field;
        if ("bitfield".equals(string(field, "descriptor"))) {
            DataType underlying = resolveNode(object(field, "underlying_type"));
            int bits = number(field, "size_bits", -1);
            int bitOffset = number(field, "bitfield_offset_bits", -1);
            if (underlying == null) {
                JsonObject source = object(field, "underlying_type");
                int ref = number(source, "data_type", -1);
                String referencedDescriptor = ref >= 0 && ref < definitions.size()
                        && definitions.get(ref).isJsonObject()
                        ? string(object(definitions.get(ref).getAsJsonObject(), "type"),
                                "descriptor") : "unavailable";
                skip("unresolved bitfield underlying type",
                        safeFieldName(field, prefix, offset) + " at +0x" +
                        Integer.toHexString(offset) + " descriptor=" +
                        string(source, "descriptor") + " class=" + string(source, "class") +
                        " typeName=" + string(source, "type_name") +
                        " dataTypeIndex=" + ref + " referencedDescriptor=" +
                        referencedDescriptor + " chain=" +
                        describeTypeReferenceChain(source) +
                        " node=" + (source == null ? "null" : source));
                return;
            }
            // CCC 2.1 misidentified full-width ordinary IOP uint32 fields
            // as bitfields because it resolved their source 0;-1 range to
            // 128 bits. Only restore those whose underlying alias was
            // positively identified in the original IOP ELF.
            if (schemaVersion <= 14 &&
                    refersToCorrectedLegacyUnsigned(
                            object(field, "underlying_type")) &&
                    bits == 32 && bitOffset == 0 && offset % 4 == 0) {
                if (applyOrdinaryStructureField(
                        structure, field, prefix, offset, underlying)) {
                    restoredOrdinaryFields++;
                }
                return;
            }
            int unitBytes = underlying.getLength();
            if (unitBytes <= 0 || unitBytes > 16) {
                skip("invalid bitfield storage width",
                        safeFieldName(field, prefix, offset) + " at +0x" +
                        Integer.toHexString(offset) + " resolvedType=" +
                        underlying.getName() + " storageBytes=" + unitBytes);
                return;
            }
            if (bits <= 0 || bitOffset < 0) {
                skip("invalid bitfield size or position",
                        safeFieldName(field, prefix, offset) + " at +0x" +
                        Integer.toHexString(offset) + " sizeBits=" + bits +
                        " bitOffset=" + bitOffset + " underlying=" + underlying.getName());
                return;
            }

            // CCC JSON v13/v14 gives an absolute bit position within the
            // containing structure, split into byte offset and bit remainder.
            // CCC v15 instead gives the storage-unit start and bit offset.
            // Ghidra's storage window need not have the same byte width as
            // its underlying integer datatype. A 32-bit bitfield referencing
            // a 128-bit integer can still occupy a 4/8-byte structure.
            int declaredUnitBytes = unitBytes;
            long firstBit = (long) offset * 8 + bitOffset;
            long storageByte = -1;
            int shift = -1;
            if (schemaVersion < 15) {
                // Prefer the declared storage width. Narrow only when that
                // width would cross the containing structure boundary or
                // otherwise cannot contain the field at this bit position.
                // Restrict alternatives to smaller power-of-two widths.
                for (int candidate = unitBytes; candidate >= 1; candidate /= 2) {
                    long candidateBits = (long) candidate * 8;
                    long start = (firstBit / candidateBits) * candidate;
                    long relativeBit = firstBit - start * 8;
                    if (start + candidate <= structure.getLength() &&
                            relativeBit + bits <= candidateBits) {
                        storageByte = start;
                        shift = (int) relativeBit;
                        unitBytes = candidate;
                        break;
                    }
                }
            } else {
                storageByte = offset;
                shift = bitOffset;
            }

            int unitBits = unitBytes * 8;
            if (storageByte < 0 || storageByte > Integer.MAX_VALUE ||
                    shift < 0 || bits > unitBits || shift + bits > unitBits ||
                    storageByte + unitBytes > structure.getLength()) {
                skip("bitfield outside storage unit",
                        safeFieldName(field, prefix, offset) + " at +0x" +
                        Integer.toHexString(offset) + " width=" + bits +
                        " baseType=" + underlying.getName() +
                        " baseBytes=" + declaredUnitBytes +
                        " structureBytes=" + structure.getLength() +
                        " shift=" + shift);
                return;
            }

            // CCC STABS offsets are measured from the MSB on big-endian targets.
            // Ghidra's parameter uses the bit shift from the LSB.
            if (program.getDataTypeManager().getDataOrganization().isBigEndian()) {
                shift = unitBits - shift - bits;
            }
            String conflict = conflictingMember(structure, firstBit, firstBit + bits);
            if (conflict != null) {
                skip("bitfield overlaps existing structure field",
                        safeFieldName(field, prefix, offset) + " at bit " +
                        firstBit + " overlaps " + conflict);
                return;
            }
            try {
                structure.insertBitFieldAt((int) storageByte, unitBytes, shift,
                        underlying, bits, safeFieldName(field, prefix, offset), "");
                placedBitfields++;
                expected.add(new ExpectedBitfield(
                        safeFieldName(field, prefix, offset), firstBit, bits));
                if (unitBytes != declaredUnitBytes) {
                    narrowedBitfieldWindows++;
                    if (narrowedBitfieldWindows <= 2) {
                        warning("Narrowed bitfield storage window " +
                                safeFieldName(field, prefix, offset) + ": " +
                                declaredUnitBytes + " -> " + unitBytes +
                                " bytes (base type unchanged: " +
                                underlying.getName() + ", baseTypeChain=" +
                                describeTypeReferenceChain(
                                        object(field, "underlying_type")) + ")");
                    }
                }
            } catch (InvalidDataTypeException | RuntimeException e) {
                skip("bitfield placement rejected",
                        safeFieldName(field, prefix, offset) + ": " + e.getMessage());
            }
            return;
        }
        DataType type = resolveNode(fieldType);
        applyOrdinaryStructureField(structure, field, prefix, offset, type);
    }

    private boolean applyOrdinaryStructureField(Structure structure,
            JsonObject field, String prefix, int offset, DataType type) {
        if (type == null || type.getLength() <= 0) {
            skip("unresolved structure field type",
                    safeFieldName(field, prefix, offset) + " descriptor=" +
                    string(field, "descriptor"));
            return false;
        }
        if ((long) offset + type.getLength() > structure.getLength()) {
            skip("ordinary field outside structure bounds",
                    safeFieldName(field, prefix, offset) + " at +0x" +
                    Integer.toHexString(offset) + " bytes=" + type.getLength() +
                    " structureBytes=" + structure.getLength());
            return false;
        }
        String conflict = conflictingMember(structure,
                (long) offset * 8, ((long) offset + type.getLength()) * 8);
        if (conflict != null) {
            skip("ordinary field overlaps existing structure field",
                    safeFieldName(field, prefix, offset) + " at +0x" +
                    Integer.toHexString(offset) + " overlaps " + conflict);
            return false;
        }
        try {
            structure.replaceAtOffset(offset, type, type.getLength(),
                    safeFieldName(field, prefix, offset), "");
            return true;
        } catch (RuntimeException e) {
            skip("structure field placement",
                    safeFieldName(field, prefix, offset) + " at +" +
                    offset + ": " + e.getMessage());
            return false;
        }
    }

    private static String safeFieldName(JsonObject node, String prefix, int offset) {
        String name = string(node, "name");
        return name.isBlank() ? prefix + "_" + Integer.toHexString(offset) : name;
    }

    private void fillUnion(Union union, JsonObject node) {
        int declaredBytes = number(node, "size_bytes", -1);
        for (JsonElement e : array(node, "fields")) {
            if (!e.isJsonObject()) continue;
            JsonObject field = e.getAsJsonObject();
            String name = safeFieldName(field, "field", 0);
            if ("bitfield".equals(string(field, "descriptor"))) {
                int byteOffset = number(field, "offset_bytes", 0);
                int bitOffset = number(field, "bitfield_offset_bits", 0);
                int bits = number(field, "size_bits", -1);
                DataType base = resolveNode(object(field, "underlying_type"));
                // A UnionDataType bitfield is always at bit zero. Nonzero CCC
                // offsets cannot be represented without an explicit wrapper,
                // so never silently turn one into an ordinary union member.
                if (byteOffset != 0 || bitOffset != 0 || bits <= 0 ||
                        base == null || base.getLength() <= 0 ||
                        (declaredBytes >= 0 && (long) bits > (long) declaredBytes * 8)) {
                    skip("unsupported union bitfield placement", name +
                            " offset=" + byteOffset + " bitOffset=" +
                            bitOffset + " bits=" + bits + " base=" +
                            (base == null ? "unresolved" : base.getName()));
                    continue;
                }
                try {
                    DataTypeComponent actual = union.addBitField(base, bits, name, "");
                    if (actual.isBitFieldComponent() &&
                            ((BitFieldDataType) actual.getDataType()).getBitSize() == bits) {
                        placedBitfields++;
                        verifiedBitfields++;
                    } else {
                        reportLayoutWarning(union.getName(),
                                "union bitfield " + name + " was not retained as " +
                                bits + " bits");
                    }
                } catch (InvalidDataTypeException | RuntimeException ex) {
                    skip("union bitfield placement", name + ": " + ex.getMessage());
                }
                continue;
            }
            DataType dt = resolveNode(field);
            if (dt == null || dt.getLength() <= 0) continue;
            if (declaredBytes >= 0 && dt.getLength() > declaredBytes) {
                skip("union member larger than declared size", name +
                        " fieldBytes=" + dt.getLength() +
                        " unionBytes=" + declaredBytes);
                continue;
            }
            try {
                union.add(dt, dt.getLength(), name, "");
            } catch (RuntimeException ex) {
                skip("union field placement", name + ": " + ex.getMessage());
            }
        }
        if (declaredBytes >= 0 && union.getLength() != declaredBytes) {
            reportLayoutWarning(union.getName(),
                    "declared size=" + declaredBytes + ", modeled size=" +
                    union.getLength());
        }
    }

    private void fillEnum(ghidra.program.model.data.Enum enumeration, JsonObject node) {
        for (JsonElement entry : array(node, "constants")) {
            if (!entry.isJsonObject()) continue;
            JsonObject value = entry.getAsJsonObject();
            String name = string(value, "name");
            if (name.isBlank()) continue;
            try { enumeration.add(name, value.get("value").getAsLong()); }
            catch (RuntimeException ex) { skip("enum constant placement", name + ": " + ex.getMessage()); }
        }
    }

    private void importFunctions() {
        JsonArray functions = array(database, "functions");
        JsonArray parameters = array(database, "parameter_variables");
        JsonArray locals = array(database, "local_variables");
        for (JsonElement element : functions) {
            if (monitor.isCancelled()) return;
            if (!element.isJsonObject()) continue;
            JsonObject symbol = element.getAsJsonObject();
            Address address = mappedAddress(symbol);
            String name = string(symbol, "name");
            if (address == null || name.isBlank()) { skip("unmapped/unnamed functions", name + " / address=" + string(symbol, "address")); continue; }
            try {
                Function function = program.getFunctionManager().getFunctionAt(address);
                if (function == null) {
                    AddressSet body = new AddressSet(address);
                    int byteLength = number(symbol, "size", 0);
                    if (byteLength > 0 && byteLength <= 0x1000000 &&
                            address.getOffset() + (long) byteLength - 1 <= 0xffffffffL) {
                        Address last = toAddr(address.getOffset() + (long) byteLength - 1);
                        if (program.getMemory().getBlock(last) ==
                                program.getMemory().getBlock(address)) {
                            body = new AddressSet(address, last);
                        }
                    }
                    // This overload accepts a function body and a single entry point.
                    // CreateFunctionCmd(AddressSetView, SourceType) instead treats EVERY
                    // address in the set as a separate entry and creates byte-sized
                    // functions throughout the CCC-reported range.
                    CreateFunctionCmd cmd = new CreateFunctionCmd(name, address, body, SourceType.ANALYSIS);
                    if (!cmd.applyTo(program, monitor)) { skip("function creation", name + " at " + address); continue; }
                    function = program.getFunctionManager().getFunctionAt(address);
                }
                if (function == null) { skip("function missing after creation", name + " at " + address); continue; }
                if (function.getComment() == null || function.getComment().isBlank()) {
                    String sourcePath = string(symbol, "relative_path");
                    if (!sourcePath.isBlank()) function.setComment(sourcePath);
                }
                importLineComments(symbol);
                Symbol primary = function.getSymbol();
                if (primary.getSource() == SourceType.DEFAULT ||
                        primary.getSource() == SourceType.ANALYSIS) {
                    try { function.setName(name, SourceType.ANALYSIS); }
                    catch (Exception e) { warning("Function name " + name + ": " + e.getMessage()); }
                }
                JsonObject functionType = object(symbol, "type");
                if (functionType != null && "function".equals(string(functionType, "descriptor"))
                        && (function.getSignatureSource() == SourceType.DEFAULT ||
                            function.getSignatureSource() == SourceType.ANALYSIS)) {
                    DataType returnType = resolveNode(object(functionType, "return_type"));
                    if (returnType != null) function.setReturnType(returnType, SourceType.ANALYSIS);
                    // Do not replace known parameters with unresolved CCC types.
                    JsonArray parameterIndices = array(symbol, "parameter_variables");
                    JsonArray parameterTypes = array(functionType, "parameters");
                    boolean hasParameterVariables = symbol.has("parameter_variables") &&
                            parameterIndices.size() > 0;
                    if (hasParameterVariables || functionType.has("parameters")) {
                        List<Variable> replacements = new ArrayList<>();
                        boolean valid = true;
                        JsonArray source = hasParameterVariables ? parameterIndices : parameterTypes;
                        for (JsonElement entry : source) {
                            JsonObject param;
                            if (hasParameterVariables) {
                                int id = entry.getAsInt();
                                if (id < 0 || id >= parameters.size() ||
                                        !parameters.get(id).isJsonObject()) {
                                    valid = false; break;
                                }
                                param = parameters.get(id).getAsJsonObject();
                            } else if (entry.isJsonObject()) {
                                param = entry.getAsJsonObject();
                            } else {
                                valid = false; break;
                            }
                            DataType type = resolveNode(object(param, "type"));
                            if (!hasParameterVariables && type == null) type = resolveNode(param);
                            if (type == null || type instanceof VoidDataType) {
                                valid = false; break;
                            }
                            JsonObject storage = object(param, "storage");
                            if (storage != null && storage.has("is_by_reference") &&
                                    storage.get("is_by_reference").getAsBoolean()) {
                                type = new PointerDataType(type);
                            }
                            String parameterName = string(param, "name");
                            if (parameterName.isBlank()) parameterName = "param_" + replacements.size();
                            replacements.add(new ParameterImpl(parameterName, type, program));
                        }
                        if (valid) {
                            function.replaceParameters(replacements,
                                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                                    true, SourceType.ANALYSIS);
                        }
                    }
                }
                if (symbol.has("local_variables")) {
                    for (JsonElement idx : array(symbol, "local_variables")) {
                        int id = idx.getAsInt();
                        if (id < 0 || id >= locals.size() || !locals.get(id).isJsonObject()) continue;
                        JsonObject local = locals.get(id).getAsJsonObject();
                        JsonObject storage = object(local, "storage");
                        if (!"stack".equals(string(storage, "type"))) continue;
                        DataType type = resolveNode(object(local, "type"));
                        int offset = number(storage, "offset", Integer.MIN_VALUE);
                        String localName = string(local, "name");
                        if (type == null || type.getLength() <= 0 || localName.isBlank()
                                || offset == Integer.MIN_VALUE) continue;
                        try {
                            function.addLocalVariable(new LocalVariableImpl(
                                    localName, type, offset, program, SourceType.ANALYSIS),
                                    SourceType.ANALYSIS);
                        } catch (Exception e) { skip("stack local insertion", localName + " at " + address + ": " + e.getMessage()); }
                    }
                }
                appliedFunctions++;
            } catch (Exception e) {
                skip("function update", name + " at " + address + ": " + e.getMessage());
            }
        }
    }

    private void importLineComments(JsonObject function) {
        if (options.outputLineNumbers) {
            for (JsonElement item : array(function, "line_numbers")) {
                if (!item.isJsonArray()) continue;
                JsonArray pair = item.getAsJsonArray();
                if (pair.size() < 2) continue;
                try {
                    long offset = pair.get(0).getAsLong();
                    if (offset < 0 || offset > 0xffffffffL) continue;
                    Address address = toAddr(offset);
                    ghidra.program.model.listing.CodeUnit code =
                            program.getListing().getCodeUnitContaining(address);
                    if (code != null && code.getComment(
                            ghidra.program.model.listing.CommentType.EOL) == null) {
                        setEOLComment(address, "Line " + pair.get(1).getAsInt());
                    }
                } catch (RuntimeException e) { skip("source line annotation", "function=" + string(function, "name") + ": " + e.getMessage()); }
            }
        }
        if (options.markInlinedCode) {
            for (JsonElement item : array(function, "sub_source_files")) {
                if (!item.isJsonArray()) continue;
                JsonArray pair = item.getAsJsonArray();
                if (pair.size() < 2) continue;
                try {
                    long offset = pair.get(0).getAsLong();
                    if (offset < 0 || offset > 0xffffffffL) continue;
                    Address address = toAddr(offset);
                    String sourcePath = pair.get(1).getAsString();
                    ghidra.program.model.listing.CodeUnit code =
                            program.getListing().getCodeUnitContaining(address);
                    if (code != null && code.getComment(
                            ghidra.program.model.listing.CommentType.PRE) == null) {
                        setPreComment(address, "inlined from " + sourcePath);
                    }
                } catch (RuntimeException e) { skip("inline source annotation", "function=" + string(function, "name") + ": " + e.getMessage()); }
            }
        }
    }

    private void importGlobals() {
        for (JsonElement element : array(database, "global_variables")) {
            if (monitor.isCancelled()) return;
            if (!element.isJsonObject()) continue;
            JsonObject symbol = element.getAsJsonObject();
            Address address = mappedAddress(symbol);
            String name = string(symbol, "name");
            if (address == null) { skip("unmapped globals", name + " / address=" + string(symbol, "address")); continue; }
            try {
                DataType type = resolveNode(object(symbol, "type"));
                if (type != null && type.getLength() > 0 &&
                        program.getListing().getDefinedDataAt(address) == null &&
                        program.getListing().getInstructionContaining(address) == null) {
                    // Never clear existing instructions or user-defined data.
                    try { program.getListing().createData(address, type); }
                    catch (Exception e) { skip("global data declaration", name + " at " + address + ": " + e.getMessage()); }
                }
                createSafeLabel(address, name);
                appliedGlobals++;
            } catch (Exception e) { skip("global update", name + ": " + e.getMessage()); }
        }
    }

    private void importLabels() {
        for (JsonElement element : array(database, "labels")) {
            if (monitor.isCancelled()) return;
            if (!element.isJsonObject()) continue;
            JsonObject symbol = element.getAsJsonObject();
            // Verified linker sentinels are not ordinary objects, even if an
            // artificial loader-created block happens to overlap their value.
            if (retainVerifiedLinkerPseudoLabel(symbol)) continue;
            Address address = mappedAddress(symbol);
            if (address == null) {
                skip("unmapped labels", string(symbol, "name") +
                        " / address=" + string(symbol, "address"));
                continue;
            }
            try { if (createSafeLabel(address, string(symbol, "name"))) appliedLabels++; }
            catch (Exception e) { skip("label processing", string(symbol, "name") + ": " + e.getMessage()); }
        }
    }

    static boolean isVerifiedLinkerPseudoLabel(String name, long value,
            long linkerEnd, long linkerGp) {
        return (("end".equals(name) || "_end".equals(name)) &&
                value >= 0 && value == linkerEnd) ||
                ("_gp".equals(name) && value >= 0 && value == linkerGp);
    }

    private boolean retainVerifiedLinkerPseudoLabel(JsonObject symbol) {
        long value = unsignedAddress(symbol, "address");
        if (value < 0) return false;
        var options = program.getOptions(IopIrxLinkerSymbols.OPTIONS);
        long linkerEnd = options.getLong(IopIrxLinkerSymbols.END_VALUE, -1);
        long linkerGp = options.getLong(IopIrxLinkerSymbols.GP_VALUE, -1);
        String name = string(symbol, "name");
        if (!isVerifiedLinkerPseudoLabel(name, value, linkerEnd, linkerGp)) {
            return false;
        }
        retainedLinkerSentinels++;
        return true;
    }

    private boolean createSafeLabel(Address address, String name) {
        if (name.isBlank()) return false;
        // No forced redefinition of any user/analysis primary symbol.
        for (Symbol symbol : program.getSymbolTable().getSymbols(address)) {
            if (name.equals(symbol.getName())) return false;
        }
        try {
            program.getSymbolTable().createLabel(address, name, SourceType.ANALYSIS);
            return true;
        } catch (Exception e) { skip("label rejected", name + " at " + address + ": " + e.getMessage()); return false; }
    }
}
