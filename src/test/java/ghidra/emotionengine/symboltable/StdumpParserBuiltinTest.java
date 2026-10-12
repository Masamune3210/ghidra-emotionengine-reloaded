package ghidra.emotionengine.symboltable;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;

import org.junit.Test;

import com.google.gson.JsonParseException;

/** Regression tests for all known stdump v1.2.1 builtin class strings. */
public class StdumpParserBuiltinTest {
    private static StdumpAST.BuiltIn parse(String className) throws Exception {
        String json = "{\"version\":7,\"files\":[],\"deduplicated_types\":[" +
            "{\"descriptor\":\"builtin\",\"class\":\"" + className +
            "\",\"name\":\"unresolved_test\",\"size_bits\":64}]}";
        StdumpAST.ParsedJsonFile ast = StdumpParser.readJson(
            json.getBytes(StandardCharsets.UTF_8));
        assertEquals(1, ast.deduplicatedTypes.size());
        return (StdumpAST.BuiltIn) ast.deduplicatedTypes.get(0);
    }

    @Test
    public void recognizesErrorSentinelEmittedByStdump121() throws Exception {
        StdumpAST.BuiltIn type = parse("error");
        assertEquals(StdumpAST.BuiltInClass.UNKNOWN_PROBABLY_ARRAY, type.builtinClass);
        assertEquals("unresolved_test", type.name);
        assertEquals(64, type.sizeBits);
    }

    @Test
    public void retainsKnownBuiltins() throws Exception {
        assertEquals(StdumpAST.BuiltInClass.VOID, parse("void").builtinClass);
        assertEquals(StdumpAST.BuiltInClass.UNSIGNED_8,
            parse("8-bit unsigned integer").builtinClass);
        assertEquals(StdumpAST.BuiltInClass.FLOAT_64,
            parse("64-bit floating point").builtinClass);
        assertEquals(StdumpAST.BuiltInClass.SIGNED_128,
            parse("128-bit signed integer").builtinClass);
    }

    @Test
    public void recoversOnlyConfirmedPs2Ilp32UnsignedNames() throws Exception {
        assertEquals(StdumpAST.BuiltInClass.UNSIGNED_32,
            StdumpAST.BuiltIn.recoverPs2Ilp32Unknown("unsigned int", -1));
        assertEquals(StdumpAST.BuiltInClass.UNSIGNED_32,
            StdumpAST.BuiltIn.recoverPs2Ilp32Unknown("long unsigned int", -1));
        assertEquals(StdumpAST.BuiltInClass.UNSIGNED_32,
            StdumpAST.BuiltIn.recoverPs2Ilp32Unknown("unsigned int", 32));
        assertEquals(StdumpAST.BuiltInClass.UNKNOWN_PROBABLY_ARRAY,
            StdumpAST.BuiltIn.recoverPs2Ilp32Unknown("long unsigned int", 64));
        assertEquals(StdumpAST.BuiltInClass.UNKNOWN_PROBABLY_ARRAY,
            StdumpAST.BuiltIn.recoverPs2Ilp32Unknown("unknown_type", -1));
        assertEquals(StdumpAST.BuiltInClass.UNKNOWN_PROBABLY_ARRAY,
            StdumpAST.BuiltIn.recoverPs2Ilp32Unknown(null, -1));
    }

    @Test
    public void rejectsUnknownClassesWithTheirActualValue() throws Exception {
        try {
            parse("unexpected new type");
            fail("Parser should reject unfamiliar stdump classes");
        }
        catch (JsonParseException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("unexpected new type"));
        }
    }
}
