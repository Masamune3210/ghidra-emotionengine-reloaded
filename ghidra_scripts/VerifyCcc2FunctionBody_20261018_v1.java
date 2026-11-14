// VerifyCcc2FunctionBody_20261018_v1.java
// @category PS2.CCC
// Read-only Ghidra API regression probe for CreateFunctionCmd overloads.
// Requires the user's preserved original PSBBN vmlinux GZF with an unoccupied
// 56-byte prefix at 0x80018000. No changes survive this script: each probe
// is wrapped in its own explicitly rolled-back database transaction.
//
// Optional command-line script argument "legacy" runs the old erroneous
// entry-set overload (expected 56 entries). The default tests the corrected
// explicit function-body overload (expected one function).

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class VerifyCcc2FunctionBody_20261018_v1 extends GhidraScript {
    private static final String ORIGINAL_SHA256 =
        "07e44b50e2558d188caa306f60c138ad6015bbabcd3bc32fba35eeb6e8a870fc";

    @Override
    public void run() throws Exception {
        if (!ORIGINAL_SHA256.equals(currentProgram.getExecutableSHA256()) ||
            !"r5900:LE:32:default".equals(currentProgram.getLanguageID().toString()) ||
            currentProgram.getImageBase().getOffset() != 0x80010000L) {
            throw new IllegalStateException("Expected preserved original PSBBN vmlinux Ghidra project");
        }

        Address start = toAddr(0x80018000L);
        AddressSet body = new AddressSet(start, start.add(55));
        if (currentProgram.getMemory().getInt(start) != 0x27bdffe0) {
            throw new IllegalStateException("Kernel fixture bytes changed");
        }
        if (currentProgram.getFunctionManager().getFunctionsOverlapping(body).hasNext()) {
            throw new IllegalStateException("Probe requires the original, undefined 56-byte prefix");
        }

        String[] args = getScriptArgs();
        if (args.length > 1 || (args.length == 1 && !"legacy".equals(args[0]))) {
            throw new IllegalArgumentException("Optional argument: legacy");
        }
        boolean legacy = args.length == 1;
        int transaction = currentProgram.startTransaction("Rolled-back CCC2 function-body API probe");
        try {
            int before = currentProgram.getFunctionManager().getFunctionCount();
            CreateFunctionCmd cmd = legacy
                ? new CreateFunctionCmd(body, SourceType.ANALYSIS)
                : new CreateFunctionCmd("ccc2_probe_only", start, body, SourceType.ANALYSIS);
            boolean accepted = cmd.applyTo(currentProgram, monitor);
            int created = currentProgram.getFunctionManager().getFunctionCount() - before;
            int expected = legacy ? 56 : 1;
            println("CCC2_FUNCTION_BODY mode=" + (legacy ? "legacy-entry-set" : "explicit-body") +
                " accepted=" + accepted + " functionsCreated=" + created +
                " expected=" + expected + " status=" + cmd.getStatusMsg());
            if (!accepted || created != expected) {
                throw new IllegalStateException("Unexpected Ghidra CreateFunctionCmd semantics");
            }
        } finally {
            currentProgram.endTransaction(transaction, false);
        }
        println("CCC2_FUNCTION_BODY_PASS; all temporary database changes rolled back");
    }
}
