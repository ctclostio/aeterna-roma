// ProbeFunc.java - dump instruction listing + xrefs for selected addresses
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.PrintWriter;

public class ProbeFunc extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        PrintWriter out = new PrintWriter(System.out);
        out.println("=== PROBE BEGIN ===");

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);

        for (String a : args) {
            Address addr = toAddr(a);
            Function f = getFunctionContaining(addr);
            if (f == null) {
                out.println("## NO FUNCTION AT " + a);
                continue;
            }
            out.println();
            out.println("################################################################");
            out.println("## FUNC " + f.getName() + " entry=" + f.getEntryPoint()
                    + " body_end=" + f.getBody().getMaxAddress()
                    + " size=" + f.getBody().getNumAddresses()
                    + " numParams=" + f.getParameterCount()
                    + " callingConvention=" + f.getCallingConventionName());
            out.println("## signature: " + f.getSignature());
            out.println("################################################################");

            // Xrefs TO the function
            ReferenceManager rm = currentProgram.getReferenceManager();
            java.util.List<Reference> refList = new java.util.ArrayList<>();
            ReferenceIterator rit = rm.getReferencesTo(f.getEntryPoint());
            while (rit.hasNext()) {
                refList.add(rit.next());
            }
            out.println("## XREFS_TO (" + refList.size() + "):");
            for (Reference r : refList) {
                out.println("   from " + r.getFromAddress() + " type=" + r.getReferenceType()
                        + " fn=" + fnName(r.getFromAddress()));
            }

            // Callers summary
            out.println("## CALLERS:");
            for (Function caller : f.getCallingFunctions(monitor)) {
                out.println("   " + caller.getName() + " @ " + caller.getEntryPoint());
            }

            // Disassembly listing
            out.println("## LISTING:");
            InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (it.hasNext()) {
                Instruction ins = it.next();
                StringBuilder refs_sb = new StringBuilder();
                for (Reference r : ins.getReferencesFrom()) {
                    Symbol s = null;
                    try {
                        s = currentProgram.getSymbolTable().getPrimarySymbol(r.getToAddress());
                    } catch (Exception ignored) {
                    }
                    refs_sb.append(" {")
                       .append(r.getReferenceType())
                       .append("->0x").append(r.getToAddress())
                       .append(s != null ? " (" + s.getName() + ")" : "")
                       .append("}");
                }
                out.println(String.format("  %s  %-28s %s%s",
                        ins.getAddress(), bytesOf(ins), ins.toString(), refs_sb));
            }

            // Decompiled C
            DecompileResults dr = di.decompileFunction(f, 90, monitor);
            if (dr != null && dr.decompileCompleted()) {
                out.println("## DECOMPILE:");
                out.println(dr.getDecompiledFunction().getC());
            } else {
                out.println("## DECOMPILE FAILED: " + (dr == null ? "null" : dr.getErrorMessage()));
            }
        }
        di.dispose();
        out.println("=== PROBE END ===");
        out.flush();
    }

    private String fnName(Address a) {
        Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
        return f == null ? "?" : f.getName();
    }

    private String bytesOf(Instruction ins) {
        byte[] b;
        try {
            b = ins.getBytes();
        } catch (Exception e) {
            return "??";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length && i < 10; i++) {
            sb.append(String.format("%02x", b[i]));
        }
        return sb.toString();
    }
}