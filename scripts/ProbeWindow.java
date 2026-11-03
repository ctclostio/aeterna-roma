// ProbeWindow.java - dump listing window around addresses + function metadata
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;

import java.io.PrintWriter;

public class ProbeWindow extends GhidraScript {

    private PrintWriter out;

    @Override
    protected void run() throws Exception {
        out = new PrintWriter(System.out);
        out.println("=== PROBE BEGIN ===");
        String[] args = getScriptArgs();
        int window = 96;
        try {
            window = Integer.parseInt(args[0]);
        } catch (Exception ignored) {
        }
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        for (int i = 1; i < args.length; i++) {
            dump(args[i], window, di);
        }
        di.dispose();
        out.println("=== PROBE END ===");
        out.flush();
    }

    private void dump(String a, int window, DecompInterface di) {
        Address addr = toAddr(a);
        Function f = getFunctionContaining(addr);
        out.println();
        out.println("================================================================");
        out.println("## ADDR " + a + " in " + (f == null ? "<none>" : f.getName())
                + " @" + (f == null ? "?" : f.getEntryPoint())
                + " size=" + (f == null ? 0 : f.getBody().getNumAddresses()));
        out.println("================================================================");
        Listing listing = currentProgram.getListing();
        Instruction ins = listing.getInstructionContaining(addr);
        if (ins == null) {
            out.println("  <no instruction>");
            return;
        }
        int back = window;
        Instruction start = ins;
        for (Instruction p = ins.getPrevious(); p != null && back > 0; p = p.getPrevious()) {
            back--;
            start = p;
        }
        Instruction it2 = start;
        InstructionIterator iter = listing.getInstructions(it2.getAddress(), true);
        int n = 0;
        while (iter.hasNext() && n < window * 3) {
            Instruction x = iter.next();
            out.println(line(x));
            n++;
            if (x.getAddress().compareTo(ins.getAddress()) > 0 && n > window) {
                break;
            }
        }
    }

    private String line(Instruction x) {
        StringBuilder refs = new StringBuilder();
        for (Reference r : x.getReferencesFrom()) {
            Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(r.getToAddress());
            refs.append(" {").append(r.getReferenceType()).append("->")
                .append(r.getToAddress()).append(s != null ? "(" + s.getName() + ")" : "").append("}");
        }
        StringBuilder stack = new StringBuilder();
        try {
            byte[] b = x.getBytes();
            StringBuilder hx = new StringBuilder();
            for (int i = 0; i < b.length && i < 10; i++) {
                hx.append(String.format("%02x", b[i]));
            }
            stack.append(hx);
        } catch (Exception ignored) {
        }
        return String.format("  %s  %-24s %s%s", x.getAddress(), stack, x.toString(), refs);
    }
}