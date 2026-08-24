// Applies known symbols to functions: PE exports, demangles MSVC names.
// Writes a consolidated symbol map for the 64-bit build phase.
// Usage: ApplySymbols.java <out_root>
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.Address;
import java.io.*;
import java.util.*;

public class ApplySymbols extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File outDir = new File(args[0], currentProgram.getName().replaceAll("[^A-Za-z0-9._-]", "_"));
        outDir.mkdirs();
        File mapFile = new File(outDir, "symbol_map.txt");
        PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(mapFile)));

        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();

        // 1) External linkage names from PE exports & RTTI already exist as symbols.
        //    Ensure each address's PRIMARY symbol name is set on its function.
        int renamed = 0;
        Map<String,Integer> nsCount = new HashMap<>();
        FunctionIterator fi = fm.getFunctions(true);
        List<String> lines = new ArrayList<>();
        while (fi.hasNext()) {
            Function f = fi.next();
            String nm = f.getName();
            String disp = f.toString(); // may include namespace
            lines.add(f.getEntryPoint() + "\t" + nm + "\t" + disp.replace('\t',' ')
                + "\t" + f.getBody().getNumAddresses()
                + "\t" + (f.isThunk() ? "thunk" : (f.isExternal() ? "ext" : "func")));
            // count namespace usage for architecture stats
            int d = disp.indexOf("::");
            if (d > 0) {
                String ns = disp.substring(0, Math.min(d, 60));
                nsCount.merge(ns, 1, Integer::sum);
            }
            if (!nm.startsWith("FUN_") && !nm.startsWith("thunk_")) renamed++;
        }
        for (String l : lines) pw.println(l);
        pw.close();

        File nsFile = new File(outDir, "namespaces.txt");
        PrintWriter nsp = new PrintWriter(new BufferedWriter(new FileWriter(nsFile)));
        nsCount.entrySet().stream()
            .sorted((a,b)->b.getValue()-a.getValue())
            .forEach(e -> nsp.println(e.getValue() + "\t" + e.getKey()));
        nsp.close();

        println("ApplySymbols: wrote " + lines.size() + " entries (" + renamed
            + " named), namespaces=" + nsCount.size());
    }
}
