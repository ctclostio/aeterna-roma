// Ghidra headless script: print function inventory and basic integrity counts.
// Usage: CountFunctions.java <output_tsv>

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

public class CountFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            println("USAGE: CountFunctions.java <output_tsv>");
            return;
        }
        int total = 0;
        int external = 0;
        int thunk = 0;
        int zeroBody = 0;
        long bodyBytes = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            total++;
            if (f.isExternal()) {
                external++;
            }
            if (f.isThunk()) {
                thunk++;
            }
            long size = f.getBody().getNumAddresses();
            if (size == 0) {
                zeroBody++;
            }
            bodyBytes += size;
        }
        println("total=" + total + " external=" + external +
            " internal=" + (total - external) + " thunks=" + thunk +
            " zero_body=" + zeroBody + " body_bytes=" + bodyBytes);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(new File(args[0])))) {
            writer.write("total\texternal\tinternal\tthunks\tzero_body\tbody_bytes");
            writer.newLine();
            writer.write(total + "\t" + external + "\t" + (total - external) + "\t" +
                thunk + "\t" + zeroBody + "\t" + bodyBytes);
            writer.newLine();
        }
    }
}
