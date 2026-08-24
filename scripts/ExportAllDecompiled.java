// Ghidra headless post-script: decompile every function and write C files.
// Output layout: <outRoot>/<binaryName>/decomp/func_<entry>.c plus globals listing.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.Address;
import java.io.*;
import java.util.*;

public class ExportAllDecompiled extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("USAGE: ExportAllDecompiled.java <output_root> [batchStart batchEnd]");
            return;
        }
        File outRoot = new File(args[0]);
        int batchStart = 0, batchEnd = Integer.MAX_VALUE;
        if (args.length >= 3) {
            batchStart = Integer.parseInt(args[1]);
            batchEnd = Integer.parseInt(args[2]);
        }

        String binName = currentProgram.getName().replaceAll("[^A-Za-z0-9._-]", "_");
        File outDir = new File(outRoot, binName);
        outDir.mkdirs();

        DecompInterface di = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        di.setOptions(opts);
        di.openProgram(currentProgram);

        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        List<Function> funcs = new ArrayList<>();
        while (fi.hasNext()) funcs.add(fi.next());
        println("Total functions: " + funcs.size());

        // Chunked manifest so batches can be re-run
        int totalBatches = (funcs.size() + 999) / 1000;

        File idxFile = new File(outDir, "function_index.txt");
        PrintWriter idx = new PrintWriter(new BufferedWriter(new FileWriter(idxFile, true)));

        int n = 0;
        int skipped = 0;
        int exported = 0;
        for (Function f : funcs) {
            int i = n++;
            if (i < batchStart || i >= batchEnd) continue;
            Address entry = f.getEntryPoint();
            String hex = entry.toString();
            String nm = f.getName().replaceAll("[^A-Za-z0-9_.$-]", "_");
            File outFile = new File(outDir, "decomp/" + hex + "_" + nm + ".c");
            // Resume support: skip functions already exported successfully
            if (outFile.exists() && outFile.length() > 0) {
                String first = null;
                try (BufferedReader br = new BufferedReader(new FileReader(outFile))) {
                    for (int lineNo = 0; lineNo < 6 && (first = br.readLine()) != null; lineNo++) {
                        if (first.contains("DECOMPILATION FAILED")) break;
                    }
                } catch (IOException ignored) {}
                if (first != null && !first.contains("DECOMPILATION FAILED")) {
                    skipped++;
                    continue;
                }
            }
            outFile.getParentFile().mkdirs();
            try {
                DecompileResults res = di.decompileFunction(f, 90, monitor);
                PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(outFile)));
                pw.println("// " + binName);
                pw.println("// Function: " + f.getName(true));
                pw.println("// Entry: 0x" + hex + "  Size: " + f.getBody().getNumAddresses());
                pw.println("// Signature: " + f.getSignature(false));
                if (res != null && res.getDecompiledFunction() != null) {
                    pw.println(res.getDecompiledFunction().getC());
                } else {
                    pw.println("// DECOMPILATION FAILED: " + (res == null ? "null" : res.getErrorMessage()));
                }
                pw.close();
                exported++;
                idx.println("0x" + hex + "\t" + f.getName() + "\t" + f.getBody().getNumAddresses()
                    + "\t" + (f.isThunk() ? "thunk" : "func"));
            } catch (Exception e) {
                idx.println("0x" + hex + "\t" + f.getName() + "\tERROR\t" + e.getMessage());
            }
            if (i % 500 == 0) {
                idx.flush();
                println("Progress: " + i + "/" + funcs.size());
            }
        }
        idx.close();
        di.dispose();
        println("DONE batch [" + batchStart + "," + batchEnd + ") total=" + funcs.size()
            + " exported_this_run=" + exported + " skipped_existing=" + skipped);
    }
}
