// Dumps recovered C++ class info: vftables w/ RTTI names, structures, function names.
// Usage: ExportClassInventory.java <out_root>
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import java.io.*;
import java.util.*;

public class ExportClassInventory extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File outDir = new File(args[0], currentProgram.getName().replaceAll("[^A-Za-z0-9._-]", "_"));
        outDir.mkdirs();

        // 1) vftable & RTTI symbols -> class names
        PrintWriter vft = new PrintWriter(new BufferedWriter(new FileWriter(new File(outDir, "vftables.txt"))));
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator si = st.getAllSymbols(true);
        int nVf = 0, nRtti = 0;
        while (si.hasNext()) {
            Symbol s = si.next();
            String nm = s.getName();
            if (nm.contains("vftable") || nm.contains("RTTI") || nm.contains("`vtable'")) {
                vft.println(s.getAddress() + "\t" + nm + "\t" + s.getParentNamespace().getName());
                if (nm.contains("vftable")) nVf++; else nRtti++;
            }
        }
        vft.close();

        // 2) named classes/structs in the datatype manager
        PrintWriter cls = new PrintWriter(new BufferedWriter(new FileWriter(new File(outDir, "classes.txt"))));
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Iterator<DataType> it = dtm.getAllDataTypes();
        int nCls = 0;
        while (it.hasNext()) {
            DataType dt = it.next();
            if ((dt instanceof Composite || dt instanceof ghidra.program.model.data.Enum) && !(dt instanceof FunctionDefinition)) {
                cls.println(dt.getCategoryPath().getPath() + "::" + dt.getName()
                    + "\tsize=" + (dt.getLength() > 0 ? dt.getLength() : "?"));
                nCls++;
            }
        }
        cls.close();

        // 3) all non-default function names (demangled or user/analysis-named)
        PrintWriter fn = new PrintWriter(new BufferedWriter(new FileWriter(new File(outDir, "named_functions.txt"))));
        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        int nNamed = 0;
        while (fi.hasNext()) {
            Function f = fi.next();
            String nm = f.getName();
            if (!nm.startsWith("FUN_") && !nm.startsWith("thunk_FUN_")) {
                fn.println(f.getEntryPoint() + "\t" + nm);
                nNamed++;
            }
        }
        fn.close();

        println("Inventory: vftables=" + nVf + " rtti_syms=" + nRtti
            + " classes=" + nCls + " named_functions=" + nNamed
            + " total_funcs=" + currentProgram.getFunctionManager().getFunctionCount());
    }
}
