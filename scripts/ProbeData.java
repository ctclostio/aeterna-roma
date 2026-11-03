// ProbeData.java - resolve data symbols: raw bytes, strings, pointer tables
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Symbol;

import java.io.PrintWriter;

public class ProbeData extends GhidraScript {
    @Override
    protected void run() throws Exception {
        PrintWriter out = new PrintWriter(System.out);
        Memory mem = currentProgram.getMemory();
        for (String a : getScriptArgs()) {
            Address addr = toAddr(a);
            out.println();
            out.println("=== DATA " + a + " ===");
            Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(addr);
            out.println("  primarySymbol=" + (s == null ? "<none>" : s.getName())
                    + " type=" + (s == null ? "-" : s.getSymbolType()));
            byte[] b = new byte[32];
            try {
                mem.getBytes(addr, b);
            } catch (Exception e) {
                out.println("  <unreadable>");
                continue;
            }
            StringBuilder hex = new StringBuilder();
            StringBuilder asc = new StringBuilder();
            for (int i = 0; i < b.length; i++) {
                hex.append(String.format("%02x ", b[i]));
                asc.append((b[i] >= 0x20 && b[i] < 0x7f) ? (char) b[i] : '.');
            }
            out.println("  hex  = " + hex);
            out.println("  ascii= " + asc);
            // 4 dwords
            for (int i = 0; i < 4; i++) {
                int v = (b[i*4] & 0xff) | ((b[i*4+1] & 0xff) << 8) | ((b[i*4+2] & 0xff) << 16) | ((b[i*4+3] & 0xff) << 24);
                out.println("  dword[" + i + "] = 0x" + Integer.toHexString(v) + " (" + v + ")");
            }
            // xrefs from
            ghidra.program.model.symbol.ReferenceIterator rit =
                currentProgram.getReferenceManager().getReferencesTo(addr);
            out.println("  xrefsFrom:");
            while (rit.hasNext()) {
                ghidra.program.model.symbol.Reference r = rit.next();
                out.println("     " + r.getFromAddress() + " " + r.getReferenceType());
            }
        }
        out.flush();
    }
}