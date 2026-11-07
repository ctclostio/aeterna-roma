// Ghidra headless script: dump instruction context around addresses.
// Usage: DumpCode.java <addresses_tsv> <output_tsv> [bytes_before] [bytes_after]
// The address TSV has one address per line (header optional).

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

public class DumpCode extends GhidraScript {

    private static String tsv(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\t", " ").replace("\r", " ").replace("\n", " ");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("USAGE: DumpCode.java <addresses_tsv> <output_tsv> [before] [after]");
            return;
        }
        int before = args.length > 2 ? Integer.parseInt(args[2]) : 8;
        int after = args.length > 3 ? Integer.parseInt(args[3]) : 24;
        List<Address> addresses = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(args[0]))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.toLowerCase().startsWith("address")) {
                    continue;
                }
                Address address = toAddr(line.split("\\s+")[0]);
                if (address != null) {
                    addresses.add(address);
                }
            }
        }
        Memory memory = currentProgram.getMemory();
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(new File(args[1])))) {
            writer.write("address\tfunction_entry\tinstruction\tbytes\tprev_instructions\tnext_instructions");
            writer.newLine();
            for (Address address : addresses) {
                monitor.checkCancelled();
                Function function = getFunctionContaining(address);
                Instruction instruction = currentProgram.getListing().getInstructionAt(address);
                StringBuilder bytes = new StringBuilder();
                try {
                    for (int i = -before; i < after; i++) {
                        Address a = address.add(i);
                        if (memory.contains(a)) {
                            bytes.append(String.format("%02x ", memory.getByte(a) & 0xff));
                        }
                    }
                }
                catch (Exception e) {
                    bytes.append("unreadable");
                }
                StringBuilder prev = new StringBuilder();
                Instruction p = currentProgram.getListing().getInstructionBefore(address);
                for (int i = 0; i < 6 && p != null; i++) {
                    if (prev.length() > 0) {
                        prev.insert(0, " ; ");
                    }
                    prev.insert(0, p.getAddress() + ": " + p.toString());
                    p = currentProgram.getListing().getInstructionBefore(p.getAddress());
                }
                StringBuilder next = new StringBuilder();
                Instruction n = currentProgram.getListing().getInstructionAfter(address);
                for (int i = 0; i < 10 && n != null; i++) {
                    if (next.length() > 0) {
                        next.append(" ; ");
                    }
                    next.append(n.getAddress()).append(": ").append(n.toString());
                    n = currentProgram.getListing().getInstructionAfter(n.getAddress());
                }
                writer.write(tsv(address.toString()) + "\t" +
                    tsv(function == null ? "" : function.getEntryPoint().toString()) + "\t" +
                    tsv(instruction == null ? "" : instruction.toString()) + "\t" +
                    tsv(bytes.toString().trim()) + "\t" +
                    tsv(prev.toString()) + "\t" + tsv(next.toString()));
                writer.newLine();
            }
        }
        println("Wrote " + args[1]);
    }
}
