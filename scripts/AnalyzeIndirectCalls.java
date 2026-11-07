// Ghidra headless script: enumerate and resolve indirect call sites.
//
// The Track 3 call-graph walk only follows direct FUN_* edges.  This script
// records every CALL whose target is not a direct address, classifies the
// operand shape, and resolves absolute memory operands by reading the pointer
// stored at the referenced address.  The output is a TSV suitable for the
// Python resolver and for deciding which unresolved targets need functions.
//
// Usage: AnalyzeIndirectCalls.java <output_tsv>
//
// Read-only: no program changes are made.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class AnalyzeIndirectCalls extends GhidraScript {

    private AddressSet executable = new AddressSet();

    private static String tsv(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\t", " ").replace("\r", " ").replace("\n", " ");
    }

    private String functionEntry(Address site) {
        Function f = getFunctionContaining(site);
        return f == null ? "" : f.getEntryPoint().toString();
    }

    private String functionName(Address site) {
        Function f = getFunctionContaining(site);
        return f == null ? "" : f.getName(true);
    }

    private Long readPointer(Address address) {
        try {
            if (!currentProgram.getMemory().contains(address)) {
                return null;
            }
            int value = currentProgram.getMemory().getInt(address);
            return Integer.toUnsignedLong(value);
        }
        catch (Exception e) {
            return null;
        }
    }

    private String resolveTarget(long value) {
        Address target = toAddr(value);
        if (target == null || !executable.contains(target)) {
            return "";
        }
        Function f = getFunctionAt(target);
        return target.toString() + (f == null ? "" : "|" + f.getName(true));
    }

    private String describeRefs(Instruction instruction) {
        StringBuilder sb = new StringBuilder();
        for (Reference ref : instruction.getReferencesFrom()) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(ref.getToAddress()).append(':').append(ref.getReferenceType());
        }
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            println("USAGE: AnalyzeIndirectCalls.java <output_tsv>");
            return;
        }
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (block.isExecute() && block.isInitialized()) {
                executable.add(block.getAddressRange());
            }
        }
        List<String> lines = new ArrayList<>();
        lines.add("site\tfunction_entry\tfunction_name\tmnemonic\toperands\tkind\tbase\toffset\tpointer\ttarget\ttarget_function\trefs\tnote");
        int totalCalls = 0;
        int indirect = 0;
        int absolute = 0;
        int register = 0;
        int registerOffset = 0;
        int other = 0;
        InstructionIterator it = currentProgram.getListing().getInstructions(executable, true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = it.next();
            if (!instruction.getFlowType().isCall()) {
                continue;
            }
            totalCalls++;
            Object[] objects = instruction.getOpObjects(0);
            boolean hasAddress = false;
            boolean hasRegister = false;
            boolean hasScalar = false;
            Address addressObject = null;
            Register registerObject = null;
            Scalar scalarObject = null;
            for (Object object : objects) {
                if (object instanceof Address) {
                    hasAddress = true;
                    addressObject = (Address) object;
                }
                else if (object instanceof Register) {
                    hasRegister = true;
                    registerObject = (Register) object;
                }
                else if (object instanceof Scalar) {
                    hasScalar = true;
                    scalarObject = (Scalar) object;
                }
            }
            // Direct call: operand is a single address and no register/scalar.
            if (hasAddress && !hasRegister && !hasScalar) {
                continue;
            }
            indirect++;
            String kind;
            String base = "";
            String offset = "";
            String pointer = "";
            String target = "";
            String targetFunction = "";
            String note = "";
            if (hasAddress && !hasRegister) {
                kind = "absolute_memory";
                absolute++;
                base = addressObject.toString();
                Long value = readPointer(addressObject);
                if (value == null) {
                    note = "unreadable";
                }
                else {
                    pointer = String.format("0x%08x", value);
                    String resolved = resolveTarget(value);
                    if (!resolved.isEmpty()) {
                        int bar = resolved.indexOf('|');
                        if (bar >= 0) {
                            target = resolved.substring(0, bar);
                            targetFunction = resolved.substring(bar + 1);
                        }
                        else {
                            target = resolved;
                        }
                    }
                    else if (value == 0) {
                        note = "null_pointer";
                    }
                    else {
                        note = "not_executable";
                    }
                }
            }
            else if (hasRegister && hasScalar) {
                kind = "register_offset";
                registerOffset++;
                base = registerObject == null ? "" : registerObject.getName();
                offset = scalarObject == null ? "" :
                    String.format("0x%x", scalarObject.getUnsignedValue());
                note = "vtable_or_struct_call";
            }
            else if (hasRegister) {
                kind = "register";
                register++;
                base = registerObject == null ? "" : registerObject.getName();
                note = "computed_target";
            }
            else {
                kind = "other";
                other++;
                note = instruction.toString();
            }
            lines.add(tsv(instruction.getAddress().toString()) + "\t" +
                tsv(functionEntry(instruction.getAddress())) + "\t" +
                tsv(functionName(instruction.getAddress())) + "\t" +
                tsv(instruction.getMnemonicString()) + "\t" +
                tsv(instruction.toString()) + "\t" +
                kind + "\t" + tsv(base) + "\t" + tsv(offset) + "\t" +
                tsv(pointer) + "\t" + tsv(target) + "\t" + tsv(targetFunction) + "\t" +
                tsv(describeRefs(instruction)) + "\t" + tsv(note));
        }
        File out = new File(args[0]);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(out))) {
            for (String line : lines) {
                writer.write(line);
                writer.newLine();
            }
        }
        println("CALL instructions: " + totalCalls + " indirect: " + indirect +
            " absolute: " + absolute + " register_offset: " + registerOffset +
            " register: " + register + " other: " + other);
        println("Wrote " + out + " (" + lines.size() + " lines)");
    }
}
