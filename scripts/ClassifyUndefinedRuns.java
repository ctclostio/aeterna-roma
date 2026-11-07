// Ghidra headless script: classify executable code that is not in any function.
//
// After the documented 1,993 addresses were recovered, the project still had
// large undefined instruction runs.  This script maps each run and records the
// evidence needed to decide whether it is a standalone function or a fragment
// (jump-table case block, thunk, SEH handler, data-adjacent code):
//   * the nearest function before/after the run and whether the run starts
//     inside the previous function's body address range
//   * reference kinds to the run start (call/jump/data/flow)
//   * the first bytes and whether the run contains an indirect jump
//
// Usage: ClassifyUndefinedRuns.java <output_tsv>
//
// Read-only.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ClassifyUndefinedRuns extends GhidraScript {

    private static class Run {
        Address start;
        Address end;
        int instructions;
        String firstMnemonic = "";
        String lastMnemonic = "";
        boolean hasIndirectCall;
        boolean hasDirectCall;
        boolean hasIndirectJump;
        boolean hasRet;
        String prevInstruction = "";
        String firstBytes = "";
        String prevFunction = "";
        String prevFunctionMax = "";
        String nextFunction = "";
        int refsCall;
        int refsJump;
        int refsData;
        int refsFlow;
        String refSources = "";
    }

    private static String tsv(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\t", " ").replace("\r", " ").replace("\n", " ");
    }

    private String describePrev(Address address) {
        Instruction p = currentProgram.getListing().getInstructionBefore(address);
        return p == null ? "" : p.getAddress() + ": " + p.toString();
    }

    private boolean isDirectAddressOperand(Instruction instruction) {
        Object[] objects = instruction.getOpObjects(0);
        boolean hasAddress = false;
        for (Object object : objects) {
            if (object instanceof Address) {
                hasAddress = true;
            }
            else {
                return false;
            }
        }
        return hasAddress;
    }

    private String firstBytes(Address address, int count) {
        Memory memory = currentProgram.getMemory();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            Address a = address.add(i);
            if (!memory.contains(a)) {
                break;
            }
            try {
                sb.append(String.format("%02x ", memory.getByte(a) & 0xff));
            }
            catch (Exception e) {
                break;
            }
        }
        return sb.toString().trim();
    }

    private void collectRefs(Run run) {
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(run.start);
        StringBuilder sources = new StringBuilder();
        while (it.hasNext()) {
            Reference ref = it.next();
            if (ref.getReferenceType().isCall()) {
                run.refsCall++;
            }
            else if (ref.getReferenceType().isJump()) {
                run.refsJump++;
            }
            else if (ref.getReferenceType().isData()) {
                run.refsData++;
            }
            else if (ref.getReferenceType().isFlow()) {
                run.refsFlow++;
            }
            if (sources.length() < 400) {
                if (sources.length() > 0) {
                    sources.append(',');
                }
                sources.append(ref.getFromAddress()).append(':').append(ref.getReferenceType());
            }
        }
        run.refSources = sources.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            println("USAGE: ClassifyUndefinedRuns.java <output_tsv>");
            return;
        }
        AddressSet executable = new AddressSet();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (block.isExecute() && block.isInitialized()) {
                executable.add(block.getAddressRange());
            }
        }
        List<Run> runs = new ArrayList<>();
        Run current = null;
        Address lastEnd = null;
        int total = 0;
        int undefined = 0;
        InstructionIterator it = currentProgram.getListing().getInstructions(executable, true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = it.next();
            total++;
            Address address = instruction.getAddress();
            if (getFunctionContaining(address) != null) {
                if (current != null) {
                    runs.add(current);
                    current = null;
                }
                lastEnd = null;
                continue;
            }
            undefined++;
            if (current == null || lastEnd == null || !address.equals(lastEnd.add(1))) {
                if (current != null) {
                    runs.add(current);
                }
                current = new Run();
                current.start = address;
                current.firstMnemonic = instruction.getMnemonicString();
                current.prevInstruction = describePrev(address);
                current.firstBytes = firstBytes(address, 8);
                Function prev = getFunctionBefore(address);
                if (prev != null) {
                    current.prevFunction = prev.getEntryPoint().toString();
                    current.prevFunctionMax = prev.getBody().getMaxAddress().toString();
                }
                Function next = getFunctionAfter(address);
                if (next != null) {
                    current.nextFunction = next.getEntryPoint().toString();
                }
                collectRefs(current);
            }
            current.end = instruction.getMaxAddress();
            current.instructions++;
            current.lastMnemonic = instruction.getMnemonicString();
            if (instruction.getFlowType().isCall()) {
                if (isDirectAddressOperand(instruction)) {
                    current.hasDirectCall = true;
                }
                else {
                    current.hasIndirectCall = true;
                }
            }
            if (instruction.getFlowType().isJump()) {
                if (!isDirectAddressOperand(instruction)) {
                    current.hasIndirectJump = true;
                }
            }
            if (instruction.getMnemonicString().startsWith("RET")) {
                current.hasRet = true;
            }
            lastEnd = instruction.getMaxAddress();
        }
        if (current != null) {
            runs.add(current);
        }

        Map<String, Integer> categories = new LinkedHashMap<>();
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(new File(args[0])))) {
            writer.write("start\tend\tsize\tinstructions\tfirst_mnemonic\tlast_mnemonic\t" +
                "has_ret\thas_direct_call\thas_indirect_call\thas_indirect_jump\t" +
                "refs_call\trefs_jump\trefs_data\trefs_flow\tprev_function\t" +
                "prev_function_max\tnext_function\tfirst_bytes\tprev_instruction\tref_sources");
            writer.newLine();
            for (Run run : runs) {
                long size = run.end.subtract(run.start) + 1;
                String category;
                boolean insidePrev = !run.prevFunctionMax.isEmpty() &&
                    run.start.compareTo(toAddr(run.prevFunctionMax)) <= 0;
                if (insidePrev) {
                    category = "inside_prev_function_range";
                }
                else if (run.refsCall > 0) {
                    category = "call_referenced";
                }
                else if (run.refsData > 0) {
                    category = "data_referenced";
                }
                else if (run.refsJump > 0) {
                    category = "jump_referenced";
                }
                else {
                    category = "unreferenced";
                }
                categories.merge(category, 1, Integer::sum);
                writer.write(run.start + "\t" + run.end + "\t" + size + "\t" +
                    run.instructions + "\t" + tsv(run.firstMnemonic) + "\t" +
                    tsv(run.lastMnemonic) + "\t" + (run.hasRet ? 1 : 0) + "\t" +
                    (run.hasDirectCall ? 1 : 0) + "\t" +
                    (run.hasIndirectCall ? 1 : 0) + "\t" +
                    (run.hasIndirectJump ? 1 : 0) + "\t" + run.refsCall + "\t" +
                    run.refsJump + "\t" + run.refsData + "\t" + run.refsFlow + "\t" +
                    tsv(run.prevFunction) + "\t" + tsv(run.prevFunctionMax) + "\t" +
                    tsv(run.nextFunction) + "\t" + tsv(run.firstBytes) + "\t" +
                    tsv(run.prevInstruction) + "\t" + tsv(run.refSources));
                writer.newLine();
            }
        }
        println("Instructions: " + total + " undefined: " + undefined + " runs: " + runs.size());
        for (Map.Entry<String, Integer> e : categories.entrySet()) {
            println("  " + e.getKey() + ": " + e.getValue());
        }
        println("Wrote " + args[0]);
    }
}
