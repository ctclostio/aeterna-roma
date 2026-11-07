// Ghidra headless script: inventory executable code that is not in any function.
//
// The canonical export can only contain functions Ghidra defined.  After the
// 1,993 documented gap addresses were recovered, indirect-call enumeration still
// found thousands of call sites with no containing function.  This script maps
// those undefined instruction runs and proposes entry points so the recovery
// pass can be extended beyond the named-address list.
//
// Usage: AnalyzeUndefinedCode.java <output_tsv>
//
// Read-only.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
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

public class AnalyzeUndefinedCode extends GhidraScript {

    private static class Run {
        Address start;
        Address end;
        int instructions;
        String firstMnemonic = "";
        String lastMnemonic = "";
        boolean hasIndirectCall;
        boolean hasDirectCall;
        boolean hasRet;
        String prevInstruction = "";
        int refsToStart;
    }

    private static String tsv(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\t", " ").replace("\r", " ").replace("\n", " ");
    }

    private String describePrev(Address address) {
        Instruction p = currentProgram.getListing().getInstructionBefore(address);
        if (p == null) {
            return "";
        }
        return p.getAddress() + ": " + p.toString();
    }

    private int countRefs(Address address) {
        int n = 0;
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(address);
        while (it.hasNext()) {
            Reference ref = it.next();
            n++;
        }
        return n;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            println("USAGE: AnalyzeUndefinedCode.java <output_tsv>");
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
            boolean inFunction = getFunctionContaining(address) != null;
            if (inFunction) {
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
                current.refsToStart = countRefs(address);
            }
            current.end = instruction.getMaxAddress();
            current.instructions++;
            current.lastMnemonic = instruction.getMnemonicString();
            if (instruction.getFlowType().isCall()) {
                if (instruction.getFlowType().isComputed() ||
                        instruction.getOpObjects(0).length == 0) {
                    current.hasIndirectCall = true;
                }
                else {
                    current.hasDirectCall = true;
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

        Map<String, Integer> sizeBuckets = new LinkedHashMap<>();
        int withIndirect = 0;
        int withRet = 0;
        int startReferenced = 0;
        int totalRunBytes = 0;
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(new File(args[0])))) {
            writer.write("start\tend\tinstructions\tfirst_mnemonic\tlast_mnemonic\thas_indirect_call\thas_direct_call\thas_ret\trefs_to_start\tprev_instruction");
            writer.newLine();
            for (Run run : runs) {
                long size = run.end.subtract(run.start) + 1;
                totalRunBytes += size;
                String bucket;
                if (size <= 16) {
                    bucket = "<=16";
                }
                else if (size <= 64) {
                    bucket = "17-64";
                }
                else if (size <= 256) {
                    bucket = "65-256";
                }
                else if (size <= 1024) {
                    bucket = "257-1024";
                }
                else {
                    bucket = ">1024";
                }
                sizeBuckets.merge(bucket, 1, Integer::sum);
                if (run.hasIndirectCall) {
                    withIndirect++;
                }
                if (run.hasRet) {
                    withRet++;
                }
                if (run.refsToStart > 0) {
                    startReferenced++;
                }
                writer.write(run.start + "\t" + run.end + "\t" + run.instructions + "\t" +
                    tsv(run.firstMnemonic) + "\t" + tsv(run.lastMnemonic) + "\t" +
                    (run.hasIndirectCall ? 1 : 0) + "\t" +
                    (run.hasDirectCall ? 1 : 0) + "\t" +
                    (run.hasRet ? 1 : 0) + "\t" + run.refsToStart + "\t" +
                    tsv(run.prevInstruction));
                writer.newLine();
            }
        }
        println("Instructions: " + total + " undefined: " + undefined +
            " runs: " + runs.size() + " run_bytes: " + totalRunBytes);
        println("Runs with indirect call: " + withIndirect +
            " with RET: " + withRet + " with referenced start: " + startReferenced);
        for (Map.Entry<String, Integer> e : sizeBuckets.entrySet()) {
            println("  size " + e.getKey() + ": " + e.getValue());
        }
        println("Wrote " + args[0]);
    }
}
