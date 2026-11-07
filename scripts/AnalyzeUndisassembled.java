// Ghidra headless script: inventory executable bytes that Ghidra never
// disassembled.  Function recovery based only on existing instructions misses
// these regions entirely (e.g. 0x100ed550 starts with a normal MSVC prologue but
// has no instruction at all).
//
// Usage: AnalyzeUndisassembled.java <output_tsv>
//
// Read-only.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
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
import java.util.List;

public class AnalyzeUndisassembled extends GhidraScript {

    private static class Gap {
        Address start;
        Address end;
        String bytes = "";
        String prevInstruction = "";
        String nextInstruction = "";
        int refs;
    }

    private static String tsv(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\t", " ").replace("\r", " ").replace("\n", " ");
    }

    private String bytes(Address start, long max) {
        Memory memory = currentProgram.getMemory();
        StringBuilder sb = new StringBuilder();
        for (long i = 0; i < max; i++) {
            Address a = start.add(i);
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

    private String describeBefore(Address address) {
        Instruction p = currentProgram.getListing().getInstructionBefore(address);
        return p == null ? "" : p.getAddress() + ": " + p.toString();
    }

    private String describeAfter(Address address) {
        Instruction n = currentProgram.getListing().getInstructionAfter(address);
        return n == null ? "" : n.getAddress() + ": " + n.toString();
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
            println("USAGE: AnalyzeUndisassembled.java <output_tsv>");
            return;
        }
        List<Gap> gaps = new ArrayList<>();
        long totalGapBytes = 0;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) {
                continue;
            }
            Address blockStart = block.getStart();
            Address blockEnd = block.getEnd();
            Address prevEnd = null;
            InstructionIterator it = currentProgram.getListing().getInstructions(
                new AddressSet(block.getAddressRange()), true);
            while (it.hasNext()) {
                monitor.checkCancelled();
                Instruction instruction = it.next();
                Address start = instruction.getAddress();
                if (prevEnd == null) {
                    if (start.compareTo(blockStart) > 0) {
                        addGap(gaps, blockStart, start.subtract(1), blockStart, start);
                    }
                }
                else if (start.compareTo(prevEnd.add(1)) > 0) {
                    addGap(gaps, prevEnd.add(1), start.subtract(1),
                        prevEnd.add(1), start);
                }
                prevEnd = instruction.getMaxAddress();
            }
            if (prevEnd == null) {
                addGap(gaps, blockStart, blockEnd, blockStart, null);
            }
            else if (prevEnd.compareTo(blockEnd) < 0) {
                addGap(gaps, prevEnd.add(1), blockEnd, prevEnd.add(1), null);
            }
        }
        for (Gap gap : gaps) {
            totalGapBytes += gap.end.subtract(gap.start) + 1;
        }
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(new File(args[0])))) {
            writer.write("start\tend\tsize\tbytes\tprev_instruction\tnext_instruction\trefs_to_start");
            writer.newLine();
            for (Gap gap : gaps) {
                long size = gap.end.subtract(gap.start) + 1;
                writer.write(gap.start + "\t" + gap.end + "\t" + size + "\t" +
                    tsv(gap.bytes) + "\t" + tsv(gap.prevInstruction) + "\t" +
                    tsv(gap.nextInstruction) + "\t" + gap.refs);
                writer.newLine();
            }
        }
        println("Disassembly gaps: " + gaps.size() + " bytes: " + totalGapBytes);
        println("Wrote " + args[0]);
    }

    private void addGap(List<Gap> gaps, Address start, Address end,
            Address bytesStart, Address nextStart) {
        if (start.compareTo(end) > 0) {
            return;
        }
        Gap gap = new Gap();
        gap.start = start;
        gap.end = end;
        gap.bytes = bytes(bytesStart, 24);
        gap.prevInstruction = describeBefore(start);
        gap.nextInstruction = nextStart == null ? "" : describeAfter(start);
        gap.refs = countRefs(start);
        gaps.add(gap);
    }
}
