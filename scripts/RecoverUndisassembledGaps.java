// Ghidra headless script: recover functions in executable bytes that were never
// disassembled.  The existing-instruction inventory cannot see these regions.
//
// The script is deliberately conservative: it only attempts gaps whose first
// bytes match a real MSVC/x86 function prologue (or a strong table/ref-backed
// pattern), disassembles flow within the gap, and creates a function only when
// the decoded body stays inside the gap and ends in RET/JMP.
//
// Usage:
//   RecoverUndisassembledGaps.java <gaps_tsv> <report_tsv> inspect
//   RecoverUndisassembledGaps.java <gaps_tsv> <report_tsv> apply
//
// Read-only in inspect mode (transaction rolled back).

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.SourceType;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class RecoverUndisassembledGaps extends GhidraScript {

    private static class Gap {
        Address start;
        Address end;
        long size;
        String bytes;
        String prevInstruction;
        int refs;
        String status = "";
        long bodySize = 0;
        String bodyRanges = "";
        String note = "";
    }

    private static String tsv(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\t", " ").replace("\r", " ").replace("\n", " ");
    }

    private static boolean startsWithAny(String value, String... prefixes) {
        for (String prefix : prefixes) {
            if (value.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private boolean isStrong(String bytes) {
        return startsWithAny(bytes,
            "83 ec", "81 ec", "55 8b ec", "55 89 e5", "8b ff 55",
            "6a ff e8", "e9 ", "ff 25", "8b 44 24", "8b 41", "8b 0d",
            "8b 15", "a1 ", "b8 ", "c7 05");
    }

    private boolean isWeak(String bytes) {
        return startsWithAny(bytes, "51 ", "53 ", "56 ", "57 ", "68 ", "6a ");
    }

    private boolean prevIsTerminator(String prev) {
        if (prev == null || prev.isBlank()) {
            return true;
        }
        String upper = prev.toUpperCase();
        return upper.contains(": RET") || upper.contains(": JMP") ||
            upper.contains(": INT3");
    }

    private List<Gap> readGaps(File file) throws IOException {
        List<Gap> gaps = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            boolean header = true;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                if (header) {
                    header = false;
                    if (line.toLowerCase().startsWith("start")) {
                        continue;
                    }
                }
                String[] f = line.split("\t", -1);
                if (f.length < 7) {
                    continue;
                }
                Gap gap = new Gap();
                gap.start = toAddr(f[0].trim());
                gap.end = toAddr(f[1].trim());
                gap.size = Long.parseLong(f[2].trim());
                gap.bytes = f[3];
                gap.prevInstruction = f[4];
                gap.refs = Integer.parseInt(f[6].trim());
                if (gap.start != null && gap.end != null) {
                    gaps.add(gap);
                }
            }
        }
        gaps.sort(Comparator.comparingLong(g -> g.start.getOffset()));
        return gaps;
    }

    private String describe(AddressSetView set) {
        StringBuilder sb = new StringBuilder();
        for (ghidra.program.model.address.AddressRange range : set) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(range.getMinAddress()).append('-').append(range.getMaxAddress());
        }
        return sb.toString();
    }

    private Gap process(Gap gap, boolean apply) {
        if (gap.size < 5) {
            gap.status = "too_small";
            return gap;
        }
        if (gap.bytes.startsWith("cc")) {
            gap.status = "padding";
            return gap;
        }
        boolean strong = isStrong(gap.bytes);
        boolean weak = isWeak(gap.bytes) && gap.refs > 0 &&
            prevIsTerminator(gap.prevInstruction);
        if (!strong && !weak) {
            gap.status = "not_code_like";
            return gap;
        }
        boolean prevJump = gap.prevInstruction != null &&
            gap.prevInstruction.toUpperCase().contains(": JMP");
        boolean controlPrologue = startsWithAny(gap.bytes,
            "83 ec", "81 ec", "55 8b ec", "55 89 e5", "8b ff 55",
            "6a ff e8");
        boolean jumpThunk = startsWithAny(gap.bytes, "e9 ", "ff 25");
        if (prevJump && !controlPrologue && !jumpThunk) {
            gap.status = "prev_jump_not_prologue";
            return gap;
        }
        if (getFunctionContaining(gap.start) != null) {
            gap.status = "already_in_function";
            return gap;
        }
        AddressSet gapSet = new AddressSet(gap.start, gap.end);
        Instruction existing = currentProgram.getListing().getInstructionAt(gap.start);
        if (existing == null) {
            DisassembleCommand disassemble = new DisassembleCommand(
                gap.start, gapSet, true);
            disassemble.applyTo(currentProgram, monitor);
        }
        Instruction first = currentProgram.getListing().getInstructionAt(gap.start);
        if (first == null) {
            gap.status = "disassembly_failed";
            return gap;
        }
        AddressSetView candidate = CreateFunctionCmd.getFunctionBody(
            currentProgram, gap.start, monitor);
        if (candidate == null || candidate.isEmpty()) {
            gap.status = "empty_body";
            return gap;
        }
        AddressSet body = new AddressSet(candidate).intersect(gapSet);
        if (body.isEmpty()) {
            gap.status = "empty_body_after_clip";
            return gap;
        }
        if (body.getMaxAddress().compareTo(gap.end) > 0) {
            gap.status = "body_outside_gap";
            return gap;
        }
        Instruction last = null;
        int count = 0;
        InstructionIterator it = currentProgram.getListing().getInstructions(body, true);
        while (it.hasNext()) {
            last = it.next();
            count++;
        }
        if (last == null || count < 2) {
            gap.status = "too_few_instructions";
            return gap;
        }
        String mnemonic = last.getMnemonicString().toUpperCase();
        if (!mnemonic.startsWith("RET") && !mnemonic.startsWith("JMP")) {
            gap.status = "no_terminal";
            gap.note = "last=" + last;
            return gap;
        }
        if (body.getNumAddresses() < 5) {
            gap.status = "body_too_small";
            return gap;
        }
        if (apply) {
            CreateFunctionCmd create = new CreateFunctionCmd(
                null, gap.start, body, SourceType.USER_DEFINED);
            if (!create.applyTo(currentProgram, monitor)) {
                gap.status = "create_failed";
                gap.note = create.getStatusMsg();
                return gap;
            }
            Function function = create.getFunction();
            if (function == null) {
                function = getFunctionAt(gap.start);
            }
            if (function == null) {
                gap.status = "create_returned_null";
                return gap;
            }
            gap.status = "created";
            gap.bodySize = function.getBody().getNumAddresses();
            gap.bodyRanges = describe(function.getBody());
        }
        else {
            gap.status = "would_create";
            gap.bodySize = body.getNumAddresses();
            gap.bodyRanges = describe(body);
        }
        return gap;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            println("USAGE: RecoverUndisassembledGaps.java <gaps_tsv> <report_tsv> inspect|apply");
            return;
        }
        List<Gap> gaps = readGaps(new File(args[0]));
        boolean apply = args[2].equalsIgnoreCase("apply");
        println("Undisassembled gap recovery: entries=" + gaps.size() +
            " mode=" + (apply ? "apply" : "inspect"));
        int transaction = currentProgram.startTransaction("Recover undisassembled gaps");
        boolean commit = false;
        try {
            for (Gap gap : gaps) {
                monitor.checkCancelled();
                process(gap, apply);
            }
            if (apply) {
                int created = 0;
                for (Gap gap : gaps) {
                    if ("created".equals(gap.status)) {
                        created++;
                    }
                }
                commit = created > 0;
                println("Created " + created + " functions.");
            }
            writeReport(new File(args[1]), gaps);
        }
        finally {
            currentProgram.endTransaction(transaction, commit);
        }
        printSummary(gaps);
    }

    private void writeReport(File file, List<Gap> gaps) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write("start\tend\tsize\tstatus\tbody_size\tbody_ranges\tbytes\tprev_instruction\tnote");
            writer.newLine();
            for (Gap gap : gaps) {
                writer.write(gap.start + "\t" + gap.end + "\t" + gap.size + "\t" +
                    gap.status + "\t" + gap.bodySize + "\t" + tsv(gap.bodyRanges) +
                    "\t" + tsv(gap.bytes) + "\t" + tsv(gap.prevInstruction) + "\t" +
                    tsv(gap.note));
                writer.newLine();
            }
        }
    }

    private void printSummary(List<Gap> gaps) {
        java.util.Map<String, Integer> counts = new java.util.TreeMap<>();
        for (Gap gap : gaps) {
            counts.merge(gap.status, 1, Integer::sum);
        }
        for (java.util.Map.Entry<String, Integer> e : counts.entrySet()) {
            println("  " + e.getKey() + ": " + e.getValue());
        }
    }
}
