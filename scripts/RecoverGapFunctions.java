// Ghidra headless script: recover function starts that the analyzer never defined.
//
// The Track 3 survey found 1,993 real .text addresses that carry names or vtable
// references but appear in neither function_index.txt nor the canonical export.
// 1,973 are MSVC SEH-prologue registration wrappers named in
// work/funcid_environment_variables.tsv; 20 are startup vtable handlers installed
// by the app_init registrar hub.  Ghidra never created functions at these
// addresses, so the canonical exporter could not emit them.
//
// Usage:
//   RecoverGapFunctions.java <address_tsv> <report_tsv> inspect
//   RecoverGapFunctions.java <address_tsv> <report_tsv> apply
//
// The address TSV must have a header and at least two columns: address and
// proposed name (empty allowed).  Only the first two columns are read.
//
// "inspect" is read-only and reports what Ghidra currently knows about each
// address.  "apply" disassembles flow from the entry, computes a body, clamps it
// to the next known function/gap boundary, and creates the function.  The whole
// apply pass is one transaction, committed only if every requested address was
// either created or already present.

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolUtilities;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class RecoverGapFunctions extends GhidraScript {

    private static class Entry {
        final Address address;
        final String proposedName;
        final String rawAddress;

        Entry(Address address, String proposedName, String rawAddress) {
            this.address = address;
            this.proposedName = proposedName;
            this.rawAddress = rawAddress;
        }
    }

    private static class Result {
        final Entry entry;
        String status = "";
        String functionEntry = "";
        long size = 0;
        String bodyRanges = "";
        String note = "";

        Result(Entry entry) {
            this.entry = entry;
        }
    }

    private static String tsv(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\t", " ").replace("\r", " ").replace("\n", " ");
    }

    private List<Entry> readEntries(File file) throws IOException {
        List<Entry> entries = new ArrayList<>();
        Set<Long> seen = new HashSet<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            boolean header = true;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                if (header) {
                    header = false;
                    if (line.toLowerCase().startsWith("address")) {
                        continue;
                    }
                }
                String[] fields = line.split("\t", -1);
                if (fields.length < 1 || fields[0].isBlank()) {
                    continue;
                }
                String raw = fields[0].trim();
                Address address = toAddr(raw);
                if (address == null) {
                    throw new IOException("invalid address: " + raw);
                }
                long key = address.getOffset();
                if (!seen.add(key)) {
                    throw new IOException("duplicate address: " + raw);
                }
                String name = fields.length > 1 ? fields[1].trim() : "";
                entries.add(new Entry(address, name, raw));
            }
        }
        entries.sort(Comparator.comparingLong(e -> e.address.getOffset()));
        return entries;
    }

    private AddressSet textSet() {
        AddressSet set = new AddressSet();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (block.isExecute() && block.isInitialized()) {
                set.add(block.getAddressRange());
            }
        }
        return set;
    }

    private Address nextFunctionEntry(Address after) {
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(after, true);
        while (it.hasNext()) {
            Function f = it.next();
            Address entry = f.getEntryPoint();
            if (entry.compareTo(after) > 0) {
                return entry;
            }
        }
        return null;
    }

    private Address nextGapEntry(Address after, List<Entry> entries) {
        int lo = 0;
        int hi = entries.size();
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (entries.get(mid).address.compareTo(after) <= 0) {
                lo = mid + 1;
            }
            else {
                hi = mid;
            }
        }
        return lo < entries.size() ? entries.get(lo).address : null;
    }

    private Address minAddress(Address a, Address b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        return a.compareTo(b) <= 0 ? a : b;
    }

    private String describe(AddressSetView set) {
        StringBuilder sb = new StringBuilder();
        for (AddressRange range : set) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(range.getMinAddress()).append('-').append(range.getMaxAddress());
        }
        return sb.toString();
    }

    private String uniqueName(String proposed, Address address) {
        if (proposed == null || proposed.isBlank() ||
                proposed.startsWith("FUN_") || proposed.startsWith("LAB_")) {
            return null;
        }
        proposed = SymbolUtilities.replaceInvalidChars(proposed, true).trim();
        if (proposed.isEmpty()) {
            return null;
        }
        SymbolTable table = currentProgram.getSymbolTable();
        String candidate = proposed;
        int suffix = 1;
        while (true) {
            SymbolIterator symbols = table.getSymbols(candidate);
            if (!symbols.hasNext()) {
                return candidate;
            }
            boolean onlySelf = true;
            while (symbols.hasNext()) {
                Symbol s = symbols.next();
                if (!s.getAddress().equals(address)) {
                    onlySelf = false;
                    break;
                }
            }
            if (onlySelf) {
                return candidate;
            }
            candidate = proposed + "_" + address.toString().substring(2);
            suffix++;
            if (suffix > 8) {
                return candidate;
            }
        }
    }

    private Result inspect(Entry entry, List<Entry> entries, AddressSet text) {
        Result result = new Result(entry);
        Function at = getFunctionAt(entry.address);
        Function containing = getFunctionContaining(entry.address);
        Instruction instruction = currentProgram.getListing().getInstructionAt(entry.address);
        result.functionEntry = at == null ? "" : at.getEntryPoint().toString();
        if (at != null) {
            result.status = "function_exists";
            result.size = at.getBody().getNumAddresses();
            result.bodyRanges = describe(at.getBody());
            return result;
        }
        if (containing != null) {
            result.status = "inside_function";
            result.functionEntry = containing.getEntryPoint().toString();
            result.note = "body=" + describe(containing.getBody());
            return result;
        }
        if (!text.contains(entry.address)) {
            result.status = "not_in_executable_block";
            return result;
        }
        result.status = instruction == null ? "no_instruction" : "undefined_code";
        Address nextFn = nextFunctionEntry(entry.address);
        Address nextGap = nextGapEntry(entry.address, entries);
        Address bound = minAddress(nextFn, nextGap);
        result.note = "next_fn=" + (nextFn == null ? "" : nextFn.toString()) +
            " next_gap=" + (nextGap == null ? "" : nextGap.toString()) +
            " mnemonic=" + (instruction == null ? "" : instruction.getMnemonicString());
        if (instruction != null) {
            AddressSetView candidate = CreateFunctionCmd.getFunctionBody(
                currentProgram, entry.address, monitor);
            if (candidate != null) {
                AddressSet range = new AddressSet(entry.address, bound == null ?
                    entry.address.getAddressSpace().getMaxAddress() : bound.subtract(1));
                AddressSet clipped = new AddressSet(candidate);
                clipped = clipped.intersect(range);
                result.size = clipped.getNumAddresses();
                result.bodyRanges = describe(clipped);
            }
        }
        return result;
    }

    private Result apply(Entry entry, List<Entry> entries, AddressSet text,
            Map<Long, Result> priorResults) {
        Result existing = priorResults.get(entry.address.getOffset());
        if (existing != null && "created".equals(existing.status)) {
            Result result = new Result(entry);
            result.status = "already_created_this_run";
            result.functionEntry = entry.address.toString();
            return result;
        }
        Function at = getFunctionAt(entry.address);
        if (at != null) {
            Result result = new Result(entry);
            result.status = "function_exists";
            result.functionEntry = at.getEntryPoint().toString();
            result.size = at.getBody().getNumAddresses();
            result.bodyRanges = describe(at.getBody());
            return result;
        }
        Function containing = getFunctionContaining(entry.address);
        if (containing != null) {
            Result result = new Result(entry);
            result.status = "inside_function";
            result.functionEntry = containing.getEntryPoint().toString();
            result.note = "body=" + describe(containing.getBody());
            return result;
        }
        Result result = new Result(entry);
        if (!text.contains(entry.address)) {
            result.status = "not_in_executable_block";
            return result;
        }
        Instruction instruction = currentProgram.getListing().getInstructionAt(entry.address);
        if (instruction == null) {
            DisassembleCommand disassemble = new DisassembleCommand(
                entry.address, text, true);
            disassemble.applyTo(currentProgram, monitor);
            instruction = currentProgram.getListing().getInstructionAt(entry.address);
        }
        if (instruction == null) {
            result.status = "disassembly_failed";
            return result;
        }
        Address nextFn = nextFunctionEntry(entry.address);
        Address nextGap = nextGapEntry(entry.address, entries);
        Address bound = minAddress(nextFn, nextGap);
        AddressSet range = new AddressSet(entry.address, bound == null ?
            entry.address.getAddressSpace().getMaxAddress() : bound.subtract(1));
        AddressSetView candidate = CreateFunctionCmd.getFunctionBody(
            currentProgram, entry.address, monitor);
        if (candidate == null || candidate.isEmpty()) {
            result.status = "empty_body";
            result.note = "next_fn=" + (nextFn == null ? "" : nextFn.toString()) +
                " next_gap=" + (nextGap == null ? "" : nextGap.toString());
            return result;
        }
        AddressSet body = new AddressSet(candidate);
        body = body.intersect(range);
        if (body.isEmpty()) {
            result.status = "empty_body_after_clip";
            result.note = "candidate=" + describe(candidate) +
                " bound=" + (bound == null ? "" : bound.toString());
            return result;
        }
        String name = uniqueName(entry.proposedName, entry.address);
        CreateFunctionCmd create = new CreateFunctionCmd(
            name, entry.address, body, SourceType.USER_DEFINED);
        boolean ok = create.applyTo(currentProgram, monitor);
        if (!ok) {
            result.status = "create_failed";
            result.note = create.getStatusMsg();
            return result;
        }
        Function function = create.getFunction();
        if (function == null) {
            function = getFunctionAt(entry.address);
        }
        if (function == null) {
            result.status = "create_returned_null";
            return result;
        }
        result.status = "created";
        result.functionEntry = function.getEntryPoint().toString();
        result.size = function.getBody().getNumAddresses();
        result.bodyRanges = describe(function.getBody());
        result.note = "clipped=" + (body.getNumAddresses() != candidate.getNumAddresses());
        return result;
    }

    private void writeReport(File file, List<Result> results) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write("address\tproposed_name\tstatus\tfunction_entry\tsize\tbody_ranges\tnote");
            writer.newLine();
            for (Result r : results) {
                writer.write(tsv(r.entry.rawAddress) + "\t" +
                    tsv(r.entry.proposedName) + "\t" +
                    tsv(r.status) + "\t" +
                    tsv(r.functionEntry) + "\t" +
                    r.size + "\t" +
                    tsv(r.bodyRanges) + "\t" +
                    tsv(r.note));
                writer.newLine();
            }
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            println("USAGE: RecoverGapFunctions.java <address_tsv> <report_tsv> inspect|apply");
            return;
        }
        File addressFile = new File(args[0]);
        File reportFile = new File(args[1]);
        String mode = args[2].toLowerCase();
        if (!mode.equals("inspect") && !mode.equals("apply") &&
                !mode.equals("apply-partial")) {
            throw new IllegalArgumentException(
                "mode must be inspect, apply, or apply-partial");
        }
        List<Entry> entries = readEntries(addressFile);
        println("Gap recovery: entries=" + entries.size() + " mode=" + mode);
        println("Program function count: " +
            currentProgram.getFunctionManager().getFunctionCount());
        AddressSet text = textSet();
        println("Executable blocks: " + describe(text));
        List<Result> results = new ArrayList<>();
        Map<Long, Result> prior = new HashMap<>();
        if (mode.equals("inspect")) {
            for (Entry entry : entries) {
                monitor.checkCancelled();
                results.add(inspect(entry, entries, text));
            }
            writeReport(reportFile, results);
            printSummary(results);
            return;
        }
        int transaction = currentProgram.startTransaction("Recover gap functions");
        boolean partial = mode.equals("apply-partial");
        boolean commit = false;
        try {
            for (Entry entry : entries) {
                monitor.checkCancelled();
                Result result = apply(entry, entries, text, prior);
                prior.put(entry.address.getOffset(), result);
                results.add(result);
            }
            writeReport(reportFile, results);
            int created = count(results, "created");
            int already = count(results, "function_exists") +
                count(results, "already_created_this_run");
            int bad = results.size() - created - already;
            println("Gap recovery result: created=" + created + " existing=" + already +
                " unresolved=" + bad);
            commit = bad == 0 || (partial && created > 0);
            if (!commit) {
                println("Transaction rolled back because " + bad +
                    " addresses did not resolve to a function.");
            }
        }
        finally {
            currentProgram.endTransaction(transaction, commit);
        }
        printSummary(results);
    }

    private int count(List<Result> results, String status) {
        int n = 0;
        for (Result r : results) {
            if (status.equals(r.status)) {
                n++;
            }
        }
        return n;
    }

    private void printSummary(List<Result> results) {
        Map<String, Integer> counts = new HashMap<>();
        for (Result r : results) {
            counts.merge(r.status, 1, Integer::sum);
        }
        List<String> keys = new ArrayList<>(counts.keySet());
        Collections.sort(keys);
        for (String key : keys) {
            println("  " + key + ": " + counts.get(key));
        }
    }
}
