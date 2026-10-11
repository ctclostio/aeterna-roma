// Ghidra headless post-script: export decompiled C with stable address-based symbols.
//
// The regular export intentionally preserves recovered names.  That is useful for
// analysis, but it is not a sound compilation identity: C++ overloads share short
// names and qualified names appear differently in definitions and call sites.
// This exporter temporarily gives every internal function and addressable global a
// unique name while the decompiler runs.  The symbol transaction is always rolled
// back, so the analyzed project keeps its recovered names.
//
// Output layout:
//   <outRoot>/<binaryName>/canonical_decomp/decomp_fn_<entry>.c
//   <outRoot>/<binaryName>/canonical_function_index.tsv
//   <outRoot>/<binaryName>/canonical_data_index.tsv

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public class ExportCanonicalDecompiled extends GhidraScript {

    private static final String FORMAT_MARKER = "canonical-address-v2";
    private static final int DEFAULT_TIMEOUT_SECONDS = 90;
    private static final int DEFAULT_RETRY_TIMEOUT_SECONDS = 600;
    private static final int RETRY_MAX_PAYLOAD_MBYTES = 512;

    private static class FunctionMeta {
        final Function function;
        final Address address;
        final String entry;
        final String canonicalName;
        final String scratchName;
        final String originalName;
        final String originalQualifiedName;
        final String originalSignature;
        final long symbolId;
        final long namespaceId;
        final String sourceType;
        final boolean thunk;
        final String directThunkTarget;
        final String resolvedThunkTarget;
        final long size;
        final String bodyRanges;

        FunctionMeta(Function function, AddressSpace defaultSpace) {
            this.function = function;
            this.address = function.getEntryPoint();
            this.entry = address.toString();
            String identity = canonicalAddress(address, defaultSpace);
            this.canonicalName = "decomp_fn_" + identity;
            this.scratchName = "__decomp_tmp_fn_" + identity;
            this.originalName = function.getName();
            this.originalQualifiedName = function.getName(true);
            this.originalSignature = function.getSignature(false).toString();
            this.symbolId = function.getSymbol().getID();
            this.namespaceId = function.getParentNamespace().getID();
            this.sourceType = function.getSymbol().getSource().toString();
            this.thunk = function.isThunk();
            this.directThunkTarget = describeFunction(function.getThunkedFunction(false));
            this.resolvedThunkTarget = describeFunction(function.getThunkedFunction(true));
            this.size = function.getBody().getNumAddresses();
            this.bodyRanges = describeBody(function);
        }
    }

    private static class DataMeta {
        final Symbol symbol;
        final String address;
        final String canonicalName;
        final String scratchName;
        final String originalName;
        final String originalQualifiedName;
        final String symbolType;
        final long symbolId;
        final long namespaceId;
        final String sourceType;
        final String dataTypePath;
        final int dataTypeLength;
        final int codeUnitLength;

        DataMeta(Symbol symbol, AddressSpace defaultSpace, Data definedData) {
            this.symbol = symbol;
            this.address = symbol.getAddress().toString();
            String identity = canonicalAddress(symbol.getAddress(), defaultSpace);
            this.canonicalName = "decomp_g_" + identity;
            this.scratchName = "__decomp_tmp_g_" + identity;
            this.originalName = symbol.getName();
            this.originalQualifiedName = symbol.getName(true);
            this.symbolType = symbol.getSymbolType().toString();
            this.symbolId = symbol.getID();
            this.namespaceId = symbol.getParentNamespace().getID();
            this.sourceType = symbol.getSource().toString();
            this.dataTypePath = definedData == null ? "" :
                definedData.getDataType().getPathName();
            this.dataTypeLength = definedData == null ? 0 :
                definedData.getDataType().getLength();
            this.codeUnitLength = definedData == null ? 0 : definedData.getLength();
        }
    }

    private static String describeBody(Function function) {
        StringBuilder result = new StringBuilder();
        AddressRangeIterator ranges = function.getBody().getAddressRanges(true);
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            if (result.length() != 0) {
                result.append(',');
            }
            result.append(range.getMinAddress()).append('-').append(range.getMaxAddress());
        }
        return result.toString();
    }

    private static String describeFunction(Function function) {
        if (function == null) {
            return "";
        }
        return (function.isExternal() ? "external:" : "internal:") +
            function.getEntryPoint() + ":" + function.getName(true);
    }

    private static String canonicalAddress(Address address, AddressSpace defaultSpace) {
        AddressSpace space = address.getAddressSpace();
        String offset = Long.toUnsignedString(address.getOffset(), 16).toLowerCase(Locale.ROOT);
        int digits = Math.max(1, (space.getSize() + 3) / 4);
        if (offset.length() < digits) {
            offset = "0".repeat(digits - offset.length()) + offset;
        }
        if (space.equals(defaultSpace)) {
            return offset;
        }
        String spaceName = space.getName().toLowerCase(Locale.ROOT)
            .replaceAll("[^a-z0-9_]", "_");
        return spaceName + "_" + offset;
    }

    private static String tsv(String value) {
        if (value == null) {
            return "";
        }
        return value.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ');
    }

    private static boolean isCompleteCanonicalFile(
            File file, String expectedName, String expectedFingerprint) {
        if (!file.isFile() || file.length() == 0) {
            return false;
        }
        boolean hasMarker = false;
        boolean hasName = false;
        boolean hasFingerprint = false;
        String lastLine = null;
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lastLine = line;
                hasMarker |= line.contains(FORMAT_MARKER);
                hasName |= line.equals("// Canonical function: " + expectedName);
                hasFingerprint |= line.equals("// Mapping fingerprint: " + expectedFingerprint);
            }
        }
        catch (IOException error) {
            return false;
        }
        String expectedEof = "// Canonical export EOF: success " + expectedName + " " +
            expectedFingerprint;
        return hasMarker && hasName && hasFingerprint && expectedEof.equals(lastLine);
    }

    private static boolean timedOut(DecompileResults results) {
        return results != null && !results.decompileCompleted() && results.isTimedOut();
    }

    private DecompInterface openConfiguredDecompiler(DecompileOptions options) {
        DecompInterface candidate = new DecompInterface();
        try {
            candidate.setOptions(options);
            if (!candidate.openProgram(currentProgram)) {
                throw new IllegalStateException("failed to open program in decompiler");
            }
            candidate.flushCache();
            return candidate;
        }
        catch (RuntimeException error) {
            candidate.dispose();
            throw error;
        }
    }

    private static void replaceAtomically(File destination, List<String> lines) throws IOException {
        File parent = destination.getParentFile();
        parent.mkdirs();
        Path temporary = Files.createTempFile(
            parent.toPath(), destination.getName() + ".", ".tmp");
        try {
            try (BufferedWriter writer = Files.newBufferedWriter(temporary, StandardCharsets.UTF_8)) {
                for (String line : lines) {
                    writer.write(line);
                    writer.newLine();
                }
            }
            Path destinationPath = destination.toPath();
            try {
                Files.move(temporary, destinationPath, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
            }
            catch (IOException atomicMoveError) {
                Files.move(temporary, destinationPath, StandardCopyOption.REPLACE_EXISTING);
            }
        }
        finally {
            Files.deleteIfExists(temporary);
        }
    }

    private List<FunctionMeta> collectFunctions() throws Exception {
        List<FunctionMeta> result = new ArrayList<>();
        AddressSpace defaultSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Function function = iterator.next();
            if (!function.isExternal()) {
                result.add(new FunctionMeta(function, defaultSpace));
            }
        }
        return result;
    }

    private List<DataMeta> collectAddressableData() throws Exception {
        List<DataMeta> result = new ArrayList<>();
        AddressSpace defaultSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
        FunctionManager functionManager = currentProgram.getFunctionManager();
        SymbolIterator iterator = currentProgram.getSymbolTable().getPrimarySymbolIterator(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Symbol symbol = iterator.next();
            SymbolType type = symbol.getSymbolType();
            if (symbol.isExternal() || symbol.isDynamic() || !symbol.getAddress().isMemoryAddress()) {
                continue;
            }
            if (type != SymbolType.LABEL && type != SymbolType.GLOBAL_VAR) {
                continue;
            }
            // Labels inside a function are control-flow/local identities, not globals.
            if (functionManager.getFunctionContaining(symbol.getAddress()) != null) {
                continue;
            }
            Data definedData = currentProgram.getListing().getDefinedDataAt(symbol.getAddress());
            result.add(new DataMeta(symbol, defaultSpace, definedData));
        }
        result.sort(Comparator.comparing((DataMeta meta) -> meta.symbol.getAddress())
            .thenComparingLong(meta -> meta.symbolId));
        return result;
    }

    private void verifyNoCanonicalCollisions(List<FunctionMeta> functions, List<DataMeta> data)
            throws Exception {
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        Set<String> planned = new HashSet<>();
        Set<Long> renamedSymbolIds = new HashSet<>();
        for (FunctionMeta meta : functions) {
            renamedSymbolIds.add(meta.symbolId);
        }
        for (DataMeta meta : data) {
            renamedSymbolIds.add(meta.symbolId);
        }
        for (FunctionMeta meta : functions) {
            verifyPlannedName(symbolTable, planned, renamedSymbolIds, meta.canonicalName, true);
            verifyPlannedName(symbolTable, planned, renamedSymbolIds, meta.scratchName, false);
        }
        for (DataMeta meta : data) {
            verifyPlannedName(symbolTable, planned, renamedSymbolIds, meta.canonicalName, true);
            verifyPlannedName(symbolTable, planned, renamedSymbolIds, meta.scratchName, false);
        }
    }

    private static void verifyPlannedName(SymbolTable symbolTable, Set<String> planned,
            Set<Long> renamedSymbolIds, String name, boolean allowRenameSetOccupant) {
        if (!planned.add(name)) {
            throw new IllegalStateException("duplicate planned name: " + name);
        }
        for (Symbol existing : symbolTable.getGlobalSymbols(name)) {
            if (!allowRenameSetOccupant || !renamedSymbolIds.contains(existing.getID())) {
                throw new IllegalStateException("planned name already exists outside rename set: " +
                    name + " (symbol id " + existing.getID() + ")");
            }
        }
    }

    private static void digestField(MessageDigest digest, String field) {
        digest.update(field.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) 0);
    }

    private static String snapshotFingerprint(String executableSha256,
            List<FunctionMeta> functions, List<DataMeta> data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digestField(digest, FORMAT_MARKER);
        digestField(digest, executableSha256 == null ? "" : executableSha256);
        for (FunctionMeta meta : functions) {
            digestField(digest, "F");
            digestField(digest, meta.entry);
            digestField(digest, meta.canonicalName);
            digestField(digest, Long.toString(meta.symbolId));
            digestField(digest, Long.toString(meta.namespaceId));
            digestField(digest, meta.sourceType);
            digestField(digest, meta.originalName);
            digestField(digest, meta.originalQualifiedName);
            digestField(digest, meta.originalSignature);
            digestField(digest, meta.directThunkTarget);
            digestField(digest, meta.resolvedThunkTarget);
            digestField(digest, Long.toString(meta.size));
            digestField(digest, meta.bodyRanges);
        }
        for (DataMeta meta : data) {
            digestField(digest, "D");
            digestField(digest, meta.address);
            digestField(digest, meta.canonicalName);
            digestField(digest, Long.toString(meta.symbolId));
            digestField(digest, Long.toString(meta.namespaceId));
            digestField(digest, meta.sourceType);
            digestField(digest, meta.originalName);
            digestField(digest, meta.originalQualifiedName);
            digestField(digest, meta.symbolType);
            digestField(digest, meta.dataTypePath);
            digestField(digest, Integer.toString(meta.dataTypeLength));
            digestField(digest, Integer.toString(meta.codeUnitLength));
        }
        StringBuilder result = new StringBuilder();
        for (byte value : digest.digest()) {
            result.append(String.format("%02x", value & 0xff));
        }
        return result.toString();
    }

    private static void writeFunctionIndex(File file, List<FunctionMeta> functions)
            throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add("entry\tcanonical_name\toriginal_name\toriginal_qualified_name\t" +
            "symbol_id\tnamespace_id\tsource_type\tsignature\tsize\tkind\t" +
            "body_ranges\tdirect_thunk_target\tresolved_thunk_target");
        for (FunctionMeta meta : functions) {
            lines.add(meta.entry + "\t" + meta.canonicalName + "\t" +
                tsv(meta.originalName) + "\t" + tsv(meta.originalQualifiedName) + "\t" +
                meta.symbolId + "\t" + meta.namespaceId + "\t" + meta.sourceType + "\t" +
                tsv(meta.originalSignature) + "\t" + meta.size + "\t" +
                (meta.thunk ? "thunk" : "func") + "\t" + tsv(meta.bodyRanges) + "\t" +
                tsv(meta.directThunkTarget) + "\t" + tsv(meta.resolvedThunkTarget));
        }
        replaceAtomically(file, lines);
    }

    private static void writeDataIndex(File file, List<DataMeta> data) throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add("address\tcanonical_name\toriginal_name\toriginal_qualified_name\t" +
            "symbol_id\tnamespace_id\tsource_type\tsymbol_type\tdata_type_path\t" +
            "data_type_length\tcode_unit_length");
        for (DataMeta meta : data) {
            lines.add(meta.address + "\t" + meta.canonicalName + "\t" +
                tsv(meta.originalName) + "\t" + tsv(meta.originalQualifiedName) + "\t" +
                meta.symbolId + "\t" + meta.namespaceId + "\t" + meta.sourceType + "\t" +
                tsv(meta.symbolType) + "\t" + tsv(meta.dataTypePath) + "\t" +
                meta.dataTypeLength + "\t" + meta.codeUnitLength);
        }
        replaceAtomically(file, lines);
    }

    private static void validateCanonicalState(Namespace global,
            List<FunctionMeta> functions, List<DataMeta> data) {
        for (FunctionMeta meta : functions) {
            if (!meta.canonicalName.equals(meta.function.getName()) ||
                    !global.equals(meta.function.getParentNamespace())) {
                throw new IllegalStateException("function canonicalization mismatch at 0x" +
                    meta.entry + ": " + meta.function.getName(true));
            }
        }
        for (DataMeta meta : data) {
            if (!meta.canonicalName.equals(meta.symbol.getName()) ||
                    !global.equals(meta.symbol.getParentNamespace())) {
                throw new IllegalStateException("data canonicalization mismatch at 0x" +
                    meta.address + ": " + meta.symbol.getName(true));
            }
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("USAGE: ExportCanonicalDecompiled.java <output_root> " +
                "[batchStart batchEnd [timeoutSeconds retryTimeoutSeconds]]");
            return;
        }

        File outRoot = new File(args[0]);
        int batchStart = 0;
        int batchEnd = Integer.MAX_VALUE;
        int timeoutSeconds = DEFAULT_TIMEOUT_SECONDS;
        int retryTimeoutSeconds = DEFAULT_RETRY_TIMEOUT_SECONDS;
        if (args.length >= 3) {
            batchStart = Integer.parseInt(args[1]);
            batchEnd = Integer.parseInt(args[2]);
        }
        if (args.length >= 5) {
            timeoutSeconds = Integer.parseInt(args[3]);
            retryTimeoutSeconds = Integer.parseInt(args[4]);
        }
        if (args.length != 1 && args.length != 3 && args.length != 5) {
            throw new IllegalArgumentException(
                "expected output root plus zero, two, or four optional arguments");
        }
        if (batchStart < 0 || batchEnd < batchStart) {
            throw new IllegalArgumentException("invalid batch range");
        }
        if (timeoutSeconds <= 0 || retryTimeoutSeconds <= 0) {
            throw new IllegalArgumentException("decompiler timeouts must be positive seconds");
        }

        String binaryName = currentProgram.getName().replaceAll("[^A-Za-z0-9._-]", "_");
        File binaryOut = new File(outRoot, binaryName);
        File decompOut = new File(binaryOut, "canonical_decomp");
        File statusFile = new File(binaryOut, "canonical_export_status.tsv");
        decompOut.mkdirs();

        List<FunctionMeta> functions = collectFunctions();
        List<DataMeta> data = collectAddressableData();
        String executableSha256 = currentProgram.getExecutableSHA256();
        String mappingFingerprint = snapshotFingerprint(executableSha256, functions, data);
        batchEnd = Math.min(batchEnd, functions.size());
        if (batchStart > functions.size()) {
            throw new IllegalArgumentException("batch start exceeds function count: " + batchStart);
        }
        println("Canonical export: functions=" + functions.size() + " data_symbols=" + data.size() +
            " batch=[" + batchStart + "," + batchEnd + ")");

        verifyNoCanonicalCollisions(functions, data);
        writeFunctionIndex(new File(binaryOut, "canonical_function_index.tsv"), functions);
        writeDataIndex(new File(binaryOut, "canonical_data_index.tsv"), data);
        replaceAtomically(new File(binaryOut, "canonical_snapshot.tsv"), List.of(
            "format\texecutable_sha256\tmapping_fingerprint\tfunctions\tdata_symbols",
            FORMAT_MARKER + "\t" + tsv(executableSha256) + "\t" + mappingFingerprint + "\t" +
                functions.size() + "\t" + data.size()));
        replaceAtomically(statusFile, List.of(
            "state\tformat\tmapping_fingerprint\tbatch_start\tbatch_end\tfunctions\tdata_symbols",
            "running\t" + FORMAT_MARKER + "\t" + mappingFingerprint + "\t" + batchStart +
                "\t" + batchEnd + "\t" +
                functions.size() + "\t" + data.size()));

        Namespace global = currentProgram.getGlobalNamespace();
        int transaction = currentProgram.startTransaction("Temporary canonical decompile names");
        DecompInterface decompiler = null;
        int succeeded = 0;
        int failed = 0;
        int skipped = 0;
        int firstPassTimeouts = 0;
        int recoveredTimeouts = 0;
        int finalTimeouts = 0;
        int otherFailures = 0;
        try {
            // A scratch phase detaches DEFAULT thunk names and makes final-name swaps safe.
            for (FunctionMeta meta : functions) {
                monitor.checkCancelled();
                meta.function.getSymbol().setNameAndNamespace(
                    meta.scratchName, global, SourceType.USER_DEFINED);
            }
            for (DataMeta meta : data) {
                monitor.checkCancelled();
                meta.symbol.setNameAndNamespace(meta.scratchName, global, SourceType.USER_DEFINED);
            }
            for (FunctionMeta meta : functions) {
                monitor.checkCancelled();
                meta.function.getSymbol().setNameAndNamespace(
                    meta.canonicalName, global, SourceType.USER_DEFINED);
            }
            for (DataMeta meta : data) {
                monitor.checkCancelled();
                meta.symbol.setNameAndNamespace(meta.canonicalName, global, SourceType.USER_DEFINED);
            }
            validateCanonicalState(global, functions, data);

            DecompileOptions options = new DecompileOptions();
            options.grabFromProgram(currentProgram);
            int normalMaxPayloadMBytes = options.getMaxPayloadMBytes();
            decompiler = openConfiguredDecompiler(options);

            for (int i = batchStart; i < batchEnd; i++) {
                monitor.checkCancelled();
                FunctionMeta meta = functions.get(i);
                File outFile = new File(decompOut, meta.canonicalName + ".c");
                if (isCompleteCanonicalFile(
                        outFile, meta.canonicalName, mappingFingerprint)) {
                    skipped++;
                    continue;
                }

                DecompileResults results =
                    decompiler.decompileFunction(meta.function, timeoutSeconds, monitor);
                boolean retriedAfterTimeout = timedOut(results);
                if (retriedAfterTimeout) {
                    firstPassTimeouts++;
                    println("Timeout at " + meta.entry + " after " + timeoutSeconds +
                        "s; retrying with a fresh decompiler process for " +
                        retryTimeoutSeconds + "s");
                    decompiler.dispose();
                    decompiler = null;
                    options.setMaxPayloadMBytes(
                        Math.max(normalMaxPayloadMBytes, RETRY_MAX_PAYLOAD_MBYTES));
                    decompiler = openConfiguredDecompiler(options);
                    results = decompiler.decompileFunction(
                        meta.function, retryTimeoutSeconds, monitor);
                }
                List<String> lines = new ArrayList<>();
                lines.add("// " + binaryName);
                lines.add("// Export format: " + FORMAT_MARKER);
                lines.add("// Mapping fingerprint: " + mappingFingerprint);
                lines.add("// Canonical function: " + meta.canonicalName);
                lines.add("// Original function: " + meta.originalQualifiedName);
                lines.add("// Entry: 0x" + meta.entry + "  Size: " + meta.size);
                lines.add("// Original signature: " + meta.originalSignature);
                if (retriedAfterTimeout) {
                    lines.add("// Timeout retry: " + timeoutSeconds + "s -> " +
                        retryTimeoutSeconds + "s; max payload " + normalMaxPayloadMBytes +
                        " MiB -> " + options.getMaxPayloadMBytes() + " MiB");
                }
                boolean completed = results != null && results.decompileCompleted() &&
                    results.getDecompiledFunction() != null;
                String signature = completed ?
                    results.getDecompiledFunction().getSignature() : "";
                String cText = completed ? results.getDecompiledFunction().getC() : "";
                boolean canonicalDefinition = signature != null &&
                    Pattern.compile("\\b" + Pattern.quote(meta.canonicalName) + "\\s*\\(")
                        .matcher(signature).find();
                boolean hasCText = cText != null && !cText.isBlank();
                if (completed && canonicalDefinition && hasCText) {
                    lines.add("// Export result: success");
                    lines.add(cText);
                    lines.add("// Canonical export EOF: success " + meta.canonicalName + " " +
                        mappingFingerprint);
                    succeeded++;
                    if (retriedAfterTimeout) {
                        recoveredTimeouts++;
                    }
                }
                else {
                    String error;
                    boolean finalTimeout = timedOut(results);
                    if (finalTimeout) {
                        finalTimeouts++;
                    }
                    else {
                        otherFailures++;
                    }
                    if (results == null) {
                        error = "null result";
                    }
                    else if (!results.decompileCompleted()) {
                        error = (finalTimeout ?
                            "timeout after retry (" + timeoutSeconds + "s + " +
                                retryTimeoutSeconds + "s): " :
                            (results.isCancelled() ? "cancelled: " : "incomplete: ")) +
                            results.getErrorMessage();
                    }
                    else if (!canonicalDefinition) {
                        error = "definition identity mismatch: " + signature;
                    }
                    else if (!hasCText) {
                        error = "decompiler returned blank C text";
                    }
                    else {
                        error = results.getErrorMessage();
                    }
                    lines.add("// Export result: " + (finalTimeout ? "timeout" : "failed"));
                    lines.add("// DECOMPILATION FAILED: " + error);
                    failed++;
                }
                replaceAtomically(outFile, lines);

                if ((i - batchStart) % 250 == 0) {
                    println("Progress: " + i + "/" + functions.size());
                }
            }
        }
        finally {
            try {
                if (decompiler != null) {
                    decompiler.dispose();
                }
            }
            finally {
                // Never persist the temporary identities, including on cancellation/error.
                currentProgram.endTransaction(transaction, false);
            }
        }

        replaceAtomically(statusFile, List.of(
            "state\tformat\tmapping_fingerprint\tbatch_start\tbatch_end\tfunctions\t" +
                "data_symbols\tsucceeded\tfailed\tskipped\tfirst_pass_timeouts\t" +
                "recovered_timeouts\tfinal_timeouts\tother_failures\t" +
                "retry_max_payload_mbytes",
            (failed == 0 ? "export_ok" : "export_partial") + "\t" + FORMAT_MARKER +
                "\t" + mappingFingerprint + "\t" + batchStart + "\t" + batchEnd + "\t" +
                functions.size() + "\t" + data.size() + "\t" + succeeded + "\t" + failed +
                "\t" + skipped + "\t" + firstPassTimeouts + "\t" + recoveredTimeouts +
                "\t" + finalTimeouts + "\t" + otherFailures + "\t" +
                RETRY_MAX_PAYLOAD_MBYTES));

        println("DONE canonical batch [" + batchStart + "," + batchEnd + ") total=" +
            functions.size() + " succeeded=" + succeeded + " failed=" + failed +
            " skipped_existing=" + skipped + " first_pass_timeouts=" + firstPassTimeouts +
            " recovered_timeouts=" + recoveredTimeouts + " final_timeouts=" + finalTimeouts +
            " other_failures=" + otherFailures +
            " rollback_pending_external_check=true");
        if (failed != 0) {
            throw new IllegalStateException("canonical export batch completed with " + failed +
                " failed decompilations");
        }
    }
}
