// Reopen-time guard for ExportCanonicalDecompiled.java.
//
// Ghidra scripts execute inside an outer transaction.  The exporter poisons its
// nested transaction with endTransaction(..., false), but the actual rollback is
// completed only after that script returns.  This verifier therefore runs in a
// fresh headless invocation and compares the reopened database with the exact
// pre-rename function/data indexes.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

public class VerifyCanonicalRollback extends GhidraScript {

    private int functionRows;
    private int dataRows;

    private static boolean isTemporaryName(String name) {
        return name.startsWith("decomp_fn_") || name.startsWith("decomp_g_") ||
            name.startsWith("__decomp_tmp_fn_") || name.startsWith("__decomp_tmp_g_");
    }

    private static Map<String, Integer> parseHeader(String line) {
        Map<String, Integer> result = new HashMap<>();
        String[] fields = line.split("\\t", -1);
        for (int i = 0; i < fields.length; i++) {
            result.put(fields[i], i);
        }
        return result;
    }

    private static String field(String[] fields, Map<String, Integer> header, String name)
            throws IOException {
        Integer index = header.get(name);
        if (index == null || index >= fields.length) {
            throw new IOException("missing TSV field: " + name);
        }
        return fields[index];
    }

    private void reportMismatch(String message, int mismatchCount) {
        if (mismatchCount <= 10) {
            printerr(message);
        }
    }

    private static String describeFunction(Function function) {
        if (function == null) {
            return "";
        }
        return (function.isExternal() ? "external:" : "internal:") +
            function.getEntryPoint() + ":" + function.getName(true);
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

    private int verifyFunctions(File indexFile) throws Exception {
        FunctionManager manager = currentProgram.getFunctionManager();
        int mismatches = 0;
        try (BufferedReader reader = new BufferedReader(new FileReader(indexFile))) {
            String headerLine = reader.readLine();
            if (headerLine == null) {
                throw new IOException("empty function index: " + indexFile);
            }
            Map<String, Integer> header = parseHeader(headerLine);
            String line;
            int row = 1;
            while ((line = reader.readLine()) != null) {
                monitor.checkCancelled();
                row++;
                functionRows++;
                String[] fields = line.split("\\t", -1);
                String entry = field(fields, header, "entry");
                Address address = currentProgram.getAddressFactory().getAddress(entry);
                Function function = address == null ? null : manager.getFunctionAt(address);
                if (function == null) {
                    mismatches++;
                    reportMismatch("Rollback function missing at " + entry + " (row " + row + ")",
                        mismatches);
                    continue;
                }

                String expectedName = field(fields, header, "original_name");
                String expectedQualified = field(fields, header, "original_qualified_name");
                long expectedId = Long.parseLong(field(fields, header, "symbol_id"));
                long expectedNamespace = Long.parseLong(field(fields, header, "namespace_id"));
                String expectedSource = field(fields, header, "source_type");
                String expectedSignature = field(fields, header, "signature");
                long expectedSize = Long.parseLong(field(fields, header, "size"));
                String expectedKind = field(fields, header, "kind");
                String expectedBody = field(fields, header, "body_ranges");
                String expectedDirectThunk = field(fields, header, "direct_thunk_target");
                String expectedResolvedThunk = field(fields, header, "resolved_thunk_target");
                boolean matches = expectedName.equals(function.getName()) &&
                    expectedQualified.equals(function.getName(true)) &&
                    expectedId == function.getSymbol().getID() &&
                    expectedNamespace == function.getParentNamespace().getID() &&
                    expectedSource.equals(function.getSymbol().getSource().toString()) &&
                    expectedSignature.equals(function.getSignature(false).toString()) &&
                    expectedSize == function.getBody().getNumAddresses() &&
                    expectedKind.equals(function.isThunk() ? "thunk" : "func") &&
                    expectedBody.equals(describeBody(function)) &&
                    expectedDirectThunk.equals(describeFunction(function.getThunkedFunction(false))) &&
                    expectedResolvedThunk.equals(describeFunction(function.getThunkedFunction(true)));
                if (!matches) {
                    mismatches++;
                    reportMismatch("Rollback function mismatch at " + entry + ": expected " +
                        expectedQualified + " id=" + expectedId + " ns=" + expectedNamespace +
                        " source=" + expectedSource + "; got " + function.getName(true) +
                        " id=" + function.getSymbol().getID() + " ns=" +
                        function.getParentNamespace().getID() + " source=" +
                        function.getSymbol().getSource(), mismatches);
                }
            }
        }
        return mismatches;
    }

    private int verifyData(File indexFile) throws Exception {
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        int mismatches = 0;
        try (BufferedReader reader = new BufferedReader(new FileReader(indexFile))) {
            String headerLine = reader.readLine();
            if (headerLine == null) {
                throw new IOException("empty data index: " + indexFile);
            }
            Map<String, Integer> header = parseHeader(headerLine);
            String line;
            int row = 1;
            while ((line = reader.readLine()) != null) {
                monitor.checkCancelled();
                row++;
                dataRows++;
                String[] fields = line.split("\\t", -1);
                String addressText = field(fields, header, "address");
                Address address = currentProgram.getAddressFactory().getAddress(addressText);
                Symbol symbol = address == null ? null : symbolTable.getPrimarySymbol(address);
                if (symbol == null) {
                    mismatches++;
                    reportMismatch("Rollback data symbol missing at " + addressText +
                        " (row " + row + ")", mismatches);
                    continue;
                }

                String expectedName = field(fields, header, "original_name");
                String expectedQualified = field(fields, header, "original_qualified_name");
                long expectedId = Long.parseLong(field(fields, header, "symbol_id"));
                long expectedNamespace = Long.parseLong(field(fields, header, "namespace_id"));
                String expectedSource = field(fields, header, "source_type");
                String expectedSymbolType = field(fields, header, "symbol_type");
                String expectedDataType = field(fields, header, "data_type_path");
                int expectedDataTypeLength =
                    Integer.parseInt(field(fields, header, "data_type_length"));
                int expectedCodeUnitLength =
                    Integer.parseInt(field(fields, header, "code_unit_length"));
                Data definedData = currentProgram.getListing().getDefinedDataAt(address);
                String actualDataType = definedData == null ? "" :
                    definedData.getDataType().getPathName();
                int actualDataTypeLength = definedData == null ? 0 :
                    definedData.getDataType().getLength();
                int actualCodeUnitLength = definedData == null ? 0 : definedData.getLength();
                boolean matches = expectedName.equals(symbol.getName()) &&
                    expectedQualified.equals(symbol.getName(true)) && expectedId == symbol.getID() &&
                    expectedNamespace == symbol.getParentNamespace().getID() &&
                    expectedSource.equals(symbol.getSource().toString()) &&
                    expectedSymbolType.equals(symbol.getSymbolType().toString()) &&
                    expectedDataType.equals(actualDataType) &&
                    expectedDataTypeLength == actualDataTypeLength &&
                    expectedCodeUnitLength == actualCodeUnitLength;
                if (!matches) {
                    mismatches++;
                    reportMismatch("Rollback data mismatch at " + addressText + ": expected " +
                        expectedQualified + " id=" + expectedId + " ns=" + expectedNamespace +
                        " source=" + expectedSource + "; got " + symbol.getName(true) +
                        " id=" + symbol.getID() + " ns=" + symbol.getParentNamespace().getID() +
                        " source=" + symbol.getSource(), mismatches);
                }
            }
        }
        return mismatches;
    }

    private int verifySnapshot(File snapshotFile) throws Exception {
        try (BufferedReader reader = new BufferedReader(new FileReader(snapshotFile))) {
            String headerLine = reader.readLine();
            String valueLine = reader.readLine();
            if (headerLine == null || valueLine == null || reader.readLine() != null) {
                printerr("Malformed canonical snapshot: " + snapshotFile);
                return 1;
            }
            Map<String, Integer> header = parseHeader(headerLine);
            String[] fields = valueLine.split("\\t", -1);
            String format = field(fields, header, "format");
            String executableSha256 = field(fields, header, "executable_sha256");
            String mappingFingerprint = field(fields, header, "mapping_fingerprint");
            int expectedFunctions = Integer.parseInt(field(fields, header, "functions"));
            int expectedData = Integer.parseInt(field(fields, header, "data_symbols"));
            boolean matches = "canonical-address-v2".equals(format) &&
                executableSha256.equals(currentProgram.getExecutableSHA256()) &&
                !mappingFingerprint.isBlank() && expectedFunctions == functionRows &&
                expectedData == dataRows;
            if (!matches) {
                printerr("Canonical snapshot mismatch: format=" + format + " executable=" +
                    executableSha256 + " mapping=" + mappingFingerprint + " functions=" +
                    expectedFunctions + "/" + functionRows + " data=" + expectedData + "/" +
                    dataRows);
                return 1;
            }
        }
        return 0;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("USAGE: VerifyCanonicalRollback.java <output_root>");
            return;
        }

        String binaryName = currentProgram.getName().replaceAll("[^A-Za-z0-9._-]", "_");
        File outDir = new File(args[0], binaryName);
        File functionIndex = new File(outDir, "canonical_function_index.tsv");
        File dataIndex = new File(outDir, "canonical_data_index.tsv");
        File snapshot = new File(outDir, "canonical_snapshot.tsv");

        int functionMismatches = verifyFunctions(functionIndex);
        int dataMismatches = verifyData(dataIndex);
        int snapshotMismatches = verifySnapshot(snapshot);

        int functionLeaks = 0;
        int actualFunctionCount = 0;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function function = functions.next();
            actualFunctionCount++;
            if (isTemporaryName(function.getName())) {
                functionLeaks++;
                if (functionLeaks <= 5) {
                    printerr("Temporary function name persisted at " +
                        function.getEntryPoint() + ": " + function.getName(true));
                }
            }
        }
        if (actualFunctionCount != functionRows) {
            snapshotMismatches++;
            printerr("Function index row count does not match reopened program: " + functionRows +
                " vs " + actualFunctionCount);
        }

        int symbolLeaks = 0;
        int actualDataCount = 0;
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            monitor.checkCancelled();
            Symbol symbol = symbols.next();
            SymbolType type = symbol.getSymbolType();
            if (symbol.isPrimary() && !symbol.isExternal() && !symbol.isDynamic() &&
                    symbol.getAddress().isMemoryAddress() &&
                    (type == SymbolType.LABEL || type == SymbolType.GLOBAL_VAR) &&
                    currentProgram.getFunctionManager().getFunctionContaining(
                        symbol.getAddress()) == null) {
                actualDataCount++;
            }
            if (isTemporaryName(symbol.getName())) {
                symbolLeaks++;
                if (symbolLeaks <= 5) {
                    printerr("Temporary symbol name persisted at " +
                        symbol.getAddress() + ": " + symbol.getName(true));
                }
            }
        }
        if (actualDataCount != dataRows) {
            snapshotMismatches++;
            printerr("Data index row count does not match reopened program: " + dataRows +
                " vs " + actualDataCount);
        }

        int totalProblems = functionMismatches + dataMismatches + snapshotMismatches +
            functionLeaks + symbolLeaks;
        outDir.mkdirs();
        File status = new File(outDir, "canonical_rollback_status.tsv");
        Files.writeString(status.toPath(),
            "state\tfunction_mismatches\tdata_mismatches\tsnapshot_mismatches\t" +
                "function_leaks\tsymbol_leaks\n" +
            (totalProblems == 0 ? "ok" : "failed") + "\t" + functionMismatches + "\t" +
            dataMismatches + "\t" + snapshotMismatches + "\t" + functionLeaks + "\t" +
                symbolLeaks + "\n",
            StandardCharsets.UTF_8);

        if (totalProblems != 0) {
            throw new IllegalStateException("canonical rollback verification failed: " +
                "function_mismatches=" + functionMismatches + " data_mismatches=" +
                dataMismatches + " snapshot_mismatches=" + snapshotMismatches +
                " function_leaks=" + functionLeaks + " symbol_leaks=" + symbolLeaks);
        }
        println("Canonical rollback verified after reopen against function/data snapshots");
    }
}
