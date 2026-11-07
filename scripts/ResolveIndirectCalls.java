// Ghidra headless script: resolve indirect CALL targets with symbolic
// propagation.  The static corpus pass can only see explicit global loads; this
// pass follows register values through the function body (including loads from
// global object pointers and vtable slots) and records concrete targets.
//
// Usage: ResolveIndirectCalls.java <output_tsv> [function_limit]
//
// Read-only.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ResolveIndirectCalls extends GhidraScript {

    private static class Site {
        Address address;
        String operands;
        String kind;
        String registerName = "";
        long value;
        boolean relative;
        String relativeRegister = "";
        String target = "";
        String targetFunction = "";
        String note = "";
    }

    private AddressSet executable = new AddressSet();

    private static String tsv(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\t", " ").replace("\r", " ").replace("\n", " ");
    }

    private Long readPointer(Address address) {
        try {
            if (!currentProgram.getMemory().contains(address)) {
                return null;
            }
            return Integer.toUnsignedLong(currentProgram.getMemory().getInt(address));
        }
        catch (Exception e) {
            return null;
        }
    }

    private void setTarget(Site site, long value) {
        Address target = toAddr(value & 0xffffffffL);
        if (target == null) {
            return;
        }
        if (executable.contains(target)) {
            site.target = target.toString();
            Function f = getFunctionAt(target);
            site.targetFunction = f == null ? "" : f.getName(true);
            site.note = "executable";
        }
        else if (currentProgram.getMemory().contains(target)) {
            Long pointer = readPointer(target);
            if (pointer != null) {
                Address indirect = toAddr(pointer & 0xffffffffL);
                if (indirect != null && executable.contains(indirect)) {
                    site.target = indirect.toString();
                    Function f = getFunctionAt(indirect);
                    site.targetFunction = f == null ? "" : f.getName(true);
                    site.note = "dereferenced_global";
                }
            }
        }
    }

    private Site classify(Instruction instruction) {
        Object[] objects = instruction.getOpObjects(0);
        boolean hasAddress = false;
        boolean hasRegister = false;
        boolean hasScalar = false;
        Register register = null;
        Scalar scalar = null;
        for (Object object : objects) {
            if (object instanceof Address) {
                hasAddress = true;
            }
            else if (object instanceof Register) {
                hasRegister = true;
                register = (Register) object;
            }
            else if (object instanceof Scalar) {
                hasScalar = true;
                scalar = (Scalar) object;
            }
        }
        if (hasAddress && !hasRegister && !hasScalar) {
            return null;
        }
        Site site = new Site();
        site.address = instruction.getAddress();
        site.operands = instruction.toString();
        if (hasRegister && hasScalar) {
            site.kind = "register_offset";
            site.registerName = register == null ? "" : register.getName();
            site.value = scalar == null ? 0 : scalar.getUnsignedValue();
        }
        else if (hasRegister) {
            site.kind = "register";
            site.registerName = register == null ? "" : register.getName();
        }
        else {
            site.kind = "other";
        }
        return site;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args.length > 2) {
            println("USAGE: ResolveIndirectCalls.java <output_tsv> [function_limit]");
            return;
        }
        int limit = args.length == 2 ? Integer.parseInt(args[1]) : Integer.MAX_VALUE;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (block.isExecute() && block.isInitialized()) {
                executable.add(block.getAddressRange());
            }
        }

        Map<Long, List<Site>> byFunction = new LinkedHashMap<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(executable, true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = it.next();
            if (!instruction.getFlowType().isCall()) {
                continue;
            }
            Site site = classify(instruction);
            if (site == null) {
                continue;
            }
            Function function = getFunctionContaining(instruction.getAddress());
            long key = function == null ? -1 : function.getEntryPoint().getOffset();
            byFunction.computeIfAbsent(key, k -> new ArrayList<>()).add(site);
        }
        println("Functions with indirect calls: " + byFunction.size());

        List<String> lines = new ArrayList<>();
        lines.add("site\tfunction_entry\toperands\tkind\tregister\tvalue\t" +
            "relative_register\ttarget\ttarget_function\tnote");
        int processedFunctions = 0;
        int totalSites = 0;
        int resolved = 0;
        int relative = 0;
        int unresolved = 0;
        for (Map.Entry<Long, List<Site>> entry : byFunction.entrySet()) {
            monitor.checkCancelled();
            if (processedFunctions >= limit) {
                break;
            }
            Function function = entry.getKey() < 0 ? null :
                getFunctionAt(toAddr(entry.getKey()));
            if (function == null) {
                for (Site site : entry.getValue()) {
                    site.note = "no_containing_function";
                    unresolved++;
                    totalSites++;
                }
                continue;
            }
            SymbolicPropogator propagator = new SymbolicPropogator(currentProgram);
            try {
                ContextEvaluatorAdapter evaluator = new ContextEvaluatorAdapter() {
                    @Override
                    public boolean evaluateContextBefore(VarnodeContext context,
                            Instruction instruction) {
                        return true;
                    }

                    @Override
                    public boolean evaluateContext(VarnodeContext context,
                            Instruction instruction) {
                        return true;
                    }

                    @Override
                    public boolean allowAccess(VarnodeContext context, Address address) {
                        return true;
                    }
                };
                propagator.flowConstants(function.getEntryPoint(), function.getBody(),
                    evaluator, true, monitor);
            }
            catch (Exception e) {
                for (Site site : entry.getValue()) {
                    site.note = "propagation_failed: " + e.getMessage();
                    unresolved++;
                    totalSites++;
                }
                continue;
            }
            for (Site site : entry.getValue()) {
                totalSites++;
                try {
                    if (site.kind.equals("register")) {
                        Register register = currentProgram.getRegister(site.registerName);
                        SymbolicPropogator.Value value =
                            propagator.getRegisterValue(site.address, register);
                        if (value != null) {
                            site.value = value.getValue() & 0xffffffffL;
                            site.relative = value.isRegisterRelativeValue();
                            if (site.relative) {
                                site.relativeRegister = value.getRelativeRegister().getName();
                                relative++;
                            }
                            else {
                                setTarget(site, site.value);
                            }
                        }
                    }
                    else if (site.kind.equals("register_offset")) {
                        Register register = currentProgram.getRegister(site.registerName);
                        SymbolicPropogator.Value value =
                            propagator.getRegisterValue(site.address, register);
                        if (value != null && !value.isRegisterRelativeValue()) {
                            long base = value.getValue() & 0xffffffffL;
                            Address object = toAddr(base);
                            if (object != null && currentProgram.getMemory().contains(object)) {
                                Long pointer = readPointer(object.add(site.value));
                                if (pointer != null) {
                                    setTarget(site, pointer);
                                }
                            }
                        }
                        else if (value != null) {
                            site.relative = true;
                            site.relativeRegister = value.getRelativeRegister().getName();
                            relative++;
                        }
                    }
                }
                catch (Exception e) {
                    site.note = "resolve_error: " + e.getMessage();
                }
                if (!site.target.isEmpty()) {
                    resolved++;
                }
                else {
                    unresolved++;
                }
                lines.add(tsv(site.address.toString()) + "\t" +
                    tsv(function.getEntryPoint().toString()) + "\t" +
                    tsv(site.operands) + "\t" + site.kind + "\t" +
                    tsv(site.registerName) + "\t" +
                    String.format("0x%08x", site.value) + "\t" +
                    tsv(site.relativeRegister) + "\t" + tsv(site.target) + "\t" +
                    tsv(site.targetFunction) + "\t" + tsv(site.note));
            }
            processedFunctions++;
        }
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(new File(args[0])))) {
            for (String line : lines) {
                writer.write(line);
                writer.newLine();
            }
        }
        println("Processed functions: " + processedFunctions + " sites: " + totalSites +
            " resolved: " + resolved + " relative: " + relative +
            " unresolved: " + unresolved);
        println("Wrote " + args[0]);
    }
}
