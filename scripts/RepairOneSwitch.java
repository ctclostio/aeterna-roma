// Ghidra headless script: repair one failed switch/jump-table by extending the
// containing function body with the table's case blocks and adding COMPUTED_JUMP
// references, then re-decompiling to report whether the warning clears.
//
// Usage: RepairOneSwitch.java <function_entry> <jump_instruction_address>

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

import java.util.ArrayList;
import java.util.List;

public class RepairOneSwitch extends GhidraScript {

    private static String tsv(String value) {
        return value == null ? "" : value.replace("\t", " ").replace("\n", " ");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            println("USAGE: RepairOneSwitch.java <function_entry> <jump_instruction_address>");
            return;
        }
        Address functionEntry = toAddr(args[0]);
        Address jumpAddress = toAddr(args[1]);
        Function function = getFunctionAt(functionEntry);
        Instruction jump = currentProgram.getListing().getInstructionAt(jumpAddress);
        if (function == null || jump == null) {
            println("missing function or instruction");
            return;
        }
        println("function=" + function.getEntryPoint() + " body=" + function.getBody());
        println("jump=" + jump);
        Address table = null;
        java.util.regex.Matcher matcher = java.util.regex.Pattern
            .compile("\\[.*\\+\\s*(?:0x)?([0-9a-fA-F]+)\\]")
            .matcher(jump.toString());
        if (matcher.find() && jump.toString().contains("*0x4")) {
            table = toAddr(Long.parseLong(matcher.group(1), 16));
        }
        if (table == null) {
            for (Object object : jump.getOpObjects(0)) {
                if (object instanceof Address) {
                    table = (Address) object;
                }
            }
        }
        if (table == null) {
            println("no table address in operand");
            return;
        }
        println("table=" + table);

        Memory memory = currentProgram.getMemory();
        AddressSet executable = new AddressSet();
        for (ghidra.program.model.mem.MemoryBlock block : memory.getBlocks()) {
            if (block.isExecute() && block.isInitialized()) {
                executable.add(block.getAddressRange());
            }
        }
        List<Address> targets = new ArrayList<>();
        for (int i = 0; i < 256; i++) {
            Address entry = table.add(4L * i);
            if (!memory.contains(entry)) {
                break;
            }
            long value = Integer.toUnsignedLong(memory.getInt(entry));
            Address target = toAddr(value);
            if (target == null || !executable.contains(target)) {
                break;
            }
            targets.add(target);
        }
        println("targets=" + targets.size());
        for (Address target : targets) {
            println("  " + target + " containing=" +
                (getFunctionContaining(target) == null ? "none" :
                    getFunctionContaining(target).getEntryPoint()));
        }

        int transaction = currentProgram.startTransaction("Repair switch table");
        boolean commit = false;
        try {
            AddressSet body = new AddressSet(function.getBody());
            for (Address target : targets) {
                if (getFunctionContaining(target) == null) {
                    Instruction instruction = currentProgram.getListing().getInstructionAt(target);
                    if (instruction == null) {
                        DisassembleCommand disassemble = new DisassembleCommand(
                            target, null, true);
                        disassemble.applyTo(currentProgram, monitor);
                    }
                    AddressSetView caseBody = ghidra.app.cmd.function.CreateFunctionCmd
                        .getFunctionBody(currentProgram, target, monitor);
                    if (caseBody != null) {
                        body.add(caseBody);
                    }
                }
                currentProgram.getReferenceManager().addMemoryReference(
                    jumpAddress, target, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED, 0);
            }
            function.setBody(body);
            println("new body=" + function.getBody());
            commit = true;
        }
        finally {
            currentProgram.endTransaction(transaction, commit);
        }

        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(currentProgram);
        options.setMaxJumpTableEntries(4096);
        options.setMaxInstructions(1000000);
        decompiler.setOptions(options);
        decompiler.openProgram(currentProgram);
        DecompileResults results = decompiler.decompileFunction(function, 120, monitor);
        String c = results.decompileCompleted() && results.getDecompiledFunction() != null ?
            results.getDecompiledFunction().getC() : "";
        boolean failed = c.contains("Could not recover jumptable") ||
            c.contains("Treating indirect jump as call");
        println("decompileCompleted=" + results.decompileCompleted() +
            " warningPresent=" + failed);
        int lineNo = 0;
        for (String line : c.split("\n")) {
            lineNo++;
            if (line.contains("WARNING") || line.contains("switch") ||
                    line.contains("case ")) {
                println("  " + lineNo + ": " + tsv(line));
            }
        }
        decompiler.dispose();
    }
}
