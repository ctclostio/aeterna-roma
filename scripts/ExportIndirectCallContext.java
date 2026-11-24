// Ghidra headless script: export read-only instruction, external-symbol,
// function stack-purge, backward register-definition, arity-hint, and
// fragment-owner context for all indirect call sites.
//
// Usage: ExportIndirectCallContext.java <input_indirect_calls_tsv> <out_dir>
//
// Read-only: no program changes are made.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExportIndirectCallContext extends GhidraScript {

    private final AddressSet executable = new AddressSet();
    private final Map<String, String> extAddrToFull = new HashMap<>();
    private final Map<Long, String> iatMemToFull = new HashMap<>();

    private static String tsv(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\t", " ").replace("\r", " ").replace("\n", " ");
    }

    private static String normReg(Register reg) {
        if (reg == null) {
            return "";
        }
        String name = reg.getName().toUpperCase();
        // Normalize 16/8-bit subregisters to 32-bit base for simple tracking if needed.
        if (name.equals("AX") || name.equals("AL") || name.equals("AH")) return "EAX";
        if (name.equals("CX") || name.equals("CL") || name.equals("CH")) return "ECX";
        if (name.equals("DX") || name.equals("DL") || name.equals("DH")) return "EDX";
        if (name.equals("BX") || name.equals("BL") || name.equals("BH")) return "EBX";
        if (name.equals("SI")) return "ESI";
        if (name.equals("DI")) return "EDI";
        if (name.equals("BP")) return "EBP";
        if (name.equals("SP")) return "ESP";
        return name;
    }

    private static class MemRefExpr {
        boolean valid;
        boolean hasBase;
        String baseReg = "";
        boolean hasIndex;
        String indexReg = "";
        boolean hasAddr;
        long absAddr;
        long disp;
        boolean hasDisp;
    }

    private MemRefExpr parseOperandMem(Instruction ins, int opIdx) {
        MemRefExpr expr = new MemRefExpr();
        Object[] objs = ins.getOpObjects(opIdx);
        String rep = ins.getDefaultOperandRepresentation(opIdx);
        boolean isMem = rep.contains("[") && rep.contains("]");
        List<Register> regs = new ArrayList<>();
        Scalar scalar = null;
        Address addr = null;
        for (Object o : objs) {
            if (o instanceof Register) {
                regs.add((Register) o);
            }
            else if (o instanceof Scalar) {
                scalar = (Scalar) o;
            }
            else if (o instanceof Address) {
                addr = (Address) o;
            }
        }
        if (!isMem) {
            return expr;
        }
        expr.valid = true;
        if (regs.size() >= 1) {
            expr.hasBase = true;
            expr.baseReg = normReg(regs.get(0));
        }
        if (regs.size() >= 2) {
            expr.hasIndex = true;
            expr.indexReg = normReg(regs.get(1));
        }
        if (addr != null) {
            expr.hasAddr = true;
            expr.absAddr = addr.getOffset() & 0xffffffffL;
        }
        if (scalar != null) {
            expr.hasDisp = true;
            expr.disp = scalar.getSignedValue();
        }
        return expr;
    }

    private String resolveExtFromRef(Reference ref) {
        Address to = ref.getToAddress();
        if (to == null) {
            return null;
        }
        String key = to.toString();
        String hit = extAddrToFull.get(key);
        if (hit != null) {
            return hit;
        }
        if (to.isExternalAddress() || ref.isExternalReference()) {
            Symbol s = currentProgram.getSymbolTable().getSymbol(ref);
            if (s != null) {
                ExternalLocation loc = currentProgram.getExternalManager().getExternalLocation(s);
                if (loc != null) {
                    String lib = loc.getLibraryName();
                    String lbl = loc.getOriginalImportedName();
                    if (lbl == null || lbl.isEmpty()) {
                        lbl = loc.getLabel();
                    }
                    String full = (lib == null ? "" : lib) + "!" + (lbl == null ? s.getName() : lbl);
                    extAddrToFull.put(key, full);
                    return full;
                }
                return s.getName(true);
            }
        }
        return null;
    }

    private String analyzeRegAndArity(Instruction callIns, String kind, String baseOp,
            BasicBlockModel bbm) throws Exception {
        // Walk backward up to 24 instructions within the same basic block.
        CodeBlock bb = bbm.getFirstCodeBlockContaining(callIns.getAddress(), monitor);
        Address bbStart = bb != null ? bb.getFirstStartAddress() : null;

        String targetReg = "";
        if (kind.equals("register") || kind.equals("register_offset")) {
            targetReg = baseOp.toUpperCase();
        }
        // Special case: CALL dword ptr [ESP + disp] or [EBP + disp] may have base=ESP/EBP
        String watchReg = targetReg;
        boolean watchActive = !watchReg.isEmpty();
        MemRefExpr callMem = parseOperandMem(callIns, 0);
        boolean isCallMem = callMem.valid;
        long pendingSlotOff = (isCallMem && callMem.hasDisp) ? callMem.disp : 0;

        List<String> chain = new ArrayList<>();
        String ecxSrc = "";
        boolean hasEcxSetup = false;
        int pushCount = 0;
        int subEspBytes = 0;
        boolean stoppedAtCall = false;

        Instruction cur = callIns.getPrevious();
        int steps = 0;
        while (cur != null && steps < 24) {
            monitor.checkCancelled();
            if (bbStart != null && cur.getAddress().compareTo(bbStart) < 0) {
                break;
            }
            FlowType ft = cur.getFlowType();
            if (ft.isCall()) {
                stoppedAtCall = true;
                if (watchActive && watchReg.equals("EAX")) {
                    Address[] flows = cur.getFlows();
                    if (flows != null && flows.length == 1) {
                        chain.add("CALL_RET:0x" + Long.toHexString(flows[0].getOffset()));
                    }
                    else {
                        chain.add("CALL_RET:indirect");
                    }
                    watchActive = false;
                }
                break;
            }
            if (ft.isJump() || ft.isTerminal()) {
                break;
            }

            String mnem = cur.getMnemonicString().toUpperCase();
            int nOps = cur.getNumOperands();

            // Arity hint tracking (until previous call/branch)
            if (mnem.equals("PUSH")) {
                pushCount++;
            }
            else if (mnem.equals("SUB") && nOps >= 2) {
                Register dst = cur.getRegister(0);
                if (dst != null && normReg(dst).equals("ESP")) {
                    Object[] sObjs = cur.getOpObjects(1);
                    for (Object o : sObjs) {
                        if (o instanceof Scalar) {
                            long v = ((Scalar) o).getSignedValue();
                            if (v > 0 && v <= 256) {
                                subEspBytes += (int) v;
                            }
                        }
                    }
                }
            }
            else if (mnem.equals("ADD") && nOps >= 2) {
                Register dst = cur.getRegister(0);
                if (dst != null && normReg(dst).equals("ESP")) {
                    Object[] sObjs = cur.getOpObjects(1);
                    for (Object o : sObjs) {
                        if (o instanceof Scalar) {
                            long v = ((Scalar) o).getSignedValue();
                            if (v < 0 && v >= -256) {
                                subEspBytes += (int) (-v);
                            }
                        }
                    }
                }
            }

            // Track ECX setup (this pointer)
            if (nOps >= 1) {
                Register dst0 = cur.getRegister(0);
                String dstName = normReg(dst0);
                if (dstName.equals("ECX") && !mnem.equals("CMP") && !mnem.equals("TEST") && !mnem.equals("PUSH")) {
                    hasEcxSetup = true;
                    if (ecxSrc.isEmpty()) {
                        ecxSrc = summarizeInsRhs(cur);
                    }
                }

                // Track watched register backwards
                if (watchActive && !dstName.isEmpty() && dstName.equals(watchReg)
                        && !mnem.equals("CMP") && !mnem.equals("TEST") && !mnem.equals("PUSH")) {
                    if (mnem.equals("MOV") || mnem.equals("MOVZX") || mnem.equals("MOVSX") || mnem.equals("LEA")) {
                        MemRefExpr rhsMem = parseOperandMem(cur, 1);
                        if (mnem.equals("LEA") && rhsMem.valid) {
                            if (rhsMem.hasBase && !rhsMem.hasIndex) {
                                chain.add("LEA:" + rhsMem.baseReg + "+0x" + Long.toHexString(rhsMem.disp));
                                watchReg = rhsMem.baseReg;
                            }
                            else {
                                chain.add("LEA:" + cur.getDefaultOperandRepresentation(1));
                                watchActive = false;
                            }
                        }
                        else if (rhsMem.valid) {
                            if (!rhsMem.hasBase && rhsMem.hasAddr) {
                                long va = rhsMem.absAddr;
                                String iat = iatMemToFull.get(va);
                                if (iat != null) {
                                    chain.add("IAT_LOAD:0x" + Long.toHexString(va) + ":" + iat);
                                    watchActive = false;
                                }
                                else {
                                    // Global pointer load: MOV reg, [global_va]
                                    chain.add("GLOBAL_PTR:0x" + Long.toHexString(va));
                                    watchActive = false;
                                }
                            }
                            else if (rhsMem.hasBase && !rhsMem.hasIndex) {
                                long disp = rhsMem.hasDisp ? rhsMem.disp : 0;
                                if (rhsMem.baseReg.equals("ESP") || rhsMem.baseReg.equals("EBP")) {
                                    chain.add("STACK_LOAD:" + rhsMem.baseReg + "+0x" + Long.toHexString(disp));
                                    watchActive = false;
                                }
                                else {
                                    if (!isCallMem && chain.isEmpty()) {
                                        chain.add("VSLOT_REG_LOAD:" + rhsMem.baseReg + ":0x" + Long.toHexString(disp));
                                    }
                                    else {
                                        chain.add("MEM_LOAD:" + rhsMem.baseReg + "+0x" + Long.toHexString(disp));
                                    }
                                    watchReg = rhsMem.baseReg;
                                }
                            }
                            else {
                                chain.add("COMPLEX_MEM:" + cur.getDefaultOperandRepresentation(1));
                                watchActive = false;
                            }
                        }
                        else {
                            // Register or immediate on RHS
                            Register rhsReg = cur.getRegister(1);
                            if (rhsReg != null) {
                                String rn = normReg(rhsReg);
                                chain.add("COPY:" + rn);
                                watchReg = rn;
                            }
                            else {
                                Object[] rObjs = cur.getOpObjects(1);
                                boolean resolvedImm = false;
                                for (Object o : rObjs) {
                                    if (o instanceof Address) {
                                        long va = ((Address) o).getOffset() & 0xffffffffL;
                                        if (executable.contains((Address) o)) {
                                            chain.add("CONST_TEXT:0x" + Long.toHexString(va));
                                        }
                                        else {
                                            chain.add("CONST_ADDR:0x" + Long.toHexString(va));
                                        }
                                        resolvedImm = true;
                                        watchActive = false;
                                        break;
                                    }
                                    else if (o instanceof Scalar) {
                                        long va = ((Scalar) o).getUnsignedValue() & 0xffffffffL;
                                        Address a = toAddr(va);
                                        if (a != null && executable.contains(a)) {
                                            chain.add("CONST_TEXT:0x" + Long.toHexString(va));
                                        }
                                        else {
                                            chain.add("CONST_IMM:0x" + Long.toHexString(va));
                                        }
                                        resolvedImm = true;
                                        watchActive = false;
                                        break;
                                    }
                                }
                                if (!resolvedImm) {
                                    chain.add("OTHER_DEF:" + cur.toString());
                                    watchActive = false;
                                }
                            }
                        }
                    }
                    else if (mnem.equals("POP")) {
                        chain.add("POP");
                        watchActive = false;
                    }
                    else if (mnem.equals("XOR") && nOps >= 2) {
                        Register r1 = cur.getRegister(1);
                        if (r1 != null && normReg(r1).equals(watchReg)) {
                            chain.add("ZERO");
                            watchActive = false;
                        }
                    }
                    else {
                        chain.add("OP:" + mnem);
                        watchActive = false;
                    }
                }
            }

            if (cur.getAddress().equals(bbStart)) {
                break;
            }
            cur = cur.getPrevious();
            steps++;
        }

        // Simplify common composite patterns cleanly for Python
        StringBuilder extraTags = new StringBuilder();
        if (chain.size() >= 2 && chain.get(0).startsWith("VSLOT_REG_LOAD:")) {
            String[] p0 = chain.get(0).split(":");
            if (chain.get(1).startsWith("MEM_LOAD:") && chain.get(1).endsWith("+0x0")) {
                String objReg = chain.get(1).substring("MEM_LOAD:".length(), chain.get(1).length() - 4);
                if (chain.size() >= 3 && chain.get(2).startsWith("GLOBAL_PTR:")) {
                    extraTags.append("GLOBAL_VTABLE_LOAD:")
                             .append(chain.get(2).substring("GLOBAL_PTR:".length()))
                             .append(":").append(p0[2]).append(";");
                }
                else if (chain.size() >= 3 && chain.get(2).startsWith("MEM_LOAD:")) {
                    String m2 = chain.get(2).substring("MEM_LOAD:".length());
                    int plusIdx = m2.indexOf("+0x");
                    if (plusIdx > 0) {
                        extraTags.append("SUBOBJ_VPTR:")
                                 .append(m2.substring(0, plusIdx)).append(":")
                                 .append(m2.substring(plusIdx + 1)).append(":")
                                 .append(p0[2]).append(";");
                    }
                }
                else if (objReg.equals("ECX")) {
                    extraTags.append("THIS_VPTR:").append(p0[2]).append(";");
                }
            }
            else if (chain.get(1).startsWith("GLOBAL_PTR:")) {
                extraTags.append("GLOBAL_VTABLE_LOAD:")
                         .append(chain.get(1).substring("GLOBAL_PTR:".length()))
                         .append(":").append(p0[2]).append(";");
            }
        }
        else if (isCallMem && chain.size() >= 1) {
            if (chain.get(0).startsWith("MEM_LOAD:") && chain.get(0).endsWith("+0x0")) {
                String objReg = chain.get(0).substring("MEM_LOAD:".length(), chain.get(0).length() - 4);
                if (chain.size() >= 2 && chain.get(1).startsWith("GLOBAL_PTR:")) {
                    extraTags.append("GLOBAL_VTABLE_LOAD:")
                             .append(chain.get(1).substring("GLOBAL_PTR:".length()))
                             .append(":0x").append(Long.toHexString(pendingSlotOff)).append(";");
                }
                else if (chain.size() >= 2 && chain.get(1).startsWith("MEM_LOAD:")) {
                    String m1 = chain.get(1).substring("MEM_LOAD:".length());
                    int plusIdx = m1.indexOf("+0x");
                    if (plusIdx > 0) {
                        extraTags.append("SUBOBJ_VPTR:")
                                 .append(m1.substring(0, plusIdx)).append(":")
                                 .append(m1.substring(plusIdx + 1)).append(":0x")
                                 .append(Long.toHexString(pendingSlotOff)).append(";");
                    }
                }
                else if (objReg.equals("ECX")) {
                    extraTags.append("THIS_VPTR:0x").append(Long.toHexString(pendingSlotOff)).append(";");
                }
            }
            else if (chain.get(0).startsWith("GLOBAL_PTR:")) {
                extraTags.append("GLOBAL_VTABLE_LOAD:")
                         .append(chain.get(0).substring("GLOBAL_PTR:".length()))
                         .append(":0x").append(Long.toHexString(pendingSlotOff)).append(";");
            }
        }

        String chainStr = extraTags.toString() + String.join("|", chain);
        if (!ecxSrc.isEmpty()) {
            chainStr = chainStr + (chainStr.isEmpty() ? "" : ";") + "ECX=" + ecxSrc;
        }
        int stackBytes = pushCount * 4 + subEspBytes;
        String arityStr = "pushes=" + pushCount + ",stack_bytes=" + stackBytes
                + ",has_ecx=" + (hasEcxSetup ? "1" : "0")
                + ",stopped_call=" + (stoppedAtCall ? "1" : "0");
        return chainStr + "\t" + arityStr;
    }

    private String summarizeInsRhs(Instruction ins) {
        String mnem = ins.getMnemonicString().toUpperCase();
        if (ins.getNumOperands() >= 2) {
            MemRefExpr mem = parseOperandMem(ins, 1);
            if (mnem.equals("LEA") && mem.valid && mem.hasBase) {
                return "LEA:" + mem.baseReg + "+0x" + Long.toHexString(mem.disp);
            }
            if (mem.valid) {
                if (!mem.hasBase && mem.hasAddr) {
                    return "GLOBAL:0x" + Long.toHexString(mem.absAddr);
                }
                if (mem.hasBase) {
                    return "MEM:" + mem.baseReg + "+0x" + Long.toHexString(mem.hasDisp ? mem.disp : 0);
                }
            }
            Register r = ins.getRegister(1);
            if (r != null) {
                return "REG:" + normReg(r);
            }
            return ins.getDefaultOperandRepresentation(1);
        }
        return mnem;
    }

    private Function findFunctionBefore(Address site) {
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(site, false);
        return it.hasNext() ? it.next() : null;
    }

    private String findFragmentOwner(Address site, BasicBlockModel bbm) throws Exception {
        CodeBlock bb = bbm.getFirstCodeBlockContaining(site, monitor);
        if (bb == null) {
            Function prev = findFunctionBefore(site);
            return prev == null ? "" : "prev_fn=" + prev.getEntryPoint().toString();
        }
        Address bbStart = bb.getFirstStartAddress();
        Set<String> owners = new LinkedHashSet<>();
        Set<Address> visited = new HashSet<>();
        List<CodeBlock> queue = new ArrayList<>();
        queue.add(bb);
        visited.add(bbStart);
        int hops = 0;
        while (!queue.isEmpty() && hops < 16 && owners.size() < 4) {
            CodeBlock cur = queue.remove(0);
            hops++;
            // Check direct references to cur start
            ReferenceIterator rit = currentProgram.getReferenceManager().getReferencesTo(cur.getFirstStartAddress());
            while (rit.hasNext()) {
                Reference ref = rit.next();
                Function f = getFunctionContaining(ref.getFromAddress());
                if (f != null) {
                    owners.add(f.getEntryPoint().toString());
                }
            }
            // Check block sources
            CodeBlockReferenceIterator srcIt = cur.getSources(monitor);
            while (srcIt.hasNext()) {
                CodeBlockReference cref = srcIt.next();
                Address srcAddr = cref.getSourceAddress();
                Function f = getFunctionContaining(srcAddr);
                if (f != null) {
                    owners.add(f.getEntryPoint().toString());
                }
                else {
                    CodeBlock srcBlock = cref.getSourceBlock();
                    if (srcBlock != null && !visited.contains(srcBlock.getFirstStartAddress())) {
                        visited.add(srcBlock.getFirstStartAddress());
                        queue.add(srcBlock);
                    }
                }
            }
        }
        StringBuilder sb = new StringBuilder();
        sb.append("bb=").append(bbStart.toString());
        if (!owners.isEmpty()) {
            sb.append("|owners=").append(String.join(",", owners));
        }
        Function prev = findFunctionBefore(site);
        if (prev != null) {
            sb.append("|prev_fn=").append(prev.getEntryPoint().toString());
        }
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            println("USAGE: ExportIndirectCallContext.java <input_indirect_calls_tsv> <out_dir>");
            return;
        }
        File inTsv = new File(args[0]);
        File outDir = new File(args[1]);
        if (!outDir.exists() && !outDir.mkdirs()) {
            throw new IllegalStateException("Failed to create output dir: " + outDir);
        }

        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (block.isExecute() && block.isInitialized()) {
                executable.add(block.getAddressRange());
            }
        }

        // 1. Export external_symbols.tsv
        SymbolTable symTab = currentProgram.getSymbolTable();
        ExternalManager extMgr = currentProgram.getExternalManager();
        List<String> extLines = new ArrayList<>();
        extLines.add("ext_addr\tlibrary\tlabel\toriginal_name\tmemory_addr\tfull_name");
        SymbolIterator extIt = symTab.getExternalSymbols();
        while (extIt.hasNext()) {
            monitor.checkCancelled();
            Symbol sym = extIt.next();
            ExternalLocation loc = extMgr.getExternalLocation(sym);
            String extAddr = sym.getAddress().toString();
            String lib = "";
            String label = sym.getName();
            String orig = "";
            String memAddr = "";
            if (loc != null) {
                if (loc.getLibraryName() != null) lib = loc.getLibraryName();
                if (loc.getLabel() != null) label = loc.getLabel();
                if (loc.getOriginalImportedName() != null) orig = loc.getOriginalImportedName();
                if (loc.getAddress() != null) {
                    memAddr = loc.getAddress().toString();
                    iatMemToFull.put(loc.getAddress().getOffset() & 0xffffffffL,
                            lib + "!" + (!orig.isEmpty() ? orig : label));
                }
            }
            String full = lib + "!" + (!orig.isEmpty() ? orig : label);
            extAddrToFull.put(extAddr, full);
            extLines.add(tsv(extAddr) + "\t" + tsv(lib) + "\t" + tsv(label) + "\t"
                    + tsv(orig) + "\t" + tsv(memAddr) + "\t" + tsv(full));
        }
        try (BufferedWriter w = new BufferedWriter(new FileWriter(new File(outDir, "external_symbols.tsv")))) {
            for (String line : extLines) {
                w.write(line);
                w.newLine();
            }
        }
        println("Wrote external_symbols.tsv (" + (extLines.size() - 1) + " symbols)");

        // 2. Export function_purges.tsv
        List<String> fnLines = new ArrayList<>();
        fnLines.add("entry\tname\tcalling_convention\tstack_purge\tstack_purge_valid\tparam_count\treturn_type");
        FunctionIterator fnIt = currentProgram.getFunctionManager().getFunctions(true);
        while (fnIt.hasNext()) {
            monitor.checkCancelled();
            Function f = fnIt.next();
            String retType = "";
            try {
                if (f.getReturnType() != null) {
                    retType = f.getReturnType().getDisplayName();
                }
            }
            catch (Exception ignored) {}
            fnLines.add(tsv(f.getEntryPoint().toString()) + "\t"
                    + tsv(f.getName(true)) + "\t"
                    + tsv(f.getCallingConventionName()) + "\t"
                    + f.getStackPurgeSize() + "\t"
                    + (f.isStackPurgeSizeValid() ? "1" : "0") + "\t"
                    + f.getParameterCount() + "\t"
                    + tsv(retType));
        }
        try (BufferedWriter w = new BufferedWriter(new FileWriter(new File(outDir, "function_purges.tsv")))) {
            for (String line : fnLines) {
                w.write(line);
                w.newLine();
            }
        }
        println("Wrote function_purges.tsv (" + (fnLines.size() - 1) + " functions)");

        // 3. Export asm_context.tsv for every row in input TSV
        BasicBlockModel bbm = new BasicBlockModel(currentProgram);
        Listing listing = currentProgram.getListing();
        List<String> ctxLines = new ArrayList<>();
        ctxLines.add("site\tfunction_entry\tmnemonic\toperands\tkind\texternal_targets\tcomputed_targets\tread_refs\treg_def_chain\tcall_arity_hint\tfragment_owner");

        int siteCount = 0;
        try (BufferedReader br = new BufferedReader(new FileReader(inTsv))) {
            String header = br.readLine(); // skip header
            String row;
            while ((row = br.readLine()) != null) {
                monitor.checkCancelled();
                if (row.isEmpty()) continue;
                String[] cols = row.split("\t", -1);
                String siteStr = cols[0];
                String fnEntry = cols.length > 1 ? cols[1] : "";
                String mnem = cols.length > 3 ? cols[3] : "";
                String ops = cols.length > 4 ? cols[4] : "";
                String kind = cols.length > 5 ? cols[5] : "";
                String baseOp = cols.length > 6 ? cols[6] : "";

                Address siteAddr = toAddr(siteStr);
                Instruction ins = siteAddr != null ? listing.getInstructionAt(siteAddr) : null;

                List<String> extTgts = new ArrayList<>();
                List<String> compTgts = new ArrayList<>();
                List<String> readRefs = new ArrayList<>();
                String regAndArity = "\t";
                String fragOwner = "";

                if (ins != null) {
                    for (Reference ref : ins.getReferencesFrom()) {
                        Address to = ref.getToAddress();
                        if (to == null) continue;
                        if (ref.isExternalReference() || to.isExternalAddress()) {
                            String ext = resolveExtFromRef(ref);
                            if (ext != null && !ext.isEmpty()) {
                                extTgts.add(ext);
                            }
                            else {
                                extTgts.add(to.toString());
                            }
                        }
                        else if ((ref.getReferenceType().isCall() || ref.getReferenceType().isComputed())
                                && executable.contains(to)) {
                            Function tf = getFunctionAt(to);
                            compTgts.add(to.toString() + (tf != null ? "|" + tf.getName(true) : ""));
                        }
                        else if (ref.getReferenceType().isData() || ref.getReferenceType().isRead()) {
                            readRefs.add(to.toString());
                        }
                    }
                    if (mnem.equals("CALL")) {
                        regAndArity = analyzeRegAndArity(ins, kind, baseOp, bbm);
                    }
                    if (fnEntry.isEmpty()) {
                        fragOwner = findFragmentOwner(siteAddr, bbm);
                    }
                }

                ctxLines.add(tsv(siteStr) + "\t"
                        + tsv(fnEntry) + "\t"
                        + tsv(mnem) + "\t"
                        + tsv(ops) + "\t"
                        + tsv(kind) + "\t"
                        + tsv(String.join(";", extTgts)) + "\t"
                        + tsv(String.join(";", compTgts)) + "\t"
                        + tsv(String.join(";", readRefs)) + "\t"
                        + regAndArity + "\t"
                        + tsv(fragOwner));
                siteCount++;
            }
        }
        try (BufferedWriter w = new BufferedWriter(new FileWriter(new File(outDir, "asm_context.tsv")))) {
            for (String line : ctxLines) {
                w.write(line);
                w.newLine();
            }
        }
        println("Wrote asm_context.tsv (" + siteCount + " sites)");
    }
}
