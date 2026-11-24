#!/usr/bin/env python3
"""Single-pass multi-threaded IR extractor over canonical_decomp C files.

Reads all 81,280 decomp_fn_*.c files once and emits work/indirect_call_cache/corpus_ir.pkl
containing per-function signatures, variable pointer strides, balanced-paren indirect-call
expressions, and statement-ordered AST assignments/stores/calls/returns.

Pure Python 3.15 stdlib only.
"""
from __future__ import annotations

import argparse
import os
import pickle
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_decomp"
DEFAULT_OUT = ROOT / "work" / "indirect_call_cache" / "corpus_ir.pkl"

RE_FUNC_SIG = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_*\s]*?)\s+"
    r"(?:(__thiscall|__fastcall|__cdecl|__stdcall)\s+)?"
    r"(decomp_fn_([0-9a-fA-F]{8}))\s*\(([^)]*)\)\s*$",
    re.S,
)
RE_HEX_FN = re.compile(r"\bdecomp_fn_([0-9a-fA-F]{8})\b")
RE_PTR_SYM = re.compile(r"&PTR_[A-Za-z0-9_]+_([0-9a-fA-F]{8})\b")
RE_DAT = re.compile(r"\b_?DAT_([0-9a-fA-F]{8})\b")
RE_MI_ADJUST = re.compile(
    r"^\(\s*int\s*\*\s*\)\s*\(\s*-\s*\(\s*uint\s*\)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*!=\s*0\s*\)\s*&\s*"
    r"\(?\s*([A-Za-z_][A-Za-z0-9_]*)\s*-\s*(0x[0-9a-fA-F]+|\d+)U?\s*\)?\s*\)$"
)
RE_CONTROL_PREFIX = re.compile(r"\b(?:if|while|for|switch)\s*$")


def type_elem_size(type_str: str) -> tuple[int, int]:
    """Return (arith_elem_size, deref_elem_size) for a Ghidra C type string.

    arith_elem_size: byte multiplier for `ptr + k` or `ptr[k]` (1 for non-pointers).
    deref_elem_size: arith_elem_size of `*ptr` (non-1 only for pointer-to-pointer `T **`).
    """
    t = " ".join(type_str.replace("const ", "").strip().split())
    stars = t.count("*")
    if stars == 0:
        return (1, 1)
    if stars >= 2:
        # T ** or T *** -> pointer arithmetic step is 4; dereferencing yields T*
        if stars == 2:
            base = t.replace("*", "").strip()
            if base in ("char", "byte", "uchar", "undefined1", "undefined", "void"):
                return (4, 1)
            if base in ("short", "ushort", "wchar_t", "undefined2"):
                return (4, 2)
            if base in ("double", "undefined8", "longlong", "ulonglong"):
                return (4, 8)
            return (4, 4)
        return (4, 4)
    # Single pointer: T *
    base = t.replace("*", "").strip()
    if base in ("char", "byte", "uchar", "sbyte", "undefined1", "undefined", "void", "bool"):
        return (1, 1)
    if base in ("short", "ushort", "wchar_t", "undefined2"):
        return (2, 1)
    if base in ("double", "undefined8", "longlong", "ulonglong"):
        return (8, 1)
    if base in ("int", "uint", "long", "ulong", "float", "undefined4", "code", "BOOL", "HANDLE", "DWORD", "FARPROC"):
        return (4, 1)
    # Named struct pointer (e.g. FxActor *): pointer indexing rare, default 4 if array
    return (4, 1)


def parse_var_decl(decl: str) -> tuple[str, str, int, int] | None:
    """Parse a single C param or local declaration into (var_name, type_str, arith_sz, deref_sz)."""
    s = decl.strip().rstrip(";").strip()
    if not s or s == "void":
        return None
    # Strip array suffix e.g. `auStack_1c [8]` -> char/byte array (`&auStack_1c`)
    m_arr = re.match(r"^(.+?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]]*\]\s*$", s)
    if m_arr:
        t_str = m_arr.group(1).strip() + " *"
        name = m_arr.group(2)
        asz, dsz = type_elem_size(t_str)
        return (name, t_str, asz, dsz)
    m = re.match(r"^(.+?[* \t])\s*([A-Za-z_][A-Za-z0-9_]*)\s*$", s)
    if not m:
        return None
    t_str = m.group(1).strip()
    name = m.group(2)
    asz, dsz = type_elem_size(t_str)
    return (name, t_str, asz, dsz)


def strip_c_comments(text: str) -> str:
    """Remove /* ... */ and // ... comments while preserving line structure."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return text


def find_matching_paren(s: str, open_idx: int) -> int:
    depth = 0
    in_str = False
    quote = ""
    i = open_idx
    n = len(s)
    while i < n:
        c = s[i]
        if in_str:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == quote:
                in_str = False
        else:
            if c in ('"', "'"):
                in_str = True
                quote = c
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def split_top_level_args(s: str) -> list[str]:
    """Split comma-separated call arguments respecting nested (), [], "", ''."""
    s = s.strip()
    if not s:
        return []
    args = []
    depth = 0
    in_str = False
    quote = ""
    start = 0
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if in_str:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == quote:
                in_str = False
        else:
            if c in ('"', "'"):
                in_str = True
                quote = c
            elif c in ("(", "["):
                depth += 1
            elif c in (")", "]"):
                depth -= 1
            elif c == "," and depth == 0:
                args.append(s[start:i].strip())
                start = i + 1
        i += 1
    tail = s[start:].strip()
    if tail:
        args.append(tail)
    return args


def _has_top_level_binop(inner: str) -> bool:
    """Return True if `inner` contains binary/relational/logical operators at paren depth 0."""
    depth = 0
    in_str = False
    quote = ""
    i = 0
    n = len(inner)
    # Skip leading casts like `(code **)` and leading unary `*`
    while i < n:
        c = inner[i]
        if in_str:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == quote:
                in_str = False
        else:
            if c in ('"', "'"):
                in_str = True
                quote = c
            elif c in ("(", "["):
                depth += 1
            elif c in (")", "]"):
                depth -= 1
            elif depth == 0:
                if c in ("=", "<", ">", "?", ":", ",", ";", "+", "-", "/", "%", "&", "|", "^", "!"):
                    return True
        i += 1
    return False


def find_indirect_calls_in_text(text: str) -> list[dict]:
    """Locate every Ghidra indirect call `(<callee>)(<args>)` via balanced-paren scanning."""
    results = []
    n = len(text)
    i = 0
    while i < n:
        idx = text.find("(", i)
        if idx < 0:
            break
        # Check prefix isn't an identifier/control keyword
        if idx > 0 and (text[idx - 1].isalnum() or text[idx - 1] == "_"):
            i = idx + 1
            continue
        before = text[max(0, idx - 16):idx]
        if RE_CONTROL_PREFIX.search(before):
            i = idx + 1
            continue
        close_callee = find_matching_paren(text, idx)
        if close_callee < 0:
            i = idx + 1
            continue
        inner = text[idx + 1:close_callee].strip()
        if not inner.startswith("*"):
            i = idx + 1
            continue
        # Must be immediately followed by whitespace* and '('
        j = close_callee + 1
        while j < n and text[j] in " \t\r\n":
            j += 1
        if j >= n or text[j] != "(":
            i = idx + 1
            continue
        if _has_top_level_binop(inner):
            i = idx + 1
            continue
        close_args = find_matching_paren(text, j)
        if close_args < 0:
            i = idx + 1
            continue
        args_str = text[j + 1:close_args]
        results.append({
            "start": idx,
            "end": close_args + 1,
            "inner": inner,
            "args_raw": split_top_level_args(args_str),
        })
        # Continue scanning inside args (in case an indirect call's arg has an indirect call)
        i = idx + 1
    return results


# --- Recursive-descent C expression AST parser ------------------------------

_TOKEN_RE = re.compile(
    r"""
    \s*(?:
        (?P<STR>"(?:\\.|[^"\\])*")
      | (?P<CHR>'(?:\\.|[^'\\])*')
      | (?P<HEX>0x[0-9a-fA-F]+)[UuLl]*
      | (?P<DEC>\d+)[UuLl]*
      | (?P<ARROW>->)
      | (?P<SHIFT><<|>>)
      | (?P<CMP>==|!=|<=|>=|&&|\|\|)
      | (?P<ID>[A-Za-z_][A-Za-z0-9_]*)
      | (?P<OP>[()\[\]*&+\-/,~!.?:])
    )
    """,
    re.X,
)


def _tokenize(expr: str) -> list[tuple[str, str]]:
    tokens = []
    pos = 0
    n = len(expr)
    while pos < n:
        m = _TOKEN_RE.match(expr, pos)
        if not m:
            pos += 1
            continue
        kind = m.lastgroup
        val = m.group(kind)
        if kind == "HEX":
            tokens.append(("NUM", str(int(val, 16))))
        elif kind == "DEC":
            tokens.append(("NUM", val))
        elif kind == "STR":
            tokens.append(("STR", val[1:-1]))
        elif kind == "CHR":
            tokens.append(("CHR", val))
        elif kind == "ID":
            tokens.append(("ID", val))
        else:
            tokens.append((val, val))
        pos = m.end()
    return tokens


_TYPE_KEYWORDS = frozenset({
    "void", "int", "uint", "short", "ushort", "char", "uchar", "byte", "sbyte",
    "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
    "long", "ulong", "longlong", "ulonglong", "float", "double", "float10",
    "bool", "code", "wchar_t", "const", "struct", "enum", "union",
    "BOOL", "HANDLE", "DWORD", "FARPROC", "LPCSTR", "LPSTR", "LPVOID", "SIZE_T",
    "FxActor", "FxActorInstance", "FxAnim", "FxAnimGroup", "FxAnimSet",
    "FxLogListener", "FxLogManager", "FxNameEntry", "FxResourceManager",
    "FxMountResult", "FxMountUnmountResult", "_Facet_base",
})


class _ExprParser:
    """Small recursive-descent parser for Ghidra C pointer/call expressions."""

    def __init__(self, tokens: list[tuple[str, str]], var_sizes: dict[str, tuple[int, int]],
                 icall_ref_map: dict[str, int] | None = None):
        self.toks = tokens
        self.pos = 0
        self.var_sizes = var_sizes
        self.icall_ref_map = icall_ref_map or {}

    def peek(self, off: int = 0) -> tuple[str, str] | None:
        idx = self.pos + off
        return self.toks[idx] if idx < len(self.toks) else None

    def consume(self) -> tuple[str, str]:
        tok = self.toks[self.pos]
        self.pos += 1
        return tok

    def _looks_like_cast(self) -> tuple[int, int, int] | None:
        """If current '(' starts a C cast `(type [*...])`, return (end_pos, arith_sz, deref_sz)."""
        if self.peek() != ("(", "("):
            return None
        j = self.pos + 1
        n = len(self.toks)
        depth = 1
        parts = []
        has_star = False
        has_type_kw = False
        # Handle function-pointer casts like `undefined4 (*)[]` conservatively
        while j < n and depth > 0:
            k, v = self.toks[j]
            if k == "(":
                depth += 1
                parts.append(v)
            elif k == ")":
                depth -= 1
                if depth == 0:
                    break
                parts.append(v)
            else:
                if v == "*":
                    has_star = True
                if k == "ID" and v in _TYPE_KEYWORDS:
                    has_type_kw = True
                parts.append(v)
            j += 1
        if depth != 0 or not parts:
            return None
        # A cast must have a type keyword or `Type *` followed by an operand token
        if not has_type_kw and not (has_star and len(parts) <= 4 and all(p in ("*", "ID") or p.startswith("Fx") for p in parts)):
            return None
        # Also if next token after ')' is end of tokens, binary op, or ')' or ',' or ']', it's not a prefix cast
        if j + 1 >= n:
            return None
        nxt_k, nxt_v = self.toks[j + 1]
        if nxt_k in (")", "]", ",", "+", "-", "*", "/", "&", "->", ".", "CMP", "SHIFT"):
            # Exception: `(int *) - ...`? No, unary `-` or `*` or `&` CAN follow a cast!
            if nxt_k not in ("-", "*", "&"):
                return None
        t_str = " ".join(parts)
        asz, dsz = type_elem_size(t_str)
        return (j + 1, asz, dsz)

    def parse(self) -> tuple[tuple, int, int]:
        return self.parse_add()

    def parse_add(self) -> tuple[tuple, int, int]:
        lhs, asz, dsz = self.parse_mul()
        while (tok := self.peek()) is not None and tok[0] in ("+", "-"):
            op = self.consume()[0]
            rhs, rasz, rdsz = self.parse_mul()
            # Scale constant or non-pointer offset by pointer arith size
            if asz > 1 and rasz == 1:
                if rhs[0] == "const":
                    rhs = ("const", rhs[1] * asz)
                else:
                    rhs = ("mul", rhs, ("const", asz))
            elif op == "+" and rdsz == 1 and rasz > 1 and asz == 1:
                if lhs[0] == "const":
                    lhs = ("const", lhs[1] * rasz)
                else:
                    lhs = ("mul", lhs, ("const", rasz))
                asz, dsz = rasz, rdsz
            node_op = "add" if op == "+" else "sub"
            # Fold (add x (const 0)) or (const a + const b)
            if lhs[0] == "const" and rhs[0] == "const":
                lhs = ("const", lhs[1] + rhs[1] if op == "+" else lhs[1] - rhs[1])
            else:
                lhs = (node_op, lhs, rhs)
        return (lhs, asz, dsz)

    def parse_mul(self) -> tuple[tuple, int, int]:
        lhs, asz, dsz = self.parse_unary()
        while (tok := self.peek()) is not None and tok[0] in ("*", "SHIFT"):
            op = self.consume()[1]
            rhs, _, _ = self.parse_unary()
            if op == "*":
                if lhs[0] == "const" and rhs[0] == "const":
                    lhs = ("const", lhs[1] * rhs[1])
                else:
                    lhs = ("mul", lhs, rhs)
            elif op == "<<" and lhs[0] == "const" and rhs[0] == "const":
                lhs = ("const", lhs[1] << rhs[1])
            else:
                lhs = ("binop", op, lhs, rhs)
            asz, dsz = 1, 1
        return (lhs, asz, dsz)

    def parse_unary(self) -> tuple[tuple, int, int]:
        cast_info = self._looks_like_cast()
        if cast_info is not None:
            new_pos, asz, dsz = cast_info
            self.pos = new_pos
            inner, _, _ = self.parse_unary()
            return (inner, asz, dsz)
        tok = self.peek()
        if tok is None:
            return (("unknown", ""), 1, 1)
        k, v = tok
        if k == "*":
            self.consume()
            inner, asz, dsz = self.parse_unary()
            return (("deref", inner), dsz, 1)
        if k == "&":
            self.consume()
            inner, asz, dsz = self.parse_unary()
            if inner[0] == "global":
                return (("globref", inner[1]), 4, 1)
            if inner[0] == "fn":
                return (inner, 4, 1)
            return (("addrof", inner), 4, 1)
        if k == "-":
            self.consume()
            inner, _, _ = self.parse_unary()
            if inner[0] == "const":
                return (("const", -inner[1]), 1, 1)
            return (("neg", inner), 1, 1)
        if k in ("~", "!"):
            self.consume()
            inner, _, _ = self.parse_unary()
            return (("unop", k, inner), 1, 1)
        return self.parse_postfix()

    def parse_postfix(self) -> tuple[tuple, int, int]:
        node, asz, dsz = self.parse_primary()
        while (tok := self.peek()) is not None:
            if tok[0] == "[":
                self.consume()
                idx_ast, _, _ = self.parse()
                if self.peek() == ("]", "]"):
                    self.consume()
                if idx_ast[0] == "const":
                    off = idx_ast[1] * asz
                    addr = node if off == 0 else ("add", node, ("const", off))
                else:
                    scaled = idx_ast if asz == 1 else ("mul", idx_ast, ("const", asz))
                    addr = ("add", node, scaled)
                node = ("deref", addr)
                asz, dsz = dsz, 1
            elif tok[0] == "(":
                # Function call on `node`
                self.consume()
                args = []
                while (t := self.peek()) is not None and t != (")", ")"):
                    arg_ast, _, _ = self.parse()
                    args.append(arg_ast)
                    if self.peek() == (",", ","):
                        self.consume()
                    else:
                        break
                if self.peek() == (")", ")"):
                    self.consume()
                if node[0] == "fn":
                    node = ("dcall", node[1], tuple(args))
                elif node[0] == "var":
                    node = ("ecall", node[1], tuple(args))
                else:
                    node = ("call", node, tuple(args))
                asz, dsz = 1, 1
            elif tok[0] in ("ARROW", "."):
                op = self.consume()[0]
                if self.peek() and self.peek()[0] == "ID":
                    fld = self.consume()[1]
                    node = ("field", op, node, fld)
                asz, dsz = 1, 1
            else:
                break
        return (node, asz, dsz)

    def parse_primary(self) -> tuple[tuple, int, int]:
        tok = self.peek()
        if tok is None:
            return (("unknown", ""), 1, 1)
        k, v = tok
        if k == "(":
            self.consume()
            node, asz, dsz = self.parse()
            if self.peek() == (")", ")"):
                self.consume()
            return (node, asz, dsz)
        if k == "NUM":
            self.consume()
            return (("const", int(v)), 1, 1)
        if k == "STR":
            self.consume()
            return (("str", v), 1, 1)
        if k == "CHR":
            self.consume()
            return (("chr", v), 1, 1)
        if k == "ID":
            self.consume()
            if v.startswith("__ICALL_REF_") and v.endswith("__"):
                return (("icall_ref", int(v[12:-2])), 4, 1)
            m_fn = RE_HEX_FN.match(v)
            if m_fn:
                return (("fn", m_fn.group(1).lower()), 1, 1)
            m_dat = RE_DAT.match(v)
            if m_dat:
                return (("global", m_dat.group(1).lower()), 1, 1)
            if v.startswith("PTR_") and len(v) > 12:
                hx = v.rsplit("_", 1)[-1]
                if len(hx) == 8 and all(c in "0123456789abcdefABCDEF" for c in hx):
                    return (("ptr_sym", hx.lower()), 4, 1)
            if v.endswith("_exref"):
                return (("exref", v[:-6]), 4, 1)
            asz, dsz = self.var_sizes.get(v, (1, 1))
            return (("var", v), asz, dsz)
        self.consume()
        return (("unknown", v), 1, 1)


def parse_c_expr(expr: str, var_sizes: dict[str, tuple[int, int]]) -> tuple:
    """Parse a C expression string into a canonical AST tuple."""
    s = expr.strip()
    m_mi = RE_MI_ADJUST.match(s)
    if m_mi:
        return ("mi_adjust", m_mi.group(1), int(m_mi.group(3), 0))
    toks = _tokenize(s)
    if not toks:
        return ("unknown", "")
    ast, _, _ = _ExprParser(toks, var_sizes).parse()
    return ast


def extract_icall_target_ast(inner: str, var_sizes: dict[str, tuple[int, int]]) -> tuple[tuple, int | None, str]:
    """From `(<inner>)(args)` parse the function-pointer AST, slot offset (if deref), and root base."""
    s = inner.strip()
    # Strip the leading deref `*` representing the function-pointer call invocation
    if s.startswith("*"):
        s_fnptr = s[1:].strip()
    else:
        s_fnptr = s
    # Strip leading `(code *)` or `(code **)` cast only if outer deref wasn't part of `*(code **)`
    # Wait: in `**(code **)(*piVar1 + 0x18)`, s[1:] is `*(code **)(*piVar1 + 0x18)`, which parses to Deref(Add(Deref(Var('piVar1')), 0x18)).
    # In `*(code *)puVar4[3]`, s[1:] is `(code *)puVar4[3]`, which parses to Deref(Add(Var('puVar4'), 0xc)).
    ast = parse_c_expr(s_fnptr, var_sizes)
    slot_off: int | None = None
    base_name = ""
    if ast[0] == "deref":
        addr = ast[1]
        if addr[0] == "add" and addr[2][0] == "const":
            slot_off = addr[2][1]
            base_name = _root_name(addr[1])
        elif addr[0] == "sub" and addr[2][0] == "const":
            slot_off = -addr[2][1]
            base_name = _root_name(addr[1])
        else:
            slot_off = 0
            base_name = _root_name(addr)
    else:
        base_name = _root_name(ast)
    return (ast, slot_off, base_name)


def _root_name(ast: tuple) -> str:
    cur = ast
    while isinstance(cur, tuple):
        k = cur[0]
        if k == "var":
            return cur[1]
        if k in ("global", "globref"):
            return f"DAT_{cur[1]}"
        if k == "deref":
            cur = cur[1]
        elif k in ("add", "sub"):
            cur = cur[1]
        else:
            return k
    return ""


def _split_top_level_assign(stmt: str) -> tuple[str, str] | None:
    """Split `lhs = rhs` at depth 0 if '=' is assignment (not ==, !=, <=, >=)."""
    depth = 0
    in_str = False
    quote = ""
    i = 0
    n = len(stmt)
    while i < n:
        c = stmt[i]
        if in_str:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == quote:
                in_str = False
        else:
            if c in ('"', "'"):
                in_str = True
                quote = c
            elif c in ("(", "["):
                depth += 1
            elif c in (")", "]"):
                depth -= 1
            elif c == "=" and depth == 0:
                prev = stmt[i - 1] if i > 0 else ""
                nxt = stmt[i + 1] if i + 1 < n else ""
                if prev not in ("=", "!", "<", ">") and nxt != "=":
                    return (stmt[:i].strip(), stmt[i + 1:].strip())
        i += 1
    return None


def _strip_condition_wrapper(stmt: str) -> list[str]:
    """Extract sub-expressions from `if (...)`, `while (...)`, `else ...` or return `[stmt]`."""
    s = stmt.strip()
    # Peel leading labels e.g. `LAB_10001234:`
    while re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*:", s):
        s = s.split(":", 1)[1].strip()
    if s.startswith("else") and len(s) > 4 and s[4] in " \t\r\n":
        s = s[4:].strip()
    if not s:
        return []
    # Check if starts with if/while/switch
    m = re.match(r"^(?:if|while|switch)\s*\(", s)
    if m:
        open_idx = s.find("(", m.start())
        close_idx = find_matching_paren(s, open_idx)
        if close_idx > 0:
            cond = s[open_idx + 1:close_idx].strip()
            tail = s[close_idx + 1:].strip()
            out = [cond] if cond else []
            if tail:
                out.extend(_strip_condition_wrapper(tail))
            return out
    return [s]


def _strip_leading_casts(expr: str) -> str:
    s = expr.strip()
    while s.startswith("("):
        c = find_matching_paren(s, 0)
        if c < 0 or c + 1 >= len(s):
            break
        inner = s[1:c].strip()
        if inner.startswith("*"):
            break
        if any(kw in inner for kw in _TYPE_KEYWORDS) or ("*" in inner and not inner.startswith("*")):
            s = s[c + 1:].strip()
        else:
            break
    return s


def _replace_icall_spans(text: str, found_icalls: list[dict], icall_indices: list[int], offset: int) -> str:
    """Substitute icall spans inside `text` (sliced from sub_stmt[offset:]) with __ICALL_REF_k__."""
    # Only replace non-overlapping outermost spans within [offset, offset+len(text)]
    reps = []
    for fc, ic_idx in zip(found_icalls, icall_indices):
        s = fc["start"] - offset
        e = fc["end"] - offset
        if 0 <= s and e <= len(text):
            reps.append((s, e, f"__ICALL_REF_{ic_idx}__"))
    if not reps:
        return text
    # Sort by start, skip nested spans inside an already-replaced span
    reps.sort()
    out = []
    pos = 0
    for s, e, tok in reps:
        if s < pos:
            continue
        out.append(text[pos:s])
        out.append(tok)
        pos = e
    out.append(text[pos:])
    return "".join(out)


_EXT_FACTORY_RE = re.compile(
    r"\b(D3D11CreateDevice(?:AndSwapChain)?|Direct3DCreate9(?:Ex)?|DirectInput8Create|"
    r"CoCreateInstance|CreateDXGIFactory\d*|XAudio2Create|GetProcAddress|"
    r"Steam(?:User|Friends|Utils|Matchmaking|UserStats|Apps|Networking|RemoteStorage|Screenshots|HTTP|Client|UGC|Controller))\s*\("
)


def _collect_dcalls_in_expr(expr: str, var_sizes: dict[str, tuple[int, int]]) -> tuple[list[tuple[str, tuple]], list[tuple[str, tuple]]]:
    """Find all decomp_fn_XXXXXXXX(...) and key external API calls anywhere inside a compound expression."""
    dcalls = []
    for m in re.finditer(r"\bdecomp_fn_([0-9a-fA-F]{8})\s*\(", expr):
        callee = m.group(1).lower()
        open_idx = m.end() - 1
        close_idx = find_matching_paren(expr, open_idx)
        args_str = expr[open_idx + 1:close_idx] if close_idx > open_idx else ""
        arg_asts = tuple(parse_c_expr(a, var_sizes) for a in split_top_level_args(args_str))
        dcalls.append((callee, arg_asts))
    ecalls = []
    for m in _EXT_FACTORY_RE.finditer(expr):
        callee = m.group(1)
        open_idx = m.end() - 1
        close_idx = find_matching_paren(expr, open_idx)
        args_str = expr[open_idx + 1:close_idx] if close_idx > open_idx else ""
        arg_asts = tuple(parse_c_expr(a, var_sizes) for a in split_top_level_args(args_str))
        ecalls.append((callee, arg_asts))
    return dcalls, ecalls


def extract_function_ir(text: str, entry_hex: str) -> dict:
    """Parse one canonical_decomp C file into a compact function IR dict."""
    # Extract header signature & local declarations cleanly
    clean = strip_c_comments(text)
    m_brace = re.search(r"^\s*\{", clean, re.M)
    body_start = m_brace.end() - 1 if m_brace else clean.find("{")
    if body_start < 0:
        return {
            "entry": entry_hex,
            "cc": "",
            "ret_type": "",
            "params": [],
            "var_sizes": {},
            "icalls": [],
            "ops": [],
            "vtable_stores": [],
            "has_delete": False,
            "idiom_tags": [],
        }
    sig_text = clean[:body_start].strip()
    body_end = clean.rfind("}")
    body_text = clean[body_start + 1:body_end] if body_end > body_start else clean[body_start + 1:]

    cc = ""
    ret_type = ""
    params: list[tuple[str, str, int, int]] = []
    var_sizes: dict[str, tuple[int, int]] = {}
    m_sig = RE_FUNC_SIG.search(sig_text)
    if m_sig:
        ret_type = " ".join(m_sig.group(1).split())
        cc = m_sig.group(2) or ""
        params_raw = m_sig.group(5)
        for p in split_top_level_args(params_raw):
            parsed = parse_var_decl(p)
            if parsed:
                params.append(parsed)
                var_sizes[parsed[0]] = (parsed[2], parsed[3])

    # Split declarations at top of function body (before first blank line after decls, or first statement)
    body_lines = body_text.splitlines()
    stmt_lines = []
    in_decls = True
    seen_decl = False
    for ln in body_lines:
        stripped = ln.strip()
        if in_decls:
            if not stripped:
                if seen_decl:
                    in_decls = False
                continue
            # Local declarations never contain `=`, `(`, `goto`, `return`, `if`, `{`, `}`
            if ("=" not in stripped and "(" not in stripped
                    and not stripped.startswith(("goto ", "return", "if ", "for ", "while ", "do ", "switch "))
                    and ":" not in stripped and stripped.endswith(";")):
                parsed = parse_var_decl(stripped)
                if parsed:
                    var_sizes[parsed[0]] = (parsed[2], parsed[3])
                    seen_decl = True
                    continue
            in_decls = False
        stmt_lines.append(ln)

    body_code = "\n".join(stmt_lines)

    # Check idiom tags quickly
    idiom_tags = []
    # CA::BinaryStream signature pattern: var[2] < var[3] + ... and var[3] == var[2]
    m_bs = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\[2\]\s*<\s*\1\[3\]\s*\+", body_code)
    if m_bs:
        m_bs2 = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\[3\]\s*==\s*\1\[2\]", body_code))
        bs_vars = sorted(set(m_bs) & m_bs2)
        if bs_vars:
            idiom_tags.append(("binary_stream", bs_vars))

    has_delete = "decomp_fn_100d12c0" in body_code

    # Split into statements by ';' and '{' / '}' at paren depth 0
    raw_stmts: list[str] = []
    cur: list[str] = []
    pdepth = 0
    in_str = False
    quote = ""
    i = 0
    n = len(body_code)
    while i < n:
        c = body_code[i]
        if in_str:
            cur.append(c)
            if c == "\\" and i + 1 < n:
                i += 1
                cur.append(body_code[i])
            elif c == quote:
                in_str = False
        else:
            if c in ('"', "'"):
                in_str = True
                quote = c
                cur.append(c)
            elif c == "(":
                pdepth += 1
                cur.append(c)
            elif c == ")":
                pdepth -= 1
                cur.append(c)
            elif c in (";", "{", "}") and pdepth == 0:
                piece = "".join(cur).strip()
                if piece:
                    raw_stmts.append(piece)
                cur = []
            else:
                cur.append(c)
        i += 1
    if cur:
        piece = "".join(cur).strip()
        if piece:
            raw_stmts.append(piece)

    icalls: list[dict] = []
    ops: list[tuple] = []
    vtable_stores: list[tuple[int, tuple, str]] = []
    last_alloc_var: str | None = None
    last_alloc_stmt = -99

    stmt_idx = 0
    for raw_stmt in raw_stmts:
        for sub_stmt in _strip_condition_wrapper(raw_stmt):
            if not sub_stmt or sub_stmt in ("else", "do"):
                continue

            # Find indirect calls inside sub_stmt in order
            found_icalls = find_indirect_calls_in_text(sub_stmt)
            assign_pair = _split_top_level_assign(sub_stmt)

            lhs_var_if_icall: str | None = None
            if assign_pair and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", assign_pair[0]) and not RE_DAT.match(assign_pair[0]):
                lhs_var_if_icall = assign_pair[0]

            # Record icalls and replace them with placeholders so AST parser captures `x = icall_ref(k)`
            icall_indices_here: list[int] = []
            if found_icalls:
                # Filter out inner nested calls when checking top-level span; keep all in source order
                for fc in found_icalls:
                    ic_idx = len(icalls)
                    icall_indices_here.append(ic_idx)
                    target_ast, slot_off, base_name = extract_icall_target_ast(fc["inner"], var_sizes)
                    arg_asts = tuple(parse_c_expr(a, var_sizes) for a in fc["args_raw"])
                    icall_span = sub_stmt[fc["start"]:fc["end"]].strip()
                    rhs_nocast = _strip_leading_casts(assign_pair[1]) if assign_pair else ""
                    is_sole_rhs = bool(
                        assign_pair
                        and lhs_var_if_icall
                        and fc["start"] >= len(assign_pair[0]) + 1
                        and (icall_span == assign_pair[1].strip() or icall_span == rhs_nocast)
                    )
                    icalls.append({
                        "stmt_idx": stmt_idx,
                        "expr": fc["inner"],
                        "target_ast": target_ast,
                        "slot_offset": slot_off,
                        "base": base_name,
                        "arg_asts": arg_asts,
                        "arg_count": len(arg_asts),
                        "lhs_var": lhs_var_if_icall if is_sole_rhs else None,
                    })

            # Handle `return ...`
            if sub_stmt.startswith("return "):
                ret_expr = sub_stmt[7:].strip()
                ret_sub = _replace_icall_spans(ret_expr, found_icalls, icall_indices_here, len(sub_stmt) - len(ret_expr))
                ret_ast = parse_c_expr(ret_sub, var_sizes)
                for ic_idx in icall_indices_here:
                    ops.append(("icall", stmt_idx, ic_idx))
                ops.append(("ret", stmt_idx, ret_ast))
                stmt_idx += 1
                continue

            # Handle assignment / store
            if assign_pair:
                lhs_str, rhs_str = assign_pair
                # Check vtable store first: LHS = (cast)* &PTR_...
                m_vt = RE_PTR_SYM.search(rhs_str)
                # Ensure RHS is purely a PTR_ symbol (with optional casts) so we don't confuse table reads
                rhs_clean_cast = re.sub(r"\([^)]*\)", "", rhs_str).strip()
                if m_vt and rhs_clean_cast.startswith("&PTR_"):
                    vt_hex = m_vt.group(1).lower()
                    lhs_ast = parse_c_expr(lhs_str, var_sizes)
                    vtable_stores.append((stmt_idx, lhs_ast, vt_hex))
                    ops.append(("vstore", stmt_idx, lhs_ast, vt_hex))
                    stmt_idx += 1
                    continue

                # Emit any icalls in this statement before the assignment consumes their return value
                for ic_idx in icall_indices_here:
                    ops.append(("icall", stmt_idx, ic_idx))

                eq_pos = sub_stmt.find("=")
                rhs_offset = len(sub_stmt) - len(rhs_str)
                if eq_pos >= 0:
                    after_eq = sub_stmt[eq_pos + 1:]
                    rhs_offset = eq_pos + 1 + (len(after_eq) - len(after_eq.lstrip()))
                rhs_sub = _replace_icall_spans(rhs_str, found_icalls, icall_indices_here, rhs_offset)
                rhs_ast = parse_c_expr(rhs_sub, var_sizes)
                if lhs_var_if_icall:
                    ops.append(("assign", stmt_idx, lhs_var_if_icall, rhs_ast))
                    if rhs_ast[0] == "dcall":
                        callee_hex = rhs_ast[1]
                        implicit_this = None
                        if not rhs_ast[2] and last_alloc_var and (stmt_idx - last_alloc_stmt) <= 3:
                            implicit_this = last_alloc_var
                        if callee_hex == "100d12b0":
                            last_alloc_var = lhs_var_if_icall
                            last_alloc_stmt = stmt_idx
                        ops.append(("dcall", stmt_idx, callee_hex, rhs_ast[2], lhs_var_if_icall, implicit_this))
                else:
                    lhs_ast = parse_c_expr(lhs_str, var_sizes)
                    ops.append(("store", stmt_idx, lhs_ast, rhs_ast))
                    if rhs_ast[0] == "dcall":
                        ops.append(("dcall", stmt_idx, rhs_ast[1], rhs_ast[2], None, None))
                stmt_idx += 1
                continue

            # Standalone expression (e.g. direct call, icall, comma-separated `cVar = f(), cVar != 0`)
            for ic_idx in icall_indices_here:
                ops.append(("icall", stmt_idx, ic_idx))

            # Check for comma-joined condition expressions `(expr1, expr2)`
            sub_replaced = _replace_icall_spans(sub_stmt, found_icalls, icall_indices_here, 0)
            emitted_dcall = False
            for part in split_top_level_args(sub_replaced):
                p_assign = _split_top_level_assign(part)
                if p_assign:
                    l_s, r_s = p_assign
                    r_ast = parse_c_expr(r_s, var_sizes)
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", l_s) and not RE_DAT.match(l_s):
                        ops.append(("assign", stmt_idx, l_s, r_ast))
                        if r_ast[0] == "dcall":
                            emitted_dcall = True
                            implicit_this = None
                            if not r_ast[2] and last_alloc_var and (stmt_idx - last_alloc_stmt) <= 3:
                                implicit_this = last_alloc_var
                            if r_ast[1] == "100d12b0":
                                last_alloc_var = l_s
                                last_alloc_stmt = stmt_idx
                            ops.append(("dcall", stmt_idx, r_ast[1], r_ast[2], l_s, implicit_this))
                    else:
                        ops.append(("store", stmt_idx, parse_c_expr(l_s, var_sizes), r_ast))
                    continue
                part_ast = parse_c_expr(part, var_sizes)
                if part_ast[0] == "dcall":
                    emitted_dcall = True
                    callee_hex = part_ast[1]
                    arg_asts = part_ast[2]
                    implicit_this = None
                    if not arg_asts and last_alloc_var and (stmt_idx - last_alloc_stmt) <= 3:
                        implicit_this = last_alloc_var
                    ops.append(("dcall", stmt_idx, callee_hex, arg_asts, None, implicit_this))
                elif part_ast[0] == "ecall":
                    ops.append(("ecall", stmt_idx, part_ast[1], part_ast[2], None))
            if not emitted_dcall and ("decomp_fn_" in sub_replaced or _EXT_FACTORY_RE.search(sub_replaced)):
                dcs, ecs = _collect_dcalls_in_expr(sub_replaced, var_sizes)
                for callee_hex, arg_asts in dcs:
                    ops.append(("dcall", stmt_idx, callee_hex, arg_asts, None, None))
                for e_name, arg_asts in ecs:
                    ops.append(("ecall", stmt_idx, e_name, arg_asts, None))
            stmt_idx += 1

    return {
        "entry": entry_hex,
        "cc": cc,
        "ret_type": ret_type,
        "params": params,
        "var_sizes": var_sizes,
        "icalls": icalls,
        "ops": ops,
        "vtable_stores": vtable_stores,
        "has_delete": has_delete,
        "idiom_tags": idiom_tags,
    }


def _scan_chunk(paths: list[Path]) -> list[tuple[str, dict]]:
    out = []
    for p in paths:
        entry_hex = p.stem[10:].lower()
        txt = p.read_text(encoding="utf-8", errors="replace")
        out.append((entry_hex, extract_function_ir(txt, entry_hex)))
    return out


def extract_corpus(corpus_dir: Path, out_path: Path, workers: int = 8, limit: int = 0) -> dict[str, dict]:
    t0 = time.time()
    files = sorted(corpus_dir.glob("decomp_fn_*.c"))
    if limit > 0:
        files = files[:limit]
    chunks = [files[i::workers] for i in range(workers)]
    ir_map: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(_scan_chunk, chunks):
            for entry_hex, ir in res:
                ir_map[entry_hex] = ir
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        pickle.dump(ir_map, f, protocol=pickle.HIGHEST_PROTOCOL)
    elapsed = time.time() - t0
    total_icalls = sum(len(v["icalls"]) for v in ir_map.values())
    total_vstores = sum(len(v["vtable_stores"]) for v in ir_map.values())
    distinct_vts = len({vt for v in ir_map.values() for _, _, vt in v["vtable_stores"]})
    total_dcalls = sum(1 for v in ir_map.values() for op in v["ops"] if op[0] == "dcall")
    print(
        f"Extracted {len(ir_map)} functions in {elapsed:.2f}s -> {out_path}\n"
        f"  C icalls: {total_icalls}, vtable_stores: {total_vstores} ({distinct_vts} distinct vtables), "
        f"direct calls: {total_dcalls}"
    )
    return ir_map


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()
    extract_corpus(args.corpus, args.out, workers=args.workers, limit=args.limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
