"""Instruction families for the lifter.

Each module registers handlers by capstone mnemonic with the ``@op`` decorator.
A handler has the signature ``handler(e, i)`` where ``e`` is the function's
``Emitter`` (see base.py) and ``i`` the instruction view; it appends C
statements with ``e.line`` and raises ``Unsupported`` for forms it does not
translate. Adding a family is a new module here plus one name in ``FAMILIES``.

The runtime the emitted C calls is declared in
port/lifted_runtime/lift_rt.h.
"""
from __future__ import annotations

import importlib

from .base import REGISTRY, Emitter, Ins, Unsupported, op  # noqa: F401

FAMILIES = ("control", "arith", "logic", "move", "string", "misc", "thunks")

for _name in FAMILIES:
    importlib.import_module(f"{__name__}.{_name}")
