"""Static Python analysis helpers. Parses with `ast` only: nothing is ever executed or imported."""

from __future__ import annotations

import ast
from collections.abc import Iterator

from .context import FileContext

MAX_AST_BYTES = 1_000_000


def parse(ctx: FileContext) -> ast.Module | None:
    """Cached parse of a Python file; None if not Python, too big, or unparseable."""
    cache = ctx.__dict__
    if "_pyast" in cache:
        return cache["_pyast"]
    tree: ast.Module | None = None
    if ctx.language == "python" and not ctx.is_binary and len(ctx.text) <= MAX_AST_BYTES:
        try:
            tree = ast.parse(ctx.text, filename=ctx.rel_path)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            tree = None
    cache["_pyast"] = tree
    return tree


def import_aliases(tree: ast.Module) -> dict[str, str]:
    """Map local names to fully qualified ones: `from os import system as s` -> {'s': 'os.system'}."""
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                out[a.asname or a.name] = f"{node.module}.{a.name}"
    return out


def dotted_name(node: ast.AST, aliases: dict[str, str] | None = None) -> str | None:
    """`os.path.join` for Attribute/Name chains, resolving import aliases on the first part."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        head = node.id
        if aliases and head in aliases:
            head = aliases[head]
        parts.append(head)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):  # e.g. __import__('os').system
        inner = dotted_name(node.func, aliases)
        if inner in {"__import__", "importlib.import_module"} and node.args:
            mod = const_str(node.args[0])
            if mod:
                parts.append(mod)
                return ".".join(reversed(parts))
    return None


def call_name(call: ast.Call, aliases: dict[str, str] | None = None) -> str | None:
    return dotted_name(call.func, aliases)


def const_str(node: ast.AST, depth: int = 0) -> str | None:
    """Constant-fold string expressions: 'ev'+'al', ''.join(['a','b']), chr(101)+..., f-strings of constants."""
    if depth > 30:
        return None
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return node.value
        if isinstance(node.value, bytes):
            return node.value.decode("latin-1")
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = const_str(node.left, depth + 1), const_str(node.right, depth + 1)
        if left is not None and right is not None:
            return left + right
        return None
    if isinstance(node, ast.JoinedStr):
        pieces: list[str] = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                pieces.append(v.value)
            elif isinstance(v, ast.FormattedValue):
                inner = const_str(v.value, depth + 1)
                if inner is None:
                    return None
                pieces.append(inner)
        return "".join(pieces)
    if isinstance(node, ast.Call):
        fn = dotted_name(node.func)
        if fn == "chr" and len(node.args) == 1 and isinstance(node.args[0], ast.Constant):
            v = node.args[0].value
            if isinstance(v, int) and 0 <= v < 0x110000:
                return chr(v)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
            and len(node.args) == 1
            and isinstance(node.args[0], (ast.List, ast.Tuple))
        ):
            sep = const_str(node.func.value, depth + 1)
            items = [const_str(e, depth + 1) for e in node.args[0].elts]
            if sep is not None and all(i is not None for i in items):
                return sep.join(items)  # type: ignore[arg-type]
        if fn == "bytes" and node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
            vals = [e.value for e in node.args[0].elts if isinstance(e, ast.Constant) and isinstance(e.value, int)]
            if len(vals) == len(node.args[0].elts) and all(0 <= v < 256 for v in vals):
                return bytes(vals).decode("latin-1")
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
        base = const_str(node.value, depth + 1)
        s = node.slice
        if base is not None and s.lower is None and s.upper is None and isinstance(s.step, ast.UnaryOp):
            if isinstance(s.step.op, ast.USub) and isinstance(s.step.operand, ast.Constant) and s.step.operand.value == 1:
                return base[::-1]
    return None


def iter_calls(tree: ast.AST) -> Iterator[ast.Call]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def enclosing_functions(tree: ast.Module) -> Iterator[ast.AST]:
    """Module plus every function body: the scopes used for intra-function dataflow checks."""
    yield tree
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            yield node


def calls_in_scope(scope: ast.AST, aliases: dict[str, str]) -> list[tuple[str, ast.Call]]:
    """(resolved name, call) for calls inside scope, not descending into nested functions."""
    out: list[tuple[str, ast.Call]] = []
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Call):
            name = call_name(node, aliases)
            if name:
                out.append((name, node))
        stack.extend(ast.iter_child_nodes(node))
    return out


def subtree_call_names(node: ast.AST, aliases: dict[str, str]) -> set[str]:
    """Every resolved call name anywhere inside node (used for decode->exec chains)."""
    names: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            n = call_name(sub, aliases)
            if n:
                names.add(n)
                names.add(n.rsplit(".", 1)[-1])
    return names


def segment(ctx: FileContext, node: ast.AST, limit: int = 200) -> str:
    line = getattr(node, "lineno", None)
    return ctx.line_text(line)[:limit] if line else ""
