"""Guards that keep the public code documented and typed, and mypy clean."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "loginsight"
SOURCE_FILES = sorted(SRC.rglob("*.py"))
LABEL = lambda path: str(path.relative_to(SRC))  # noqa: E731


def _is_dunder(name):
    return name.startswith("__") and name.endswith("__")


def public_definitions(tree):
    """Public functions, methods and classes, wherever they are written.

    That includes the ones inside ``if``, ``try`` and ``with`` blocks, and the special methods
    Python calls itself (``__init__``, ``__call__``, ...). Not included: anything inside a
    function, and anything inside a class or function whose name starts with an underscore.
    """

    def walk(body, hidden=False):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                is_function = not isinstance(node, ast.ClassDef)
                private = node.name.startswith("_") and not _is_dunder(node.name)
                if not hidden and not private:
                    yield node
                yield from walk(node.body, hidden or private or is_function)
            else:
                for field in ("body", "orelse", "finalbody"):
                    yield from walk(getattr(node, field, None) or [], hidden)
                for handler in getattr(node, "handlers", []):
                    yield from walk(handler.body, hidden)
                for case in getattr(node, "cases", []):
                    yield from walk(case.body, hidden)

    return walk(tree.body)


def where(path, node):
    return f"{path.relative_to(ROOT)}:{node.lineno} {node.name}"


def undocumented(tree, path=ROOT / "x.py"):
    """Public functions and classes with no docstring (special methods need none)."""
    return [
        where(path, node)
        for node in public_definitions(tree)
        if not _is_dunder(node.name) and not ast.get_docstring(node)
    ]


def untyped(tree, path=ROOT / "x.py"):
    """Public functions with a parameter or a return value that has no type."""
    problems = []
    for node in public_definitions(tree):
        if isinstance(node, ast.ClassDef):
            continue
        args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        args += [a for a in (node.args.vararg, node.args.kwarg) if a]
        missing = [a.arg for a in args if a.annotation is None and a.arg not in ("self", "cls")]
        if missing:
            problems.append(f"{where(path, node)}: parameters without a type: {missing}")
        if node.returns is None:
            problems.append(f"{where(path, node)}: no return type")
    return problems


@pytest.mark.parametrize("path", SOURCE_FILES, ids=LABEL)
def test_every_module_has_a_docstring(path):
    if path.name == "__init__.py" and path.stat().st_size == 0:
        pytest.skip("an empty package marker")
    assert ast.get_docstring(ast.parse(path.read_text(encoding="utf-8"))), path


@pytest.mark.parametrize("path", SOURCE_FILES, ids=LABEL)
def test_every_public_function_and_class_has_a_docstring(path):
    missing = undocumented(ast.parse(path.read_text(encoding="utf-8")), path)
    assert not missing, f"no docstring: {missing}"


@pytest.mark.parametrize("path", SOURCE_FILES, ids=LABEL)
def test_every_public_function_has_typed_parameters_and_a_return_type(path):
    problems = untyped(ast.parse(path.read_text(encoding="utf-8")), path)
    assert not problems, "\n".join(problems)


def test_mypy_reports_no_errors():
    pytest.importorskip("mypy")
    command = [sys.executable, "-m", "mypy", "src"]
    try:
        done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        pytest.fail("mypy did not finish in 300 seconds")
    assert done.returncode == 0, done.stdout + done.stderr


# --- the guards themselves must be able to fail -------------------------------------------


def names(source):
    return [node.name for node in public_definitions(ast.parse(source))]


def test_the_traversal_finds_public_names_wherever_they_are():
    assert names(
        "def public(a, b: int):\n    pass\n"
        "def _private(a):\n    pass\n"
        "class C:\n    def method(self, x):\n        def inner(y):\n            pass\n"
        "    def __init__(self, z):\n        pass\n"
        "    def _hidden(self):\n        pass\n"
    ) == ["public", "C", "method", "__init__"]


def test_the_traversal_looks_inside_if_try_with_for_and_match_blocks():
    source = (
        "if True:\n    def in_if(a): ...\nelse:\n    def in_else(a): ...\n"
        "try:\n    def in_try(a): ...\nexcept ValueError:\n    def in_except(a): ...\n"
        "else:\n    def in_try_else(a): ...\nfinally:\n    def in_finally(a): ...\n"
        "with open('x') as f:\n    def in_with(a): ...\n"
        "for _ in []:\n    def in_for(a): ...\n"
        "while False:\n    def in_while(a): ...\n"
        "match 1:\n    case 1:\n        def in_match(a): ...\n"
    )
    assert names(source) == [
        "in_if", "in_else", "in_try", "in_try_else", "in_finally", "in_except",
        "in_with", "in_for", "in_while", "in_match",
    ]  # fmt: skip


def test_the_traversal_skips_what_is_inside_private_classes_and_functions():
    assert names("class _Hidden:\n    def method(self): ...\ndef f():\n    class Inner: ...\n") == [
        "f"
    ]


def test_the_docstring_guard_flags_what_has_none():
    tree = ast.parse(
        'def good():\n    """Doc."""\n'
        "def bad(): ...\n"
        "class Bad:\n    def method(self): ...\n"
        "if True:\n    def hidden_in_if(): ...\n"
        "class Ok:\n    '''Doc.'''\n    def __call__(self): ...\n"
    )
    assert [m.split(" ", 1)[1] for m in undocumented(tree)] == [
        "bad", "Bad", "method", "hidden_in_if",
    ]  # fmt: skip


def test_the_typing_guard_flags_missing_types_including_special_methods():
    tree = ast.parse(
        "def good(a: int) -> int: ...\n"
        "def no_param(a) -> int: ...\n"
        "def no_return(a: int): ...\n"
        "class C:\n    def __call__(self, y): ...\n    def __enter__(self): ...\n"
        "    def fine(self, x: int) -> None: ...\n"
        "try:\n    def in_try(*args, **kwargs) -> None: ...\nexcept OSError:\n    pass\n"
    )
    flagged = [p.split(":", 2)[1].split(" ", 1)[1].split(":")[0] for p in untyped(tree)]
    assert flagged == [
        "no_param", "no_return", "__call__", "__call__", "__enter__", "in_try",
    ]  # fmt: skip
