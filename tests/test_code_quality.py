"""Guards that keep the public code documented and typed, and mypy clean."""

import ast
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "loginsight"
SOURCE_FILES = sorted(SRC.rglob("*.py"))
# Methods that Python calls itself still need their parameters typed.
SPECIAL = ("__init__", "__post_init__")


def public_definitions(tree):
    """Public functions, methods and classes (not nested inside a function)."""

    def walk(body, in_function=False):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                is_function = not isinstance(node, ast.ClassDef)
                if not in_function and not node.name.startswith("_"):
                    yield node
                elif not in_function and node.name in SPECIAL:
                    yield node
                yield from walk(node.body, in_function or is_function)

    return walk(tree.body)


def where(path, node):
    return f"{path.relative_to(ROOT)}:{node.lineno} {node.name}"


@pytest.mark.parametrize("path", SOURCE_FILES, ids=lambda p: str(p.relative_to(SRC)))
def test_every_module_has_a_docstring(path):
    if path.name == "__init__.py" and path.stat().st_size == 0:
        pytest.skip("an empty package marker")
    assert ast.get_docstring(ast.parse(path.read_text(encoding="utf-8"))), path


@pytest.mark.parametrize("path", SOURCE_FILES, ids=lambda p: str(p.relative_to(SRC)))
def test_every_public_function_and_class_has_a_docstring(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    missing = [
        where(path, node)
        for node in public_definitions(tree)
        if node.name not in SPECIAL and not ast.get_docstring(node)
    ]
    assert not missing, f"no docstring: {missing}"


@pytest.mark.parametrize("path", SOURCE_FILES, ids=lambda p: str(p.relative_to(SRC)))
def test_every_public_function_has_typed_parameters_and_a_return_type(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    problems = []
    for node in public_definitions(tree):
        if isinstance(node, ast.ClassDef):
            continue
        args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        args += [a for a in (node.args.vararg, node.args.kwarg) if a]
        untyped = [a.arg for a in args if a.annotation is None and a.arg not in ("self", "cls")]
        if untyped:
            problems.append(f"{where(path, node)}: parameters without a type: {untyped}")
        if node.returns is None:
            problems.append(f"{where(path, node)}: no return type")
    assert not problems, "\n".join(problems)


@pytest.mark.skipif(
    shutil.which("mypy") is None and not Path(sys.executable).with_name("mypy").exists(),
    reason="mypy is not installed",
)
def test_mypy_reports_no_errors():
    command = [sys.executable, "-m", "mypy", "src"]
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stdout + done.stderr


def test_the_guards_find_what_they_are_meant_to_find():
    tree = ast.parse(
        "def public(a, b: int):\n    pass\n"
        "def _private(a):\n    pass\n"
        "class C:\n    def method(self, x):\n        def inner(y):\n            pass\n"
        "    def __init__(self, z):\n        pass\n"
    )
    names = [node.name for node in public_definitions(tree)]
    assert names == ["public", "C", "method", "__init__"]
