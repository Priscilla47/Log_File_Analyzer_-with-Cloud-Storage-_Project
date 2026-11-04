"""The helpers behind the dashboard import and work without Streamlit."""

import importlib
import subprocess
import sys
import textwrap

from loginsight.dashboard import data


def test_the_module_has_the_texts_the_page_shows():
    assert data.APP_TITLE == "LogInsight"
    assert "access log" in data.EMPTY_MESSAGE.lower()


def test_importing_the_helpers_never_imports_streamlit():
    # in a fresh interpreter, so another test that imported Streamlit cannot hide a problem
    code = textwrap.dedent(
        """
        import sys
        import loginsight.dashboard
        import loginsight.dashboard.data
        import loginsight.dashboard.launch
        import loginsight.cli
        print("streamlit" in sys.modules)
        """
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert done.stdout.strip() == "False"


def test_the_helpers_import_when_streamlit_is_missing():
    code = textwrap.dedent(
        """
        import sys
        sys.modules["streamlit"] = None   # an import of it now raises ImportError
        import loginsight.dashboard.data, loginsight.dashboard.launch, loginsight.cli
        from loginsight.dashboard.launch import streamlit_available
        print(streamlit_available())
        """
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert done.stdout.strip() == "False"


def test_the_module_can_be_reloaded():
    assert importlib.reload(data).APP_TITLE == "LogInsight"


def test_the_page_file_holds_layout_only_and_no_logic():
    import ast
    from pathlib import Path

    from loginsight.dashboard.launch import APP_FILE

    tree = ast.parse(Path(APP_FILE).read_text(encoding="utf-8"))
    logic = (ast.If, ast.For, ast.While, ast.Try, ast.FunctionDef, ast.ClassDef, ast.Lambda,
             ast.comprehension, ast.IfExp, ast.BoolOp, ast.BinOp, ast.Compare)  # fmt: skip
    found = sorted({type(node).__name__ for node in ast.walk(tree) if isinstance(node, logic)})
    assert found == [], f"app.py must only lay out what data.py provides, found: {found}"


def test_the_page_file_is_left_out_of_coverage_for_that_reason():
    from pathlib import Path

    text = (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    assert 'omit = ["src/loginsight/dashboard/app.py"]' in text
