"""Tests that keep the documentation true: its commands run and its links and names exist."""

import re
import shlex
from pathlib import Path

import pytest

from loginsight.cli import main

ROOT = Path(__file__).parents[1]
SRC = ROOT / "src" / "loginsight"
DOCS = ROOT / "docs"
USAGE = DOCS / "USAGE.md"
MARKDOWN_FILES = [ROOT / "README.md", *sorted(DOCS.glob("*.md"))]

COMMAND = re.compile(r"^\$ (loginsight .+)$", re.MULTILINE)
LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)\)")
BACKTICKED_PY = re.compile(r"`((?:[\w.-]+/)*[\w-]+\.py)`")


def usage_commands() -> list[str]:
    return COMMAND.findall(USAGE.read_text(encoding="utf-8"))


def with_temporary_output(arguments: list[str], folder: Path) -> list[str]:
    """The arguments with the folder after ``--output`` replaced by ``folder``."""
    result = list(arguments)
    if "--output" in result:
        result[result.index("--output") + 1] = str(folder)
    return result


class TestUsageCommands:
    def test_the_guide_has_commands_to_check(self):
        commands = usage_commands()
        assert len(commands) >= 8
        assert any("--output" in command for command in commands)
        assert any("analyze" in command for command in commands)
        assert any("detect" in command for command in commands)
        assert any("--version" in command for command in commands)

    @pytest.mark.parametrize("command", usage_commands())
    def test_each_command_runs_successfully(self, command, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(ROOT)  # the commands name files relative to the repository
        arguments = shlex.split(command)
        assert arguments[0] == "loginsight"
        status = main(with_temporary_output(arguments[1:], tmp_path / "out"))
        captured = capsys.readouterr()
        assert status == 0, captured.err
        assert captured.out.strip()
        assert "Traceback" not in captured.err

    def test_every_sample_path_in_the_guide_exists(self):
        text = USAGE.read_text(encoding="utf-8")
        for path in set(re.findall(r"data/samples/[\w.]+", text)):
            assert (ROOT / path).exists(), path

    def test_every_option_of_the_commands_is_documented(self):
        text = USAGE.read_text(encoding="utf-8")
        for option in ("--format", "--output", "--top", "--bucket", "--min-severity", "--version"):
            assert option in text, option


class TestLinks:
    @pytest.mark.parametrize("path", MARKDOWN_FILES, ids=lambda path: path.name)
    def test_relative_links_point_to_existing_files(self, path):
        broken = []
        for target in LINK.findall(path.read_text(encoding="utf-8")):
            if re.match(r"[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
                continue  # a web address, an e-mail address or a link within the page
            if not (path.parent / target.split("#")[0]).exists():
                broken.append(target)
        assert not broken, f"broken links in {path.name}: {broken}"

    def test_the_documents_link_to_each_other(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for name in ("GOALS", "ARCHITECTURE", "STRUCTURE", "USAGE"):
            assert f"docs/{name}.md" in readme, name

    def test_the_link_finder_finds_links(self):
        assert LINK.findall("see [a](docs/A.md) and [b](https://x.org/y#z) ![i](p.png)") == [
            "docs/A.md",
            "https://x.org/y#z",
        ]


def source_modules() -> list[Path]:
    return sorted(
        path for path in SRC.rglob("*.py") if path.name != "__init__.py" and path.stat().st_size
    )


def source_packages() -> list[str]:
    return sorted(path.name for path in SRC.iterdir() if path.is_dir() and path.name[0] != "_")


class TestArchitecture:
    text = (DOCS / "ARCHITECTURE.md").read_text(encoding="utf-8")

    def test_every_module_it_names_exists(self):
        missing = []
        for name in BACKTICKED_PY.findall(self.text):
            home = ROOT if name.startswith(("tests/", "scripts/")) else SRC
            if not any(home.rglob(name)) if "/" not in name else not (home / name).exists():
                missing.append(name)
        assert not missing, f"ARCHITECTURE.md names modules that do not exist: {missing}"

    def test_every_module_that_exists_is_named(self):
        named = set(BACKTICKED_PY.findall(self.text))
        unnamed = [
            str(path.relative_to(SRC))
            for path in source_modules()
            if path.name not in named and str(path.relative_to(SRC)) not in named
        ]
        assert not unnamed, f"ARCHITECTURE.md leaves out: {unnamed}"

    def test_every_package_has_a_section(self):
        for package in source_packages():
            assert f"`{package}/`" in self.text, package

    def test_planned_parts_are_marked_planned(self):
        assert re.search(r"Storage \(`storage/`\), planned", self.text)
        assert re.search(r"Dashboard \(`dashboard/`\), planned", self.text)

    def test_the_rule_counts_are_right(self):
        from loginsight.detection import load_rules

        rules = load_rules()
        by_label = {}
        for rule in rules.signatures:
            by_label[rule.label] = by_label.get(rule.label, 0) + 1
        assert f"There are {len(rules.signatures)} signature rules" in self.text
        for label, count in by_label.items():
            assert count == int(
                re.search(rf"(\d+) {re.escape(LABEL_WORDS[label])}", self.text).group(1)
            )

    def test_the_finders_work(self):
        assert BACKTICKED_PY.findall("`a.py` `b/c.py` `d.toml` `e`") == ["a.py", "b/c.py"]


LABEL_WORDS = {
    "sql_injection": "SQL injection",
    "xss": "XSS",
    "path_traversal": "path traversal",
    "command_injection": "command injection",
    "sensitive_file_probe": "sensitive-file probes",
}


class TestStructure:
    text = (DOCS / "STRUCTURE.md").read_text(encoding="utf-8")

    def test_every_package_is_listed(self):
        for package in source_packages():
            assert f"{package}/" in self.text, package

    def test_nothing_is_called_planned_that_exists(self):
        assert "planned design" not in self.text
