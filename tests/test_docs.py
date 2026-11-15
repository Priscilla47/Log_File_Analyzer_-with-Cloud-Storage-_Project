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
        if arguments[1] == "dashboard":
            pytest.skip("starts a server: its arguments are checked by the next test")
        status = main(with_temporary_output(arguments[1:], tmp_path / "out"))
        captured = capsys.readouterr()
        assert status == 0, captured.err
        assert captured.out.strip()
        assert "Traceback" not in captured.err

    @pytest.mark.parametrize("command", [c for c in usage_commands() if " dashboard" in c])
    def test_a_documented_dashboard_command_is_valid_without_starting_it(self, command):
        from loginsight.cli import build_parser

        arguments = shlex.split(command)[1:]
        assert build_parser().parse_args(arguments).command == "dashboard"

    def test_the_guide_documents_the_dashboard_command(self):
        assert any(" dashboard" in command for command in usage_commands())

    def test_every_sample_path_in_the_guide_exists(self):
        text = USAGE.read_text(encoding="utf-8")
        for path in set(re.findall(r"data/samples/[\w.]+", text)):
            assert (ROOT / path).exists(), path

    def test_every_option_of_the_commands_is_documented(self):
        text = USAGE.read_text(encoding="utf-8")
        for option in (
            "--format",
            "--output",
            "--top",
            "--bucket",
            "--min-severity",
            "--rules",
            "--port",
            "--version",
        ):
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
        assert re.search(r"Storage \(`storage/`\)\n", self.text)  # built: not marked planned
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


class TestImages:
    IMAGE = re.compile(r"!\[([^\]]*)\]\(([^)\s]+)\)")

    @pytest.mark.parametrize("path", MARKDOWN_FILES, ids=lambda path: path.name)
    def test_every_image_exists_and_has_a_description(self, path):
        for alt, target in self.IMAGE.findall(path.read_text(encoding="utf-8")):
            if re.match(r"[a-z][a-z0-9+.-]*:", target):
                continue  # a web address
            assert (path.parent / target).is_file(), f"{path.name}: missing image {target}"
            assert len(alt) >= 15, f"{path.name}: the image {target} needs a real description"

    def test_the_dashboard_is_shown_in_the_readme_and_the_usage_guide(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        usage = USAGE.read_text(encoding="utf-8")
        assert "docs/images/dashboard-overview.png" in readme
        assert (
            "images/dashboard-overview.png" in usage and "images/dashboard-detections.png" in usage
        )

    def test_the_images_are_small_enough_for_a_repository(self):
        sizes = {path.name: path.stat().st_size for path in (DOCS / "images").glob("*.png")}
        assert sizes and all(size < 200_000 for size in sizes.values()), sizes

    def test_the_images_show_only_synthetic_data(self):
        # the page in the pictures was made from data/samples/demo.log, whose addresses all come
        # from the ranges reserved for documentation (see data/samples/README.md)
        text = (DOCS / "USAGE.md").read_text(encoding="utf-8")
        assert "data/samples/demo.log" in text and "synthetic" in text

    def test_the_image_finder_finds_images_and_not_links(self):
        found = self.IMAGE.findall("see [a](x.md) and ![a picture of a chart](p.png)")
        assert found == [("a picture of a chart", "p.png")]


class TestPerformanceGuide:
    text = (DOCS / "PERFORMANCE.md").read_text(encoding="utf-8")

    def test_the_limit_it_states_is_the_one_the_dashboard_keeps(self):
        from loginsight.dashboard.data import UPLOAD_LIMIT_BYTES, UPLOAD_LIMIT_MB

        assert UPLOAD_LIMIT_BYTES == UPLOAD_LIMIT_MB * 1_000_000
        assert f"{UPLOAD_LIMIT_MB} MB" in self.text and f"{UPLOAD_LIMIT_BYTES:,} bytes" in self.text

    def test_it_is_linked_from_the_readme_and_the_usage_guide(self):
        assert "docs/PERFORMANCE.md" in (ROOT / "README.md").read_text(encoding="utf-8")
        assert "PERFORMANCE.md" in USAGE.read_text(encoding="utf-8")

    def test_the_log_it_measured_is_under_the_limit(self):
        from loginsight.dashboard.data import UPLOAD_LIMIT_BYTES

        size = int(re.search(r"\*\*Log:\*\* ([\d,]+) bytes", self.text).group(1).replace(",", ""))
        assert size < UPLOAD_LIMIT_BYTES
