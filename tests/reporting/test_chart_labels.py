"""Chart labels never trigger a missing-glyph warning; unusual characters become escapes."""

import warnings

import pytest

from loginsight.cli import EXIT_OK, main
from loginsight.reporting import charts
from loginsight.reporting.charts import MAX_LABEL_LENGTH, plot_top_paths, top_paths_png


class TestLabel:
    @pytest.mark.parametrize(
        "path", ["/", "/index.html", "/a/b?c=d&e=f", "/café", "/Ελλάδα", "/москва"]
    )
    def test_characters_the_font_has_are_kept(self, path):
        assert charts._label(path) == path

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("/a\tb", "/a\\x09b"),
            ("/a\x1bb", "/a\\x1bb"),
            ("/a\x00b", "/a\\x00b"),
            ("/日本", "/\\u65e5\\u672c"),
            ("/🙂", "/\\U0001f642"),
            ("/a\u202eb", "/a\\u202eb"),  # right-to-left override: invisible, can reorder
            ("/a\u200bb", "/a\\u200bb"),  # zero-width space
            ("/a\u2028b", "/a\\u2028b"),
            ("/a\x85b", "/a\\x85b"),
        ],
    )
    def test_characters_the_font_lacks_become_escapes(self, path, expected):
        assert charts._label(path) == expected

    def test_the_label_is_still_shortened_and_the_dollar_still_escaped(self):
        assert len(charts._label("/" + "a" * 100)) == MAX_LABEL_LENGTH
        assert charts._label("/" + "a" * 100).endswith("…")
        assert charts._label("/price$5") == "/price\\$5"
        assert charts._label("") == "(no path)"

    def test_a_long_run_of_missing_characters_stays_bounded(self):
        assert len(charts._label("日" * 500)) <= MAX_LABEL_LENGTH

    def test_the_result_is_always_drawable(self):
        for path in ("\x00\x01\x02", "日本語", "🙂" * 5, "퟿￿"):
            label = charts._label(path)
            assert all(c.isprintable() and (charts._has_glyph(c) or c == "\\") for c in label), (
                label
            )


class TestNoWarnings:
    PATHS = [("/a\tb", 5), ("/\x1b[31m", 4), ("/日本語", 3), ("/🙂", 2), ("/ok", 1)]

    def test_drawing_the_chart_raises_no_warning(self, tmp_path):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            assert plot_top_paths(self.PATHS, tmp_path / "t.png").is_file()
            assert top_paths_png(self.PATHS).startswith(b"\x89PNG")

    def test_the_command_line_is_quiet_on_stderr(self, tmp_path, capsys):
        log = tmp_path / "odd.log"
        lines = []
        for n, path in enumerate(["/a%09b", "/%1b%5b31m", "/%E6%97%A5%E6%9C%AC", "/ok"]):
            lines.append(
                f'203.0.113.9 - - [10/Oct/2026:10:00:0{n} +0000] "GET {path} HTTP/1.1" '
                '200 5 "-" "x"'
            )
        # raw characters, as a server that does not escape them would write
        lines.append(
            '203.0.113.9 - - [10/Oct/2026:10:00:09 +0000] "GET /日本\t🙂 HTTP/1.1" 200 5 "-" "x"'
        )
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            assert main(["analyze", str(log), "--output", str(tmp_path / "out")]) == EXIT_OK
        assert capsys.readouterr().err == ""
