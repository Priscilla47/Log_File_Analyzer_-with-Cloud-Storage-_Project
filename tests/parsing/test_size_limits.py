"""A size field that is not a plausible byte count is a bad line, never a crash."""

import json

import pytest

from loginsight.cli import EXIT_OK, main
from loginsight.parsing.parser import MAX_SIZE_DIGITS, LogParseError, parse_line, parse_text
from loginsight.reporting.report import human_bytes

GOOD = '203.0.113.9 - - [10/Oct/2026:10:00:0{n} +0000] "GET /a HTTP/1.1" 200 {size} "-" "x"'


def line(size, n=1):
    return GOOD.format(n=n, size=size)


class TestParser:
    def test_the_limit_is_nineteen_digits(self):
        assert MAX_SIZE_DIGITS == 19

    @pytest.mark.parametrize("digits", [1, 10, 18, 19])
    def test_up_to_the_limit_is_accepted(self, digits):
        assert parse_line(line("9" * digits)).size == int("9" * digits)

    @pytest.mark.parametrize("digits", [20, 21, 100, 400, 4299, 4300, 4301, 5000, 8000])
    def test_beyond_the_limit_is_a_bad_size_not_a_crash(self, digits):
        with pytest.raises(LogParseError) as raised:
            parse_line(line("9" * digits))
        assert raised.value.reason == "bad_size"

    def test_leading_zeros_count_as_digits(self):
        assert parse_line(line("0" * 18 + "7")).size == 7  # 19 digits
        with pytest.raises(LogParseError) as raised:
            parse_line(line("0" * 20 + "7"))
        assert raised.value.reason == "bad_size"

    def test_a_dash_and_zero_are_unchanged(self):
        assert parse_line(line("-")).size == 0
        assert parse_line(line("0")).size == 0

    def test_other_bad_sizes_are_unchanged(self):
        for size in ("12a", "-5", "1.5", "١٢٣"):
            with pytest.raises(LogParseError) as raised:
                parse_line(line(size))
            assert raised.value.reason == "bad_size"

    def test_the_line_is_skipped_and_counted_and_the_rest_is_read(self):
        text = "\n".join([line("5", 1), line("9" * 5000, 2), line("9" * 400, 3), line("7", 4)])
        result = parse_text(text)
        assert [e.size for e in result.entries] == [5, 7]
        assert result.stats.skipped_by_reason == {"bad_size": 2}

    def test_the_largest_accepted_totals_still_render(self):
        count = int("9" * 19) * 1_000_000  # a million of the largest accepted sizes
        assert human_bytes(count).endswith("TiB")


class TestWholeProgram:
    @pytest.fixture
    def log(self, tmp_path):
        path = tmp_path / "huge.log"
        path.write_text(
            "\n".join(
                [line("9" * 5000, 1), line("9" * 400, 2)]
                + [line(str(1000 + n), n % 10) for n in range(30)]
            )
            + "\n"
        )
        return path

    @pytest.mark.parametrize("fmt", ["text", "md", "json"])
    def test_every_format_works_and_exits_zero(self, log, capsys, fmt):
        assert main(["analyze", str(log), "--format", fmt]) == EXIT_OK
        out, err = capsys.readouterr()
        assert "Traceback" not in err and out
        if fmt == "json":
            data = json.loads(out)
            assert data["source"]["parse"]["skipped_by_reason"] == {"bad_size": 2}
            assert data["summary"]["total_requests"] == 30

    def test_many_maximal_sizes_do_not_overflow_a_report(self, tmp_path, capsys):
        path = tmp_path / "big.log"
        path.write_text("\n".join(line("9" * 19, n % 10) for n in range(40)) + "\n")
        for fmt in ("text", "md"):
            assert main(["analyze", str(path), "--format", fmt]) == EXIT_OK
            assert "TiB" in capsys.readouterr().out
