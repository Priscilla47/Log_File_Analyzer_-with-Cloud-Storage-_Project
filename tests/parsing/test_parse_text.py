"""parse_text must give exactly what parse_file gives for the same bytes."""

import pytest

from loginsight.parsing.parser import parse_file, parse_text

GOOD = '203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "GET /a HTTP/1.1" 200 15 "-" "x"'
OTHER = '198.51.100.7 - - [10/Oct/2026:10:00:02 +0000] "GET /b HTTP/1.1" 404 0 "-" "x"'

CASES = {
    "empty": "",
    "only blanks": "\n  \n\t\n",
    "unix": f"{GOOD}\n{OTHER}\n",
    "no final newline": f"{GOOD}\n{OTHER}",
    "windows": f"{GOOD}\r\n{OTHER}\r\n",
    "old mac": f"{GOOD}\r{OTHER}\r",
    "mixed endings": f"{GOOD}\r\n{OTHER}\rjunk\nmore junk\r\n",
    "junk between": f"junk\n{GOOD}\n\n\nnot a log line\n{OTHER}\n",
    "line separators that are not line ends": f"{GOOD}\x0b\x0c\x1c \n{OTHER}\n",
    "separator inside a line": f"first\x0bsecond\x1cthird\x85fourth\u2028fifth\n{GOOD}\n",
    "blank lines keep line numbers": f"\n\nbad\n\n{GOOD}\nbad again\n",
    "non-ascii": f'{GOOD}\n198.51.100.8 - - [10/Oct/2026:10:00:03 +0000] "GET /é HTTP/1.1" 200 1\n',
    "very long line": "x" * 20000 + f"\n{GOOD}\n",
    "more than ten problems": "".join(f"bad {n}\n" for n in range(25)) + GOOD + "\n",
}


@pytest.mark.parametrize("name", CASES)
def test_same_result_as_parse_file(name, tmp_path):
    path = tmp_path / "x.log"
    path.write_bytes(CASES[name].encode("utf-8"))
    assert parse_text(path.read_bytes().decode("utf-8")) == parse_file(path)


def test_the_line_numbers_in_the_problems_are_those_of_the_text():
    result = parse_text(f"\n\nbad\n\n{GOOD}\nbad again\n")
    assert [(i.line_number, i.reason) for i in result.stats.first_errors] == [
        (3, "no_match"),
        (6, "no_match"),
    ]
    assert (result.stats.total_lines, result.stats.parsed, result.stats.skipped) == (3, 1, 2)


def test_an_empty_text_has_no_entries_and_no_lines():
    result = parse_text("")
    assert result.entries == [] and result.stats.total_lines == 0
    assert result.stats.success_rate == 1.0


def test_a_carriage_return_is_not_kept_in_the_problem_text():
    issue = parse_text("bad line\r\n").stats.first_errors[0]
    assert issue.line == "bad line"
