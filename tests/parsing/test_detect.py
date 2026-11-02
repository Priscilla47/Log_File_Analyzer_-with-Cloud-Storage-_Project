"""detect_log_format: Apache or Nginx, from how special characters are escaped."""

import time
from pathlib import Path

import pytest

from loginsight.parsing import detect
from loginsight.parsing.detect import MAX_ESCAPES_EXAMINED, detect_log_format

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"


def line(request="GET / HTTP/1.1", agent="x"):
    return f'203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "{request}" 200 15 "-" "{agent}"\n'


class TestSamples:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("demo.log", "apache"),
            ("demo_nginx.log", "nginx"),
            ("clean.log", "apache"),
            ("access_sample.log", "apache"),
        ],
    )
    def test_the_committed_samples(self, name, expected):
        assert detect_log_format((SAMPLES / name).read_text()) == expected


class TestEvidence:
    @pytest.mark.parametrize(
        "request_text",
        [r"GET /\x22 HTTP/1.1", r"GET /\x5C HTTP/1.1", r"GET /caf\xC3\xA9 HTTP/1.1",
         r"GET /\xFF HTTP/1.1", r"GET /\xA0 HTTP/1.1", r"GET /\x1B HTTP/1.1"],
    )  # fmt: skip
    def test_nginx_escapes(self, request_text):
        assert detect_log_format(line(request_text)) == "nginx"

    @pytest.mark.parametrize(
        "request_text",
        [r"GET /\"x\" HTTP/1.1", r"GET /a\\b HTTP/1.1", r"GET /caf\xc3\xa9 HTTP/1.1",
         r"GET /\xff HTTP/1.1", r"GET /\x1b HTTP/1.1", r"GET /\xa0 HTTP/1.1"],
    )  # fmt: skip
    def test_apache_escapes(self, request_text):
        assert detect_log_format(line(request_text)) == "apache"

    @pytest.mark.parametrize("request_text", [r"GET /\x16\x03\x01 HTTP/1.1", r"\x00\x01\x02"])
    def test_digits_only_escapes_prove_nothing(self, request_text):
        # both servers write \x16 the same way, so the default applies
        assert detect_log_format(line(request_text)) == "apache"

    def test_no_escape_at_all(self):
        assert detect_log_format(line() * 50) == "apache"

    def test_empty_text(self):
        assert detect_log_format("") == "apache"

    def test_the_agent_field_counts_too(self):
        assert detect_log_format(line(agent=r"x \x22y\x22")) == "nginx"

    def test_an_incomplete_or_mixed_case_escape_is_not_evidence(self):
        assert detect_log_format(line(r"GET /\x2 \xZZ \xAf \xaF HTTP/1.1")) == "apache"


class TestMajority:
    def test_more_nginx_than_apache_evidence(self):
        text = line(r"GET /\x22 HTTP/1.1") * 3 + line(r"GET /\"x HTTP/1.1")
        assert detect_log_format(text) == "nginx"

    def test_more_apache_than_nginx_evidence(self):
        text = line(r"GET /\x22 HTTP/1.1") + line(r"GET /\"x HTTP/1.1") * 3
        assert detect_log_format(text) == "apache"

    def test_a_tie_is_apache(self):
        text = line(r"GET /\x22 HTTP/1.1") + line(r"GET /\"x HTTP/1.1")
        assert detect_log_format(text) == "apache"

    def test_lower_case_escapes_count_as_apache_evidence(self):
        text = line(r"GET /\x22 HTTP/1.1") + line(r"GET /\xc3\xa9\xff HTTP/1.1")
        assert detect_log_format(text) == "apache"  # three lower-case against one Nginx escape

    def test_escaped_backslash_pairs_count_as_apache_evidence(self):
        text = line(r"GET /\x22\x22 HTTP/1.1") + line(r"GET /a\\b\\c\\d HTTP/1.1")
        assert detect_log_format(text) == "apache"  # two Nginx escapes against three pairs

    def test_one_odd_line_does_not_decide(self):
        text = line(r"GET /\x22 HTTP/1.1") * 20 + line(r"GET /\"x HTTP/1.1")
        assert detect_log_format(text) == "nginx"


class TestAClientCannotFakeIt:
    def test_an_escaped_backslash_hides_what_follows_it(self):
        # Apache logs a client's own text  \x22  as  \\x22 : a backslash pair, then plain text
        assert detect_log_format(line(r"GET /\\x22\\x5C\\xFF HTTP/1.1")) == "apache"

    def test_an_nginx_log_shows_the_clients_backslash_as_x5c(self):
        # the client's own text  \x22  appears in an Nginx log as  \x5Cx22
        assert detect_log_format(line(r"GET /\x5Cx22 HTTP/1.1")) == "nginx"


class TestLimits:
    def test_only_the_first_escapes_are_examined(self, monkeypatch):
        monkeypatch.setattr(detect, "MAX_ESCAPES_EXAMINED", 3)
        text = r"\"\"\"" + r"\x22" * 10  # three apache escapes first, then plenty of nginx
        assert detect_log_format(text) == "apache"

    def test_the_limit_is_exact(self, monkeypatch):
        monkeypatch.setattr(detect, "MAX_ESCAPES_EXAMINED", 2)
        # the first two (nginx, apache) tie; a third look would tip it to nginx
        assert detect_log_format(r"\x22 \" \x22") == "apache"

    def test_the_default_limit(self):
        assert MAX_ESCAPES_EXAMINED == 100_000

    def test_a_text_of_nothing_but_backslashes_is_quick(self):
        started = time.perf_counter()
        assert detect_log_format("\\" * 3_000_000) == "apache"
        assert time.perf_counter() - started < 2

    def test_a_large_log_is_quick(self):
        text = line(r"GET /\x22 HTTP/1.1") * 100_000
        started = time.perf_counter()
        assert detect_log_format(text) == "nginx"
        assert time.perf_counter() - started < 2
