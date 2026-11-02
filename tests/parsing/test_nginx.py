"""The nginx parsing mode: Nginx's \\xHH escapes are decoded, everything else is unchanged."""

import pytest

from loginsight.parsing.parser import LOG_FORMATS, LogParseError, parse_file, parse_line, parse_text


def line(request="GET / HTTP/1.1", referer="-", agent="Mozilla/5.0", status="200"):
    return (
        f'203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "{request}" {status} 15 '
        f'"{referer}" "{agent}"'
    )


class TestDecoding:
    def test_a_quote_and_a_backslash(self):
        entry = parse_line(line(request=r"GET /p?q=\x22x\x22&b=\x5C HTTP/1.1"), "nginx")
        assert entry.query == 'q="x"&b=\\'
        assert entry.request == 'GET /p?q="x"&b=\\ HTTP/1.1'

    def test_a_run_of_escapes_is_read_as_utf8(self):
        entry = parse_line(line(request=r"GET /caf\xC3\xA9 HTTP/1.1"), "nginx")
        assert entry.path == "/café"

    def test_invalid_utf8_becomes_the_replacement_character(self):
        entry = parse_line(line(request=r"GET /\xFF\xFEx HTTP/1.1"), "nginx")
        assert entry.path == "/��x"

    def test_a_truncated_multibyte_sequence_does_not_crash(self):
        assert parse_line(line(request=r"GET /\xC3 HTTP/1.1"), "nginx").path == "/�"

    def test_a_binary_request_is_kept_readable(self):
        entry = parse_line(line(request=r"\x16\x03\x01\x02\x00\x01", status="400"), "nginx")
        assert (entry.method, entry.path, entry.status) == ("", "", 400)
        assert entry.request == "\x16\x03\x01\x02\x00\x01"

    def test_referer_and_user_agent_are_decoded_too(self):
        entry = parse_line(line(referer=r"http://x/\x22", agent=r"ua \x5C \xE2\x9C\x93"), "nginx")
        assert entry.referer == 'http://x/"'
        assert entry.user_agent == "ua \\ ✓"

    def test_a_dash_stays_a_missing_value(self):
        entry = parse_line(line(agent="-"), "nginx")
        assert entry.referer is None and entry.user_agent is None

    def test_a_decoded_backslash_is_not_decoded_again(self):
        # \x5C followed by x41 is a backslash and the text "x41", not the letter A
        assert parse_line(line(request=r"GET /\x5Cx41 HTTP/1.1"), "nginx").path == "/\\x41"

    def test_only_upper_case_hex_is_an_nginx_escape(self):
        # Nginx always writes upper-case digits, so these are the client's own text
        assert parse_line(line(request=r"GET /\x2f\x4a HTTP/1.1"), "nginx").path == r"/\x2f\x4a"

    def test_an_incomplete_escape_is_left_alone(self):
        assert parse_line(line(request=r"GET /\x2 HTTP/1.1"), "nginx").path == r"/\x2"
        assert parse_line(line(request=r"GET /\xZZ HTTP/1.1"), "nginx").path == r"/\xZZ"

    def test_an_escape_can_hide_the_method_or_the_protocol(self):
        entry = parse_line(line(request=r"G\x45T /x HTTP/1.1"), "nginx")  # \x45 is E
        assert (entry.method, entry.path) == ("GET", "/x")

    def test_a_decoded_space_changes_the_split_like_a_real_space_would(self):
        entry = parse_line(line(request=r"GET /a\x20b HTTP/1.1"), "nginx")
        assert entry.path == "/a b" and entry.protocol == "HTTP/1.1"

    def test_a_line_without_escapes_is_the_same_in_both_modes(self):
        text = line(request="GET /search?q=1'+OR+1=1 HTTP/1.1", referer="http://e/", agent="x y")
        assert parse_line(text, "nginx") == parse_line(text, "apache")

    def test_the_other_fields_are_untouched(self):
        entry = parse_line(line(request=r"GET /\x22 HTTP/1.1"), "nginx")
        assert (entry.ip, entry.status, entry.size) == ("203.0.113.5", 200, 15)


class TestApacheModeIsUnchanged:
    def test_it_is_the_default(self):
        text = line(request=r"GET /\x22 HTTP/1.1")
        assert parse_line(text) == parse_line(text, "apache")

    def test_escapes_are_kept_as_logged(self):
        assert parse_line(line(request=r"GET /\x22 HTTP/1.1")).path == r"/\x22"

    def test_an_apache_escaped_quote_is_kept_as_logged_in_both_modes(self):
        text = line(request=r"GET /p?q=\"x\" HTTP/1.1")
        assert parse_line(text, "apache").query == r"q=\"x\""
        assert parse_line(text, "nginx").query == r"q=\"x\""  # not an nginx escape


class TestFormatNames:
    def test_the_known_formats(self):
        assert LOG_FORMATS == ("apache", "nginx")

    @pytest.mark.parametrize("name", ["", "NGINX", "iis", "combined", None])
    def test_an_unknown_format_is_refused(self, name):
        with pytest.raises(ValueError, match="unknown log format"):
            parse_line(line(), name)
        with pytest.raises(ValueError, match="unknown log format"):
            parse_text(line(), name)

    def test_an_empty_text_is_refused_too_with_an_unknown_format(self):
        with pytest.raises(ValueError, match="unknown log format"):
            parse_text("", "iis")

    def test_parse_file_refuses_an_unknown_format_before_opening_the_file(self, tmp_path):
        with pytest.raises(ValueError, match="unknown log format"):
            parse_file(tmp_path / "does-not-exist.log", "iis")

    def test_a_bad_line_is_still_a_bad_line_in_nginx_mode(self):
        with pytest.raises(LogParseError) as raised:
            parse_line("not a log line", "nginx")
        assert raised.value.reason == "no_match"


class TestWholeTexts:
    TEXT = (
        line(request=r"GET /a?x=\x22 HTTP/1.1")
        + "\r\n"
        + "junk\n"
        + line(request=r"GET /b\xC3\xA9 HTTP/1.1")
        + "\n"
    )

    def test_parse_text_decodes_every_line_and_counts_the_junk(self):
        result = parse_text(self.TEXT, "nginx")
        assert [e.target for e in result.entries] == ['/a?x="', "/bé"]
        assert (result.stats.total_lines, result.stats.skipped) == (3, 1)

    def test_parse_file_gives_what_parse_text_gives(self, tmp_path):
        path = tmp_path / "n.log"
        path.write_text(self.TEXT, encoding="utf-8", newline="")
        assert parse_file(path, "nginx") == parse_text(self.TEXT, "nginx")

    def test_the_default_mode_of_the_whole_text_functions_is_apache(self, tmp_path):
        path = tmp_path / "n.log"
        path.write_text(self.TEXT, encoding="utf-8", newline="")
        assert parse_text(self.TEXT).entries[0].target == r"/a?x=\x22"
        assert parse_file(path).entries[0].target == r"/a?x=\x22"
