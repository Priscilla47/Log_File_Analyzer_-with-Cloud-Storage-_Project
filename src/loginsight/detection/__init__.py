"""Attack detection: rules that turn parsed log entries into explained detections.

Most callers need only :func:`detect`, which runs every rule and returns the findings from
most to least serious. The rules themselves are data, loaded from a TOML file with
:func:`load_rules`.
"""

from loginsight.detection.models import Detection, Severity, SignatureRule
from loginsight.detection.pipeline import detect
from loginsight.detection.ruleset import RuleSet, load_rules

__all__ = ["Detection", "RuleSet", "Severity", "SignatureRule", "detect", "load_rules"]
