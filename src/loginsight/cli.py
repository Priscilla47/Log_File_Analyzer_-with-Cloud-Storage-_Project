"""The ``loginsight`` command line: a thin layer over the library.

It collects arguments, calls the shared analysis and the report code, and prints or writes the
result, or starts the dashboard. Exit codes: 0 success (finding attacks is not an error), 1 a
problem with a file, 2 wrong usage.
"""

import argparse
import errno
import os
import signal
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from loginsight import __version__
from loginsight.dashboard.launch import (
    DEFAULT_PORT,
    MAX_PORT,
    MIN_PORT,
    dashboard_url,
    streamlit_available,
    streamlit_command,
)
from loginsight.detection import Severity, load_rules
from loginsight.detection.ruleset import RulesError, RuleSet, parse_rules
from loginsight.reporting.report import render_json, render_markdown
from loginsight.reporting.text import printable, render_text
from loginsight.reporting.writers import write_to_storage
from loginsight.storage import LocalStorage
from loginsight.workflow import NothingReadError, analyze_text

PROG = "loginsight"

EXIT_OK = 0
EXIT_PROBLEM = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130


def _at_least_one(text: str) -> int:
    try:
        number = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a whole number") from None
    if number < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {number}")
    return number


def _port(text: str) -> int:
    try:
        number = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"port {text!r} is not a whole number") from None
    if not MIN_PORT <= number <= MAX_PORT:
        raise argparse.ArgumentTypeError(
            f"port must be between {MIN_PORT} and {MAX_PORT}, got {number}"
        )
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG, description="Analyze web server access logs and detect attacks."
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def common(command: argparse.ArgumentParser) -> None:
        command.add_argument("file", metavar="FILE", help="Apache or Nginx access log")
        command.add_argument(
            "--format",
            choices=("text", "json", "md"),
            default="text",
            help="what to print: text (default), the JSON report or the Markdown report",
        )
        command.add_argument(
            "--rules",
            metavar="FILE",
            help="use the detection rules in this TOML file instead of the built-in ones",
        )
        command.add_argument(
            "--output",
            metavar="DIR",
            help="write report.json, report.md and the charts to DIR and print their paths "
            "instead of printing the report",
        )

    analyze = commands.add_parser(
        "analyze", help="summarise the traffic", description="Summarise the traffic in a log."
    )
    common(analyze)
    analyze.add_argument(
        "--top", type=_at_least_one, default=10, metavar="N", help="list N top IPs and paths"
    )
    analyze.add_argument(
        "--bucket",
        choices=("minute", "hour"),
        default="hour",
        help="size of the traffic periods (default: hour)",
    )

    detection = commands.add_parser(
        "detect", help="list suspected attacks", description="List the attacks found in a log."
    )
    common(detection)
    detection.add_argument(
        "--min-severity",
        type=str.lower,
        choices=[str(severity) for severity in Severity],
        default="low",
        help="hide detections below this level (default: low)",
    )

    dashboard = commands.add_parser(
        "dashboard",
        help="open the web dashboard",
        description="Open the web dashboard in the browser (needs the dashboard extra).",
    )
    dashboard.add_argument(
        "--port",
        type=_port,
        default=DEFAULT_PORT,
        metavar="N",
        help=f"port to serve the dashboard on (default: {DEFAULT_PORT})",
    )
    return parser


def _warn(message: str) -> None:
    print(f"{PROG}: warning: {message}", file=sys.stderr)


def _fail(message: str) -> int:
    print(f"{PROG}: error: {message}", file=sys.stderr)
    return EXIT_PROBLEM


def _print(text: str) -> None:
    """Print ``text``, replacing characters the terminal cannot show instead of crashing."""
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "ascii"
        sys.stdout.write(text.encode(encoding, "replace").decode(encoding))
    sys.stdout.flush()


def _silence_stdout() -> None:
    """Point stdout at the null device so the flush at exit cannot fail on the closed pipe."""
    try:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    except (OSError, ValueError):  # no real file descriptor, for example under a test
        pass


def _read_file(name: str) -> str:
    """The text of the file ``name``, read through the storage layer.

    The file is resolved first, so a link such as ``/var/log/access.log`` that points elsewhere
    works, and the storage is confined to the folder that really holds the file.
    """
    path = Path(name).resolve()
    if not path.name:  # the root of the file system
        raise IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR), name)
    return LocalStorage(path.parent).read_text(path.name)


def _load_rules(name: str | None) -> RuleSet:
    """The rules in the file ``name``, or the built-in rules for ``None``.

    Raises :class:`OSError` if the file cannot be read and :class:`RulesError` if it is wrong.
    """
    if name is None:
        return load_rules()
    return parse_rules(_read_file(name), source=name)


def _dashboard(args: argparse.Namespace) -> int:
    """Start the Streamlit app, or say how to install it."""
    if not streamlit_available():
        print(
            f"{PROG}: error: the dashboard needs Streamlit, which is not installed. "
            "Install it with:  pip install 'loginsight[dashboard]'",
            file=sys.stderr,
        )
        return EXIT_USAGE
    try:
        process = subprocess.Popen(streamlit_command(args.port))
    except OSError as error:
        reason = error.strerror or type(error).__name__
        return _fail(f"cannot start Streamlit: {reason}")
    # Streamlit is told not to open a browser (see streamlit_command), so say where it is.
    _print(
        f"LogInsight dashboard: open {dashboard_url(args.port)} in your browser "
        "(press Ctrl+C to stop)\n"
    )

    def stop(number: int, frame: object) -> None:
        raise KeyboardInterrupt  # being asked to terminate ends the dashboard like Ctrl+C

    previous = signal.signal(signal.SIGTERM, stop)
    try:
        return process.wait()
    except KeyboardInterrupt:  # Ctrl+C is how the dashboard is stopped, not a failure
        try:  # the terminal sent it to Streamlit too; give it a moment to finish
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        return EXIT_OK
    finally:
        signal.signal(signal.SIGTERM, previous)
        if process.poll() is None:  # whatever ended this command, the server must not stay behind
            process.terminate()


def _run(args: argparse.Namespace) -> int:
    if args.command == "dashboard":
        return _dashboard(args)
    try:
        rules = _load_rules(args.rules)
    except RulesError as error:
        return _fail(
            "\n".join(printable(line) if line else line for line in str(error).split("\n"))
        )
    except OSError as error:
        reason = error.strerror or type(error).__name__
        return _fail(f"cannot read {printable(args.rules)}: {reason}")
    try:
        text = _read_file(args.file)
    except OSError as error:
        reason = error.strerror or type(error).__name__
        return _fail(f"cannot read {args.file}: {reason}")
    minimum = Severity.from_name(args.min_severity) if args.command == "detect" else Severity.LOW
    try:
        analysis = analyze_text(
            text,
            args.file,
            rules=rules,
            min_severity=minimum,
            top_n=getattr(args, "top", 10),
            bucket=getattr(args, "bucket", "hour"),
        )
    except NothingReadError as error:
        return _fail(
            f"none of the {error.total_lines} lines in {printable(args.file)} could be read "
            f"as an access-log entry ({error.reasons})"
        )
    for warning in analysis.warnings:
        _warn(warning)
    report = analysis.report

    if args.output is not None:
        try:
            keys = write_to_storage(report, LocalStorage(args.output))
        except OSError as error:
            reason = error.strerror or type(error).__name__
            return _fail(f"cannot write to {args.output}: {reason}")
        _print("".join(f"{Path(args.output) / key}\n" for key in keys))
    elif args.format == "json":
        _print(render_json(report))
    elif args.format == "md":
        _print(render_markdown(report))
    else:
        _print(render_text(report, args.command))
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return the exit status."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as stop:  # --help, --version and usage errors
        return stop.code  # argparse always exits with a number
    try:
        return _run(args)
    except KeyboardInterrupt:
        print(f"\n{PROG}: interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except BrokenPipeError:  # the reader (for example `head`) closed the pipe: not an error
        _silence_stdout()
        return EXIT_OK
