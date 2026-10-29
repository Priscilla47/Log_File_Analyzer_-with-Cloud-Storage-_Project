"""The ``loginsight`` command line: a thin layer over the library.

It collects arguments, calls the parser, the detection rules and the report code, and prints or
writes the result. Exit codes: 0 success (finding attacks is not an error), 1 a problem with a
file, 2 wrong usage.
"""

import argparse
import os
import sys
from collections.abc import Sequence

from loginsight import __version__
from loginsight.detection import Severity, detect
from loginsight.parsing.parser import parse_file
from loginsight.reporting.report import build_report, render_json, render_markdown
from loginsight.reporting.text import printable, render_text
from loginsight.reporting.writers import write_report

PROG = "loginsight"
# More skipped lines than this share of the file earns a warning on stderr.
SKIP_WARNING_SHARE = 0.10

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


def _run(args: argparse.Namespace) -> int:
    # Temporary exception to the architecture: every file access should go through the storage
    # layer, which is built next. The command reads the file directly until it is switched over.
    try:
        result = parse_file(args.file)
    except OSError as error:
        reason = error.strerror or type(error).__name__
        return _fail(f"cannot read {args.file}: {reason}")

    stats = result.stats
    if stats.total_lines and not stats.parsed:
        # Nothing was read, so a report would say "no attacks" about a file never understood.
        reasons = ", ".join(f"{name}: {count}" for name, count in stats.skipped_by_reason.items())
        return _fail(
            f"none of the {stats.total_lines} lines in {printable(args.file)} could be read "
            f"as an access-log entry ({reasons})"
        )
    if stats.total_lines and stats.skipped / stats.total_lines > SKIP_WARNING_SHARE:
        _warn(
            f"{stats.skipped} of {stats.total_lines} lines "
            f"({stats.skipped / stats.total_lines:.0%}) could not be read"
        )

    detections = detect(result.entries)
    if args.command == "detect":
        minimum = Severity.from_name(args.min_severity)
        detections = [d for d in detections if d.severity >= minimum]
    report = build_report(
        result,
        detections,
        source_name=args.file,
        top_n=getattr(args, "top", 10),
        bucket=getattr(args, "bucket", "hour"),
    )

    if args.output is not None:
        try:
            paths = write_report(report, args.output)
        except OSError as error:
            reason = error.strerror or type(error).__name__
            return _fail(f"cannot write to {args.output}: {reason}")
        _print("".join(f"{path}\n" for path in paths))
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
