"""The Dockerfile and .dockerignore: what goes into the image, and what must never.

Building the image needs Docker and a network, so it is checked by hand and recorded in the pull
request (docs/USAGE.md has the commands). These tests check what can be checked without it.
"""

import fnmatch
import re
import sys
from pathlib import Path

import pytest

from loginsight.dashboard.launch import DEFAULT_PORT

if sys.version_info >= (3, 11):
    import tomllib
else:  # the project supports Python 3.10, which has tomli instead
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
IGNORE = (ROOT / ".dockerignore").read_text(encoding="utf-8")
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def instructions(name):
    """The arguments of every ``name`` instruction of the Dockerfile (continuations joined)."""
    text = re.sub(r"\\\n\s*", " ", DOCKERFILE)
    return [
        line.split(None, 1)[1].strip()
        for line in text.splitlines()
        if line.split(None, 1)[:1] == [name]
    ]


def ignored(path):
    patterns = [
        line.strip() for line in IGNORE.splitlines() if line.strip() and not line.startswith("#")
    ]
    return any(fnmatch.fnmatch(path, p) or path.split("/")[0] == p.rstrip("/") for p in patterns)


class TestWhatIsLeftOut:
    @pytest.mark.parametrize(
        "name",
        [".git", ".venv", ".private", ".local-tool", "logub-master", ".env", "build"],
    )
    def test_these_never_enter_the_build_context(self, name):
        assert ignored(name), name

    @pytest.mark.parametrize("name", ["secret.pem", "id.key", ".env.production"])
    def test_keys_and_environment_files_are_left_out(self, name):
        assert ignored(name), name

    def test_every_private_or_third_party_folder_ignored_by_git_is_ignored_here(self):
        git = (ROOT / ".gitignore").read_text(encoding="utf-8")
        for line in git.splitlines():
            if line.endswith("/") and not line.startswith(("#", "*")) and "logub" in line:
                assert ignored(line.rstrip("/")), line

    @pytest.mark.parametrize(
        "name", ["pyproject.toml", "README.md", "LICENSE", "src", "data/samples/demo.log"]
    )
    def test_what_the_image_needs_is_not_left_out(self, name):
        assert not ignored(name), name


class TestWhatTheImageHolds:
    def test_every_copied_path_exists_and_is_in_the_build_context(self):
        copies = instructions("COPY")
        assert copies
        for arguments in copies:
            *sources, _target = arguments.split()
            for source in sources:
                assert (ROOT / source).exists(), source
                assert not ignored(source.rstrip("/")), source

    def test_nothing_is_copied_wholesale(self):
        for arguments in instructions("COPY") + instructions("ADD"):
            *sources, _target = arguments.split()
            for source in sources:
                assert source not in {".", "./", "*", "/"}, arguments
        assert instructions("ADD") == []  # ADD fetches URLs and unpacks archives: COPY is enough

    def test_the_base_image_is_a_slim_python_that_supports_the_package(self):
        (base,) = instructions("FROM")
        match = re.fullmatch(r"python:(\d+)\.(\d+)-slim", base)
        assert match, base
        minimum = tuple(
            int(n) for n in PYPROJECT["project"]["requires-python"].strip(">=").split(".")
        )
        assert (int(match[1]), int(match[2])) >= minimum

    def test_it_installs_the_package_with_the_extras_the_dashboard_and_s3_need(self):
        (install,) = [i for i in instructions("RUN") if i.startswith("pip install")]
        extras = set(re.search(r"\[(.*?)\]", install)[1].split(","))
        assert extras == {"dashboard", "s3"}
        assert extras <= set(PYPROJECT["project"]["optional-dependencies"])

    def test_the_command_that_runs_is_loginsight(self):
        assert instructions("ENTRYPOINT") == ['["loginsight"]']
        assert PYPROJECT["project"]["scripts"]["loginsight"].startswith("loginsight.cli")

    def test_it_shows_the_help_when_given_nothing(self):
        assert instructions("CMD") == ['["--help"]']

    def test_the_dashboard_port_is_the_one_the_dashboard_uses(self):
        assert instructions("EXPOSE") == [str(DEFAULT_PORT)]


class TestSafety:
    def test_it_does_not_run_as_root(self):
        users = instructions("USER")
        assert users and users[-1] not in {"root", "0"}
        # the user exists, and is made before it is used
        assert any(i.startswith("useradd") and users[-1] in i for i in instructions("RUN"))

    def test_the_working_folder_is_owned_by_that_user_so_reports_can_be_written(self):
        assert any("chown" in i and "/data" in i for i in instructions("RUN"))
        assert instructions("WORKDIR")[-1] == "/data"

    def test_no_secret_is_built_in(self):
        words = re.compile(r"secret|password|token|credential|aws_|api_?key|private", re.I)
        for kind in ("ENV", "ARG", "LABEL"):
            for arguments in instructions(kind):
                assert not words.search(arguments), arguments

    def test_it_is_told_where_credentials_come_from(self):
        assert "AWS_" in DOCKERFILE  # the comment pointing at environment variables

    def test_nothing_is_downloaded_with_a_pipe_to_a_shell(self):
        assert not re.search(r"curl[^\n]*\|\s*(sh|bash)|wget[^\n]*\|\s*(sh|bash)", DOCKERFILE)

    def test_the_dashboard_is_only_offered_beyond_the_container_when_asked(self):
        # the image does not start the dashboard by itself, so nothing listens until the person
        # runs the dashboard command with --address and publishes the port
        assert "0.0.0.0" not in DOCKERFILE

    def test_the_usage_guide_publishes_the_port_to_this_computer_only(self):
        usage = (ROOT / "docs" / "USAGE.md").read_text(encoding="utf-8")
        run = [line for line in usage.splitlines() if "dashboard --address" in line]
        assert run and all("-p 127.0.0.1:" in line for line in run)


def test_the_guide_documents_the_container():
    usage = (ROOT / "docs" / "USAGE.md").read_text(encoding="utf-8")
    assert "## Running in a container" in usage and "docker build -t loginsight ." in usage
    assert "/samples/demo.log" in usage
