import importlib.util
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def memory_storage_class():
    """The in-memory Storage test double (loaded by path, as tests are not importable)."""
    spec = importlib.util.spec_from_file_location(
        "storage_memory", Path(__file__).parent / "storage" / "memory.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.MemoryStorage


@pytest.fixture(autouse=True)
def no_real_cloud_account(monkeypatch, tmp_path_factory):
    """No test can reach a real AWS account: fake credentials, no profile, no metadata lookup.

    The configuration file asks for path-style addresses (``host/bucket/key``), which is what
    the mocked S3 of the tests understands; real S3 is not affected, as the file exists only
    here.
    """
    config = tmp_path_factory.mktemp("aws") / "config"
    config.write_text("[default]\ns3 =\n    addressing_style = path\n")
    for name in ("AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/credentials")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))


@pytest.fixture
def s3_bucket():
    """A mocked S3 with an empty bucket, and a client for it. Nothing leaves this computer."""
    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")
    with moto.mock_aws():
        client = boto3.client("s3")  # from the fake environment of tests/conftest.py
        client.create_bucket(Bucket="logs")
        yield client
