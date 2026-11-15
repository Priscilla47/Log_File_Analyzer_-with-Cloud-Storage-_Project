# LogInsight in a container: the command line and the dashboard, without installing Python
# packages on your machine. Build and run: see "Running in a container" in docs/USAGE.md.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=10 \
    MPLCONFIGDIR=/tmp/matplotlib

# A user without privileges: nothing here needs root once the package is installed.
RUN useradd --create-home --uid 10001 loginsight

WORKDIR /app
# Only what the package needs to be built (see .dockerignore for what is left out).
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install ".[dashboard,s3]"

# The synthetic sample logs, so `docker run IMAGE analyze /samples/demo.log` works at once.
COPY data/samples /samples

# Your own logs go in /data (mount a folder there); reports are written below it too.
RUN mkdir /data && chown loginsight /data
WORKDIR /data
USER loginsight

# No secrets are built into the image. For S3, pass the usual AWS_* environment variables.
EXPOSE 8501
ENTRYPOINT ["loginsight"]
CMD ["--help"]
