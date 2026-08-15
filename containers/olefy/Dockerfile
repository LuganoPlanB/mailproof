ARG PYTHON_BASE=python@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419
FROM ${PYTHON_BASE}

COPY containers/olefy/requirements.lock /requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /requirements.lock \
    && groupadd --gid 1000 mailproof \
    && useradd --uid 1000 --gid 1000 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin mailproof
COPY containers/analyzer/olefy.py /usr/local/lib/mailproof-olefy.py
USER mailproof:mailproof
EXPOSE 10050
ENTRYPOINT ["python3", "/usr/local/lib/mailproof-olefy.py"]
