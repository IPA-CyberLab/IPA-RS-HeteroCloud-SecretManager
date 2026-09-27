FROM python:3.12.12-alpine3.21@sha256:d4f9227f21409479c7fe92288f2e40b1a56ae591c8ad3b5446dfeaef90f67857
RUN apk add --no-cache age=1.2.1-r5
COPY snapshot-agent.py /usr/local/bin/snapshot-agent.py
USER 10001:10001
ENTRYPOINT ["python3", "/usr/local/bin/snapshot-agent.py"]
