FROM python:3.12.12-alpine3.21
RUN apk add --no-cache age=1.2.1-r0
COPY snapshot-agent.py /usr/local/bin/snapshot-agent.py
USER 10001:10001
ENTRYPOINT ["python3", "/usr/local/bin/snapshot-agent.py"]
