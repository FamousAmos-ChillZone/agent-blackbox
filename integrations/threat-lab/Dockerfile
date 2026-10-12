# The clean, read-only sandbox image every level-1/2 probe runs in (gVisor, runsc).
# Build it on the lab host and run the runner with the image pinned by DIGEST:
#   docker build -t threat-lab-probe integrations/threat-lab
#   docker inspect --format '{{index .RepoDigests 0}}' threat-lab-probe   (after a push to a local registry)
# Pin the base image by digest too when deploying (FROM python:3.12-slim@sha256:…).
# The image carries only the in-sandbox modules: no plugin code, no keys, no credentials.
FROM python:3.12-slim
COPY threat_lab/__init__.py threat_lab/identifiers.py threat_lab/probe.py threat_lab/rules.py /opt/threat-lab/threat_lab/
ENV PYTHONPATH=/opt/threat-lab PYTHONDONTWRITEBYTECODE=1
USER 65534:65534
WORKDIR /work
