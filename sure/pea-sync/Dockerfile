FROM python:3.12-slim
ARG WOOB_COMMIT=d4c5c533ad45e3ef0f0900c0d8166e0a6c23a77c
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/* \
 && git clone https://gitlab.com/woob/woob.git /opt/woob && git -C /opt/woob checkout $WOOB_COMMIT \
 && pip install --no-cache-dir /opt/woob && rm -rf /opt/woob/.git
RUN useradd -u 1000 -m woob
USER 1000
ENV WOOB_MODULES=/opt/woob/modules
