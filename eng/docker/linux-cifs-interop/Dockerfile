FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends cifs-utils procps util-linux coreutils \
    && rm -rf /var/lib/apt/lists/*
