ARG BASE_IMAGE=rclone/rclone:latest

FROM debian:stable-slim AS builder

RUN apt-get update -y
RUN apt-get install -y \
    libcurl4-openssl-dev \
    libsodium-dev \
    libmicrohttpd-dev \
    libsecret-1-dev \
    libqrencode-dev \
    libwebkit2gtk-4.0-dev \
    git make gcc g++ \
    libcjson-dev \
    help2man \
    desktop-file-utils \
    jq

RUN git clone https://github.com/indigo-dc/oidc-agent --branch v5.2.2
WORKDIR /oidc-agent

RUN make
RUN make install_bin
RUN make install_lib
RUN make install_lib-dev
RUN make install
RUN make post_install


FROM ${BASE_IMAGE} as rclone_binaries

# build plugin image
FROM debian:stable-slim

# Prepare OIDC
RUN apt-get update -y
RUN apt-get install -y \
    libsodium-dev \
    libcjson-dev \
    jq

COPY --from=builder /lib/x86_64-linux-gnu/liboidc-agent.so.5 /lib/x86_64-linux-gnu/liboidc-agent.so.5
COPY --from=builder /oidc-agent/bin/oidc-token /bin/oidc-token
COPY --from=builder /oidc-agent/bin/oidc-add /bin/oidc-add
ENV OIDC_ENCRYPTION_PW=
ENV OIDC_SOCK=/oidc_sock

# put rclone in /usr/bin, reserve /usr/local/bin for plugin wrappers
COPY --from=rclone_binaries /usr/local/bin/rclone /usr/bin/rclone

RUN mkdir -p /data/config /data/cache /mnt \
 && apt-get install -y ca-certificates fuse3 tzdata \
 && echo "user_allow_other" >> /etc/fuse.conf \
 && rclone version

ENV RCLONE_CONFIG=/data/config/rclone.conf
ENV RCLONE_CACHE_DIR=/data/cache
ENV RCLONE_BASE_DIR=/mnt
ENV RCLONE_VERBOSE=0

ENV HTTP_PROXY=
ENV HTTPS_PROXY=
ENV NO_PROXY=

WORKDIR /data
ENTRYPOINT ["rclone", "serve", "docker"]
