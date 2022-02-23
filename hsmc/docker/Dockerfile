#
# Copyright 2022 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#

FROM debian:buster-20211011

COPY apt.conf sources.list /etc/apt/

RUN    apt-get update \
    && apt-get install -V -y --no-install-recommends --allow-downgrades \
         autoconf \
         automake \
         bison \
         build-essential \
         flex \
         libtool \
         m4 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /home/builder /opt/nfast/gcc /opt/nfast/c/csd

ARG UID=0
ARG GID=0

#Create a user to map the host user to.
RUN    groupadd -o -g "${GID}" builder \
    && useradd -m -o -u "${UID}" -g "${GID}" -G "adm,sudo" -s /bin/bash builder \
    && echo "builder:builder" | chpasswd

USER builder
ENV HOME /home/builder
ENV USER builder
ENV SHELL /bin/bash

WORKDIR /home/builder

CMD [ "make", "build/bin/hsm_enclave_onhsm", "build/bin/hsm_enclave_onhsm_debug" ]
