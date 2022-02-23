#
# Copyright 2022 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#

# This Dockerfile is meant solely for use by Micronaut/Maven's packaging:
#   mvn package -Dpackaging=docker
# It executes within the context of the "target" directory, as described
# in the "Bringing your own Dockerfile" section of
#   https://micronaut-projects.github.io/micronaut-maven-plugin/latest/examples/package.html
# We do this because the default base image used by Micronaut/Maven packaging
# fails to handle the writing/running of the 'hsm_enclave_native' binary we create as a
# subprocess.
FROM azul/zulu-openjdk@sha256:cc09a5a89d1731a63ce11155f586a1d82d9556bc60165e7e940d3ddff4d8f3c2

COPY classes /app/classes
COPY dependency/* /app/libs/

ENTRYPOINT ["java", "-cp", "/app/resources:/app/classes:/app/libs/*", "org.signal.hsmenclave.FrontEnd"]
