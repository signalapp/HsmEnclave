#!/bin/bash
#
# Copyright 2022 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# This binary runs the steps necessary to generate and utilize
# all keys to create a secure remote-attestation environment
# based on HsmEnclave.
#
# Arguments (passed in as environmental variables):
#   SUFFIX - "namespaces" the created objects, default=<current epoch secs>
#   MODULE - module number, default=1
#
# It will:
#  * Create OCS hsmenclaveseeinteg_ocs$SUFFIX
#  * Create a seeinteg key "hsmenclaveseeinteg$SUFFIX" backed by that OCS
#  * Sign any binaries passed in on the command line with that key
#  * Utilize ./generate_hsm_enclave_keys to generate a `key_blob` file
#  * Sign that file with the seeinteg key as well.
#  * Destroy (via erasure) the hsmenclaveseeinteg_ocs$SUFFIX cardset, rendering future
#    binary/userdata signing impossible and thus protecting "hsmenclaveprivate$SUFFIX"
#    from any subsequent use.

set -ex

if [[ $# < 1 ]]; then
  echo 1>&2 "Usage: $0 <binary> [binary] ..."
  exit 1
fi
for binary in "$@"; do
  if [ ! -f "$binary" ]; then
    echo 1>&2 "Unable to find binary to sign: '$binary'"
    exit 1
  fi
  echo "Will sign '$(realpath $binary)'"
done

SUFFIX="${SUFFIX:-$(date +%s)}"
MODULE="${MODULE:-1}"
PATH=/opt/nfast/bin:/usr/bin:/bin
OCS=hsmenclaveseeinteg_ocs$SUFFIX
INTEGRITY=hsmenclaveseeinteg$SUFFIX
MACHINE_TYPE=PowerPCELF

for executable in generatekey nfkminfo createocs tct2 sha256sum ./generate_hsm_enclave_keys; do
  if ! which "$executable"; then
    echo "Missing '$executable'"
    exit 1
  fi
done

echo "Generating SEE OCS"
createocs --module="$MODULE" --ocs-quorum 1/1 --name $OCS --no-persist --no-pp-recovery

echo "Generating SEE Key ($INTEGRITY), use $OCS to protect"
generatekey --module="$MODULE" --cardset=$OCS --generate seeinteg plainname=$INTEGRITY size=4096 recovery=no protect=token type=RSA pubexp="" nvram=no
nfkminfo -k seeinteg $INTEGRITY

echo "Generating necessary keys"
NFLOG_FILE=/tmp/nflog NFLOG_SEVERITY=DEBUG1 ./generate_hsm_enclave_keys "$SUFFIX"

tct2 --module="$MODULE" --sign-and-pack --key=$INTEGRITY --machine-key-ident=$INTEGRITY --infile=key_blob --outfile=/tmp/userdata.sar
for binary in "$@"; do
  echo "Signing binary '$binary'"
  tct2 --module="$MODULE" --sign-and-pack --key=$INTEGRITY --machine-type=$MACHINE_TYPE --is-machine --infile="$binary" --outfile="/tmp/$(basename "$binary").sar"
done

sha256sum /tmp/*.sar

createocs --erase --module="$MODULE"

echo "Complete"
