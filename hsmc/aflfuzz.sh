#!/bin/bash
#
# Copyright 2022 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# This script sets up and runs AFL fuzzing (https://lcamtuf.coredump.cx/afl/)
# on the HsmEnclave.

set -x

if ! which afl-clang; then
  sudo apt-get install afl++
fi

SUFFIX="${SUFFIX:-}"

cd "$(dirname "$0")"
echo "Making environment"
BASEDIR=`pwd`/aflfuzz$SUFFIX
OUTPUT_DIR=$BASEDIR/findings
INPUT_DIR="-"
mkdir -p $OUTPUT_DIR
if [ ! -d $BASEDIR/testcases ]; then
  echo "Generating new test cases"
  INPUT_DIR=$BASEDIR/testcases
  mkdir -p $INPUT_DIR
  python3 afl_testcases.py "$SUFFIX"
fi

echo "Configuring system for fuzzers"
# aflfuzz requires the following actions be taken to set up the CPUs it's
# running on so they're more optimized for fuzzing workloads.  It will
# crash on startup if they're not set, so let's set it up in advance:
echo core | sudo tee /proc/sys/kernel/core_pattern
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Have AFL tell us which (new) test cases are dumb and we can throw away
echo "Running fuzzer"

function kill_fuzzers {
  killall afl-fuzz
}
trap kill_fuzzers EXIT

# Run multiple parallel fuzzers.  Note that we 'nice' all of these, which
# makes the system we're running on still usable for other tasks while the
# fuzzers are running.  Removing 'nice' here may increase the performance
# slightly of the fuzzers themselves, but it will decrease usability of other
# programs running in parallel on the same CPUs.
CPUS="$(cat /proc/cpuinfo | grep processor | wc -l)"
# Run the master in the shell we're executing in.  This gives us the ability to
# see any errors it might pop out.
AFL_BIN=./build/bin/hsm_enclave_afl$SUFFIX
nice afl-fuzz -i $INPUT_DIR -o $OUTPUT_DIR -M fuzz1 -- $AFL_BIN & 
for (( i=2 ; i<=$CPUS ; i++ )); do
  FLAG="-S"
  # Run the secondary processors (all the other cores) in xterms, so we can see
  # their progress independently.  If they crash, though, we'll lose their
  # output logs.
  xterm -e bash -c "nice afl-fuzz -i $INPUT_DIR -o $OUTPUT_DIR $FLAG fuzz$i -- $AFL_BIN" & 
done
wait
