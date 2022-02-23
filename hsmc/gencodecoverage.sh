#!/bin/bash
#
# Copyright 2022 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#

cd "$(dirname "$0")"
for cfile in $(ls *.c | sed 's/\.c//'); do
  if [ -f "build/test/$cfile.gcda" ]; then
    echo "Processing $cfile.c" 1>&2
    gcov "$cfile.c" --object-directory=build/test --stdout --use-hotness-colors --use-colors | sed "s/^/$cfile.c\t/"
  fi
done > build/test/code_coverage_report

echo "Wrote coverage, view with: less -R build/test/code_coverage_report"

