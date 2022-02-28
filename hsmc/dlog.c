/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "dlog.h"

#include <sys/time.h>

int64_t time_micros(void) {
  struct timeval tv;
  if (0 != gettimeofday(&tv, NULL)) return -1;
  return tv.tv_usec + (1000000 * tv.tv_sec);
}
