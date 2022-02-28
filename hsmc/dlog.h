/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef _HSM_ENCLAVE_DLOG_H
#define _HSM_ENCLAVE_DLOG_H

#include <stdio.h>
#include <stdint.h>

/** Returns the current microseconds since epoch, for use in logging. */
int64_t time_micros(void);

#ifndef LOGOUT
// We allow this to be overridden on the command line (via -DLOGOUT=stderr)
// because Java tests want this to be stderr, but the HSM wants it to be
// stdout in order to get in the trace buffer.
#define LOGOUT stdout
#endif

// Very simple logging to use within HsmEnclave.

#define LOG(format, ...) fprintf(LOGOUT, "%jd %s:%03d " format "\n", time_micros(), __FILE__, __LINE__, ##__VA_ARGS__)
#ifdef DEBUG
#define DLOG(...) LOG("DEBUG: " __VA_ARGS__)
#else
#define DLOG(...)
#endif

#endif  // _HSM_ENCLAVE_DLOG_H
