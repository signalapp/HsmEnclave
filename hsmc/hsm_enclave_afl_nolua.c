/*
 * Copyright 2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>

#include "hsm_enclave.h"
#include "processstate.h"

// This binary is solely for use by AFL fuzzing.  AFL provides
// fuzz input via STDIN.  We want to make sure multiple commands
// are being run, so we treat input as a [len][command] list, where
// [len] is a two-byte length (0-65535).  We allow for up to 2MB
// of input to be provided via STDIN, then execute the set of
// commands within that buffer in-order.

int main(int argc, char** argv) {
  processstate_run_lua = false;
  unsigned char in_buf[2<<20];
  size_t in_offset = 0;
  while (in_offset < sizeof(in_buf)) {
    ssize_t got = read(0 /*stdin*/, in_buf+in_offset, sizeof(in_buf)-in_offset);
    if (got == 0) {
      break;
    } else if (got < 0) {
      perror("reading");
      exit(1);
    } else {
      in_offset += got;
    }
  }
  hsm_enclave_t* os = NULL;
  error_t err;
  if (err_SUCCESS != (err = hsm_enclave_new(&os))) {
    LOG_ERR(err);
    ERR_FREE(err);
    exit(1);
  }
  int i;
  // Generate multiple messages from our input.
  for (i = 0; i < sizeof(in_buf) - 1; ) {
    size_t bufsize = (in_buf[i] << 8) | in_buf[i+1];
    i += 2;
    if (bufsize == 0 || sizeof(in_buf) < i + bufsize) {
      return 0;  // reached end
    }
    command_free(hsm_enclave_handle_command(os, in_buf+i, bufsize));
    i += bufsize;
  }
}
