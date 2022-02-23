/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef _HSM_ENCLAVE_ERROR_INTERNAL_H
#define _HSM_ENCLAVE_ERROR_INTERNAL_H

#include <stddef.h>

// Internal API for errors, should not be used directly.
struct error_internal_t {
  const char* msg;
  struct error_internal_t* next;
  char ownedstring[];
};
typedef struct error_internal_t* error_t;

error_t errorinternal_new(const char* msg);
error_t errorinternal_new_owning_message(const char* msg, size_t size);
error_t errorinternal_context(error_t eorig, const char* msg);
error_t errorinternal_connect(error_t eorig, error_t econtext);

void errorinternal_free(error_t err);
size_t errorinternal_dumpsize(error_t err);
size_t errorinternal_dump(error_t, char* buf, size_t size);

#endif  // _HSM_ENCLAVE_ERROR_INTERNAL_H
