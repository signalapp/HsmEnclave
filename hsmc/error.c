/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "error.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

error_t err_SUCCESS = NULL;

static struct error_internal_t erri_OOM = { .msg = "OOM" };
error_t err_OOM = &erri_OOM;

error_t errorinternal_new(const char* msg) {
  error_t e = (error_t) malloc(sizeof(struct error_internal_t));
  if (e == NULL) { return err_OOM; }
  e->msg = msg;
  e->next = NULL;
  return e;
}

error_t errorinternal_new_owning_message(const char* msg, size_t size) {
  // Very pedantic check that we're getting null-terminated messages.
  if (msg[size-1] != '\0') {
    return errorinternal_new("invalid error owned message: not null terminated");
  }
  error_t e = (error_t) calloc(sizeof(struct error_internal_t) + size, 1);
  if (e == NULL) { return err_OOM; }
  memcpy(e->ownedstring, msg, size);
  e->msg = e->ownedstring;
  e->next = NULL;
  return e;
}

void errorinternal_free(error_t e) {
  while (e != err_SUCCESS && e != err_OOM) {
    error_t curr = e;
    e = e->next;
    free(curr);
  }
}

error_t errorinternal_context(error_t eorig, const char* msg) {
  if (eorig == err_SUCCESS ||
      eorig == err_OOM) {
    return eorig;
  }
  return errorinternal_connect(eorig, errorinternal_new(msg));
}

error_t errorinternal_connect(error_t eorig, error_t econtext) {
  assert(econtext->next == NULL);
  econtext->next = eorig;
  return econtext;
}

size_t errorinternal_dumpsize(error_t e) {
  if (e == err_SUCCESS) return 8;  // "SUCCESS\0"
  size_t out = 0;
  while (e != err_SUCCESS) {
    out += strlen(e->msg) + 1;  // add 1 for newline or \x00
    e = e->next;
  }
  return out;
}

#define ERROR_SUCCESS_STRING "SUCCESS"
#define ERROR_SUCCESS_STRING_SIZE (sizeof(ERROR_SUCCESS_STRING)/sizeof(ERROR_SUCCESS_STRING[0]))

// copying strings into a buffer is insanely scary in C.
size_t errorinternal_dump(error_t e, char* buf, size_t size) {
  if (size == 0) return 0;
  if (e == err_SUCCESS) {
    size_t s = ERROR_SUCCESS_STRING_SIZE < size ? ERROR_SUCCESS_STRING_SIZE : size;
    memcpy(buf, ERROR_SUCCESS_STRING, s);
    buf[size-1] = '\x00';  // pedantically guarantee null termination
    return s;
  }
  size_t written = 0;
  for (; e != NULL && written < size; e = e->next) {
    char* write_at = buf + written;
    size_t remaining = size - written;
    size_t to_write = strlen(e->msg);
    if (to_write + 1 > remaining) {
      to_write = remaining - 1;
    }
    memcpy(write_at, e->msg, to_write);  // does not write null-term
    write_at[to_write] = '<';  // add separator
    written += to_write + 1;
  }
  buf[written-1] = '\x00';  // null-terminate
  return written;
}
