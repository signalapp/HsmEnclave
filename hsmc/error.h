/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// This library provides a robust error passing scheme reminiscent of
// GoLang's fmt.Errorf().  Errors are passed up a call stack, where
// higher callers may add additional context.  Errors are string-based
// and meant for human consumption.  The code only ever cares "was there
// an error or not" by equality-checking against err_SUCCESS.

#ifndef _HSM_ENCLAVE_ERROR_H
#define _HSM_ENCLAVE_ERROR_H

#include <stdlib.h>
#include <string.h>

// Do not use the functions from error_internal.  Instead, use the macros and constants defined below.
#include "dlog.h"
#include "error_internal.h"

// Create a new error, based on a given string literal.
//   Example:  return ERR("bad thing happened");
#define ERR(msg) errorinternal_new("" msg "")  // must be string literal

// Creates a new error that allocates and copies a null-terminated string.
#define ERR_COPYSTR(msg) errorinternal_new_owning_message(msg, strlen(msg)+1)

// Add context to an existing error with a new string literal.
//   Example:  return ERR_CTX(err, "within foo()");
#define ERR_CTX(e, msg) errorinternal_context(e, msg)

// Free an error.  Works with all errors (including err_SUCCESS).
#define ERR_FREE(e) errorinternal_free(e)

// Dump the error [e] into a character buffer [buf] of size [size].
// DUMP_ERR guarantees that the end result is null terminated,
// except in the corner case where size=0 and thus null termination
// can't happen.
#define DUMP_ERR(e, buf, size) errorinternal_dump(e, buf, size)

#define _ERR_STRINGIFY2(x) #x
#define _ERR_STRINGIFY(x) _ERR_STRINGIFY2(x)
#define ASSERT_ERR(x) do { \
  if (!(x)) { return ERR(_ERR_STRINGIFY(x) " at " __FILE__ ":" _ERR_STRINGIFY(__LINE__)); } \
} while (0)

#define DLOG_ERR(e) do { \
  error_t _dlogerr_e_ = (e); \
  if (_dlogerr_e_ == err_SUCCESS) { \
    DLOG("SUCCESS"); \
  } else { \
    for (; _dlogerr_e_ != err_SUCCESS; _dlogerr_e_ = _dlogerr_e_->next) { \
      DLOG("* ERR: %s", _dlogerr_e_->msg); \
    } \
  } \
} while (0)

#define LOG_ERR(e) do { \
  error_t _logerr_e_ = (e); \
  if (_logerr_e_ == err_SUCCESS) { \
    LOG("SUCCESS"); \
  } else { \
    for (; _logerr_e_ != err_SUCCESS; _logerr_e_ = _logerr_e_->next) { \
      LOG("ERR: %s", _logerr_e_->msg); \
    } \
  } \
} while (0)

// Return ERR_CTX(err, msg) if expression [e] returns non-err_SUCCESS [err].
#define RETURN_IF_ERROR(msg, e) do { \
  error_t _returniferr_e_ = (e); \
  if (_returniferr_e_ != err_SUCCESS) { return ERR_CTX(_returniferr_e_, msg); } \
} while (0)

extern error_t err_SUCCESS;  // success (not an error)
extern error_t err_OOM;  // out of memory error

// Helpers for allocating with error handling:

// malloc and zero-initialize memory of size (sizeof(typ) + siz).
#define MALLOCZ_WITH_ADDITIONAL_SIZE_OR_RETURN_ERROR(var, typ, siz) do { \
  (var) = (typ*) calloc(1, sizeof(typ) + (siz)); \
  if ((var) == NULL) { return err_OOM; } \
} while (0)

// malloc and zero-initialize memory of size sizeof(typ).
#define MALLOCZ_OR_RETURN_ERROR(var, typ) MALLOCZ_WITH_ADDITIONAL_SIZE_OR_RETURN_ERROR(var, typ, 0)

#endif  // _HSM_ENCLAVE_ERROR_H
