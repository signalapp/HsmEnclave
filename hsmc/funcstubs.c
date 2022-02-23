/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// This file stubs out some functions for dynamically loading and
// handling shared objects.  These are glibc functions, but are not
// provided by the nCipher libc library.  They're utilized by Lua.
// We stub them out to safely "fail" to load and error out in all
// calls.

#include <stddef.h>

void* dlopen(const char* filename, int flags);
void* dlopen(const char* filename, int flags) {
  return NULL;
}

int dlclose(void* handle);
int dlclose(void* handle) {
  return -1;
}

char* dlerror(void);
char* dlerror(void) {
  return (char*) "HsmEnclave: stubbed out";
}

void* dlsym(void* handle, const char* symbol);
void* dlsym(void* handle, const char* symbol) {
  return NULL;
}
