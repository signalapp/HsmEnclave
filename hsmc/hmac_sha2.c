/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "hmac_sha2.h"

#include <sha2/sha256.h>
#include <string.h>

static void xor_32bytes(unsigned char* data, unsigned char xor) {
  int i;
  for (i = 0; i < 32; i++) {
    data[i] ^= xor;
  }
}

void hmac_sha256(const unsigned char* key, const unsigned char* data, size_t size, unsigned char* output) {
  unsigned char pad[64];
  sha256_context_t s;

  memcpy(pad, key, 32);
  memset(pad+32, 0x36, 32);
  xor_32bytes(pad, 0x36);

  sha256_reset(&s);
  sha256_update(&s, pad, 64);
  sha256_update(&s, data, size);
  sha256_finish(&s, output);

  memcpy(pad, key, 32);
  memset(pad+32, 0x5c, 32);
  xor_32bytes(pad, 0x5c);

  sha256_reset(&s);
  sha256_update(&s, pad, 64);
  sha256_update(&s, output, 32);
  sha256_finish(&s, output);
}

void hkdf_sha256(const unsigned char* salt_32b, const unsigned char* ikm, size_t size, unsigned char* output_32b) {
  unsigned char prk[32];
  hmac_sha256(salt_32b, ikm, size, prk);
  unsigned char counter = 1;
  hmac_sha256(prk, &counter, 1, output_32b);
}
