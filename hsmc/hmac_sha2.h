/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// Simple additional crypto operations (hmac, hkdf) built on top
// of SHA256.

#ifndef _HSM_ENCLAVE_HMAC_SHA2
#define _HSM_ENCLAVE_HMAC_SHA2

#include <stddef.h>

/** Compute a HMAC_SHA256 of data/size into output[0..32], using key key[0..32]. */
void hmac_sha256(const unsigned char* key, const unsigned char* data, size_t size, unsigned char* output);
/** Compute a HKDF_SHA256 of ikm/size using salt_32b[0..32] into output_32b[0..32]. */
void hkdf_sha256(const unsigned char* salt_32b, const unsigned char* ikm, size_t size, unsigned char* output_32b);

#endif  // _HSM_ENCLAVE_HMAC_SHA2
