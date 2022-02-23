/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "crypt.h"
#include "error.h"
#include "processstate.h"
#include "hmac_sha2.h"

struct cryptfactory_t {
  unsigned char secret_key[NOISE_KEY_SIZE];
};

struct crypt_t {
  unsigned char process_key[32];
};

// Natively, we use the same key for private key and crypt key.
error_t env_cryptfactory(
    cryptfactory_t** f) {
  MALLOCZ_OR_RETURN_ERROR(*f, cryptfactory_t);
  return err_SUCCESS;
}

void cryptfactory_free(cryptfactory_t* f) {
  free(f);
}

void crypt_free(crypt_t* crypt) {
  free(crypt);
}

// Natively, keys are derived as:
//    factory.secret_key
//    --HMAC_SHA256(process_hash)-->  (cryptfactory_derive)
//    crypt.process_key
//    --HMAC_SHA256(iv)-->            (crypt_key)
//    base_key
//
// Note that after this derivation, a final one is done with the userkey optionally
// provided by clients (in crypt_{en,de}crypt functions).
//
//    base_key
//    --HMAC_SHA256(userkey)-->
//    final_key

error_t cryptfactory_derive(
    cryptfactory_t* initial,
    const unsigned char* code_hash,
    crypt_t** derived) {
  MALLOCZ_OR_RETURN_ERROR(*derived, crypt_t);
  hmac_sha256(initial->secret_key, code_hash, CODEHASH_LENGTH, (*derived)->process_key);
  return err_SUCCESS;
}

error_t crypt_key(
    crypt_t* c,
    const unsigned char iv[CRYPT_IV_BYTES],
    unsigned char key[NOISE_KEY_SIZE]) {
  ASSERT_ERR(NOISE_KEY_SIZE == 32);
  hmac_sha256(c->process_key, iv, CRYPT_IV_BYTES, key);
  return err_SUCCESS;
}
