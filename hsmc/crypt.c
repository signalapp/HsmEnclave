/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "crypt.h"
#include "noise.h"
#include "hmac_sha2.h"
#include <stdbool.h>

// All zero bytes.
static unsigned char crypt_userkey_empty[CRYPT_USERKEY_BYTES] = {};

error_t crypt_encrypt(
    crypt_t* crypt,
    NoiseRandState* rand,
    const unsigned char* plaintext,
    size_t plaintext_size,
    const unsigned char* userkey,
    unsigned char* ciphertext,
    size_t* ciphertext_size) {
  DLOG("crypt_encrypt");
  if (plaintext_size == 0) {
    *ciphertext_size = 0;
    return err_SUCCESS;
  }
  if (*ciphertext_size < plaintext_size + CRYPT_OVERHEAD) return ERR("ciphertext too small");

  unsigned char iv[CRYPT_IV_BYTES];
  if (NOISE_ERROR_NONE != noise_randstate_generate(rand, iv, CRYPT_IV_BYTES)) return ERR("noise_randstate_generate");

  unsigned char initial_key[NOISE_KEY_SIZE];
  RETURN_IF_ERROR("key from iv",
      crypt_key(crypt, iv, initial_key));
  if (userkey == NULL) {
    userkey = crypt_userkey_empty;
  }
  unsigned char final_key[NOISE_KEY_SIZE];
  hmac_sha256(initial_key, userkey, CRYPT_USERKEY_BYTES, final_key);

  error_t err = err_SUCCESS;
  NoiseCipherState* s;
  if (NOISE_ERROR_NONE != noise_cipherstate_new_by_id(&s, CRYPT_CIPHER)) {
    err = ERR("noise_cipherstate_new_by_id");
    goto clean_key;
  }
  if (NOISE_ERROR_NONE != noise_cipherstate_init_key(s, final_key, sizeof(final_key))) {
    err = ERR("noise_cipherstate_init_key");
    goto free_noise;
  }

  memcpy(ciphertext, iv, CRYPT_IV_BYTES);
  unsigned char* ciphertext_data = ciphertext + CRYPT_IV_BYTES;
  size_t ciphertext_data_size = *ciphertext_size - CRYPT_IV_BYTES;

  memcpy(ciphertext_data, plaintext, plaintext_size);
  NoiseBuffer buf;
  noise_buffer_set_inout(buf, ciphertext_data, plaintext_size, ciphertext_data_size);
  DLOG("noise encrypt");
  if (NOISE_ERROR_NONE != noise_cipherstate_encrypt(s, &buf)) {
    err = ERR("noise_cipherstate_encrypt");
    goto free_noise;
  }
  *ciphertext_size = buf.size+CRYPT_IV_BYTES;

free_noise:
  noise_cipherstate_free(s);
clean_key:
  noise_clean(final_key, NOISE_KEY_SIZE);
  noise_clean(initial_key, NOISE_KEY_SIZE);
  return err;
}

error_t crypt_decrypt(
    crypt_t* crypt,
    const unsigned char* ciphertext,
    size_t ciphertext_size,
    const unsigned char* userkeys,
    size_t userkeys_size,
    unsigned char* plaintext,
    size_t* plaintext_size) {
  DLOG("crypt_decrypt");
  ASSERT_ERR(userkeys_size > 0);
  ASSERT_ERR(userkeys_size <= CRYPT_USERKEY_BYTES * 4);
  ASSERT_ERR(userkeys_size % CRYPT_USERKEY_BYTES == 0);
  if (ciphertext_size == 0) {
    *plaintext_size = 0;
    return err_SUCCESS;
  }
  if (*plaintext_size < ciphertext_size) return ERR("plaintext too small");
  if (CRYPT_OVERHEAD > ciphertext_size) return ERR("ciphertext too small");

  // IV is the first CRYPT_IV_BYTES of the ciphertext.
  const unsigned char* iv = ciphertext;
  size_t ciphertext_data_size = ciphertext_size - CRYPT_IV_BYTES;

  unsigned char initial_key[NOISE_KEY_SIZE];
  RETURN_IF_ERROR("key from iv",
      crypt_key(crypt, iv, initial_key));
  if (userkeys == NULL) {
    userkeys = crypt_userkey_empty;
    userkeys_size = CRYPT_USERKEY_BYTES;
  }
  unsigned char final_key[NOISE_KEY_SIZE];

  error_t err = err_SUCCESS;
  NoiseCipherState* s;
  if (NOISE_ERROR_NONE != noise_cipherstate_new_by_id(&s, CRYPT_CIPHER)) {
    err = ERR("noise_cipherstate_new_by_id");
    goto clean_key;
  }
  bool success = false;
  size_t userkey_offset;
  for (userkey_offset = 0; !success && userkey_offset < userkeys_size; userkey_offset += CRYPT_USERKEY_BYTES) {
    // We've done our first (possibly expensive, HSM-side) key derivation already,
    // so now when we try out the N userkey keys, we can do so from that base state
    // stored in initial_key.
    DLOG("decrypting with key %ld", userkey_offset);
    hmac_sha256(initial_key, userkeys+userkey_offset, CRYPT_USERKEY_BYTES, final_key);
    if (NOISE_ERROR_NONE != noise_cipherstate_init_key(s, final_key, sizeof(final_key))) {
      err = ERR("noise_cipherstate_init_key");
      goto free_noise;
    }

    NoiseBuffer buf;
    // A previous decryption attempt may have munged the ciphertext we copied over
    // last time, so re-copy every time.
    memcpy(plaintext, ciphertext + CRYPT_IV_BYTES, ciphertext_data_size);
    noise_buffer_set_inout(buf, plaintext, ciphertext_data_size, *plaintext_size);
    DLOG("noise decrypt offset %ld", userkey_offset);
    int rc = noise_cipherstate_decrypt(s, &buf);
    if (rc == NOISE_ERROR_MAC_FAILURE) {
      DLOG("noise_cipherstate_decrypt failed, bad key");
      continue;
    } else if (rc != NOISE_ERROR_NONE) {
      err = ERR("noise_cipherstate_decrypt");
      goto free_noise;
    }
    *plaintext_size = buf.size;
    success = true;
  }
  if (!success) {
    err = ERR("noise decryption failure");
  }

free_noise:
  noise_cipherstate_free(s);
clean_key:
  noise_clean(initial_key, NOISE_KEY_SIZE);
  noise_clean(final_key, NOISE_KEY_SIZE);
  return err;
}

