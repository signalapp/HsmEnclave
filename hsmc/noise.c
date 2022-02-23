/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "noise.h"
#include "dlog.h"

size_t noise_encrypt_max_size(size_t plaintext_size) {
  return (plaintext_size / NOISE_MAX_DATA_SIZE + 1) * NOISE_MAC_SIZE + plaintext_size;
}

error_t noise_encrypt_message(
    NoiseCipherState* tx,
    const unsigned char* plaintext_data,
    size_t plaintext_size,
    unsigned char* ciphertext_data,
    size_t* ciphertext_size) {
  size_t plaintext_offset;
  size_t ciphertext_offset = 0;
  for (plaintext_offset = 0; plaintext_offset < plaintext_size; plaintext_offset += NOISE_MAX_DATA_SIZE) {
    size_t to_encrypt = NOISE_MAX_DATA_SIZE;
    if (plaintext_offset + to_encrypt > plaintext_size) {
      to_encrypt = plaintext_size - plaintext_offset;
    }
    memcpy(ciphertext_data+ciphertext_offset, plaintext_data+plaintext_offset, to_encrypt);
    NoiseBuffer buf;
    noise_buffer_set_inout(
        buf,
        ciphertext_data+ciphertext_offset,
        to_encrypt,
        *ciphertext_size-ciphertext_offset);
    if (NOISE_ERROR_NONE != noise_cipherstate_encrypt(tx, &buf)) {
      return ERR("noise_cipherstate_encrypt failed");
    }
    ciphertext_offset += buf.size;
  }
  *ciphertext_size = ciphertext_offset;
  return err_SUCCESS;
}

size_t noise_decrypt_max_size(size_t plaintext_size) {
  return plaintext_size;
}

error_t noise_decrypt_message(
    NoiseCipherState* rx,
    const unsigned char* ciphertext_data,
    size_t ciphertext_size,
    unsigned char* plaintext_data,
    size_t* plaintext_size) {
  size_t plaintext_offset = 0;
  size_t ciphertext_offset;
  for (ciphertext_offset = 0; ciphertext_offset < ciphertext_size; ciphertext_offset += NOISE_MAX_PACKET_SIZE) {
    size_t to_decrypt = NOISE_MAX_PACKET_SIZE;
    if (plaintext_offset + to_decrypt > ciphertext_size) {
      to_decrypt = ciphertext_size - ciphertext_offset;
    }
    memcpy(plaintext_data+plaintext_offset, ciphertext_data+ciphertext_offset, to_decrypt);
    NoiseBuffer buf;
    noise_buffer_set_inout(buf, plaintext_data+plaintext_offset, to_decrypt, *plaintext_size-plaintext_offset);
    if (NOISE_ERROR_NONE != noise_cipherstate_decrypt(rx, &buf)) {
      return ERR("noise_cipherstate_decrypt failed");
    }
    plaintext_offset += buf.size;
  }
  *plaintext_size = plaintext_offset;
  return err_SUCCESS;
}
