/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef _HSM_ENCLAVE_NOISE_H
#define _HSM_ENCLAVE_NOISE_H

#include <noise/protocol.h>
#define NOISE_DH_TYPE "25519"
#define NOISE_TYPE_SUFFIX NOISE_DH_TYPE "_ChaChaPoly_SHA256"
#define NOISE_MAX_OVERHEAD 64
#define NOISE_KEY_SIZE 32
#define NOISE_MAX_PACKET_SIZE NOISE_MAX_PAYLOAD_LEN
#define NOISE_MAC_SIZE 16
#define NOISE_MAX_DATA_SIZE (NOISE_MAX_PACKET_SIZE - NOISE_MAC_SIZE)

#include "error.h"

size_t noise_encrypt_max_size(size_t plaintext_size);

error_t noise_encrypt_message(
    NoiseCipherState* tx,
    const unsigned char* plaintext_data,
    size_t plaintext_size,
    unsigned char* ciphertext_data,
    size_t* ciphertext_size);

size_t noise_decrypt_max_size(size_t plaintext_size);

error_t noise_decrypt_message(
    NoiseCipherState* rx,
    const unsigned char* ciphertext_data,
    size_t ciphertext_size,
    unsigned char* plaintext_data,
    size_t* plaintext_size);

#endif  // _HSM_ENCLAVE_NOISE_H
