/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef _HSM_ENCLAVE_CRYPT_H
#define _HSM_ENCLAVE_CRYPT_H

#include "error.h"
#include "noise.h"

/** cryptfactory_t creates process-specific crypt_t instantiations to encrypt/decrypt
 *  data to pass to the host.  This struct is platform-specific.  It is defined in
 *  crypt_native.c and crypt_hsm.c respectively.
 */
struct cryptfactory_t;
typedef struct cryptfactory_t cryptfactory_t;

/** crypt_t handles per-process encryption/decryption of host-side data.
 *  This struct is platform-specific.  It is defined in crypt_native.c and
 *  crypt_hsm.c respectively.
 */
struct crypt_t;
typedef struct crypt_t crypt_t;

#define CRYPT_INTEGRITY_BYTES 16  // additional bytes added to ciphertext for integrity checking
#define CRYPT_IV_BYTES 32         // size in bytes of IV used for key generation and prepended to ciphertext
#define CRYPT_USERKEY_BYTES 32    // size in bytes of user-provided keys
#define CRYPT_OVERHEAD (CRYPT_IV_BYTES + CRYPT_INTEGRITY_BYTES)  // |encrypt(plaintext)| = |plaintext| + CRYPT_OVERHEAD
#define CRYPT_CIPHER NOISE_CIPHER_CHACHAPOLY  // Cipher utilized for encrypt/decrypt ops.

/** Creates a new cryptfactory based on the current environment.
 * \memberof cryptfactory_t */
error_t env_cryptfactory(
    cryptfactory_t** cf);

/** Deallocates a cryptfactory.
 * \memberof cryptfactory_t */
void cryptfactory_free(cryptfactory_t* cf);

/** Derives a process-specific crypt instantiation based on a process hash.
 * \memberof cryptfactory_t
 *
 * Args:
 *   @param f this
 *   @param code_hash Code hash of length CODEHASH_LENGTH
 *   @param *derived crypt_t will be output here upon success.
 */
error_t cryptfactory_derive(
    cryptfactory_t* f,
    const unsigned char* code_hash,
    crypt_t** derived);

/** Deallocate a crypt_t allocated with cryptfactory_derive.
 * \memberof crypt_t */
void crypt_free(crypt_t* c);

/** Encrypt host-handled data.
 * \memberof crypt_t
 *
 * This method is not platform-specific, but relies on the platform-specific crypt_key function
 * to generate a key utilized during the encryption process.
 *
 * Always encrypts "" as "", since encryption of the empty string is recognizable regardless.
 *
 * Args:
 *   @param crypt this
 *   @param rand PRNG utilized for secure generation of random numbers as part of encryption
 *   @param plaintext/plaintext_size Data to be encrypted
 *   @param userkey User key to derive with.  [userkey] may be NULL, in which case
 *          no user-provided key is utilized.  Otherwise, it points to a buffer of size
 *          CRYPT_USERKEY_BYTES
 *   @param ciphertext Location to put encrypted data
 *   @param *ciphertext_size Initially stores the max size of the [ciphertext] buffer, will
 *          be set upon success to a size <= its initial size detailing the final size of the
 *          generated ciphertext.  Must initially be at least [plaintext_size + CRYPT_OVERHEAD].
 */
error_t crypt_encrypt(
    crypt_t* crypt,
    NoiseRandState* rand,
    const unsigned char* plaintext,
    size_t plaintext_size,
    const unsigned char* userkey,
    unsigned char* ciphertext,
    size_t* ciphertext_size);

/** Decrypt host-handled data.
 * \memberof crypt_t
 *
 * This method is not platform-specific, but relies on the platform-specific crypt_key function
 * to generate a key utilized during the decryption process.
 *
 * Always decrypts "" as "", since encryption of the empty string is recognizable regardless.
 * This also allows for the "zero value" of as-yet-unwritten state to be utilized as empty.
 *
 * Args:
 *   @param crypt this
 *   @param ciphertext/ciphertext_size Data to be decrypted
 *   @param plaintext Location to put decrypted data
 *   @param userkeys A concatenated list of user keys to attempt to use for decryption,
 *          each of which is CRYPT_USERKEY_BYTES long, and all of which are [userkeys_size] long.
 *          May be null, in which case no userkeys are utilized.
 *   @param userkeys_size Size of all user keys combined.  It must be true that
 *          [userkeys_size % CRYPT_USERKEY_BYTES == 0]
 *   @param *plaintext_size Initially stores the max size of the [plaintext] buffer, will
 *          be set upon success to a size <= its initial size detailing the final size of the
 *          generated plaintext.  Must initially be at least [ciphertext_size].
 */
error_t crypt_decrypt(
    crypt_t* crypt,
    const unsigned char* ciphertext,
    size_t ciphertext_size,
    const unsigned char* userkeys,
    size_t userkeys_size,
    unsigned char* plaintext,
    size_t* plaintext_size);

/** Platform-specific key derivation function, generating an encryption/decryption key from
 *  a passed-in IV.
 * \memberof crypt_t */
error_t crypt_key(
    crypt_t* crypt,
    const unsigned char iv[CRYPT_IV_BYTES],
    unsigned char key[NOISE_KEY_SIZE]);

#endif  // _HSM_ENCLAVE_CRYPT_H
