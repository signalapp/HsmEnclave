/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef _HSM_ENCLAVE_ENV_HSM_H
#define _HSM_ENCLAVE_ENV_HSM_H

#include "error.h"
#include <seelib.h>

// Enumeration of the set of keys read from userdata.
// Userdata consists of N keys, of the form [length1][keyblob1]...[lengthN][keyblobN],
// where [lengthX] is a 2-byte big-endian unsigned integer.
// - Template key allowing KEY_NOISE to be derived with DeriveMech_PublicFromPrivate
#define ENVHSM_KEY_NOISE_DERIVE_TOPUB 0
// - Base Noise key, for terminating client requests
#define ENVHSM_KEY_NOISE 1
// - AES key (all zero bits) used for encrypt/decrypt derivation
#define ENVHSM_KEY_CRYPT_DERIVE_ENCDEC 2
// - Template key for crypt derivation step 3: RawDecrypt(AES,DERIVE_ENCDEC)
#define ENVHSM_KEY_CRYPT_DERIVETMPL_DEC 3
// - Template key for crypt derivation step 2: RawEncrypt(AES,DERIVE_ENCDEC)
#define ENVHSM_KEY_CRYPT_DERIVETMPL_ENC 4
// - Template key for crypt derivation step 1: RawEncrypt(HMACSHA256,CRYPT_ROOT)
#define ENVHSM_KEY_CRYPT_DERIVETMPL_SIGN 5
// - Root key for crypt derivation step 1: RawEncrypt(HMACSHA256,CRYPT_ROOT)
#define ENVHSM_KEY_CRYPT_ROOT 6
// The total expected number of keys in userdata.
#define ENVHSM_TOTAL_KEYS 7

////////////////////////////////////////////////////////////////////////////////
// envhsm_globals_t contains a set of HSM-specific global variables.
struct envhsm_globals_t {
  M_CertificateList see_global_signers;
  M_KeyID keys[ENVHSM_TOTAL_KEYS];
  unsigned char public_key[NOISE_KEY_SIZE];
};
extern struct envhsm_globals_t* envhsm_globals;

/** envhsm_init_globals initiates *envhsm_globals.
 *
 * Args:
 *   @param userdata/userdata_len Userdata passed in on command-line.
 * \memberof envhsm_globals_t */
error_t envhsm_init_globals(unsigned char* userdata, size_t userdata_len);

/** seelib_err translates an SEElib_*-returned error to an error_t. */
error_t seelib_err(int rc);

/** seelib_transact runs the given SEElib command.
 *
 * Args:
 *  @param command Command to run
 *  @param reply On success, set to an allocated reply
 *
 * @return
 *   err_SUCCESS: *reply contains the reply
 *   err:  *reply unchanged
 */
int seelib_transact(M_Command* command, M_Reply** reply);

/** Runs the given command, allocating a reply on success or returning an error on failure. */
inline error_t seelib_transact_err(M_Command* command, M_Reply** reply) {
  return seelib_err(seelib_transact(command, reply));
}

/** Destroy the given key ID, deallocating it from nCore. */
void see_destroy_key_besteffort(M_KeyID id);

/** Derive a key with nCore APIs.  If [wrap] is zero, it's ignored.  On success,
 *  derived key's ID is output to *out. */
error_t see_derive_key(M_DKMechParams* params, M_KeyID base, M_KeyID wrap, M_KeyID tmpl, M_KeyID* out);

#define STACKVAR_ZERO(t, v) \
  t v; \
  memset(&v, 0, sizeof(t))

#endif  // _HSM_ENCLAVE_ENV_HSM_H
