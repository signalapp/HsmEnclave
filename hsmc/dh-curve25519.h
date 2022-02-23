/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef _HSM_ENCLAVE_DH_CURVE25519_H
#define _HSM_ENCLAVE_DH_CURVE25519_H

#include "noise.h"
#include <seelib.h>

/** noise_hsm25519_set_private_keyid converts a software-backed NoiseDHState
 *  to a HSM-backed DHState, utilizing the provided M_KeyID as the backing key.
 *  Called only by env_noise_dhstate (env.h) when running on an HSM,
 *  and currently only called for the backing root private key.
 *
 * Args:
 *  @param s DHState to convert to HSM-backed
 *  @param id Key ID of private key to utilize.  Note that the public key
 *     for this DHState should already be the one associated with the backing
 *     private key ID'd by [id].
 *
 * @return
 *   NOISE_ERROR_NONE: on success.  private_key will be 0'd out after a successful
 *      call.  Future calls to noise_dhstate_copy of [s] will provide HSM-backed
 *      copies.
 *   NOISE_ERROR_SYSTEM: on any HSM-backing error
 */
int noise_hsm25519_set_private_keyid(NoiseDHState* s, M_KeyID id);

#endif  // _HSM_ENCLAVE_DH_CURVE25519_H
