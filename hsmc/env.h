/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef _HSM_ENCLAVE_ENV_H
#define _HSM_ENCLAVE_ENV_H

#include "error.h"
#include "noise.h"

/** env_noise_dhstate initiates a base NoiseDHState based on the environment.
 *
 * Args:
 *  @param state State will be output here
 *
 * @return
 *  err_SUCCESS: *state contains a DHState that can be copied/used as
 *               the private-key side of Noise operations.
 *  err:  *state unchanged.
 */
error_t env_noise_dhstate(
    NoiseDHState** state);

#endif  // _HSM_ENCLAVE_ENV_H
