/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "env.h"
#include "noise.h"
#include "error.h"

error_t env_noise_dhstate(
    NoiseDHState** out) {
  NoiseDHState* dh;
  if (NOISE_ERROR_NONE != noise_dhstate_new_by_name(&dh, NOISE_DH_TYPE)) {
    return ERR("noise_dhstate_new_by_name");
  }
  error_t err = err_SUCCESS;
  // Private key is always all zeros in native environment.
  unsigned char private_key[NOISE_KEY_SIZE];
  memset(private_key, 0, sizeof(private_key));
  if (NOISE_ERROR_NONE != noise_dhstate_set_keypair_private(dh, private_key, NOISE_KEY_SIZE)) {
    err = ERR("noise_dhstate_set_keypair_private");
    goto free_dh;
  }
  *out = dh;
  return err_SUCCESS;

free_dh:
  noise_dhstate_free(dh);
  return err;
}
