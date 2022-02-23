/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// The actual HsmEnclave binary to be run on the HSM, utilizing the seelib
// nCipher library to receive and return commands.

#include <stdio.h>
#include <stdlib.h>
#include <seelib.h>
#include <assert.h>

#include "hsm_enclave.h"
#include "dlog.h"
#include "env_hsm.h"

#define HSM_ENCLAVE_H2O_COMMAND_BUFFER_SIZE (256<<10)

int main(void) {
  SEElib_init();

  // Read in userdata
  M_Word userdata_len = SEElib_GetUserDataLen();
  hsm_enclave_t* os;
  unsigned char* userdata_buf = malloc(userdata_len);
  unsigned char* command_buf = calloc(HSM_ENCLAVE_H2O_COMMAND_BUFFER_SIZE, sizeof(unsigned char));

  error_t err = err_SUCCESS;
  if (userdata_buf == NULL) {
    err = ERR("failed to allocate userdata buffer");
  } else if (command_buf == NULL) {
    err = ERR("failed to allocate command buffer");
  } else if (0 != SEElib_ReadUserData(0, userdata_buf, userdata_len)) {
    err = ERR("failed to read userdata");
  } else if (err_SUCCESS != (err = envhsm_init_globals(userdata_buf, userdata_len))) {
    err = ERR_CTX(err, "envhsm_init_globals");
  } else if (err_SUCCESS != (err = hsm_enclave_new(&os))) {
    err = ERR_CTX(err, "hsm_enclave_new");
  } else {
    LOG("Read in %ld bytes of userdata and successfully initiated HsmEnclave", userdata_len);
  }

  free(userdata_buf);
  SEElib_ReleaseUserData();

  int result = err == err_SUCCESS ? 0 : 1;
  LOG("Initiation");
  LOG_ERR(err);
  SEElib_InitComplete(result);
  if (err != err_SUCCESS) return result;

  while (true) {
    M_Word length = HSM_ENCLAVE_H2O_COMMAND_BUFFER_SIZE;
    M_Word tag;
    assert(Status_OK == SEElib_AwaitJob(&tag, command_buf, &length));
    command_t* response = hsm_enclave_handle_command(os, command_buf, length);
    assert(response != NULL);
    assert(Status_OK == SEElib_ReturnJob(tag, (void*) response, command_total_size(response)));
    command_free(response);
  }
}
