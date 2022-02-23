/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef _HSM_ENCLAVE_PROCESSSTATE_H
#define _HSM_ENCLAVE_PROCESSSTATE_H

#include <stdint.h>
#include <stdbool.h>
#include <lua.h>

#include "error.h"
#include "commandqueue.h"
#include "crypt.h"

#define CODEHASH_LENGTH 32

struct hsm_enclave_t;

// Set to false to not actually run any user-supplied Lua.
// Default: true
// Currently used solely for certain fuzz testing.
extern bool processstate_run_lua;

////////////////////////////////////////////////////////////
// processstate_t
//   Stores the state of a single Lua process, including a hash of the code
//   used to create this process.
typedef struct {
  unsigned char codehash[CODEHASH_LENGTH];
  uint32_t process_id;
  lua_State* L;
  int sandbox_env;

  // Ints pointing to global functions.
  int handle_channel_create;
  int handle_channel_close;
  int handle_channel_message;

  // enclave_ref is used to send process output, and by lua encrypt/decrypt
  // functions, which require access to the secret key from the os level.
  struct hsm_enclave_t* enclave_ref;

  // Used for hsm_enclave_lua_encrypt and hsm_enclave_lua_decrypt.
  crypt_t* crypt;
} processstate_t;

/** processstate_new allocates and initializes a new process state.
 * \memberof processstate_t
 *
 * Args:
 *  @param out Output of new processstate upon success
 *  @param code/code_size Buffer containing Lua (compiled or cleartext) to use for process
 *  @param process_id Process ID for new process
 *  @param enclave_ref Reference to hsm_enclave_t grandparent of this processstate, does not take ownership
 *
 * @return
 *  err_SUCCESS: *out contains a newly allocated processstate_t
 *  err:  Process initialization failed, *out unchanged
 */
error_t processstate_new(processstate_t** out, const void* code, size_t code_size, uint32_t process_id, struct hsm_enclave_t* enclave_ref);

/** processstate_free deallocates a processstate allocated with processstate_new.
 * \memberof processstate_t */
void processstate_free(processstate_t* p);

/** processstate_channel_add tells the underlying Lua process that a channel is available.
 * \memberof processstate_t
 *
 * This should be called after a channel has been fully initialized, as it signals
 * to the underlying process that sending on this channel is now allowed.
 *
 * @return
 *   err_SUCCESS: process's HandleChannelCreate function successfully called,
 *       and any outputs successfully added to enclave_ref->output_from_process
 *   err:  Some failure occurred.  enclave_ref->output_from_process may contain spurious data
 */
error_t processstate_channel_add(processstate_t* p, uint32_t channel_id, int lua_channel_type);

/** processstate_channel_message sends a cleartext message to a process' Lua state
 * \memberof processstate_t
 *
 * Args:
 *  @param p this
 *  @param channel_id Channel to send message to
 *  @param msg/size Message buffer (cleartext, already preprocessed by channel) to send.
 *         Function does not take ownership of this buffer.
 *
 * @return
 *   err_SUCCESS: process's HandleChannelMessage function successfully called,
 *       and any outputs successfully added to enclave_ref->output_from_process
 *   err:  Some failure occurred.  enclave_ref->output_from_process may contain spurious data
 */
error_t processstate_channel_message(processstate_t* p, uint32_t channel_id, const unsigned char* msg, size_t size);

/** processstate_channel_remove tells the underlying Lua process that a channel
 *  has been closed and is no longer available.
 * \memberof processstate_t
 *
 * Args:
 *  @param p this
 *  @param p channel_id Channel that was closed
 *
 * @return
 *   err_SUCCESS: process's HandleChannelClose function successfully called,
 *       and any outputs successfully added to enclave_ref->output_from_process
 *   err:  Some failure occurred.  enclave_ref->output_from_process may contain spurious data
 */
error_t processstate_channel_remove(processstate_t* p, uint32_t channel_id);

#endif  // _HSM_ENCLAVE_PROCESSSTATE_H
