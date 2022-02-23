/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef _HSM_ENCLAVE_PROCESS_H
#define _HSM_ENCLAVE_PROCESS_H

#include <stdint.h>

#include "error.h"
#include "processstate.h"
#include "fixedmap.h"
#include "channel.h"

struct hsm_enclave_t;

////////////////////////////////////////////////////////////
// process_t
//   Stores everything related to a current process, including process state
//   and any channels associated with the process.
typedef struct process_t {
  processstate_t* process_state;
  fixedmap_t* channels;
  uint32_t chanid_gen;
} process_t;

/** process_new allocates a new process.
 * \memberof process_t
 *
 * Args:
 *  @param p Output upon success
 *  @param ps Takes ownership of the provided process state on success.
 *
 * @return
 *  err_SUCCESS:  *p contains an allocated process, which has successfully taken ownership
 *     of [ps].
 *  err:  Ownership of [ps] remains with the caller, and [p] is unchanged.
 */
error_t process_new(process_t** p, processstate_t* ps);

/** process_free deallocates a process allocated with process_new.
 * \memberof process_t */
void process_free(process_t* p);

/** process_id returns the process ID for the given process.
 * \memberof process_t. */
uint32_t process_id(const process_t* p);

/** process_channel_add adds a channel to a process.
 * \memberof process_t
 *
 * Args:
 *   @param p this
 *   @param c Channel to add, on success takes ownership.
 *
 * Returns:
 *   err_SUCCESS:  [p] takes ownership of [c].
 *   err:  [c] remains owned by caller
 */
error_t process_channel_add(process_t* p, channel_t* c);

/** process_channel_remove removes a channel from a process.
 * \memberof process_t */
error_t process_channel_remove(process_t* p, uint32_t channel_id);
/** process_channel_message sends a message to a channel.
 * \memberof process_t
 *
 * Args:
 *   @param p this
 *   @param channel_id Channel to send process message to
 *   @param msg/size Buffer to send to process (possibly wrapped in such
 *          a way that the channel may need to unwrap it.  This call does
 *          not take ownership of the [msg] buffer; it's retained by the
 *          caller.
 *
 * @return
 *   err_SUCCESS:  Process successfully received and processed message on
 *       the given channel.
 *   err:  Process failed to handle the message on the given channel.
 */
error_t process_channel_message(process_t* p, uint32_t channel_id, void* msg, size_t size);
/** process_create_channel_id asks the process to generate a unique
 *  id for a new channel.
 * \memberof process_t
 *
 * Args:
 *  @param p this
 *  @param channel_id On success, output written here
 *
 * @return
 *   err_SUCCESS:  *channel_id contains an ID for a new channel
 *   err:  *channel_id unchanged.
 */
error_t process_create_channel_id(process_t* p, uint32_t* channel_id);

/** process_free_channel cleans up a channel, _without_ calling the
 *  Lua process's HandleChannelClose, since it's used in cases where
 *  Lua itself requests channel closure.
 * \memberof process_t
 *
 * Args:
 *   p:  this
 *   cid: channel ID of channel to close/deallocate
 */
void process_free_channel(process_t* p, uint32_t cid);

#endif  // _HSM_ENCLAVE_PROCESS_H
