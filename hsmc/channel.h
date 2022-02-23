/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef _HSM_ENCLAVE_CHANNEL_H
#define _HSM_ENCLAVE_CHANNEL_H

#include <stdbool.h>

#include "error.h"
#include "command.h"
#include "noise.h"
#include "commandqueue.h"

////////////////////////////////////////////////////////////
// Channel Types
typedef int channeltype_t;

// Raw channels are unencrypted; data flows in and out without any
// obfuscation.  These should thus only be used within trusted environments,
// and are designed for use between the HSM processes and their handlers.
#define CHANNELTYPE_RAW 0

// NoiseNK channels allow any client, without prior authentication,
// to connect, but guarantee to said client that the HsmEnclave knows the
// private key for an associated public key.  These are meant for client
// connections to the HSM.  They also verify the hash of the code they're
// using within the payload of the handshake.
#define CHANNELTYPE_NOISE_NK 1

// NoiseKK* channels are used for a server to talk to another server.
// Both sides verify that the other side utilizes the same private key
// and is running code with the same hash.
#define CHANNELTYPE_NOISE_KK_INITIATOR 2
#define CHANNELTYPE_NOISE_KK_RESPONDER 3

#define LUA_CHANNELTYPE_UNKNOWN 0
#define LUA_CHANNELTYPE_UNENCRYPTED 1
#define LUA_CHANNELTYPE_CLIENTNK 2
#define LUA_CHANNELTYPE_SERVERKK 3

struct process_t;
struct hsm_enclave_t;

////////////////////////////////////////////////////////////
// channel_noise_t
//   Implements a noise channel.
typedef struct {
  NoiseHandshakeState* handshake;
  NoiseCipherState* rx;
  NoiseCipherState* tx;
} channel_noise_t;

////////////////////////////////////////////////////////////
// channel_t
//   Implementation of a channel between the host and a process in the OS.
//   Each process can have a number of channels associated with it.  These
//   channels may relate to a variety of endpoints, including external clients,
//   the host itself, other HSMs, etc.
typedef struct {
  uint32_t channel_id;
  uint32_t channel_type;
  struct process_t* proc_ref;  // reference (unowned) to parent process for this channel
  struct hsm_enclave_t* os_ref;
  union {
    channel_noise_t noise;
  };
} channel_t;

/** channel_new allocates a new channel.
 * \memberof channel_t
 *
 * Args:
 *  out:  location where allocated pointer will be output upon success.
 *  id:  channel identifier
 *  channel_type:  one of CHANNELTYPE_*
 *  os_ref:  reference to hsm_enclave_t holding this channel.  Does not transfer ownership.
 *  proc_ref:  reference to process_t holding this channel.  Does not transfer ownership.
 *
 * Returns:
 *  err_SUCCESS:  *out has been set to a newly allocated channel, owned by the caller
 *  err:  *out is unchanged, [err] details what went wrong
 */
error_t channel_new(channel_t** out, uint32_t id, channeltype_t channel_type, struct hsm_enclave_t* os_ref, struct process_t* proc_ref);

/** channel_free deallocates a channel.
 * \memberof channel_t
 *
 * Args:
 *  c:  this
 */
void channel_free(channel_t* c);

/** channel_initialization_complete returns whether a channel has finished initializing.
 * \memberof channel_t
 *
 * Args:
 *  c:  this
 *
 * Returns:
 *  true:  This channel has finished initialization, and subsequent channel messages should
 *         be passed to channel_preprocess_incoming_process_message before being passed to
 *         a process, and with the process' outgoing messages going through
 *         channel_push_outgoing_process_message.
 *  false: This channel is still initializing.  Incoming channel messages should be passed
 *         to channel_handle_initiation_message.  channel_output_initiation_message should
 *         be called after each such message is received.
 */
bool channel_initialization_complete(channel_t* c);

/** channel_preprocess_incoming_process_message unwraps a potentially encrypted channel message
 *      payload for use by a process.
 * \memberof channel_t
 *
 * PRECONDITION: true == channel_initialization_complete(c)
 *
 * Args:
 *  c:  this
 *  msg,size:  buffer of data (probably a command_extrabytes(x),command_extrabytes_size(x))
 *      to be unwrapped for use by a process.  Does not take ownership of incoming buffer.
 *  *pp_msg,*pp_size:  preprocessed buffer.  If *pp_msg!=msg, it is now an allocated buffer
 *      owned by the caller and should be deallocated after use.
 */
error_t channel_preprocess_incoming_process_message(channel_t* c, void* msg, size_t size, void** pp_msg, size_t* pp_size);

/** channel_push_outgoing_process_message pushes a CHANNEL_MESSAGE command for this channel
 *      into the output queue.
 * \memberof channel_t
 *
 * PRECONDITION: true == channel_initialization_complete(c)
 *
 * Args:
 *  c: this
 *  msg:  message to output.  This should be a CHANNEL_MESSAGE x with
 *      - command_process_id(x) == process_id(c->proc_ref)
 *      - command_channel_id(x) == c->channel_id
 *
 * Returns:
 *  err_SUCCESS:  successfully took ownership of [msg] and added it to output queue
 *  err:  failed to add to output queue, did not take ownership of [msg]
 */
error_t channel_push_outgoing_process_message(channel_t* c, command_t* msg);

/** channel_handle_initiation_message receives a channel message on a channel that has not
 *     yet been fully initialized, possibly completing its initialization.
 * \memberof channel_t
 *
 * PRECONDITION: false == channel_initialization_complete(c)
 *
 * Args:
 *   c: this
 *   msg/size: A buffer of data, probably from command_extrabytes(x),command_extrabytes_size(x)
 *     to use to further initialize the channel.
 *
 * Returns:
 *   err_SUCCESS:  channel initialization can continue, channel_output_initiation_message may
 *      have new messages to send.
 *
 * For noise-related channels, this will be the handshake request or response, which
 * includes the code hash of the process.
 */
error_t channel_handle_initiation_message(channel_t* c, void* msg, size_t size);

/** channel_output_initiation_message outputs any messages necessary to continue initialization
 *      for this channel.  Should be called upon channel creation and every time
 *      channel_handle_initiation_message is called, until channel_initialization_complete returns
 *      true.
 * \memberof channel_t
 *
 * PRECONDITION: false == channel_initialization_complete(c)
 *
 * Args:
 *   c: this
 *
 * Returns:
 *   err_SUCCESS if initialization has continued successfully.  This may add messages to the
 *       output queue, and may flip channel_initialization_complete().
 */
error_t channel_output_initiation_message(channel_t* c);

/** channel_lua_type returns a LUA_CHANNELTYPE for the given channel.
 * \memberof channel_t */
int channel_lua_type(channel_t* c);

#endif  // _HSM_ENCLAVE_CHANNEL_H
