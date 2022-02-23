/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "channel.h"

#include "hsm_enclave.h"
#include "process.h"

// If [x] denotes a noise-c failure, sets the already-defined [error_t err]
// variable to an error detailing that failure and jumps to code location [on_fail].
#define NOISE_ERR(msg, x, on_fail) do { \
  int _n_ = (x); \
  if (_n_ != NOISE_ERROR_NONE) { \
    char buf[64]; \
    int _noise_strerror_result = noise_strerror(_n_, buf, sizeof(buf)); \
    if (_noise_strerror_result != 0) { \
      err = ERR("unable to get Noise error string"); \
    } else { \
      err = ERR_COPYSTR(buf); \
    } \
    err = ERR_CTX(err, msg ": Noise error"); \
    goto on_fail; \
  } \
} while(0)

static bool channel_is_noise(channel_t* c) {
  switch (c->channel_type) {
  case CHANNELTYPE_NOISE_NK:
  case CHANNELTYPE_NOISE_KK_INITIATOR:
  case CHANNELTYPE_NOISE_KK_RESPONDER:
    return true;
  default:
    return false;
  }
}

int channel_lua_type(channel_t* c) {
  switch (c->channel_type) {
  case CHANNELTYPE_RAW:
    return LUA_CHANNELTYPE_UNENCRYPTED;
  case CHANNELTYPE_NOISE_NK:
    return LUA_CHANNELTYPE_CLIENTNK;
  case CHANNELTYPE_NOISE_KK_INITIATOR:
  case CHANNELTYPE_NOISE_KK_RESPONDER:
    return LUA_CHANNELTYPE_SERVERKK;
  default:
    return LUA_CHANNELTYPE_UNKNOWN;
  }
}

static error_t channel_init_noise(channel_t* c, NoiseDHState* dhstate) {
  DLOG("channel_init_noise(type=%d)", c->channel_type);
  channel_noise_t* n = &c->noise;
  ASSERT_ERR(n->handshake == NULL);
  ASSERT_ERR(n->tx == NULL);
  ASSERT_ERR(n->rx == NULL);
  
  error_t err = err_SUCCESS;
  // Initiate the local-side Noise handshake element and populate with our local secret key.
  const char* noise_type = "INVALID";
  switch (c->channel_type) {
    case CHANNELTYPE_NOISE_KK_INITIATOR:
    case CHANNELTYPE_NOISE_KK_RESPONDER:
      noise_type = "Noise_KK_" NOISE_TYPE_SUFFIX;
      break;
    case CHANNELTYPE_NOISE_NK:
      noise_type = "Noise_NK_" NOISE_TYPE_SUFFIX;
      break;
    default:
      return ERR("invalid channel type");
  }
  DLOG("Creating handshake %s", noise_type);
  NOISE_ERR("create server-side handshake",
      noise_handshakestate_new_by_name(&n->handshake, noise_type, c->channel_type == CHANNELTYPE_NOISE_KK_INITIATOR ? NOISE_ROLE_INITIATOR : NOISE_ROLE_RESPONDER),
      return_err);
  NoiseDHState* priv_dh = noise_handshakestate_get_local_keypair_dh(n->handshake);
  NOISE_ERR("copy dhstate",
      noise_dhstate_copy(priv_dh, dhstate),
      return_err);
  if (c->channel_type == CHANNELTYPE_NOISE_KK_INITIATOR ||
      c->channel_type == CHANNELTYPE_NOISE_KK_RESPONDER) {
    // We're talking to another server that should have our same private key.
    // Set the public key accordingly.
    unsigned char public_key[NOISE_KEY_SIZE];
    NOISE_ERR("get public",
        noise_dhstate_get_public_key(priv_dh, public_key, sizeof(public_key)),
        return_err);
    NoiseDHState* pub_dh = noise_handshakestate_get_remote_public_key_dh(n->handshake);
    NOISE_ERR("set public",
        noise_dhstate_set_public_key(pub_dh, public_key, sizeof(public_key)),
        return_err);
  }
  NOISE_ERR("noise_start",
      noise_handshakestate_start(n->handshake),
      return_err);
  DLOG("  - state: %d", noise_handshakestate_get_action(n->handshake));
  return err_SUCCESS;

return_err:
  return err;
}

error_t channel_output_initiation_message(channel_t* c) {
  DLOG("channel_output_initiation_message(%d)", c->channel_id);
  ASSERT_ERR(!channel_initialization_complete(c));
  ASSERT_ERR(channel_is_noise(c));
  channel_noise_t* n = &c->noise;
  ASSERT_ERR(n->handshake != NULL);

  command_t* out = NULL;
  error_t err = err_SUCCESS;

  if (NOISE_ACTION_WRITE_MESSAGE == noise_handshakestate_get_action(n->handshake)) {
    RETURN_IF_ERROR("creating output command for noise write",
        command_new(&out, O2H_COMMAND_CHANNEL_MESSAGE, process_id(c->proc_ref), c->channel_id, NOISE_MAX_OVERHEAD+CODEHASH_LENGTH));
    NoiseBuffer payload;
    noise_buffer_set_input(payload, c->proc_ref->process_state->codehash, CODEHASH_LENGTH);
    NoiseBuffer message;
    noise_buffer_set_output(message, command_extrabytes(out), command_extrabytes_size(out));
    NOISE_ERR("handshake write",
        noise_handshakestate_write_message(n->handshake, &message, &payload),
        free_command);
    if (err_SUCCESS != (err = command_shrink_extrabytes(out, message.size))) goto free_command;
    if (err_SUCCESS != (err = commandqueue_pushback(c->os_ref->output_from_command, out))) goto free_command;
  }
  if (NOISE_ACTION_SPLIT == noise_handshakestate_get_action(n->handshake)) {
    NOISE_ERR("handshakestate init split",
        noise_handshakestate_split(n->handshake, &n->tx, &n->rx),
        return_error);
    noise_handshakestate_free(n->handshake);
    n->handshake = NULL;
    DLOG("  - channel %d split", c->channel_id);
  } else {
    DLOG("  - not yet split");
  }
  return err_SUCCESS;

free_command:
  command_free(out);
return_error:
  return err;
}

bool channel_initialization_complete(channel_t* c) {
  switch (c->channel_type) {
    case CHANNELTYPE_RAW:
      return true;
    case CHANNELTYPE_NOISE_KK_INITIATOR:
    case CHANNELTYPE_NOISE_KK_RESPONDER:
    case CHANNELTYPE_NOISE_NK:
      return c->noise.handshake == NULL;
    default:
      return false;
  }
}

error_t channel_new(channel_t** out, uint32_t id, channeltype_t channel_type, hsm_enclave_t* os_ref, process_t* proc_ref) {
  channel_t* c;
  MALLOCZ_OR_RETURN_ERROR(c, channel_t);
  DLOG("channel_new(id=%d, type=%d) -> %p", id, channel_type, c);
  c->channel_id = id;
  c->channel_type = channel_type;
  c->proc_ref = proc_ref;
  c->os_ref = os_ref;
  error_t err = err_SUCCESS;
  if (channel_is_noise(c)) {
    if (err_SUCCESS != (err = channel_init_noise(c, os_ref->base_state))) goto free_channel;
  }
  *out = c;
  return err_SUCCESS;

free_channel:
  channel_free(c);
  return err;
}

void channel_free(channel_t* c) {
  DLOG("channel_free(%p)", c);
  if (channel_is_noise(c)) {
    if (c->noise.handshake != NULL) noise_handshakestate_free(c->noise.handshake);
    if (c->noise.tx != NULL) noise_cipherstate_free(c->noise.tx);
    if (c->noise.rx != NULL) noise_cipherstate_free(c->noise.rx);
  }
  free(c);
}

static error_t channel_push_outgoing_message_noise(channel_t* c, command_t* cmd) {
  DLOG("channel_push_outgoing_message_noise()");
  ASSERT_ERR(channel_initialization_complete(c));
  ASSERT_ERR(channel_is_noise(c));
  ASSERT_ERR(command_extrabytes_size(cmd) > 0);
  channel_noise_t* n = &c->noise;
  ASSERT_ERR(n->tx != NULL);
  ASSERT_ERR(command_type(cmd) == O2H_COMMAND_CHANNEL_MESSAGE);

  error_t err = err_SUCCESS;
  unsigned char* plaintext_data = command_extrabytes(cmd);
  size_t plaintext_size = command_extrabytes_size(cmd);

  size_t ciphertext_size = noise_encrypt_max_size(plaintext_size);
  command_t* out = NULL;
  RETURN_IF_ERROR(
      "creating command for output",
      command_new(&out, O2H_COMMAND_CHANNEL_MESSAGE, command_process_id(cmd), command_channel_id(cmd), ciphertext_size));
  unsigned char* ciphertext_data = command_extrabytes(out);

  if (err_SUCCESS != (err = noise_encrypt_message(n->tx, plaintext_data, plaintext_size, ciphertext_data, &ciphertext_size))) goto free_command;
  if (err_SUCCESS != (err = command_shrink_extrabytes(out, ciphertext_size))) goto free_command;
  if (err_SUCCESS != (err = commandqueue_pushback(c->os_ref->output_from_command, out))) goto free_command;
  command_free(cmd);
  return err_SUCCESS;

free_command:
  command_free(out);
  return err;
}

// This maximum value is pretty arbitrary, and is a safety measure against
// particularly misbehaving clients.  We never really expect more than 10
// hashes for a single connection, hopefully 1-2 is more the norm.
#define MAX_CODEHASHES 32

error_t channel_handle_initiation_message(channel_t* c, void* msg, size_t size) {
  ASSERT_ERR(!channel_initialization_complete(c));
  ASSERT_ERR(channel_is_noise(c));
  channel_noise_t* n = &c->noise;
  ASSERT_ERR(n->handshake != NULL);
  DLOG("  - handshake accept");
  ASSERT_ERR(NOISE_ACTION_READ_MESSAGE == noise_handshakestate_get_action(n->handshake));

  error_t err = err_SUCCESS;
  unsigned char in_buf[CODEHASH_LENGTH*MAX_CODEHASHES];
  NoiseBuffer message;
  noise_buffer_set_input(message, msg, size);
  NoiseBuffer payload;
  noise_buffer_set_output(payload, in_buf, sizeof(in_buf));
  NOISE_ERR("handshakestate init read",
      noise_handshakestate_read_message(n->handshake, &message, &payload),
      return_error);
  ASSERT_ERR(payload.size % CODEHASH_LENGTH == 0);
  int i = 0;
  bool found_hash = false;
  for (; i < payload.size && !found_hash; i += CODEHASH_LENGTH) {
    if (0 == memcmp(payload.data+i, c->proc_ref->process_state->codehash, CODEHASH_LENGTH)) {
      found_hash = true;
    }
  }
  ASSERT_ERR(found_hash);
  return err_SUCCESS;

return_error:
  return err;
}

static error_t channel_preprocess_incoming_message_noise(channel_t* c, void* ciphertext_data, size_t ciphertext_size, void** pp_msg, size_t* pp_size) {
  ASSERT_ERR(channel_initialization_complete(c));
  ASSERT_ERR(channel_is_noise(c));
  DLOG("channel_preprocess_incoming_message_noise()");
  channel_noise_t* n = &c->noise;
  ASSERT_ERR(n->rx != NULL);

  // The plaintext will shrink, but we allocate the entire size.
  size_t plaintext_size = noise_decrypt_max_size(ciphertext_size);
  unsigned char* plaintext_data = calloc(plaintext_size, sizeof(unsigned char));
  if (plaintext_data == NULL) return err_OOM;

  error_t err = err_SUCCESS;
  if (err_SUCCESS != (err = noise_decrypt_message(n->rx, ciphertext_data, ciphertext_size, plaintext_data, &plaintext_size))) goto free_plaintext;
  *pp_msg = plaintext_data;
  *pp_size = plaintext_size;
  return err_SUCCESS;

free_plaintext:
  free(plaintext_data);
  return err;
}

#undef NOISE_ERR

// Allow the channel to preprocess the given message, either consuming it and
// providing nothing to the process, providing it directly, or mutating it,
// possibly in place.  This could result in:
//   *pp_msg == msg  - pass msg to process state (may have been mutated in-place)
//   *pp_msg != msg  - pass newly allocated message to process state, then free it
// On an error, it's guaranteed that pp_msg does not need free-ing.
error_t channel_preprocess_incoming_process_message(channel_t* c, void* msg, size_t size, void** pp_msg, size_t* pp_size) {
  DLOG("channel_preprocess_incoming_process_message(size=%ld, type=%d)", size, c->channel_type);
  switch (c->channel_type) {
  case CHANNELTYPE_RAW:
    *pp_msg = msg;
    *pp_size = size;
    return err_SUCCESS;
  case CHANNELTYPE_NOISE_NK:
  case CHANNELTYPE_NOISE_KK_INITIATOR:
  case CHANNELTYPE_NOISE_KK_RESPONDER:
    return channel_preprocess_incoming_message_noise(c, msg, size, pp_msg, pp_size);
  default:
    return ERR("unimplemented");
  }
}

error_t channel_push_outgoing_process_message(channel_t* c, command_t* cmd) {
  DLOG("channel_push_outgoing_process_message(type=%08x,p=%d,c=%d,ebsz=%d,chtype=%d)", command_type(cmd), process_id(c->proc_ref), c->channel_id, command_extrabytes_size(cmd), c->channel_type);
  ASSERT_ERR(command_channel_id(cmd) == c->channel_id);
  ASSERT_ERR(command_process_id(cmd) == process_id(c->proc_ref));
  switch (c->channel_type) {
  case CHANNELTYPE_RAW:
    return commandqueue_pushback(c->os_ref->output_from_command, cmd);
  case CHANNELTYPE_NOISE_NK:
  case CHANNELTYPE_NOISE_KK_INITIATOR:
  case CHANNELTYPE_NOISE_KK_RESPONDER:
    return channel_push_outgoing_message_noise(c, cmd);
  default:
    return ERR("unimplemented");
  }
}

