/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// Copied from noise-c/src/backend/ref/dh-curve25519.c, then special-cased
// for HSM-backed calculation.

#include "dh-curve25519.h"
#include "noise-c/src/protocol/internal.h"
#include "noise-c/src/crypto/ed25519/ed25519.h"
#include "dlog.h"
#include "env_hsm.h"
#include <string.h>
#include <seelib.h>
#include <stdlib.h>
#include <stdbool.h>

/** Underlying DHState object for 25519 calculations that can utilize
 *  either an in-software private key (if private_key_id == 0) or HSM-backed
 *  private key (if private_key_id != 0) */
typedef struct {
  struct NoiseDHState_s parent;
  M_KeyID private_key_id;
  uint8_t private_key[32];
  uint8_t public_key[32];
} NoiseHSMCurve25519State;

/** Called by env_noise_dhstate (env.h) on HSM to instantiate with
 * HSM-backed private key. */
int noise_hsm25519_set_private_keyid(NoiseDHState* s, M_KeyID id) {
  DLOG("noise_hsm25519_set_private_keyid(%d)", id);
  NoiseHSMCurve25519State* st = (NoiseHSMCurve25519State*) s;
  st->private_key_id = id;
  memset(st->private_key, 0, st->parent.private_key_len);
  return NOISE_ERROR_NONE;
}

static int noise_hsm25519_generate_keypair(
    NoiseDHState *state,
    const NoiseDHState *other) {
  DLOG("noise_hsm25519_generate_keypair");
  NoiseHSMCurve25519State *st = (NoiseHSMCurve25519State *)state;
  noise_rand_bytes(st->private_key, 32);
  st->private_key[0] &= 0xF8;
  st->private_key[31] = (st->private_key[31] & 0x7F) | 0x40;
  curved25519_scalarmult_basepoint(st->public_key, st->private_key);
  return NOISE_ERROR_NONE;
}

static int noise_hsm25519_set_keypair(
    NoiseDHState *state,
    const uint8_t *private_key,
    const uint8_t *public_key) {
  DLOG("noise_hsm25519_set_keypair");
  NoiseHSMCurve25519State *st = (NoiseHSMCurve25519State *)state;
  memcpy(st->private_key, private_key, state->private_key_len);
  memcpy(st->public_key, public_key, state->public_key_len);
  return NOISE_ERROR_NONE;
}

static int noise_hsm25519_set_keypair_private(
    NoiseDHState *state,
    const uint8_t *private_key) {
  DLOG("noise_hsm25519_set_keypair_private");
  NoiseHSMCurve25519State *st = (NoiseHSMCurve25519State *)state;
  memcpy(st->private_key, private_key, state->private_key_len);
  curved25519_scalarmult_basepoint(st->public_key, st->private_key);
  return NOISE_ERROR_NONE;
}

static int noise_hsm25519_validate_public_key(
    const NoiseDHState *state,
    const uint8_t *public_key) {
  return NOISE_ERROR_NONE;
}

static int noise_hsm25519_copy(
    NoiseDHState *state,
    const NoiseDHState *from,
    const NoiseDHState *other) {
  NoiseHSMCurve25519State *st = (NoiseHSMCurve25519State *)state;
  const NoiseHSMCurve25519State *from_st = (const NoiseHSMCurve25519State *)from;
  st->private_key_id = from_st->private_key_id;
  memcpy(st->private_key, from_st->private_key, 32);
  memcpy(st->public_key, from_st->public_key, 32);
  return NOISE_ERROR_NONE;
}

int curve25519_donna(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint);

static int noise_hsm25519_calculate(
    const NoiseDHState *private_key_state,
    const NoiseDHState *public_key_state,
    uint8_t *shared_key) {
  NoiseHSMCurve25519State* st = (NoiseHSMCurve25519State*) private_key_state;
  if (st->private_key_id == 0) {
    DLOG("noise_hsm25519_calculate:NORMAL");
    curve25519_donna(shared_key, private_key_state->private_key,
                     public_key_state->public_key);
    return NOISE_ERROR_NONE;
  }
  DLOG("noise_hsm25519_calculate:HSM");
  M_Command cmd_decrypt;
  memset(&cmd_decrypt, 0, sizeof(cmd_decrypt));
  cmd_decrypt.cmd = Cmd_Decrypt;
  cmd_decrypt.args.decrypt.mech = Mech_X25519KeyExchange;
  cmd_decrypt.args.decrypt.key = st->private_key_id;
  cmd_decrypt.args.decrypt.reply_type = PlainTextType_Bytes;
  cmd_decrypt.args.decrypt.cipher.mech = Mech_X25519KeyExchange;
  cmd_decrypt.args.decrypt.cipher.data.generic256.cipher.len = public_key_state->public_key_len;
  cmd_decrypt.args.decrypt.cipher.data.generic256.cipher.ptr = public_key_state->public_key;

  M_Reply* reply = NULL;
  if (Status_OK != seelib_transact(&cmd_decrypt, &reply) ||
    reply->reply.decrypt.plain.type != PlainTextType_Bytes ||
    reply->reply.decrypt.plain.data.bytes.data.len != 32) {
    return NOISE_ERROR_SYSTEM;
  }
  memcpy(shared_key, reply->reply.decrypt.plain.data.bytes.data.ptr, 32);
  SEElib_FreeReply(reply);
  return NOISE_ERROR_NONE;
}

NoiseDHState *noise_curve25519_new(void) {
  NoiseHSMCurve25519State *state = noise_new(NoiseHSMCurve25519State);
  if (!state)
      return 0;
  state->parent.dh_id = NOISE_DH_CURVE25519;
  state->parent.nulls_allowed = 1;
  state->parent.private_key_len = 32;
  state->parent.public_key_len = 32;
  state->parent.shared_key_len = 32;
  state->parent.private_key = state->private_key;
  state->parent.public_key = state->public_key;
  state->parent.generate_keypair = noise_hsm25519_generate_keypair;
  state->parent.set_keypair = noise_hsm25519_set_keypair;
  state->parent.set_keypair_private = noise_hsm25519_set_keypair_private;
  state->parent.validate_public_key = noise_hsm25519_validate_public_key;
  state->parent.copy = noise_hsm25519_copy;
  state->parent.calculate = noise_hsm25519_calculate;
  return &(state->parent);
}

/* Choose the version of curve25519-donna based on the word size */
#if __WORDSIZE == 64 && defined(__GNUC__)
#include "noise-c/src/crypto/donna/curve25519-donna-c64.c"
#else
#include "noise-c/src/crypto/donna/curve25519-donna.c"
#endif
