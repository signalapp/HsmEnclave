/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "env.h"
#include "dlog.h"
#include "noise.h"
#include "error.h"
#include "env_hsm.h"
#include "dh-curve25519.h"
#include <seelib.h>

static struct envhsm_globals_t globals;
struct envhsm_globals_t* envhsm_globals = &globals;

// SEE-specific functions for deriving stuff.

// Given the base key [base] and wrap key [wrap], derive the key [out] using
// the derivation mechanism [params] and with the final ACL [derived_action].
// Note that [wrap] is only necessary if the [params] require a wrapping key.
// If they don't, [wrap] may be zero, in which case it is ignored.
error_t see_derive_key(M_DKMechParams* params, M_KeyID base, M_KeyID wrap, M_KeyID tmpl, M_KeyID* out) {
  DLOG("Deriving tmpl=%d base=%d wrap=%d", tmpl, base, wrap);
  STACKVAR_ZERO(M_Command, cmd);
  cmd.cmd = Cmd_DeriveKey;
  M_KeyID keys[3];
  keys[0] = tmpl;
  keys[1] = base;
  keys[2] = wrap;
  cmd.args.derivekey.n_keys = wrap != 0 ? 3 : 2;
  cmd.args.derivekey.keys = keys;
  cmd.args.derivekey.mech = params->mech;
  cmd.args.derivekey.params = params->params;

  M_Reply* reply;
  RETURN_IF_ERROR("key derivation command",
      seelib_transact_err(&cmd, &reply));

  *out = reply->reply.derivekey.key;
  DLOG("Derived %u", *out);
  return err_SUCCESS;
}

static void env_set_global_signers(M_Command* cmd) {
  if (envhsm_globals->see_global_signers.n_certs > 0) {
    cmd->flags |= Command_flags_certs_present;
    cmd->certs = &envhsm_globals->see_global_signers;
  }
}

error_t seelib_err(int rc) {
  switch (rc) {
    case Status_OK: return err_SUCCESS;
    case Status_NoMemory: return err_OOM;
  }
  char buf[128];
  error_t err = err_SUCCESS;
  if (0 != NFast_StrError(buf, sizeof(buf), rc, 0)) {
    err = ERR("unable to convert status to error");
  } else {
    err = ERR_COPYSTR(buf);
  }
  return ERR_CTX(err, "SEElib error");
}

void see_destroy_key_besteffort(M_KeyID id) {
  STACKVAR_ZERO(M_Command, cmd);
  cmd.cmd = Cmd_Destroy;
  cmd.args.destroy.key = id;
  M_Reply* reply = NULL;
  if (Status_OK == seelib_transact(&cmd, &reply)) {
    DLOG("Successfully destroyed key %d", id);
    SEElib_FreeReply(reply);
  } else {
    DLOG("Failed to destroy key %d", id);
  }
}

static error_t env_init_global_signers(void) {
  error_t err = err_SUCCESS;

  DLOG("Getting global signers");
  STACKVAR_ZERO(M_Command, cmd_signers);
  cmd_signers.cmd = Cmd_GetWorldSigners;

  M_Reply* reply_signers = NULL;
  if (err_SUCCESS != (err = ERR_CTX(seelib_err(seelib_transact(&cmd_signers, &reply_signers)), "signers"))) return err;
  DLOG("Got signers: %d", reply_signers->reply.getworldsigners.n_sigs);
  if (reply_signers->reply.getworldsigners.n_sigs != 1) {
    err = ERR("did not get exactly one signer");
    goto free_reply;
  }

  DLOG("Received global signers, copying to global");
  M_Certificate* cert = calloc(1, sizeof(M_Certificate));
  if (cert == NULL) {
    err = err_OOM;
    goto free_reply;
  }
  cert->type = CertType_SEECert;
  memcpy(&cert->keyhash, &reply_signers->reply.getworldsigners.sigs[0].hash, sizeof(M_KeyHash));
  envhsm_globals->see_global_signers.n_certs = 1;
  envhsm_globals->see_global_signers.certs = cert;

free_reply:
  SEElib_FreeReply(reply_signers);
  return err;
}

static error_t env_pop_key(unsigned char** from, size_t* from_size, unsigned char** to, size_t* to_size) {
  ASSERT_ERR(*from_size >= 2);
  size_t sz = ((*from)[0] << 8) | (*from)[1];  // 16-bit size, BE
  DLOG("key size: %d", sz);
  *from += 2;
  *from_size -= 2;
  ASSERT_ERR(*from_size >= sz);
  *to = *from;
  *to_size = sz;
  *from += sz;
  *from_size -= sz;
  return err_SUCCESS;
}

static error_t env_keys(unsigned char* blob, size_t blob_size) {
  int i;
  for (i = 0; i < ENVHSM_TOTAL_KEYS; i++) {
    DLOG("Loading key %d", i);
    unsigned char* keyblob = NULL;
    size_t keyblob_size = 0;
    RETURN_IF_ERROR("key blob from userdata", env_pop_key(&blob, &blob_size, &keyblob, &keyblob_size));
    STACKVAR_ZERO(M_Command, cmd);
    cmd.cmd = Cmd_LoadBlob;
    cmd.args.loadblob.blob.ptr = keyblob;
    cmd.args.loadblob.blob.len = keyblob_size;
    M_Reply* reply;
    RETURN_IF_ERROR("loading blob", seelib_transact_err(&cmd, &reply));
    envhsm_globals->keys[i] = reply->reply.loadblob.idka;
    SEElib_FreeReply(reply);
    DLOG("Key %d: %d", i, envhsm_globals->keys[i]);
  }
  ASSERT_ERR(blob_size == 0);

  DLOG("Extracting public key"); {
    DLOG("- Deriving");
    STACKVAR_ZERO(M_DKMechParams, dkparams);
    dkparams.mech = DeriveMech_PublicFromPrivate;
    STACKVAR_ZERO(M_Action, derived_action);
    derived_action.type = Act_OpPermissions;
    derived_action.details.oppermissions.perms = Act_OpPermissions_Details_perms_ExportAsPlain;
    M_KeyID pub = 0;
    RETURN_IF_ERROR("deriving public key",
        see_derive_key(
            &dkparams,
            envhsm_globals->keys[ENVHSM_KEY_NOISE],
            0,
            envhsm_globals->keys[ENVHSM_KEY_NOISE_DERIVE_TOPUB],
            &pub));
    ASSERT_ERR(pub != 0);

    DLOG("- Exporting");
    STACKVAR_ZERO(M_Command, cmd);
    cmd.cmd = Cmd_Export;
    cmd.args.export.key = pub;
    M_Reply* reply;
    RETURN_IF_ERROR("exporting public key",
        seelib_transact_err(&cmd, &reply));
    ASSERT_ERR(reply->reply.export.data.type == KeyType_X25519Public);
    ASSERT_ERR(reply->reply.export.data.data.random.k.len == NOISE_KEY_SIZE);
    memcpy(envhsm_globals->public_key, reply->reply.export.data.data.random.k.ptr, NOISE_KEY_SIZE);
    unsigned char* k = envhsm_globals->public_key;
    LOG("Public key: "
        "%02x%02x%02x%02x%02x%02x%02x%02x"
        "%02x%02x%02x%02x%02x%02x%02x%02x"
        "%02x%02x%02x%02x%02x%02x%02x%02x"
        "%02x%02x%02x%02x%02x%02x%02x%02x",
        k[0x00], k[0x01], k[0x02], k[0x03], k[0x04], k[0x05], k[0x06], k[0x07],
        k[0x08], k[0x09], k[0x0a], k[0x0b], k[0x0c], k[0x0d], k[0x0e], k[0x0f],
        k[0x10], k[0x11], k[0x12], k[0x13], k[0x14], k[0x15], k[0x16], k[0x17],
        k[0x18], k[0x19], k[0x1a], k[0x1b], k[0x1c], k[0x1d], k[0x1e], k[0x1f]);
    see_destroy_key_besteffort(pub);
  }

  DLOG("Key loading succeeded");
  return err_SUCCESS;
}

error_t envhsm_init_globals(unsigned char* userdata, size_t userdata_len) {
  RETURN_IF_ERROR("env_init_global_signers", env_init_global_signers());
  RETURN_IF_ERROR("env_keys", env_keys(userdata, userdata_len));
  return err_SUCCESS;
}

error_t env_noise_dhstate(
    NoiseDHState** out) {
  DLOG("env_noise_dhstate()");
  if (envhsm_globals->see_global_signers.n_certs != 1) {
    return ERR("global signers not yet initiated");
  }

  NoiseDHState* dh = NULL;
  if (NOISE_ERROR_NONE != noise_dhstate_new_by_name(&dh, NOISE_DH_TYPE)) return ERR("noise_dhstate_new_by_name");

  error_t err = err_SUCCESS;
  unsigned char zero_private_key[NOISE_KEY_SIZE];
  memset(zero_private_key, 0, NOISE_KEY_SIZE);

  if (NOISE_ERROR_NONE != noise_dhstate_set_keypair(dh, zero_private_key, NOISE_KEY_SIZE, envhsm_globals->public_key, NOISE_KEY_SIZE)) {
    err = ERR("noise_dhstate_set_keypair");
    goto free_dh;
  }
  if (NOISE_ERROR_NONE != noise_hsm25519_set_private_keyid(dh, envhsm_globals->keys[ENVHSM_KEY_NOISE])) {
    err = ERR("set_private_key_id");
    goto free_dh;
  }

  *out = dh;
  return err_SUCCESS;

free_dh:
  noise_dhstate_free(dh);
  return err;
}

int seelib_transact(M_Command* command, M_Reply** reply_out) {
  M_Reply* reply = calloc(1, sizeof(M_Reply));
  if (reply == NULL) {
    return Status_NoMemory;
  }
  env_set_global_signers(command);
  int rc = Status_OK;
  if (Status_OK != (rc = SEElib_MarshalSendCommand(command))) goto free_reply;
  if (Status_OK != (rc = SEElib_GetUnmarshalResponse(reply))) goto free_reply;
  if (Status_OK != (rc = reply->status)) goto free_reply;
  *reply_out = reply;
  return Status_OK;

free_reply:
  SEElib_FreeReply(reply);
  return rc;
}

// Override Noise-C's "noise_rand_bytes" function to utilize HSM-generated
// randomness.  We expect it's already doing so, as Noise-C opens and reads
// "/dev/urandom", which the nCipher-provided C library appears to support.
// However, while it's supported, it's not entirely clear that it's directing
// the randomness generation request to nCipher's core API, so better safe
// than sorry - we'll override it ourselves.
void __wrap_noise_rand_bytes(void* bytes, size_t size);
void __wrap_noise_rand_bytes(void* bytes, size_t size) {
  DLOG("__wrap_noise_rand_bytes(%ld)", size);
  STACKVAR_ZERO(M_Command, cmd);
  cmd.cmd = Cmd_GenerateRandom;
  cmd.args.generaterandom.lenbytes = size;

  M_Reply* reply;
  error_t err = err_SUCCESS;
  if (err_SUCCESS != (err = seelib_transact_err(&cmd, &reply))) {
    LOG_ERR(err);
    ERR_FREE(err);
    exit(1);
  }
  if (reply->reply.generaterandom.data.len != size) {
    LOG("random size mismatch");
    SEElib_FreeReply(reply);
    exit(1);
  }
  memcpy(bytes, reply->reply.generaterandom.data.ptr, size);
  SEElib_FreeReply(reply);
  DLOG("__wrap_noise_rand_bytes success");
}
