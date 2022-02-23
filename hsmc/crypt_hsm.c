/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "crypt.h"
#include "env_hsm.h"
#include "processstate.h"

struct cryptfactory_t {
  int unused;
};

struct crypt_t {
  M_KeyID process_key;
};

error_t env_cryptfactory(
    cryptfactory_t** f) {
  MALLOCZ_OR_RETURN_ERROR(*f, cryptfactory_t);
  return err_SUCCESS;
}

void cryptfactory_free(cryptfactory_t* f) {
  free(f);
}

void crypt_free(crypt_t* crypt) {
  see_destroy_key_besteffort(crypt->process_key);
  free(crypt);
}

static void see_derive_action(M_Action* action, M_DKMechParams* from, M_DeriveRole role) {
  memset(action, 0, sizeof(*action));
  action->type = Act_DeriveKey;
  action->details.derivekey.flags = Act_DeriveKey_Details_flags_params_present;
  action->details.derivekey.role = role;
  action->details.derivekey.mech = from->mech;
  action->details.derivekey.params = from;
}

static void see_make_acl(M_ACL* to, M_Action* from, M_PermissionGroup* pgroup) {
  to->n_groups = 1;
  to->groups = pgroup;
  pgroup->flags = PermissionGroup_flags_certifier_present;
  pgroup->certifier = &envhsm_globals->see_global_signers.certs[0].keyhash;
  pgroup->n_actions = 1;
  pgroup->actions = from;
}

static error_t see_upload(M_KeyType type, M_Action* action, unsigned char* data, size_t size, M_KeyID* out) {
  STACKVAR_ZERO(M_Command, cmd);
  memset(&cmd, 0, sizeof(cmd));
  cmd.cmd = Cmd_Import;
  cmd.args.import.data.type = type;
  cmd.args.import.data.data.random.k.len = size;
  cmd.args.import.data.data.random.k.ptr = data;
  STACKVAR_ZERO(M_PermissionGroup, pgroup);
  see_make_acl(&cmd.args.import.acl, action, &pgroup);

  M_Reply* reply;
  RETURN_IF_ERROR("uploading random key", seelib_transact_err(&cmd, &reply));
  *out = reply->reply.import.key;
  DLOG("uploaded random key of %d bytes to %d", size, *out);
  return err_SUCCESS;
}

error_t cryptfactory_derive(
    cryptfactory_t* factory,
    const unsigned char* codehash,
    crypt_t** derived) {
  DLOG("cryptfactory_derive");
  STACKVAR_ZERO(M_DKMechParams, derive_params);
  derive_params.mech = DeriveMech_RawEncrypt;
  derive_params.params.rawencrypt.iv.mech = Mech_HMACSHA256;

  STACKVAR_ZERO(M_DKMechParams, enc_params);
  enc_params.mech = DeriveMech_RawEncrypt;
  enc_params.params.rawdecrypt.iv.mech = Mech_RijndaelmECBpNONE;

  STACKVAR_ZERO(M_DKMechParams, dec_params);
  dec_params.mech = DeriveMech_RawDecrypt;
  dec_params.params.rawdecrypt.iv.mech = Mech_RijndaelmECBpNONE;
  dec_params.params.rawdecrypt.dst_type = KeyType_HMACSHA256;

  // After we derive our initial key through our first derivation, we're left
  // with a key of KeyType_Wrapped.  We need to make that into a KeyType_HMACSHA256.
  // However, there appears no good way to do this.  So, we do it a slightly hacky
  // way:  we RawEncrypt(Wrapped)->Wrapped with AES, then RawDecrypt(Wrapped)->HMACSHA256
  // with AES, using the same key for both.  The end result is a key with exactly the
  // same data (since the enc+dec is a NOP) but with the correct destination key type.
  // We use a key of all zeros for this.

  DLOG("uploading codehash key");

  STACKVAR_ZERO(M_Action, derive_base_action);
  see_derive_action(&derive_base_action, &derive_params, DeriveRole_BaseKey);
  M_KeyID derive_base = 0;
  RETURN_IF_ERROR("upload derive base", see_upload(KeyType_Random, &derive_base_action, (unsigned char*) codehash, CODEHASH_LENGTH, &derive_base));

  error_t err = err_SUCCESS;
  DLOG("derive");
  M_KeyID enc_base = 0;
  if (err_SUCCESS != (err = ERR_CTX(see_derive_key(
          &derive_params,
          derive_base,
          envhsm_globals->keys[ENVHSM_KEY_CRYPT_ROOT],
          envhsm_globals->keys[ENVHSM_KEY_CRYPT_DERIVETMPL_SIGN],
          &enc_base), "derive"))) goto destroy_derive_base;
  DLOG("encrypt");
  M_KeyID dec_base = 0;
  if (err_SUCCESS != (err = ERR_CTX(see_derive_key(
          &enc_params,
          enc_base,
          envhsm_globals->keys[ENVHSM_KEY_CRYPT_DERIVE_ENCDEC],
          envhsm_globals->keys[ENVHSM_KEY_CRYPT_DERIVETMPL_ENC],
          &dec_base), "encrypt"))) goto destroy_enc_base;
  DLOG("decrypt");
  M_KeyID final = 0;
  if (err_SUCCESS != (err = ERR_CTX(see_derive_key(
          &dec_params,
          dec_base,
          envhsm_globals->keys[ENVHSM_KEY_CRYPT_DERIVE_ENCDEC],
          envhsm_globals->keys[ENVHSM_KEY_CRYPT_DERIVETMPL_DEC],
          &final), "decrypt"))) goto destroy_dec_base;

  DLOG("Process key derivation complete");
  crypt_t* out = calloc(1, sizeof(crypt_t));
  if (out == NULL) {
    err = err_OOM;
    goto destroy_final;
  }
  out->process_key = final;
  *derived = out;
  goto destroy_dec_base;  // don't destroy the final key

destroy_final:
  see_destroy_key_besteffort(final);
destroy_dec_base:
  see_destroy_key_besteffort(dec_base);
destroy_enc_base:
  see_destroy_key_besteffort(enc_base);
destroy_derive_base:
  see_destroy_key_besteffort(derive_base);
  return err;
}

error_t crypt_key(
    crypt_t* c,
    const unsigned char iv[CRYPT_IV_BYTES],
    unsigned char key[NOISE_KEY_SIZE]) {
  DLOG("crypt_key start");
  ASSERT_ERR(NOISE_KEY_SIZE == 32);
  STACKVAR_ZERO(M_Command, cmd);
  cmd.cmd = Cmd_Sign;
  cmd.args.sign.key = c->process_key;
  cmd.args.sign.mech = Mech_HMACSHA256;
  cmd.args.sign.plain.type = PlainTextType_Bytes;
  cmd.args.sign.plain.data.bytes.data.ptr = (unsigned char*) iv;
  cmd.args.sign.plain.data.bytes.data.len = CRYPT_IV_BYTES;
  DLOG(" - hsm request");
  M_Reply* reply = NULL;
  RETURN_IF_ERROR("hmac(iv)", seelib_transact_err(&cmd, &reply));
  DLOG(" - responded");
  memcpy(key, reply->reply.sign.sig.data.sha256hash.h.bytes, 32);
  SEElib_FreeReply(reply);
  DLOG(" - done");
  return err_SUCCESS;
}
