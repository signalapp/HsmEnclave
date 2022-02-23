/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <nfkm.h>
#include <nfinttypes.h>
#include <nfastapp.h>
#include <time.h>
#include <rqcard-applic.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>

// This is a simple use of the nCipher C API, meant to be run on
// a host with a security world and with an HSM installed.  It
// will generate a set of keys necessary to act as an HsmEnclave
// root of trust, storing them concatenated in a single file named
// 'key_blob'.  All errors are treated as crashing failures.

// If !x, crash in a method that displays error information from errno
#define ERRNO(x) do { \
  if (!(x)) { \
    fprintf(stderr, "Failure at %d: %s\n", __LINE__, #x); \
    perror("FAIL"); \
    exit(1); \
  } \
} while (0)

// If x != 0, crash in a method that displays nCipher NFast error information
#define NF(x) do { \
  int rc = (x); \
  if (rc != 0) { \
    fprintf(stderr, "Failure at %d\n", __LINE__); \
    NFast_Perror("FAIL", rc); \
    exit(1); \
  } \
} while (0)

// Create a new stack var of type `t` named `v`, and memset it to zero.
#define STACKVAR_ZERO(t, v) \
  t v; \
  memset(&v, 0, sizeof(t))
#define STACKVAR_ZERO_ARR(t,v,n) \
  t v[n]; \
  memset(&v, 0, sizeof(v))

// Necessary to define for nfkm.h, but unused.
struct NFast_Call_Context {
  int notused;
};

// Prints the given key hash to STDOUT as 20 hex chars.
static void print_keyhash(M_KeyHash* hash) {
  printf("KEY HASH: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
      hash->bytes[0], hash->bytes[1], hash->bytes[2], hash->bytes[3],
      hash->bytes[4], hash->bytes[5], hash->bytes[6], hash->bytes[7],
      hash->bytes[8], hash->bytes[9], hash->bytes[10], hash->bytes[11],
      hash->bytes[12], hash->bytes[13], hash->bytes[14], hash->bytes[15],
      hash->bytes[16], hash->bytes[17], hash->bytes[18], hash->bytes[19]);
}

// Writes the given bytes/byte_size out to the file descriptor [f] in their entirety.
static void write_all(int f, unsigned char* bytes, size_t byte_size) {
  unsigned char* start = bytes;
  unsigned char* end = bytes + byte_size;
  while (start < end) {
    int r = write(f, start, end-start);
    ERRNO(r > 0);
    start += r;
  }
}

// Struct for gathering all necessary common pieces necessary to run all operations against nCore.
typedef struct {
  NFast_AppHandle app;
  NFastApp_Connection conn;
  NFKM_WorldInfo* worldinfo;
  NFKM_ModuleInfo* moduleinfo;
  NFKM_Key* see;
  struct NFast_Call_Context cctx;
  int fd;
} Environment;

// Extract the given key ID as a blob and write it out to env->fd.
static void blob_key_to_file(Environment* env, M_KeyID id) {
  STACKVAR_ZERO(M_Command, cmd);
  cmd.cmd = Cmd_MakeBlob;
  cmd.args.makeblob.idka = id;
  cmd.args.makeblob.format = BlobFormat_Module;
  memcpy(&cmd.args.makeblob.blobkey.module.hkm, &env->worldinfo->hkm, sizeof(env->worldinfo->hkm));
  STACKVAR_ZERO(M_Reply, reply);
  NF(NFastApp_Transact(env->conn, 0, &cmd, &reply, 0));
  NF(reply.status);
  size_t len = reply.reply.makeblob.blob.len;
  printf("Got blob of size: %lu\n", len);
  if (len > 65535) exit(1);
  unsigned char size[2] = { len >> 8, len };
  write_all(env->fd, size, sizeof(size));
  write_all(env->fd, reply.reply.makeblob.blob.ptr, reply.reply.makeblob.blob.len);
}

// Get the key hash for key [id].
static void get_key_hash(Environment* env, M_KeyID id, M_KeyHash* hash) {
  STACKVAR_ZERO(M_Command, cmd);
  cmd.cmd = Cmd_GetKeyInfo;
  cmd.args.getkeyinfo.key = id;
  STACKVAR_ZERO(M_Reply, reply);
  NF(NFastApp_Transact(env->conn, 0, &cmd, &reply, 0));
  NF(reply.status);
  memcpy(hash, &reply.reply.getkeyinfo.hash, sizeof(M_KeyHash));
  print_keyhash(hash);
}

// Create a new template key that itself has acl [key_acl], and that contains
// the nested ACL [contained_acl].  Fills in [hash] with the hash of that key,
// for reference elsewhere.
static void create_template_key(Environment* env, M_ACL* key_acl, M_ACL* contained_acl, M_KeyHash* hash) {
  printf(" - Creating template key\n");
  STACKVAR_ZERO_ARR(unsigned char, buf, 1024);
  STACKVAR_ZERO(NF_Marshal_Context, ctx);
  ctx.op = buf;
  ctx.remain = sizeof(buf);
  NF(NF_MarshalFast_ACL(&ctx, contained_acl));
  STACKVAR_ZERO(M_ByteBlock, byteblock);
  byteblock.ptr = buf;
  byteblock.len = sizeof(buf) - ctx.remain;
  STACKVAR_ZERO(M_Command, cmd);
  cmd.cmd = Cmd_Import;
  cmd.args.import.data.type = KeyType_DKTemplate;
  cmd.args.import.data.data.dktemplate.nested_acl = byteblock;
  cmd.args.import.acl = *key_acl;

  STACKVAR_ZERO(M_Reply, reply);
  NF(NFastApp_Transact(env->conn, 0, &cmd, &reply, 0));
  NF(reply.status);
  printf(" - Blobbing template key to file\n");
  blob_key_to_file(env, reply.reply.import.key);

  printf(" - Getting key hash\n");
  get_key_hash(env, reply.reply.import.key, hash);
}

static void add_unique_limit_id(M_UseLimit* limit) {
  // Make a globally unique ID for this use limit.
  int f = open("/dev/urandom", 0);
  ERRNO(f > 0);
  ERRNO(sizeof(M_LimitID) == read(f, limit->details.global.id.bytes, sizeof(M_LimitID)));
  ERRNO(0 == close(f));
}

// Fills in pgroup/action with a MakeBlob operation, allowing
// anyone to request MakeBlob against the given key.
static void blob_pgroup(
    Environment* env,
    M_PermissionGroup* pgroup,
    M_Action* action,
    M_UseLimit* limit) {
  action->type = Act_MakeBlob;
  action->details.makeblob.flags =
      Act_MakeBlob_Details_flags_AllowKmOnly |
      Act_MakeBlob_Details_flags_AllowNonKm0 |
      Act_MakeBlob_Details_flags_kmhash_present;
  action->details.makeblob.kmhash = &env->worldinfo->hkm;
  pgroup->n_actions = 1;
  pgroup->actions = action;
  pgroup->n_limits = 1;
  pgroup->limits = limit;
  limit->type = UseLim_Global;
  limit->details.global.max = 1;
  add_unique_limit_id(limit);
}

// Fills in [action] with the ability to derive a key as described
// in [dk] and with role [role].
static void derive_action(M_Action* action, M_DKMechParams* dk, M_DeriveRole role) {
  action->type = Act_DeriveKey;
  action->details.derivekey.flags = Act_DeriveKey_Details_flags_params_present;
  action->details.derivekey.role = role;
  action->details.derivekey.mech = dk->mech;
  action->details.derivekey.params = dk;
}

// Adds flags to [pgroup] such that the actions it contains can only
// be requested by an entity signed with the SEE key.
static void see_pgroup(Environment* env, M_PermissionGroup* pgroup) {
  pgroup->certifier = &env->see->hash;
  pgroup->flags = PermissionGroup_flags_certifier_present;
}

// Adds an 'otherkey' derivekey to the given action, tying the given [role]
// to the given [hash].  [krid] is for storage only, and it's entirely overwritten.
static void other_key(M_Action* action, M_DeriveRole role, M_KeyRoleID* krid, M_KeyHash* hash) {
  memcpy(&krid->hash, hash, sizeof(*hash));
  krid->role = role;
  action->details.derivekey.n_otherkeys = 1;
  action->details.derivekey.otherkeys = krid;
}

// Generate the Noise private key utilized for terminating user-initiated connections.
static void generate_noise_keys(Environment* env) {
  STACKVAR_ZERO(M_DKMechParams, derive_pub);
  derive_pub.mech = DeriveMech_PublicFromPrivate;

  STACKVAR_ZERO(M_KeyHash, privtopub_hash);
  printf("Creating privtopub template key\n"); {
    // ACL for template key
    STACKVAR_ZERO_ARR(M_PermissionGroup, pgroup_key, 2);

    // Actions for SEE
    see_pgroup(env, &pgroup_key[0]);
    STACKVAR_ZERO_ARR(M_Action, action0_key, 1);
    //  - SEE permission 1: Derive (public from private)
    derive_action(&action0_key[0], &derive_pub, DeriveRole_TemplateKey);
    pgroup_key[0].n_actions = sizeof(action0_key) / sizeof(M_Action);
    pgroup_key[0].actions = action0_key;

    // Action for non-SEE - make blob of key
    STACKVAR_ZERO(M_Action, action1_key);
    STACKVAR_ZERO(M_UseLimit, uselimit1);
    blob_pgroup(env, &pgroup_key[1], &action1_key, &uselimit1);

    STACKVAR_ZERO(M_ACL, key_acl);
    key_acl.n_groups = sizeof(pgroup_key) / sizeof(M_PermissionGroup);
    key_acl.groups = pgroup_key;

    STACKVAR_ZERO_ARR(M_PermissionGroup, pgroup_contained, 1);
    // Actions for SEE
    see_pgroup(env, &pgroup_contained[0]);
    STACKVAR_ZERO_ARR(M_Action, action0_contained, 1);
    //  - SEE permission 1: ExportAsPlain
    //    This is the permission on the derived _public_ key, and ExportAsPlain
    //    allows us to get the raw bytes of that (again, _public_) key.
    action0_contained[0].type = Act_OpPermissions;
    action0_contained[0].details.oppermissions.perms = Act_OpPermissions_Details_perms_ExportAsPlain;
    pgroup_contained[0].n_actions = sizeof(action0_contained) / sizeof(M_Action);
    pgroup_contained[0].actions = action0_contained;

    STACKVAR_ZERO(M_ACL, contained_acl);
    contained_acl.n_groups = sizeof(pgroup_contained) / sizeof(M_PermissionGroup);
    contained_acl.groups = pgroup_contained;

    create_template_key(env, &key_acl, &contained_acl, &privtopub_hash);
  }

  M_KeyID keypub = 0;
  printf("Generating private key\n"); {
    STACKVAR_ZERO_ARR(M_PermissionGroup, pgroup_priv, 2);

    STACKVAR_ZERO(M_DKMechParams, derive_public);
    derive_public.mech = DeriveMech_PublicFromPrivate;

    // Actions for SEE
    see_pgroup(env, &pgroup_priv[0]);
    STACKVAR_ZERO_ARR(M_Action, action_priv0, 2);
    //  - SEE permission 1:  Decrypt (for use with X25519KeyExchange)
    action_priv0[0].type = Act_OpPermissions;
    action_priv0[0].details.oppermissions.perms = Act_OpPermissions_Details_perms_Decrypt;
    //  - SEE permission 2:  Derive public key
    derive_action(&action_priv0[1], &derive_public, DeriveRole_BaseKey);
    STACKVAR_ZERO(M_KeyRoleID, krid);
    other_key(&action_priv0[1], DeriveRole_TemplateKey, &krid, &privtopub_hash);

    pgroup_priv[0].n_actions = sizeof(action_priv0) / sizeof(M_Action);
    pgroup_priv[0].actions = action_priv0;

    // Action for non-SEE - make blob of key
    STACKVAR_ZERO(M_Action, action_priv1);
    STACKVAR_ZERO(M_UseLimit, uselimit1);
    blob_pgroup(env, &pgroup_priv[1], &action_priv1, &uselimit1);

    // Action for public - ExportAsPlain, once
    STACKVAR_ZERO_ARR(M_Action, action_pub0, 1);
    action_pub0[0].type = Act_OpPermissions;
    action_pub0[0].details.oppermissions.perms = Act_OpPermissions_Details_perms_ExportAsPlain;
    STACKVAR_ZERO(M_UseLimit, limit_pub0);
    limit_pub0.type = UseLim_Global;
    limit_pub0.details.global.max = 1;
    add_unique_limit_id(&limit_pub0);
    STACKVAR_ZERO_ARR(M_PermissionGroup, pgroup_pub, 1);
    pgroup_pub[0].n_actions = sizeof(action_pub0) / sizeof(M_Action);
    pgroup_pub[0].actions = action_pub0;
    pgroup_pub[0].n_limits = 1;
    pgroup_pub[0].limits = &limit_pub0;

    STACKVAR_ZERO(M_Command, command);
    command.cmd = Cmd_GenerateKeyPair;
    command.args.generatekeypair.params.type = KeyType_X25519Private;
    command.args.generatekeypair.params.params.random.lenbytes=32;
    command.args.generatekeypair.module = env->moduleinfo->module;
    command.args.generatekeypair.aclpriv.n_groups = sizeof(pgroup_priv) / sizeof(M_PermissionGroup);
    command.args.generatekeypair.aclpriv.groups = pgroup_priv;
    command.args.generatekeypair.aclpub.n_groups = sizeof(pgroup_pub) / sizeof(M_PermissionGroup);
    command.args.generatekeypair.aclpub.groups = pgroup_pub;

    STACKVAR_ZERO(M_Reply, reply);
    NF(NFastApp_Transact(env->conn, 0, &command, &reply, 0));
    NF(reply.status);
    blob_key_to_file(env, reply.reply.generatekeypair.keypriv);
    keypub = reply.reply.generatekeypair.keypub;

    // Print out but otherwise ignore private key hash
    STACKVAR_ZERO(M_KeyHash, hash_priv);
    get_key_hash(env, reply.reply.generatekeypair.keypriv, &hash_priv);

    // Print out but otherwise ignore public key hash
    STACKVAR_ZERO(M_KeyHash, hash_pub);
    get_key_hash(env, reply.reply.generatekeypair.keypub, &hash_pub);
  }

  printf("Exporting public key to log\n"); {
    STACKVAR_ZERO(M_Command, command);
    command.cmd = Cmd_Export;
    command.args.export.key = keypub;
    STACKVAR_ZERO(M_Reply, reply);
    NF(NFastApp_Transact(env->conn, 0, &command, &reply, 0));
    NF(reply.status);

    if (reply.reply.export.data.type != KeyType_X25519Public ||
        reply.reply.export.data.data.random.k.len != 32) {
      fprintf(stderr, "Invalid public key!\n");
      exit(1);
    }
    unsigned char* k = reply.reply.export.data.data.random.k.ptr;
    printf("Writing public key to ./public_key file as hex\n");
    FILE* f = fopen("public_key", "w");
    ERRNO(f != NULL);
    fprintf(f,
        "%02x%02x%02x%02x%02x%02x%02x%02x"
        "%02x%02x%02x%02x%02x%02x%02x%02x"
        "%02x%02x%02x%02x%02x%02x%02x%02x"
        "%02x%02x%02x%02x%02x%02x%02x%02x"
        "\n",
        k[0x00], k[0x01], k[0x02], k[0x03], k[0x04], k[0x05], k[0x06], k[0x07],
        k[0x08], k[0x09], k[0x0a], k[0x0b], k[0x0c], k[0x0d], k[0x0e], k[0x0f],
        k[0x10], k[0x11], k[0x12], k[0x13], k[0x14], k[0x15], k[0x16], k[0x17],
        k[0x18], k[0x19], k[0x1a], k[0x1b], k[0x1c], k[0x1d], k[0x1e], k[0x1f]);
    ERRNO(fclose(f) == 0);
  }
}

// Generate the set of {en,de}crypt keys necessary for persistent state.
static void generate_crypt_keys(Environment* env) {
  STACKVAR_ZERO(M_DKMechParams, derive_dec);
  derive_dec.mech = DeriveMech_RawDecrypt;
  derive_dec.params.rawdecrypt.iv.mech = Mech_RijndaelmECBpNONE;
  derive_dec.params.rawdecrypt.dst_type = KeyType_HMACSHA256;

  STACKVAR_ZERO(M_DKMechParams, derive_enc);
  derive_enc.mech = DeriveMech_RawEncrypt;
  derive_enc.params.rawencrypt.iv.mech = Mech_RijndaelmECBpNONE;

  STACKVAR_ZERO(M_DKMechParams, derive_sign);
  derive_sign.mech = DeriveMech_RawEncrypt;
  derive_sign.params.rawencrypt.iv.mech = Mech_HMACSHA256;

  STACKVAR_ZERO(M_KeyHash, encdec_hash);
  printf("Creating encdec key (AES)\n"); {
    STACKVAR_ZERO_ARR(M_PermissionGroup, pgroup_key, 2);

    // Actions for SEE
    see_pgroup(env, &pgroup_key[0]);
    STACKVAR_ZERO_ARR(M_Action, action0_key, 2);
    //  - SEE permission 1: Derive (RawEncrypt AES)
    derive_action(&action0_key[0], &derive_enc, DeriveRole_WrapKey);
    //  - SEE permission 1: Derive (RawDecrypt AES)
    derive_action(&action0_key[1], &derive_dec, DeriveRole_WrapKey);
    pgroup_key[0].n_actions = sizeof(action0_key) / sizeof(M_Action);
    pgroup_key[0].actions = action0_key;

    // Action for non-SEE - make blob of key
    STACKVAR_ZERO(M_Action, action1_key);
    STACKVAR_ZERO(M_UseLimit, uselimit1);
    blob_pgroup(env, &pgroup_key[1], &action1_key, &uselimit1);

    STACKVAR_ZERO(M_ACL, key_acl);
    key_acl.n_groups = sizeof(pgroup_key) / sizeof(M_PermissionGroup);
    key_acl.groups = pgroup_key;

    STACKVAR_ZERO_ARR(unsigned char, key, 32);

    STACKVAR_ZERO(M_Command, cmd);
    cmd.cmd = Cmd_Import;
    cmd.args.import.data.type = KeyType_Rijndael;
    cmd.args.import.data.data.random.k.len = sizeof(key);
    cmd.args.import.data.data.random.k.ptr = key;
    cmd.args.import.acl = key_acl;

    STACKVAR_ZERO(M_Reply, reply);
    NF(NFastApp_Transact(env->conn, 0, &cmd, &reply, 0));
    NF(reply.status);
    printf(" - Blobbing encdec key to file\n");
    blob_key_to_file(env, reply.reply.import.key);
    printf(" - Getting encdec key hash\n");
    get_key_hash(env, reply.reply.import.key, &encdec_hash);
  }

  STACKVAR_ZERO(M_KeyHash, derive3_hash);
  printf("Creating derive key 3 (dec key)\n"); {
    // ACL for template key
    STACKVAR_ZERO_ARR(M_PermissionGroup, pgroup_key, 2);

    // Actions for SEE
    see_pgroup(env, &pgroup_key[0]);
    STACKVAR_ZERO_ARR(M_Action, action0_key, 1);
    //  - SEE permission 1: Derive (AES decrypt)
    derive_action(&action0_key[0], &derive_dec, DeriveRole_TemplateKey);
    STACKVAR_ZERO(M_KeyRoleID, krid_key);
    other_key(&action0_key[0], DeriveRole_WrapKey, &krid_key, &encdec_hash);
    pgroup_key[0].n_actions = sizeof(action0_key) / sizeof(M_Action);
    pgroup_key[0].actions = action0_key;

    // Action for non-SEE - make blob of key
    STACKVAR_ZERO(M_Action, action1_key);
    STACKVAR_ZERO(M_UseLimit, uselimit1);
    blob_pgroup(env, &pgroup_key[1], &action1_key, &uselimit1);

    STACKVAR_ZERO(M_ACL, key_acl);
    key_acl.n_groups = sizeof(pgroup_key) / sizeof(M_PermissionGroup);
    key_acl.groups = pgroup_key;

    STACKVAR_ZERO_ARR(M_PermissionGroup, pgroup_contained, 1);
    // Actions for SEE
    see_pgroup(env, &pgroup_contained[0]);
    STACKVAR_ZERO_ARR(M_Action, action0_contained, 1);
    //  - SEE permission 1: Sign
    action0_contained[0].type = Act_OpPermissions;
    action0_contained[0].details.oppermissions.perms = Act_OpPermissions_Details_perms_Sign;
    pgroup_contained[0].n_actions = sizeof(action0_contained) / sizeof(M_Action);
    pgroup_contained[0].actions = action0_contained;

    STACKVAR_ZERO(M_ACL, contained_acl);
    contained_acl.n_groups = sizeof(pgroup_contained) / sizeof(M_PermissionGroup);
    contained_acl.groups = pgroup_contained;

    create_template_key(env, &key_acl, &contained_acl, &derive3_hash);
  }
  
  STACKVAR_ZERO(M_KeyHash, derive2_hash);
  printf("Creating derive key 2 (enc key)\n"); {
    // ACL for template key
    STACKVAR_ZERO_ARR(M_PermissionGroup, pgroup_key, 2);

    // Actions for SEE
    see_pgroup(env, &pgroup_key[0]);
    STACKVAR_ZERO_ARR(M_Action, action0_key, 1);
    //  - SEE permission 1: Derive (AES encrypt)
    derive_action(&action0_key[0], &derive_enc, DeriveRole_TemplateKey);
    STACKVAR_ZERO(M_KeyRoleID, krid_key);
    other_key(&action0_key[0], DeriveRole_WrapKey, &krid_key, &encdec_hash);
    pgroup_key[0].n_actions = sizeof(action0_key) / sizeof(M_Action);
    pgroup_key[0].actions = action0_key;
    // Action for non-SEE - make blob of key
    STACKVAR_ZERO(M_Action, action1_key);
    STACKVAR_ZERO(M_UseLimit, uselimit1);
    blob_pgroup(env, &pgroup_key[1], &action1_key, &uselimit1);

    STACKVAR_ZERO(M_ACL, key_acl);
    key_acl.n_groups = sizeof(pgroup_key) / sizeof(M_PermissionGroup);
    key_acl.groups = pgroup_key;

    STACKVAR_ZERO_ARR(M_PermissionGroup, pgroup_contained, 1);
    // Actions for SEE
    see_pgroup(env, &pgroup_contained[0]);
    //  - SEE permission 1: Derive(AES decrypt, derive3_hash)
    STACKVAR_ZERO_ARR(M_Action, action0_contained, 1);
    derive_action(&action0_contained[0], &derive_dec, DeriveRole_BaseKey);
    STACKVAR_ZERO(M_KeyRoleID, krid_contained);
    other_key(&action0_contained[0], DeriveRole_TemplateKey, &krid_contained, &derive3_hash);
    pgroup_contained[0].n_actions = sizeof(action0_contained) / sizeof(M_Action);
    pgroup_contained[0].actions = action0_contained;

    STACKVAR_ZERO(M_ACL, contained_acl);
    contained_acl.n_groups = sizeof(pgroup_contained) / sizeof(M_PermissionGroup);
    contained_acl.groups = pgroup_contained;

    create_template_key(env, &key_acl, &contained_acl, &derive2_hash);
  }
  
  STACKVAR_ZERO(M_KeyHash, derive1_hash);
  printf("Creating derive key 1 (enc key)\n"); {
    // ACL for template key
    STACKVAR_ZERO_ARR(M_PermissionGroup, pgroup_key, 2);

    // Actions for SEE
    see_pgroup(env, &pgroup_key[0]);
    STACKVAR_ZERO_ARR(M_Action, action0_key, 1);
    //  - SEE permission 1: Derive (AES encrypt)
    derive_action(&action0_key[0], &derive_sign, DeriveRole_TemplateKey);
    pgroup_key[0].n_actions = sizeof(action0_key) / sizeof(M_Action);
    pgroup_key[0].actions = action0_key;
    // Action for non-SEE - make blob of key
    STACKVAR_ZERO(M_Action, action1_key);
    STACKVAR_ZERO(M_UseLimit, uselimit1);
    blob_pgroup(env, &pgroup_key[1], &action1_key, &uselimit1);

    STACKVAR_ZERO(M_ACL, key_acl);
    key_acl.n_groups = sizeof(pgroup_key) / sizeof(M_PermissionGroup);
    key_acl.groups = pgroup_key;

    STACKVAR_ZERO_ARR(M_PermissionGroup, pgroup_contained, 1);
    // Actions for SEE
    see_pgroup(env, &pgroup_contained[0]);
    //  - SEE permission 1: Derive(AES decrypt, derive2_hash)
    STACKVAR_ZERO_ARR(M_Action, action0_contained, 1);
    derive_action(&action0_contained[0], &derive_enc, DeriveRole_BaseKey);
    STACKVAR_ZERO(M_KeyRoleID, krid_contained);
    other_key(&action0_contained[0], DeriveRole_TemplateKey, &krid_contained, &derive2_hash);
    pgroup_contained[0].n_actions = sizeof(action0_contained) / sizeof(M_Action);
    pgroup_contained[0].actions = action0_contained;

    STACKVAR_ZERO(M_ACL, contained_acl);
    contained_acl.n_groups = sizeof(pgroup_contained) / sizeof(M_PermissionGroup);
    contained_acl.groups = pgroup_contained;

    create_template_key(env, &key_acl, &contained_acl, &derive1_hash);
  }
  
  STACKVAR_ZERO(M_KeyHash, crypt_hash);
  printf("Creating main crypt key\n"); {
    STACKVAR_ZERO_ARR(M_PermissionGroup, pgroup, 2);

    STACKVAR_ZERO(M_DKMechParams, derive_hmac);
    derive_hmac.mech = DeriveMech_RawEncrypt;
    derive_hmac.params.rawencrypt.iv.mech = Mech_HMACSHA256;

    // Actions for SEE
    see_pgroup(env, &pgroup[0]);
    STACKVAR_ZERO_ARR(M_Action, action0, 1);
    //  - SEE permission 1: Derive (HMACSHA256)
    derive_action(&action0[0], &derive_hmac, DeriveRole_WrapKey);
    STACKVAR_ZERO(M_KeyRoleID, krid);
    other_key(&action0[0], DeriveRole_TemplateKey, &krid, &derive1_hash);
    pgroup[0].n_actions = sizeof(action0) / sizeof(M_Action);
    pgroup[0].actions = action0;

    // Action for non-SEE - make blob of key
    STACKVAR_ZERO(M_Action, action1);
    STACKVAR_ZERO(M_UseLimit, uselimit1);
    blob_pgroup(env, &pgroup[1], &action1, &uselimit1);

    STACKVAR_ZERO(M_Command, command);
    command.cmd = Cmd_GenerateKey;
    command.args.generatekey.params.type = KeyType_HMACSHA256;
    command.args.generatekey.params.params.random.lenbytes=32;
    command.args.generatekey.module = env->moduleinfo->module;
    command.args.generatekey.acl.n_groups = sizeof(pgroup) / sizeof(M_PermissionGroup);
    command.args.generatekey.acl.groups = pgroup;

    STACKVAR_ZERO(M_Reply, reply);
    NF(NFastApp_Transact(env->conn, 0, &command, &reply, 0));
    NF(reply.status);

    blob_key_to_file(env, reply.reply.generatekey.key);
    get_key_hash(env, reply.reply.generatekey.key, &crypt_hash);
  }
}

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [key_suffix]\n", argv[0]);
    exit(1);
  }
  char* key_suffix = argv[1];

  printf("Generating necessary names\n");
  const char* seeinteg_basename = "hsmenclaveseeinteg";
  char* seeinteg_keyname = malloc(strlen(key_suffix) + strlen(seeinteg_basename) + 1);
  strcpy(seeinteg_keyname, seeinteg_basename);
  strcat(seeinteg_keyname, key_suffix);
  printf("Using key name seeinteg='%s'\n", seeinteg_keyname);

  STACKVAR_ZERO(Environment, env);

  printf("Connecting to nCipher HSM\n");
  NF(NFastApp_Init(&env.app, NULL, NULL, NULL, NULL));
  NF(NFastApp_Connect(env.app, &env.conn, 0, &env.cctx));
  NF(NFKM_getinfo(env.app, &env.worldinfo, &env.cctx));
  NF(NFKM_getusablemodule(env.worldinfo, 0, &env.moduleinfo));

  printf("Finding existing seeinteg/%s key to use\n", seeinteg_keyname);
  STACKVAR_ZERO(NFKM_KeyIdent, seekey);
  seekey.appname = "seeinteg";
  seekey.ident = seeinteg_keyname;
  NF(NFKM_findkey(env.app, seekey, &env.see, &env.cctx));
  if (env.see == NULL) {
    fprintf(stderr, "Could not find hsmenclaveseeinteg\n");
    exit(1);
  }
  printf("- seeinteg key hash: ");
  for (int i = 0; i < sizeof(env.see->hash); i++) {
    printf("%02x", env.see->hash.bytes[i]);
  }
  printf("\n");

  printf("Creating key_blob file\n");
  env.fd = creat("key_blob", 0600);
  ERRNO(env.fd > 0);
  generate_noise_keys(&env);
  generate_crypt_keys(&env);
  ERRNO(close(env.fd) == 0);
  printf("SUCCESS\n");
  return 0;
}
