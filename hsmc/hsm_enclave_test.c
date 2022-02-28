/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// A very simple set of tests for the HsmEnclave.  It would be nice
// to find a more fully featured testing library so iteration on
// this would be easier.

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include <noise/protocol.h>
#include <sha2/sha256.h>

#include "hsm_enclave.h"
#include "error.h"
#include "hmac_sha2.h"
#include "fixedmap.h"
#include "process.h"
#include "processstate.h"

#define ASSERT_SUCCESS(x) do { \
  error_t __e_ = (x); \
  if (__e_ != err_SUCCESS) { \
    LOG("Error at %s:%d", __FILE__, __LINE__); \
    LOG_ERR(__e_); \
    exit(1); \
  } \
} while (0)

static command_t* cmd(uint32_t t, uint32_t p, uint32_t c, const char* e) {
  command_t* command;
  ASSERT_SUCCESS(command_new(&command, t, p, c, strlen(e)));
  memcpy(command_extrabytes(command), e, strlen(e));
  return command;
}

static void dump_bytes(void* bytes, size_t s) {
  size_t i;
  unsigned char* c = bytes;
  for (i = 0; i < s; i++) {
    if (i % 16 == 0) fprintf(stderr, "\n");
    char readable = c[i];
    if (!isprint(readable)) {
      readable = '.';
    }
    fprintf(stderr, "%02x _%c_  ", c[i], readable);
  }
  fprintf(stderr, "\n");
}

static void dump_command(command_t* c) {
  fprintf(stderr, "CMD: ");
  dump_bytes(c, command_total_size(c));
}

static void test_command(void) {
  command_t* c;
  ASSERT_SUCCESS(command_new(&c, H2O_COMMAND_CHANNEL_MESSAGE, 1, 2, 3));
  memcpy(command_extrabytes(c), "abc", 3);
  assert(H2O_COMMAND_CHANNEL_MESSAGE == command_type(c));
  assert(1 == command_process_id(c));
  assert(2 == command_channel_id(c));
  assert(3 == command_extrabytes_size(c));
  assert(0 == memcmp(command_extrabytes(c), "abc", 3));

  unsigned char zero[4] = {0,0,0,0};
  assert(O2H_COMMAND_RESPONSE_MSGS == command_type(o2h_command_ZERO));
  assert(0 == command_process_id(o2h_command_ZERO));
  assert(0 == command_channel_id(o2h_command_ZERO));
  assert(4 == command_extrabytes_size(o2h_command_ZERO));
  assert(0 == memcmp(command_extrabytes(o2h_command_ZERO), zero, 4));

  assert(O2H_COMMAND_OOM == command_type(o2h_command_OOM));
  assert(0 == command_process_id(o2h_command_OOM));
  assert(0 == command_channel_id(o2h_command_OOM));
  assert(0 == command_extrabytes_size(o2h_command_OOM));

  command_free(c);
  // These should do nothing:
  command_free(o2h_command_OOM);
  command_free(o2h_command_OOM);
  command_free(o2h_command_OOM);
  command_free(o2h_command_ZERO);
  command_free(o2h_command_ZERO);
  command_free(o2h_command_ZERO);
}

static void test_commandqueue(void) {
  commandqueue_t* q;
  ASSERT_SUCCESS(commandqueue_new(&q));
  ASSERT_SUCCESS(commandqueue_pushback(q, o2h_command_ZERO));
  ASSERT_SUCCESS(commandqueue_pushback(q, o2h_command_ZERO));
  ASSERT_SUCCESS(commandqueue_pushback(q, o2h_command_OOM));
  ASSERT_SUCCESS(commandqueue_pushback(q, o2h_command_ZERO));
  assert(o2h_command_ZERO == commandqueue_popfront(q));
  assert(o2h_command_ZERO == commandqueue_popfront(q));
  assert(o2h_command_OOM == commandqueue_popfront(q));
  assert(o2h_command_ZERO == commandqueue_popfront(q));
  assert(NULL == commandqueue_popfront(q));
  commandqueue_free(q);
}

#define NERR(msg, x) do { \
  int _n_ = (x); \
  if (_n_ != NOISE_ERROR_NONE) { \
    noise_perror("NOISE ERROR: " msg "", _n_); \
    exit(1); \
  } \
} while(0)

const char* echo_code =
  "function HandleChannelCreate(cid, name) end\n"
  "function HandleChannelClose(cid) end\n"
  "function HandleChannelMessage(cid, msg)\n"
  "  return {{1,msg}}\n"
  "end\n";
unsigned char echo_codehash[] = {
  0xd8, 0x37, 0x54, 0x83, 0x56, 0xed, 0x7f, 0x06, 0x5e, 0xb3, 0xf6, 0x0f, 0xbe, 0x9a, 0x1f, 0x7c, 0xbb, 0x7f, 0xd2, 0xbc, 0x97, 0x19, 0x57, 0xc7, 0xaf, 0xce, 0xd8, 0x79, 0x0b, 0xfd, 0x8d, 0x9e,
};
unsigned char secretest_key[32] = {
  0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,
};

void check_noop(command_t* cmd) {
  assert(command_total_size(o2h_command_ZERO) == command_total_size(cmd));
  assert(0 == memcmp(o2h_command_ZERO, cmd, command_total_size(o2h_command_ZERO)));
}

static void test_noisenk(void) {
  // Grab out the public key we should know for the server.
  NoiseDHState* pkey_dh;
  unsigned char public_key[32];
  NERR("pkey dhstate_new", noise_dhstate_new_by_name(&pkey_dh, "25519"));
  NERR("pkey set_keypair_private", noise_dhstate_set_keypair_private(pkey_dh, secretest_key, 32));
  NERR("pkey get_public_key", noise_dhstate_get_public_key(pkey_dh, public_key, 32));
  noise_dhstate_free(pkey_dh);
  for (int i = 0; i < sizeof(public_key); i++) {
    printf("%02x", public_key[i]);
  }
  printf("\n");

  // Set up client-side handshake.
  NoiseHandshakeState* client_handshake;
  NERR("client handshakestate_new", noise_handshakestate_new_by_name(&client_handshake, "Noise_NK_" NOISE_TYPE_SUFFIX, NOISE_ROLE_INITIATOR));
  NoiseDHState* client_remote_dh = noise_handshakestate_get_remote_public_key_dh(client_handshake);
  NERR("client set_public_key", noise_dhstate_set_public_key(client_remote_dh, public_key, 32));
  NERR("client start", noise_handshakestate_start(client_handshake));

  unsigned char request_msgbuf[4096];

  NoiseBuffer request_payload;
  noise_buffer_set_input(request_payload, echo_codehash, sizeof(echo_codehash));
  NoiseBuffer request_message;
  noise_buffer_set_output(request_message, request_msgbuf, sizeof(request_msgbuf));
  NERR("client write_message", noise_handshakestate_write_message(client_handshake, &request_message, &request_payload));

  hsm_enclave_t* enclave;
  DLOG("\n\n-- creating new");
  ASSERT_SUCCESS(hsm_enclave_new(&enclave));

  uint32_t process_id;
  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, (char*) echo_code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    process_id = command_process_id(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- creating noisenk channel");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_CREATE_NOISENK, process_id, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(command_type(response) == O2H_COMMAND_NEW_ID);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- send on noisenk channel");
  {
    command_t* c;
    ASSERT_SUCCESS(command_new(&c, H2O_COMMAND_CHANNEL_MESSAGE, process_id, 1, request_message.size));
    memcpy(command_extrabytes(c), request_message.data, request_message.size);
    dump_command(c);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);

    // decrypt received response
    unsigned char response_buf[4096];
    NoiseBuffer message;
    NoiseBuffer payload;
    noise_buffer_set_input(message, command_extrabytes(response), command_extrabytes_size(response));
    noise_buffer_set_output(payload, response_buf, sizeof(response_buf));
    NERR("client decrypt", noise_handshakestate_read_message(client_handshake, &message, &payload));

    assert(sizeof(echo_codehash) == payload.size);
    assert(0 == memcmp(echo_codehash, payload.data, sizeof(echo_codehash)));
    assert(NOISE_ACTION_SPLIT == noise_handshakestate_get_action(client_handshake));

    command_free(c);
    command_free(response);
  }

  NoiseCipherState* tx;
  NoiseCipherState* rx;
  NERR("split", noise_handshakestate_split(client_handshake, &tx, &rx));
  noise_handshakestate_free(client_handshake);

  DLOG("\n\n-- sending request");
  {
    unsigned char msg[4096];
    const char* payload_str = "abcdefghijklmnopqrstuvwxyz";
    memcpy(msg, payload_str, strlen(payload_str));
    NoiseBuffer message;
    noise_buffer_set_inout(message, msg, strlen(payload_str), sizeof(msg));
    NERR("client msg encrypt", noise_cipherstate_encrypt(tx, &message));
    command_t* c;
    ASSERT_SUCCESS(command_new(&c, H2O_COMMAND_CHANNEL_MESSAGE, 1, 1, message.size));
    memcpy(command_extrabytes(c), message.data, message.size);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_CHANNEL_MESSAGE == command_type(response));
    noise_buffer_set_inout(message, command_extrabytes(response), command_extrabytes_size(response), command_extrabytes_size(response));
    NERR("client msg decrypt", noise_cipherstate_decrypt(rx, &message));
    assert(strlen(payload_str) == message.size);
    assert(0 == memcmp(payload_str, message.data, message.size));

    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending large request");
  {
    size_t bigmsg_size = (3<<20)+13;
    unsigned char* bigmsg = calloc(bigmsg_size, sizeof(unsigned char));  // all zeros
    // Make this not be all zeros to really make sure decryption works.
    bigmsg[16] = 0xff;
    bigmsg[4099] = 0xff;
    bigmsg[bigmsg_size - 3] = 0xff;
    size_t cipher_size = noise_encrypt_max_size(bigmsg_size);
    unsigned char* cipher = calloc(cipher_size, sizeof(unsigned char));
    assert(bigmsg != NULL && cipher != NULL);
    ASSERT_SUCCESS(noise_encrypt_message(tx, bigmsg, bigmsg_size, cipher, &cipher_size));
    command_t* c;
    ASSERT_SUCCESS(command_new(&c, H2O_COMMAND_CHANNEL_MESSAGE, 1, 1, cipher_size));
    memcpy(command_extrabytes(c), cipher, cipher_size);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    // dump_command(response);  // this is very large
    assert(O2H_COMMAND_CHANNEL_MESSAGE == command_type(response));
    size_t plaintext_size = noise_decrypt_max_size(command_extrabytes_size(response));
    unsigned char* plaintext = calloc(plaintext_size, sizeof(unsigned char));
    assert(plaintext != NULL);
    ASSERT_SUCCESS(noise_decrypt_message(rx, command_extrabytes(response), command_extrabytes_size(response), plaintext, &plaintext_size));

    assert(bigmsg_size == plaintext_size);
    assert(0 == memcmp(bigmsg, plaintext, plaintext_size));
    command_free(c);
    command_free(response);
    free(bigmsg);
    free(cipher);
    free(plaintext);
  }

  DLOG("\n\n-- freeing");
  hsm_enclave_free(enclave);
  noise_cipherstate_free(tx);
  noise_cipherstate_free(rx);
}

static void test_noisenk_bad_message_after_good_handshake(void) {
  // Grab out the public key we should know for the server.
  NoiseDHState* pkey_dh;
  unsigned char public_key[32];
  NERR("pkey dhstate_new", noise_dhstate_new_by_name(&pkey_dh, "25519"));
  NERR("pkey set_keypair_private", noise_dhstate_set_keypair_private(pkey_dh, secretest_key, 32));
  NERR("pkey get_public_key", noise_dhstate_get_public_key(pkey_dh, public_key, 32));
  noise_dhstate_free(pkey_dh);
  for (int i = 0; i < sizeof(public_key); i++) {
    printf("%02x", public_key[i]);
  }
  printf("\n");

  // Set up client-side handshake.
  NoiseHandshakeState* client_handshake;
  NERR("client handshakestate_new", noise_handshakestate_new_by_name(&client_handshake, "Noise_NK_" NOISE_TYPE_SUFFIX, NOISE_ROLE_INITIATOR));
  NoiseDHState* client_remote_dh = noise_handshakestate_get_remote_public_key_dh(client_handshake);
  NERR("client set_public_key", noise_dhstate_set_public_key(client_remote_dh, public_key, 32));
  NERR("client start", noise_handshakestate_start(client_handshake));

  unsigned char request_msgbuf[4096];

  NoiseBuffer request_payload;
  noise_buffer_set_input(request_payload, echo_codehash, sizeof(echo_codehash));
  NoiseBuffer request_message;
  noise_buffer_set_output(request_message, request_msgbuf, sizeof(request_msgbuf));
  NERR("client write_message", noise_handshakestate_write_message(client_handshake, &request_message, &request_payload));

  hsm_enclave_t* enclave;
  DLOG("\n\n-- creating new");
  ASSERT_SUCCESS(hsm_enclave_new(&enclave));

  uint32_t process_id = 0;
  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, (char*) echo_code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    process_id = command_process_id(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- creating noisenk channel");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_CREATE_NOISENK, process_id, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- send on noisenk channel");
  {
    command_t* c;
    ASSERT_SUCCESS(command_new(&c, H2O_COMMAND_CHANNEL_MESSAGE, process_id, 1, request_message.size));
    memcpy(command_extrabytes(c), request_message.data, request_message.size);
    dump_command(c);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);

    // decrypt received response
    unsigned char response_buf[4096];
    NoiseBuffer message;
    NoiseBuffer payload;
    noise_buffer_set_input(message, command_extrabytes(response), command_extrabytes_size(response));
    noise_buffer_set_output(payload, response_buf, sizeof(response_buf));
    NERR("client decrypt", noise_handshakestate_read_message(client_handshake, &message, &payload));

    assert(sizeof(echo_codehash) == payload.size);
    assert(0 == memcmp(echo_codehash, payload.data, sizeof(echo_codehash)));
    assert(NOISE_ACTION_SPLIT == noise_handshakestate_get_action(client_handshake));

    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending bad request");
  {
    command_t* c;
    ASSERT_SUCCESS(command_new(&c, H2O_COMMAND_CHANNEL_MESSAGE, process_id, 1, 128));  // just send zeros
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_ERROR == command_type(response));
    command_free(c);
    command_free(response);
  }
  DLOG("\n\n-- freeing");
  hsm_enclave_free(enclave);
  noise_handshakestate_free(client_handshake);
}

static void test_noisenk_good_handshake_hash_mismatch(void) {
  // Grab out the public key we should know for the server.
  NoiseDHState* pkey_dh;
  unsigned char public_key[32];
  NERR("pkey dhstate_new", noise_dhstate_new_by_name(&pkey_dh, "25519"));
  NERR("pkey set_keypair_private", noise_dhstate_set_keypair_private(pkey_dh, secretest_key, 32));
  NERR("pkey get_public_key", noise_dhstate_get_public_key(pkey_dh, public_key, 32));
  noise_dhstate_free(pkey_dh);
  for (int i = 0; i < sizeof(public_key); i++) {
    printf("%02x", public_key[i]);
  }
  printf("\n");

  // Set up client-side handshake.
  NoiseHandshakeState* client_handshake;
  NERR("client handshakestate_new", noise_handshakestate_new_by_name(&client_handshake, "Noise_NK_" NOISE_TYPE_SUFFIX, NOISE_ROLE_INITIATOR));
  NoiseDHState* client_remote_dh = noise_handshakestate_get_remote_public_key_dh(client_handshake);
  NERR("client set_public_key", noise_dhstate_set_public_key(client_remote_dh, public_key, 32));
  NERR("client start", noise_handshakestate_start(client_handshake));

  unsigned char request_msgbuf[4096];

  unsigned char bad_codehash[32];
  memset(bad_codehash, 0, 32);
  NoiseBuffer request_payload;
  noise_buffer_set_input(request_payload, bad_codehash, sizeof(bad_codehash));
  NoiseBuffer request_message;
  noise_buffer_set_output(request_message, request_msgbuf, sizeof(request_msgbuf));
  NERR("client write_message", noise_handshakestate_write_message(client_handshake, &request_message, &request_payload));

  hsm_enclave_t* enclave;
  DLOG("\n\n-- creating new");
  ASSERT_SUCCESS(hsm_enclave_new(&enclave));

  uint32_t process_id;
  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, (char*) echo_code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    process_id = command_process_id(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- creating noisenk channel");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_CREATE_NOISENK, process_id, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- send on noisenk channel");
  {
    command_t* c;
    ASSERT_SUCCESS(command_new(&c, H2O_COMMAND_CHANNEL_MESSAGE, process_id, 1, request_message.size));
    memcpy(command_extrabytes(c), request_message.data, request_message.size);
    dump_command(c);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_ERROR == command_type(response));
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- freeing");
  hsm_enclave_free(enclave);
  noise_handshakestate_free(client_handshake);
}

static void test_noisenk_bad_handshake(void) {
  hsm_enclave_t* enclave;
  DLOG("\n\n-- creating new");
  ASSERT_SUCCESS(hsm_enclave_new(&enclave));

  uint32_t process_id;
  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, (char*) echo_code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    process_id = command_process_id(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- creating noisenk channel");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_CREATE_NOISENK, process_id, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- send on noisenk channel");
  {
    command_t* c;
    ASSERT_SUCCESS(command_new(&c, H2O_COMMAND_CHANNEL_MESSAGE, process_id, 1, 80));
    // Don't overwrite command_extrabytes, it's just zeros.
    dump_command(c);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_ERROR == command_type(response));
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- send on bad channel");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_MESSAGE, process_id, 1, "abc");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_ERROR == command_type(response));
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- freeing");
  hsm_enclave_free(enclave);
}

static void test_noisekk(void) {
  /*
   This test checks noiseKK channels, which are by definition channels between
   the same code on equivalent HSMs.  To make testing work here, we actually
   create a loopack channel, as shown:
  
     HOST <--chan3--> PROC --chan1-
                        |\         \
                         \__chan2__|
  
   The host sends an unencrypted message on chan3.  The process receives on
   3 and outputs on 1.  We make the output from 1 be the input to 2.  The
   process receives on 2 and outputs back to 3.  If all goes well, the thing
   we get back on 3 should be the same thing we sent in.  It was just encrypted
   when sending to 1 and decrypted when receiving from 2.  The message we send
   in and check on the way out is "sendme".
  */

  const char* code =
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  if cid == 3 then return {{1,msg}} end\n"
      "  if cid == 2 then return {{3,msg}} end\n"
      "  return {}\n"
      "end\n";

  hsm_enclave_t* enclave;
  DLOG("\n\n-- creating new");
  ASSERT_SUCCESS(hsm_enclave_new(&enclave));

  uint32_t process_id;
  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, (char*) code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    process_id = command_process_id(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending noisekk_resp channel create");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_CREATE_NOISEKK_RESP, process_id, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(1 == command_process_id(response));
    assert(1 == command_channel_id(response));
    assert(0 == command_extrabytes_size(response));
    command_free(c);
    command_free(response);
  }

  command_t* next = NULL;
  DLOG("\n\n-- sending noisekk_init channel create");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_CREATE_NOISEKK_INIT, process_id, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_RESPONSE_MSGS == command_type(response));
    unsigned char expected[] = {0, 0, 0, 2};
    assert(sizeof(expected) == command_extrabytes_size(response));
    assert(0 == memcmp(command_extrabytes(response), expected, sizeof(expected)));
    command_free(response);

    command_free(c);
    c = cmd(H2O_COMMAND_POLL, 0, 0, "");
    response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(2 == command_channel_id(response));
    command_free(response);

    command_free(c);
    c = cmd(H2O_COMMAND_POLL, 0, 0, "");
    response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    assert(O2H_COMMAND_CHANNEL_MESSAGE == command_type(response));
    assert(2 == command_channel_id(response));
    ASSERT_SUCCESS(command_new(&next, H2O_COMMAND_CHANNEL_MESSAGE, command_process_id(response), 1, command_extrabytes_size(response)));
    memcpy(command_extrabytes(next), command_extrabytes(response), command_extrabytes_size(response));
    command_free(response);
    command_free(c);
  }

  DLOG("\n\n-- creating raw channel 3");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_CREATE_RAW, process_id, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(1 == command_process_id(response));
    assert(3 == command_channel_id(response));
    assert(0 == command_extrabytes_size(response));
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- passing back 1");
  {
    command_t* response = hsm_enclave_handle_command(enclave, next, command_total_size(next));
    dump_command(response);
    assert(O2H_COMMAND_CHANNEL_MESSAGE == command_type(response));
    assert(1 == command_channel_id(response));
    command_free(next);
    ASSERT_SUCCESS(command_new(&next, H2O_COMMAND_CHANNEL_MESSAGE, command_process_id(response), 2, command_extrabytes_size(response)));
    memcpy(command_extrabytes(next), command_extrabytes(response), command_extrabytes_size(response));
    command_free(response);
  }

  DLOG("\n\n-- passing back 2");
  {
    command_t* response = hsm_enclave_handle_command(enclave, next, command_total_size(next));
    dump_command(response);
    check_noop(response);
    command_free(next);
    command_free(response);
  }

  // At this point, the encrypted 1/2 channel is entirely set up.  We send in
  // a message on chan 3 that we expect to round-trip 3->1

  DLOG("\n\n-- sending message 1");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_MESSAGE, process_id, 3, "sendme");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_CHANNEL_MESSAGE == command_type(response));
    assert(1 == command_channel_id(response));
    ASSERT_SUCCESS(command_new(&next, H2O_COMMAND_CHANNEL_MESSAGE, command_process_id(response), 2, command_extrabytes_size(response)));
    memcpy(command_extrabytes(next), command_extrabytes(response), command_extrabytes_size(response));
    command_free(response);
    command_free(c);
  }

  // We got back the KK-encrypted message on channel 1, send it in to channel 2
  // and get the decrypted message back out of channel 3.

  DLOG("\n\n-- sending message 2");
  {
    command_t* response = hsm_enclave_handle_command(enclave, next, command_total_size(next));
    dump_command(response);
    assert(O2H_COMMAND_CHANNEL_MESSAGE == command_type(response));
    assert(3 == command_channel_id(response));
    const unsigned char expected[] = {'s', 'e', 'n', 'd', 'm', 'e'};
    assert(sizeof(expected) == command_extrabytes_size(response));
    assert(0 == memcmp(expected, command_extrabytes(response), sizeof(expected)));
    command_free(response);
    command_free(next);
  }

  hsm_enclave_free(enclave);
}

static void test_hmac_sha256(void) {
  const char input[] = {'a', 'b', 'c'};
  const char key[32] = {
      1, 2, 3, 4, 5, 6, 7, 8,
      9, 0, 1, 2, 3, 4, 5, 6,
      7, 8, 9, 0, 1, 2, 3, 4,
      5, 6, 7, 8, 9, 0, 1, 2};
  unsigned char output[32];
  hmac_sha256((unsigned char*) key, (unsigned char*) input, 3, output);
  dump_bytes(output, 32);
  const unsigned char expected[] = {
      0xb9, 0x00, 0x30, 0x8e, 0x9d, 0x77, 0x66, 0xd0,
      0xbc, 0x69, 0xed, 0xff, 0x52, 0xd5, 0x90, 0x42,
      0x4a, 0x8e, 0xec, 0x62, 0x7d, 0xad, 0xc4, 0x9a,
      0x32, 0x11, 0xfa, 0xc9, 0x85, 0xdc, 0x2b, 0x42}; 
  assert(0 == memcmp(output, expected, 32));
}

static void test_encrypt_decrypt(void) {
  const char* code =
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "first = true\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  if first then\n"
      "    first = false\n"
      "    msg = enclave.encrypt(msg)\n"
      "  else\n"
      "    msg = enclave.decrypt(msg)\n"
      "  end\n"
      "  return {{cid,msg}}\n"
      "end\n";
  hsm_enclave_t* enclave;
  DLOG("\n\n-- creating new");
  ASSERT_SUCCESS(hsm_enclave_new(&enclave));

  uint32_t process_id;
  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, (char*) code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    process_id = command_process_id(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- creating raw channel");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_CREATE_RAW, process_id, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(1 == command_process_id(response));
    assert(1 == command_channel_id(response));
    assert(0 == command_extrabytes_size(response));
    command_free(c);
    command_free(response);
  }

  command_t* next = NULL;
  DLOG("\n\n-- sending first");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_MESSAGE, process_id, 1, "ping");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_CHANNEL_MESSAGE == command_type(response));
    assert(1 == command_process_id(response));
    assert(1 == command_channel_id(response));
    assert(4 < command_extrabytes_size(response));
    assert(0 != memcmp(command_extrabytes(response), "ping", 4));
    ASSERT_SUCCESS(command_new(&next, H2O_COMMAND_CHANNEL_MESSAGE, process_id, 1, command_extrabytes_size(response)));
    memcpy(command_extrabytes(next), command_extrabytes(response), command_extrabytes_size(response));
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending second");
  {
    command_t* response = hsm_enclave_handle_command(enclave, next, command_total_size(next));
    dump_command(response);
    assert(O2H_COMMAND_CHANNEL_MESSAGE == command_type(response));
    assert(1 == command_process_id(response));
    assert(1 == command_channel_id(response));
    assert(4 == command_extrabytes_size(response));
    assert(0 == memcmp(command_extrabytes(response), "ping", 4));
    command_free(next);
    command_free(response);
  }

  hsm_enclave_free(enclave);
}

static void test_channel_open_close_send(void) {
  hsm_enclave_t* enclave;
  DLOG("\n\n-- creating new");
  ASSERT_SUCCESS(hsm_enclave_new(&enclave));

  uint32_t process_id;
  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, (char*) echo_code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    process_id = command_process_id(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- creating raw channel");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_CREATE_RAW, process_id, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(1 == command_process_id(response));
    assert(1 == command_channel_id(response));
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- closing channel");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_CLOSE, process_id, 1, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    check_noop(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending after close");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_MESSAGE, process_id, 1, "abc");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_ERROR == command_type(response));
    command_free(c);
    command_free(response);
  }

  hsm_enclave_free(enclave);
}

static void test_reset_clears_output_queue(void) {
  const char* code =
    "function HandleChannelCreate(cid, name) end\n"
    "function HandleChannelClose(cid) end\n"
    "function HandleChannelMessage(cid, msg)\n"
    "  return {{cid,msg},{cid,msg},{cid,msg},{cid,msg}}\n"
    "end\n";

  hsm_enclave_t* enclave;
  DLOG("\n\n-- creating new");
  ASSERT_SUCCESS(hsm_enclave_new(&enclave));

  uint32_t process_id;
  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, (char*) code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    process_id = command_process_id(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- creating raw channel");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_CREATE_RAW, process_id, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(1 == command_process_id(response));
    assert(1 == command_channel_id(response));
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending request");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_MESSAGE, process_id, 1, "abc");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_RESPONSE_MSGS == command_type(response));
    assert(4 == command_extrabytes_size(response));
    assert(0 == memcmp(command_extrabytes(response), "\0\0\0\x04", 4));
    command_free(c);
    command_free(response);
  }

  NoiseDHState* pkey_dh;
  unsigned char public_key[32];
  NERR("pkey dhstate_new", noise_dhstate_new_by_name(&pkey_dh, "25519"));
  NERR("pkey set_keypair_private", noise_dhstate_set_keypair_private(pkey_dh, secretest_key, sizeof(public_key)));
  NERR("pkey get_public_key", noise_dhstate_get_public_key(pkey_dh, public_key, sizeof(public_key)));
  noise_dhstate_free(pkey_dh);

  DLOG("\n\n-- sending reset");
  {
    command_t* c = cmd(H2O_COMMAND_RESET_REQUEST, 0, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_RESET_COMPLETE == command_type(response));
    assert(sizeof(public_key) == command_extrabytes_size(response));
    assert(0 == memcmp(command_extrabytes(response), public_key, sizeof(public_key)));
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending poll, expect nothing back");
  {
    command_t* c = cmd(H2O_COMMAND_POLL, 0, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    check_noop(response);
    command_free(c);
    command_free(response);
  }

  hsm_enclave_free(enclave);
}

static void test_hkdf(void) {
  unsigned char salt[32] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
    1, 2
  };
  unsigned char secret[] = {'a', 'b', 'c'};

  unsigned char output[32];
  hkdf_sha256(salt, secret, 3, output);
  dump_bytes(output, 32);
  unsigned char expected[] = {
      0x9f, 0x97, 0x0e, 0xa4, 0x7a, 0x1d, 0xad, 0x29,
      0x84, 0xcb, 0xbe, 0xc8, 0xea, 0xec, 0x12, 0x99,
      0x7d, 0x30, 0x6a, 0xcd, 0x52, 0x5a, 0xf0, 0x0a,
      0x73, 0x6d, 0xaa, 0x80, 0x6a, 0x8c, 0xe0, 0x2e};
  assert(0 == memcmp(expected, output, 32));
}

static void call_lua_with_one_input(
    const char* code,
    const char* input,
    const char* expected_output) {
  hsm_enclave_t* enclave;
  DLOG("\n\n-- creating new");
  ASSERT_SUCCESS(hsm_enclave_new(&enclave));

  uint32_t process_id;
  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    process_id = command_process_id(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- creating raw channel");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_CREATE_RAW, process_id, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(1 == command_process_id(response));
    assert(1 == command_channel_id(response));
    assert(0 == command_extrabytes_size(response));
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending request");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_MESSAGE, process_id, 1, input);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    if (expected_output != NULL) {
      assert(O2H_COMMAND_CHANNEL_MESSAGE == command_type(response));
      assert(strlen(expected_output) == command_extrabytes_size(response));
      assert(0 == memcmp(expected_output, command_extrabytes(response), strlen(expected_output)));
    } else {
      assert(O2H_COMMAND_ERROR == command_type(response));
    }
    command_free(c);
    command_free(response);
  }

  hsm_enclave_free(enclave);
}

static void test_fixedmap(void) {
  fixedmap_t* h;
  uint32_t k = 1234;
  uint32_t v = 5678;
  ASSERT_SUCCESS(fixedmap_new(&h, sizeof(uint32_t), sizeof(uint32_t)));
  assert(!fixedmap_get(h, &k, NULL));
  assert(fixedmap_size(h) == 0);
  bool got = true;
  ASSERT_SUCCESS(fixedmap_upsert(h, &k, &v, NULL, &got));
  assert(!got);
  assert(fixedmap_size(h) == 1);
  ASSERT_SUCCESS(fixedmap_upsert(h, &k, &v, NULL, &got));
  assert(got);
  assert(fixedmap_size(h) == 1);

  for (k = 0; k < 300; k++) {
    v = k;
    got = true;
    ASSERT_SUCCESS(fixedmap_upsert(h, &k, &v, NULL, &got));
    assert(!got);
  }
  for (k = 0; k < 300; k++) {
    assert(fixedmap_get(h, &k, &v));
    assert(k == v);
  }
  for (k = 0; k < 300; k++) {
    assert(fixedmap_remove(h, &k, &v));
    assert(k == v);
  }
  for (k = 0; k < 300; k++) {
    assert(!fixedmap_get(h, &k, NULL));
  }
  k = 1234;
  uint32_t cap = fixedmap_capacity(h);
  assert(fixedmap_get(h, &k, NULL));
  fixedmap_clear(h);
  assert(0 == fixedmap_size(h));
  assert(cap == fixedmap_capacity(h));
  assert(!fixedmap_get(h, &k, NULL));
  fixedmap_free(h);
}

static void test_fixedmap_in_lua(void) {
  const char* code =
      "h = enclave.fixedmap(4, 4)\n"
      "vals = {}\n"
      "for i=1,1000 do\n"
      "  sb = {}\n"
      "  for j=1,4 do\n"
      "    sb[j] = string.char(i%256)\n"
      "    i = math.floor(i / 256)\n"
      "  end\n"
      "  s = table.concat(sb)\n"
      "  table.insert(vals, s)\n"
      "end\n"
      "for i, s in ipairs(vals) do\n"
      "  h:upsert(s, s)\n"
      "end\n"
      "for i, s in ipairs(vals) do\n"
      "  if s ~= h:get(s) then\n"
      "    error(\"failed at get \" .. i)\n"
      "  end\n"
      "end\n"
      "for i, s in ipairs(vals) do\n"
      "  if s ~= h:remove(s) then\n"
      "    error(\"failed at get \" .. i)\n"
      "  end\n"
      "end\n"
      "for i, s in ipairs(vals) do\n"
      "  s = table.concat(sb)\n"
      "  if \"\" ~= h:get(s) then\n"
      "    error(\"failed at get \" .. i)\n"
      "  end\n"
      "end\n"
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg) end\n";

  hsm_enclave_t* enclave;
  DLOG("\n\n-- creating new");
  ASSERT_SUCCESS(hsm_enclave_new(&enclave));

  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, (char*) code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    command_free(c);
    command_free(response);
  }

  hsm_enclave_free(enclave);
}

static void test_lua_channel_close(void) {
  const char* code =
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  return {{cid,STATUS_INVALID_ARGUMENT}}\n"
      "end\n";

  hsm_enclave_t* enclave;
  DLOG("\n\n-- creating new");
  ASSERT_SUCCESS(hsm_enclave_new(&enclave));

  uint32_t process_id;
  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, (char*) code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    process_id = command_process_id(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending unencrypted channel create");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_CREATE_RAW, process_id, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(1 == command_process_id(response));
    assert(1 == command_channel_id(response));
    assert(0 == command_extrabytes_size(response));
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending unencrypted channel message");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_MESSAGE, process_id, 1, "abc");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_CHANNEL_CLOSE == command_type(response));
    assert(1 == command_process_id(response));
    assert(1 == command_channel_id(response));
    assert(4 == command_extrabytes_size(response));
    unsigned char expected[] = {0,0,0,3};
    assert(0 == memcmp(command_extrabytes(response), expected, 4));
    command_free(c);
    command_free(response);
  }

  hsm_enclave_free(enclave);
}

static void test_lua_close_nonexistent_channel(void) {
  const char* code =
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  return {{12345,STATUS_INVALID_ARGUMENT}}\n"
      "end\n";

  hsm_enclave_t* enclave;
  DLOG("\n\n-- creating new");
  ASSERT_SUCCESS(hsm_enclave_new(&enclave));

  uint32_t process_id;
  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, (char*) code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    process_id = command_process_id(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending unencrypted channel create");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_CREATE_RAW, process_id, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(1 == command_process_id(response));
    assert(1 == command_channel_id(response));
    assert(0 == command_extrabytes_size(response));
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending unencrypted channel message");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_MESSAGE, process_id, 1, "abc");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_ERROR == command_type(response));
    assert(0 == command_process_id(response));
    assert(0 == command_channel_id(response));
    command_free(c);
    command_free(response);
  }

  hsm_enclave_free(enclave);
}

static void test_lua_error_message() {
  const char* code =
          "function HandleChannelCreate(cid, name) end\n"
          "function HandleChannelClose(cid) end\n"
          "function HandleChannelMessage(cid, msg)\n"
          "  error(\"lua fail\")\n"
          "end\n";

  hsm_enclave_t* enclave;
  DLOG("\n\n-- creating new");
  ASSERT_SUCCESS(hsm_enclave_new(&enclave));

  uint32_t process_id;
  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, (char*) code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    process_id = command_process_id(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending unencrypted channel create");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_CREATE_RAW, process_id, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(1 == command_process_id(response));
    assert(1 == command_channel_id(response));
    assert(0 == command_extrabytes_size(response));
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending unencrypted channel message");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_MESSAGE, process_id, 1, "abc");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_ERROR == command_type(response));
    // "process" is the name set in processstate; "4" is the program line number
    assert(NULL != strstr(command_extrabytes(response), "[string \"process\"]:4: lua fail"));
    command_free(c);
    command_free(response);
  }

  hsm_enclave_free(enclave);
}

static void test_lua_sha256(void) {
  DLOG("single argument");
  call_lua_with_one_input(
      // code
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  return {{cid,enclave.sha256(msg)}}\n"
      "end\n",
      // input
      "abcd",
      // output
      "\x88\xd4\x26\x6f\xd4\xe6\x33\x8d"
      "\x13\xb8\x45\xfc\xf2\x89\x57\x9d"
      "\x20\x9c\x89\x78\x23\xb9\x21\x7d"
      "\xa3\xe1\x61\x93\x6f\x03\x15\x89");
  DLOG("empty hash");
  call_lua_with_one_input(
      // code
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  return {{cid,enclave.sha256()}}\n"
      "end\n",
      // input
      "abcd",
      // output
      "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55");
  DLOG("multiple arguments");
  call_lua_with_one_input(
      // code
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  return {{cid,enclave.sha256('abc', 'def', 'ghi')}}\n"
      "end\n",
      // input
      "abcd",
      // output
      "\x19\xcc\x02\xf2\x6d\xf4\x3c\xc5\x71\xbc\x9e\xd7\xb0\xc4\xd2\x92\x24\xa3\xec\x22\x95\x29\x22\x17\x25\xef\x76\xd0\x21\xc8\x32\x6f");
  DLOG("invalid arguments -> error");
  call_lua_with_one_input(
      // code
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  if pcall(enclave.sha256, {}) then\n"
      "    error('unexpected success')\n"
      "  end\n"
      "  return {{cid, 'expected failure'}}\n"
      "end\n",
      // input
      "abcd",
      // output
      "expected failure");
}

static void test_lua_sandbox_string_fn(void) {
  call_lua_with_one_input(
      // code
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  return {{cid, \"\" .. string.len(msg)}}\n"
      "end\n",
      // input
      "abcd",
      // output
      "4");
}

static void test_lua_sandbox_removes_functions(void) {
  call_lua_with_one_input(
      // code
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  return {{cid, string.dump(HandleChannelCreate)}}\n"
      "end\n",
      // input
      "abcd",
      // output
      NULL);  // error
}

static void test_lua_sandbox_print(void) {
  call_lua_with_one_input(
      // code
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  print(msg)\n"
      "  return {{cid, msg}}\n"
      "end\n",
      // input
      "abcd",
      // output
      "abcd");
}

static void test_lua_sandbox_log(void) {
  call_lua_with_one_input(
      // code
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  enclave.log(msg)\n"
      "  return {{cid, msg}}\n"
      "end\n",
      // input
      "abcd",
      // output
      "abcd");
}

static void test_lua_state_across_functions(void) {
  call_lua_with_one_input(
      // code
      "s = {}\n"
      "function HandleChannelCreate(cid, name)\n"
      "  s[cid] = 'abc'\n"
      "end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  print(msg)\n"
      "  return {{cid, s[cid]}}\n"
      "end\n",
      // input
      "def",
      // output
      "abc");
}

static void test_lua_stack(void) {
  const char* code =
      "function HandleChannelCreate(cid, typ) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  if msg == 'success' then\n"
      "    return {{cid, 'success'}}\n"
      "  end\n"
      "  error('error')\n"
      "end\n";
  hsm_enclave_t* enclave;
  DLOG("\n\n-- creating new");
  ASSERT_SUCCESS(hsm_enclave_new(&enclave));
  uint32_t process_id;

  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    process_id = command_process_id(response);
    command_free(c);
    command_free(response);
  }

  // Reach in and get the actual lua state object
  process_t* process;
  assert(fixedmap_get(enclave->processes, &process_id, &process));
  processstate_t* processstate = process->process_state;
  lua_State* L = processstate->L;
  int lua_stack_size = lua_gettop(L);

  int i;
  for (i = 0; i < 100; i++) {
    uint32_t channel_id = 0;
    DLOG("\n\n-- creating raw channel");
    {
      command_t* c = cmd(H2O_COMMAND_CHANNEL_CREATE_RAW, process_id, 0, "");
      command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
      dump_command(response);
      assert(O2H_COMMAND_NEW_ID == command_type(response));
      assert(process_id == command_process_id(response));
      channel_id = command_channel_id(response);
      assert(0 == command_extrabytes_size(response));
      command_free(c);
      command_free(response);
    }

    DLOG("\n\n-- sending request success");
    {
      command_t* c = cmd(H2O_COMMAND_CHANNEL_MESSAGE, process_id, channel_id, "success");
      command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
      dump_command(response);
      const char* expected_output = "success";
      assert(O2H_COMMAND_CHANNEL_MESSAGE == command_type(response));
      assert(strlen(expected_output) == command_extrabytes_size(response));
      assert(0 == memcmp(expected_output, command_extrabytes(response), strlen(expected_output)));
      command_free(c);
      command_free(response);
    }

    DLOG("\n\n-- sending request error");
    {
      command_t* c = cmd(H2O_COMMAND_CHANNEL_MESSAGE, process_id, channel_id, "error");
      command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
      dump_command(response);
      assert(O2H_COMMAND_ERROR == command_type(response));
      command_free(c);
      command_free(response);
    }

    DLOG("\n\n-- closing channel");
    {
      command_t* c = cmd(H2O_COMMAND_CHANNEL_CLOSE, process_id, channel_id, "");
      command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
      dump_command(response);
      check_noop(response);
      command_free(c);
      command_free(response);
    }
  }

  // Make sure that stack size hasn't grown or shrunk.
  assert(lua_stack_size == lua_gettop(L));

  hsm_enclave_free(enclave);
}

static void test_process_list(void) {
  const char* code =
      "function HandleChannelCreate(cid, typ) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg) end\n";
  hsm_enclave_t* enclave;
  DLOG("\n\n-- creating new");
  ASSERT_SUCCESS(hsm_enclave_new(&enclave));

  unsigned char codehash[32];
  sha256_context_t s;
  sha256_reset(&s);
  sha256_update(&s, code, strlen(code));
  sha256_finish(&s, codehash);

  command_t* find = cmd(H2O_COMMAND_PROCESS_LIST, 0, 0, "");

  DLOG("\n\n-- sending find");
  {
    command_t* response = hsm_enclave_handle_command(enclave, find, command_total_size(find));
    dump_command(response);
    check_noop(response);
    command_free(response);
  }

  uint32_t process_id1;
  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    process_id1 = command_process_id(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending find");
  {
    command_t* response = hsm_enclave_handle_command(enclave, find, command_total_size(find));
    dump_command(response);
    assert(command_type(response) == O2H_COMMAND_PROCESS_HASH);
    assert(command_process_id(response) == process_id1);
    assert(command_channel_id(response) == 0);
    assert(sizeof(codehash) == command_extrabytes_size(response));
    assert(0 == memcmp(command_extrabytes(response), codehash, sizeof(codehash)));
    command_free(response);
  }

  uint32_t process_id2;
  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    process_id2 = command_process_id(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending find");
  {
    command_t* response = hsm_enclave_handle_command(enclave, find, command_total_size(find));
    dump_command(response);
    assert(command_type(response) == O2H_COMMAND_RESPONSE_MSGS);
    assert(4 == command_extrabytes_size(response));
    assert(0 == memcmp(command_extrabytes(response), "\0\0\0\x02", 4));
    command_free(response);
  }

  bool found_1 = false;
  bool found_2 = false;

  DLOG("\n\n-- sending find noop 1");
  {
    command_t* c = cmd(H2O_COMMAND_POLL, 0, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(command_type(response) == O2H_COMMAND_PROCESS_HASH);
    if (process_id1 == command_process_id(response)) {
      found_1 = true;
    } else if (process_id2 == command_process_id(response)) {
      found_2 = true;
    } else {
      assert(false);
    }
    assert(sizeof(codehash) == command_extrabytes_size(response));
    assert(0 == memcmp(command_extrabytes(response), codehash, sizeof(codehash)));
    command_free(response);
    command_free(c);
  }
  DLOG("\n\n-- sending find noop 2");
  {
    command_t* c = cmd(H2O_COMMAND_POLL, 0, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(command_type(response) == O2H_COMMAND_PROCESS_HASH);
    if (process_id1 == command_process_id(response)) {
      found_1 = true;
    } else if (process_id2 == command_process_id(response)) {
      found_2 = true;
    } else {
      assert(false);
    }
    assert(sizeof(codehash) == command_extrabytes_size(response));
    assert(0 == memcmp(command_extrabytes(response), codehash, sizeof(codehash)));
    command_free(response);
    command_free(c);
  }

  assert(found_1);
  assert(found_2);

  command_free(find);
  hsm_enclave_free(enclave);
}

static void test_lua_encrypt_empty(void) {
  call_lua_with_one_input(
      // code
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  return {{cid, 'enc=' .. enclave.encrypt('')}}\n"
      "end\n",
      // input
      "foo",
      // output
      "enc=");
}

static void test_lua_decrypt_empty(void) {
  call_lua_with_one_input(
      // code
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  return {{cid, 'dec=' .. enclave.decrypt('')}}\n"
      "end\n",
      // input
      "foo",
      // output
      "dec=");
}

static void test_lua_encrypt_decrypt_userkey(void) {
  call_lua_with_one_input(
      // code
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  nokey = enclave.encrypt('abc')\n"
      "  enclave.decrypt(nokey)\n"
      "  enclave.decrypt(nokey, '\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0')\n"
      "  keyed = enclave.encrypt('abc', '\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1')\n"
      "  enclave.decrypt(keyed, '\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1')\n"
      "  enclave.decrypt(keyed,\n"
      "    '\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1' ..\n"
      "    '\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2')\n"
      "  enclave.decrypt(keyed,\n"
      "    '\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2\\2' ..\n"
      "    '\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1')\n"
      "  return {{cid, 'success'}}\n"
      "end\n",
      // input
      "foo",
      // output
      "success");
}

static void test_lua_decrypt_userkey_failures(void) {
  call_lua_with_one_input(
      // code
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  nokey = enclave.encrypt('abc')\n"
      "  if pcall(enclave.decrypt, nokey, 'aa') then error('bad') end\n"
      "  if pcall(enclave.decrypt, nokey, string.rep('a', 1024)) then error('bad') end\n"
      "  return {{cid, 'success'}}\n"
      "end\n",
      // input
      "foo",
      // output
      "success");
}

static void test_timestamp_micros(void) {
  const char* code =
      "function HandleChannelCreate(cid, name) end\n"
      "function HandleChannelClose(cid) end\n"
      "function HandleChannelMessage(cid, msg)\n"
      "  print(msg)\n"
      "  return {{cid, tostring(enclave.timestamp_micros() - msg)}}\n"
      "end\n";

  hsm_enclave_t* enclave;
  DLOG("\n\n-- creating new");
  ASSERT_SUCCESS(hsm_enclave_new(&enclave));

  uint32_t process_id;
  DLOG("\n\n-- sending process create");
  {
    command_t* c = cmd(H2O_COMMAND_PROCESS_CREATE, 0, 0, code);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(0 == command_channel_id(response));
    process_id = command_process_id(response);
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- creating raw channel");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_CREATE_RAW, process_id, 0, "");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_NEW_ID == command_type(response));
    assert(1 == command_process_id(response));
    assert(1 == command_channel_id(response));
    assert(0 == command_extrabytes_size(response));
    command_free(c);
    command_free(response);
  }

  DLOG("\n\n-- sending request 1");
  char* msg_1;
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_MESSAGE, process_id, 1, "0");
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_CHANNEL_MESSAGE == command_type(response));
    msg_1 = malloc(command_extrabytes_size(response)+1);
    memcpy(msg_1, command_extrabytes(response), command_extrabytes_size(response));
    msg_1[command_extrabytes_size(response)] = 0;
    command_free(c);
    command_free(response);
  }

  // this is longer than needed, but usleep/nanosleep aren't available
  sleep(1);

  DLOG("\n\n-- sending request 2");
  {
    command_t* c = cmd(H2O_COMMAND_CHANNEL_MESSAGE, process_id, 1, msg_1);
    command_t* response = hsm_enclave_handle_command(enclave, c, command_total_size(c));
    dump_command(response);
    assert(O2H_COMMAND_CHANNEL_MESSAGE == command_type(response));
    char *response_eb = malloc(command_extrabytes_size(response) + 1);
    response_eb[command_extrabytes_size(response)] = '\0';
    memcpy(response_eb, command_extrabytes(response), command_extrabytes_size(response));
    const uint64_t diff = atoll(response_eb);
    DLOG("time diff in microseconds, %lu", diff);
    assert(diff >= 1000000 && diff < 2000000);
    command_free(c);
    command_free(response);
    free(response_eb);
  }

  free(msg_1);
  hsm_enclave_free(enclave);
}

#define RUN_TEST(x) do { \
  if (argc >= 2 && strcmp(argv[1], #x) != 0) break; \
  LOG("\n\n\n\n******************** %s ********************", #x); \
  x(); \
  LOG("- PASSED"); \
} while (0)

int main(int argc, char** argv) {
  RUN_TEST(test_noisenk);
  RUN_TEST(test_noisekk);
  RUN_TEST(test_command);
  RUN_TEST(test_commandqueue);
  RUN_TEST(test_hmac_sha256);
  RUN_TEST(test_encrypt_decrypt);
  RUN_TEST(test_hkdf);
  RUN_TEST(test_noisenk_bad_message_after_good_handshake);
  RUN_TEST(test_noisenk_good_handshake_hash_mismatch);
  RUN_TEST(test_noisenk_bad_handshake);
  RUN_TEST(test_channel_open_close_send);
  RUN_TEST(test_reset_clears_output_queue);
  RUN_TEST(test_lua_sha256);
  RUN_TEST(test_fixedmap);
  RUN_TEST(test_fixedmap_in_lua);
  RUN_TEST(test_lua_channel_close);
  RUN_TEST(test_lua_close_nonexistent_channel);
  RUN_TEST(test_lua_error_message);
  RUN_TEST(test_lua_sandbox_string_fn);
  RUN_TEST(test_lua_sandbox_removes_functions);
  RUN_TEST(test_lua_sandbox_print);
  RUN_TEST(test_lua_sandbox_log);
  RUN_TEST(test_lua_state_across_functions);
  RUN_TEST(test_lua_stack);
  RUN_TEST(test_process_list);
  RUN_TEST(test_lua_encrypt_empty);
  RUN_TEST(test_lua_decrypt_empty);
  RUN_TEST(test_lua_encrypt_decrypt_userkey);
  RUN_TEST(test_lua_decrypt_userkey_failures);
  RUN_TEST(test_timestamp_micros);
  return 0;
}
