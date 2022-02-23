/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "hsm_enclave.h"

#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <ctype.h>

#include "error.h"
#include "process.h"
#include "env.h"

#define CHECK_EQUAL_ZERO 0x01
#define CHECK_NOTEQUAL_ZERO 0x02
#define CHECK_ANY 0x03

static inline error_t command_check(command_t* cmd, int type, char check_process, char check_channel, char check_extrabytes) {
  uint32_t extrabytes_size = command_extrabytes_size(cmd);
  uint32_t process_id = command_process_id(cmd);
  uint32_t channel_id = command_channel_id(cmd);
  // extremely pedantic re-check of command type.
  if (type != command_type(cmd)) return ERR("command type mismatch");
  switch (check_process) {
    case CHECK_EQUAL_ZERO:
      if (process_id != 0) return ERR("process should be zero but is not");
      break;
    case CHECK_NOTEQUAL_ZERO:
      if (process_id == 0) return ERR("process should not be zero but is");
      break;
    case CHECK_ANY:
      break;
    default:
      assert(0);
  }
  switch (check_channel) {
    case CHECK_EQUAL_ZERO:
      if (channel_id != 0) return ERR("channel should be zero but is not");
      break;
    case CHECK_NOTEQUAL_ZERO:
      if (channel_id == 0) return ERR("channel should not be zero but is");
      break;
    case CHECK_ANY:
      break;
    default:
      assert(0);
  }
  switch (check_extrabytes) {
    case CHECK_EQUAL_ZERO:
      if (extrabytes_size != 0) return ERR("should not have nonempty extrabytes but does");
      break;
    case CHECK_NOTEQUAL_ZERO:
      if (extrabytes_size == 0) return ERR("should have nonempty extrabytes but does not");
      break;
    case CHECK_ANY:
      break;
    default:
      assert(0);
  }
  return err_SUCCESS;
}

static void hsm_enclave_free_processes(hsm_enclave_t* enclave) {
  if (enclave->processes == NULL) return;
  fixedmap_iter_t iter;
  process_t* p;
  uint32_t pid;
  fixedmap_iter_reset(&iter, enclave->processes);
  while (fixedmap_iter_next(&iter, &pid, &p)) {
    process_free(p);
  }
  fixedmap_clear(enclave->processes);
  enclave->procid_gen = 0;
}

static uint32_t hsm_enclave_create_process_id(hsm_enclave_t* enclave) {
  while (true) {
    ++enclave->procid_gen;
    // This allows for a maximum of 2B channels open at once.
    // Since the HSM currently has ~2-2.5G of memory available to it,
    // and channels take up >1B of memory, we're guaranteed to OOM
    // before we reach that point.
    if (enclave->procid_gen >= 0x8000000) enclave->procid_gen = 1;
    uint32_t pid = enclave->procid_gen;
    if (!fixedmap_get(enclave->processes, &pid, NULL)) {
      return pid;
    }
  }
}


void hsm_enclave_free(hsm_enclave_t* h) {
  DLOG("hsm_enclave_free(%p)", h);
  if (h->processes != NULL) {
    hsm_enclave_free_processes(h);
    fixedmap_free(h->processes);
  }
  if (h->output_from_process != NULL) commandqueue_free(h->output_from_process);
  if (h->output_from_command != NULL) commandqueue_free(h->output_from_command);
  if (h->output_to_host != NULL) commandqueue_free(h->output_to_host);
  if (h->base_state != NULL) noise_dhstate_free(h->base_state);
  if (h->base_crypt != NULL) cryptfactory_free(h->base_crypt);
  if (h->rand != NULL) noise_randstate_free(h->rand);
  free(h);
}

error_t hsm_enclave_new(hsm_enclave_t** out) {
  hsm_enclave_t* h;
  MALLOCZ_OR_RETURN_ERROR(h, hsm_enclave_t);
  DLOG("hsm_enclave_new() -> %p", h);
  h->procid_gen = 0;
  error_t err;
  if (err_SUCCESS != (err = fixedmap_new(&h->processes, sizeof(uint32_t), sizeof(process_t*)))) goto hsm_enclave_new_free;
  if (err_SUCCESS != (err = commandqueue_new(&h->output_from_process))) goto hsm_enclave_new_free;
  if (err_SUCCESS != (err = commandqueue_new(&h->output_from_command))) goto hsm_enclave_new_free;
  if (err_SUCCESS != (err = commandqueue_new(&h->output_to_host))) goto hsm_enclave_new_free;
  if (NOISE_ERROR_NONE != noise_randstate_new(&h->rand)) goto hsm_enclave_new_free;
  if (err_SUCCESS != (err = env_noise_dhstate(&h->base_state))) goto hsm_enclave_new_free;
  if (err_SUCCESS != (err = env_cryptfactory(&h->base_crypt))) goto hsm_enclave_new_free;
  *out = h;
  return err_SUCCESS;

hsm_enclave_new_free:
  hsm_enclave_free(h);
  return err;
}

static error_t hsm_enclave_command_POLL(hsm_enclave_t* enclave, command_t* cmd) {
  RETURN_IF_ERROR("validate", command_check(cmd,
      H2O_COMMAND_POLL,
      CHECK_EQUAL_ZERO,      // process_id
      CHECK_EQUAL_ZERO,      // channel_id
      CHECK_EQUAL_ZERO));    // extrabytes
  return err_SUCCESS;
}

static error_t hsm_enclave_command_CHANNEL_MESSAGE(hsm_enclave_t* enclave, command_t* cmd) {
  RETURN_IF_ERROR("validate", command_check(cmd,
      H2O_COMMAND_CHANNEL_MESSAGE,
      CHECK_NOTEQUAL_ZERO,   // process_id
      CHECK_NOTEQUAL_ZERO,   // channel_id
      CHECK_NOTEQUAL_ZERO)); // extrabytes
  process_t* p;
  uint32_t pid = command_process_id(cmd);
  if (!fixedmap_get(enclave->processes, &pid, &p)) return ERR("process not found");
  RETURN_IF_ERROR("process handles received command",
      process_channel_message(p, command_channel_id(cmd), command_extrabytes(cmd), command_extrabytes_size(cmd)));
  return err_SUCCESS;
}

static error_t hsm_enclave_command_CHANNEL_CLOSE(hsm_enclave_t* enclave, command_t* cmd) {
  RETURN_IF_ERROR("validate", command_check(cmd,
      H2O_COMMAND_CHANNEL_CLOSE,
      CHECK_NOTEQUAL_ZERO,   // process_id
      CHECK_NOTEQUAL_ZERO,   // channel_id
      CHECK_EQUAL_ZERO));    // extrabytes
  process_t* p;
  uint32_t pid = command_process_id(cmd);
  if (!fixedmap_get(enclave->processes, &pid, &p)) return ERR("process not found");
  RETURN_IF_ERROR("removing channel", process_channel_remove(p, command_channel_id(cmd)));
  return err_SUCCESS;
}

static error_t hsm_enclave_command_PROCESS_CREATE(hsm_enclave_t* enclave, command_t* cmd) {
  RETURN_IF_ERROR("validate", command_check(cmd,
      H2O_COMMAND_PROCESS_CREATE,
      CHECK_EQUAL_ZERO,      // process_id
      CHECK_EQUAL_ZERO,      // channel_id
      CHECK_NOTEQUAL_ZERO)); // extrabytes
  uint32_t pid = hsm_enclave_create_process_id(enclave);
  command_t* out = NULL;
  RETURN_IF_ERROR("output command",
      command_new(&out, O2H_COMMAND_NEW_ID, pid, 0, 0));
  error_t err = err_SUCCESS;
  processstate_t* ps = NULL;
  if (err_SUCCESS != (err = processstate_new(&ps,
          command_extrabytes(cmd),
          command_extrabytes_size(cmd),
          pid,
          enclave))) goto free_out;
  process_t* p = NULL;
  if (err_SUCCESS != (err = process_new(&p, ps))) goto free_processstate;
  ps = NULL;  // [ps] is now owned within [p], so freeing it separately would be bad.
  if (err_SUCCESS != (err = fixedmap_upsert(enclave->processes, &pid, &p, NULL, NULL))) goto free_process;
  if (err_SUCCESS != (err = commandqueue_pushback(enclave->output_from_command, out))) goto remove_process;
  return err_SUCCESS;

remove_process:
  fixedmap_remove(enclave->processes, &pid, NULL);
free_process:
  process_free(p);
free_processstate:
  if (ps) processstate_free(ps);
free_out:
  command_free(out);
  return err;
}

static error_t hsm_enclave_command_PROCESS_DESTROY(hsm_enclave_t* enclave, command_t* cmd) {
  RETURN_IF_ERROR("validate", command_check(cmd,
      H2O_COMMAND_PROCESS_DESTROY,
      CHECK_NOTEQUAL_ZERO,   // process_id
      CHECK_EQUAL_ZERO,      // channel_id
      CHECK_EQUAL_ZERO));    // extrabytes
  process_t* p = NULL;
  uint32_t pid = command_process_id(cmd);
  if (fixedmap_remove(enclave->processes, &pid, &p)) {
    process_free(p);
  }
  return err_SUCCESS;
}

static error_t hsm_enclave_command_PROCESS_LIST(hsm_enclave_t* enclave, command_t* cmd) {
  RETURN_IF_ERROR("validate", command_check(cmd,
      H2O_COMMAND_PROCESS_LIST,
      CHECK_EQUAL_ZERO,      // process_id
      CHECK_EQUAL_ZERO,      // channel_id
      CHECK_EQUAL_ZERO));    // extrabytes
  fixedmap_iter_t iter;
  fixedmap_iter_reset(&iter, enclave->processes);
  uint32_t pid = 0;
  process_t* p = NULL;
  while (fixedmap_iter_next(&iter, &pid, &p)) {
    command_t* out = NULL;
    RETURN_IF_ERROR("allocating response command",
        command_new(&out, O2H_COMMAND_PROCESS_HASH, pid, 0, CODEHASH_LENGTH));
    memcpy(command_extrabytes(out), p->process_state->codehash, CODEHASH_LENGTH);
    error_t err = err_SUCCESS;
    if (err_SUCCESS != (err = commandqueue_pushback(enclave->output_from_command, out))) {
      command_free(out);
      return err;
    }
  }
  return err_SUCCESS;
}

static error_t hsm_enclave_process_add_channel(hsm_enclave_t* enclave, process_t* p, channel_t* c) {
  error_t err = err_SUCCESS;
  command_t* out = NULL;
  if (err_SUCCESS != (err = command_new(&out, O2H_COMMAND_NEW_ID, process_id(p), c->channel_id, 0))) goto free_channel;
  if (err_SUCCESS != (err = commandqueue_pushback(enclave->output_from_command, out))) goto free_command;
  if (err_SUCCESS != (err = process_channel_add(p, c))) goto free_channel;
  return err_SUCCESS;
 
free_command:
  command_free(out);
free_channel:
  channel_free(c);
  return err;
}

static error_t hsm_enclave_command_channel_create(hsm_enclave_t* enclave, command_t* cmd, channeltype_t channel_type) {
  RETURN_IF_ERROR("validate", command_check(cmd,
      command_type(cmd),
      CHECK_NOTEQUAL_ZERO,   // process_id
      CHECK_EQUAL_ZERO,      // channel_id
      CHECK_EQUAL_ZERO));    // extrabytes
  process_t* p = NULL;
  uint32_t pid = command_process_id(cmd);
  if (!fixedmap_get(enclave->processes, &pid, &p)) return ERR("process not found");
  channel_t* c = NULL;
  uint32_t channel_id = 0;
  RETURN_IF_ERROR("getting channel ID",
      process_create_channel_id(p, &channel_id));
  RETURN_IF_ERROR("creating channel",
      channel_new(&c, channel_id, channel_type, enclave, p));
  RETURN_IF_ERROR("adding channel to process",
      hsm_enclave_process_add_channel(enclave, p, c));
  return err_SUCCESS;
}

static error_t hsm_enclave_command_CHANNEL_CREATE_RAW(hsm_enclave_t* enclave, command_t* cmd) {
  return hsm_enclave_command_channel_create(enclave, cmd, CHANNELTYPE_RAW);
}

static error_t hsm_enclave_command_CHANNEL_CREATE_NOISENK(hsm_enclave_t* enclave, command_t* cmd) {
  return hsm_enclave_command_channel_create(enclave, cmd, CHANNELTYPE_NOISE_NK);
}

static error_t hsm_enclave_command_CHANNEL_CREATE_NOISEKK_INIT(hsm_enclave_t* enclave, command_t* cmd) {
  return hsm_enclave_command_channel_create(enclave, cmd, CHANNELTYPE_NOISE_KK_INITIATOR);
}

static error_t hsm_enclave_command_CHANNEL_CREATE_NOISEKK_RESP(hsm_enclave_t* enclave, command_t* cmd) {
  return hsm_enclave_command_channel_create(enclave, cmd, CHANNELTYPE_NOISE_KK_RESPONDER);
}

static error_t hsm_enclave_command_RESET_REQUEST(hsm_enclave_t* enclave, command_t* cmd) {
  RETURN_IF_ERROR("validate", command_check(cmd,
      H2O_COMMAND_RESET_REQUEST,
      CHECK_EQUAL_ZERO,   // process_id
      CHECK_EQUAL_ZERO,   // channel_id
      CHECK_EQUAL_ZERO)); // extrabytes
  command_t* out = NULL;
  RETURN_IF_ERROR("creating command",
      command_new(&out, O2H_COMMAND_RESET_COMPLETE, 0, 0, NOISE_KEY_SIZE));
  if (NOISE_ERROR_NONE != noise_dhstate_get_public_key(
    enclave->base_state, command_extrabytes(out), command_extrabytes_size(out))) {
    command_free(out);
    return ERR("getting public key bytes");
  }
  // Everything that could fail has at this point succeeded, so do the actual resetting.
  hsm_enclave_free_processes(enclave);
  commandqueue_clear(enclave->output_from_process);
  commandqueue_clear(enclave->output_from_command);
  commandqueue_clear(enclave->output_to_host);
  return ERR_CTX(commandqueue_pushback(enclave->output_from_command, out), "pushing command");
}

// hsm_enclave_run_command handles a command, possibly pushing any number of responses onto
// the outgoing message queue on success.  On failure, it returns an error.
// May add zero or more messages to the queue, but should not add a message
// for the error it returns.
//
// PRECONDITION: enclave->output_from_command is empty
static error_t hsm_enclave_run_command(hsm_enclave_t* enclave, unsigned char* cmd_bytes, size_t cmd_length) {
  DLOG("hsm_enclave_run_command()");
  ASSERT_ERR(enclave->output_from_command->n == 0);

  // Cast incoming bytes to a command, and validate that it's well-formed.
  command_t* cmd = (command_t*) cmd_bytes;
  if (cmd_length < COMMAND_HEADER_SIZE) return ERR("command length less than COMMAND_HEADER_SIZE");
  uint32_t extrabytes_size = command_extrabytes_size(cmd);
  if (extrabytes_size != cmd_length - COMMAND_HEADER_SIZE) return ERR("command length mismatches extrabytes size");

  // Per-type handling of the command.
  switch (command_type(cmd)) {
    case H2O_COMMAND_POLL:
      DLOG("H2O_COMMAND_POLL");
      RETURN_IF_ERROR("H2O_COMMAND_POLL",
          hsm_enclave_command_POLL(enclave, cmd));
      break;
    case H2O_COMMAND_CHANNEL_MESSAGE:
      DLOG("H2O_COMMAND_CHANNEL_MESSAGE");
      RETURN_IF_ERROR("H2O_COMMAND_CHANNEL_MESSAGE",
          hsm_enclave_command_CHANNEL_MESSAGE(enclave, cmd));
      break;
    case H2O_COMMAND_CHANNEL_CLOSE:
      DLOG("H2O_COMMAND_CHANNEL_CLOSE");
      RETURN_IF_ERROR("H2O_COMMAND_CHANNEL_CLOSE",
          hsm_enclave_command_CHANNEL_CLOSE(enclave, cmd));
      break;
    case H2O_COMMAND_PROCESS_CREATE:
      DLOG("H2O_COMMAND_PROCESS_CREATE");
      RETURN_IF_ERROR("H2O_COMMAND_PROCESS_CREATE",
          hsm_enclave_command_PROCESS_CREATE(enclave, cmd));
      break;
    case H2O_COMMAND_PROCESS_DESTROY:
      DLOG("H2O_COMMAND_PROCESS_DESTROY");
      RETURN_IF_ERROR("H2O_COMMAND_PROCESS_DESTROY",
          hsm_enclave_command_PROCESS_DESTROY(enclave, cmd));
      break;
    case H2O_COMMAND_PROCESS_LIST:
      DLOG("H2O_COMMAND_PROCESS_LIST");
      RETURN_IF_ERROR("H2O_COMMAND_PROCESS_LIST",
          hsm_enclave_command_PROCESS_LIST(enclave, cmd));
      break;
    case H2O_COMMAND_CHANNEL_CREATE_RAW:
      DLOG("H2O_COMMAND_CHANNEL_CREATE_RAW");
      RETURN_IF_ERROR("H2O_COMMAND_CHANNEL_CREATE_RAW",
          hsm_enclave_command_CHANNEL_CREATE_RAW(enclave, cmd));
      break;
    case H2O_COMMAND_CHANNEL_CREATE_NOISENK:
      DLOG("H2O_COMMAND_CHANNEL_CREATE_NOISENK");
      RETURN_IF_ERROR("H2O_COMMAND_CHANNEL_CREATE_NOISENK",
          hsm_enclave_command_CHANNEL_CREATE_NOISENK(enclave, cmd));
      break;
    case H2O_COMMAND_CHANNEL_CREATE_NOISEKK_INIT:
      DLOG("H2O_COMMAND_CHANNEL_CREATE_NOISEKK_INIT");
      RETURN_IF_ERROR("H2O_COMMAND_CHANNEL_CREATE_NOISEKK_INIT",
          hsm_enclave_command_CHANNEL_CREATE_NOISEKK_INIT(enclave, cmd));
      break;
    case H2O_COMMAND_CHANNEL_CREATE_NOISEKK_RESP:
      DLOG("H2O_COMMAND_CHANNEL_CREATE_NOISEKK_RESP");
      RETURN_IF_ERROR("H2O_COMMAND_CHANNEL_CREATE_NOISEKK_RESP",
          hsm_enclave_command_CHANNEL_CREATE_NOISEKK_RESP(enclave, cmd));
      break;
    case H2O_COMMAND_RESET_REQUEST:
      DLOG("H2O_COMMAND_RESET_REQUEST");
      RETURN_IF_ERROR("H2O_COMMAND_RESET_REQUEST",
          hsm_enclave_command_RESET_REQUEST(enclave, cmd));
      break;
    default:
      return ERR("unrecognized command type");
  }
  return err_SUCCESS;
}

static error_t hsm_enclave_process_channel_outputs_for_host(hsm_enclave_t* enclave) {
  DLOG("hsm_enclave_process_channel_outputs_for_host()");
  command_t* cmd = NULL;
  error_t err = err_SUCCESS;

  while (err == err_SUCCESS) {
    cmd = commandqueue_popfront(enclave->output_from_process);
    if (cmd == NULL) return err_SUCCESS;
    uint32_t pid = command_process_id(cmd);
    uint32_t cid = command_channel_id(cmd);
    DLOG("* hsm_enclave_process_channel_outputs_for_host() processing p=%d,c=%d", pid, cid);

    // Get associated process.
    process_t* p;
    if (!fixedmap_get(enclave->processes, &pid, &p)) {
      err = ERR("output process not found");
      break;
    }

    // Get associated channel.
    channel_t* c;
    if (!fixedmap_get(p->channels, &cid, &c)) {
      err = ERR("channel not found within process");
      break;
    }
    switch (command_type(cmd)) {
    case O2H_COMMAND_CHANNEL_MESSAGE:
      err = channel_push_outgoing_process_message(c, cmd);
      break;
    case O2H_COMMAND_CHANNEL_CLOSE:
      process_free_channel(p, cid);
      err = commandqueue_pushback(enclave->output_from_command, cmd);
      break;
    default:
      err = ERR("unexpected command type");
      break;
    }
  }
  command_free(cmd);
  return err;
}

#define HSM_ENCLAVE_ERROR_CMDBUF_SIZE 4096

// Try as hard as we can to add a meaningful error to output.  Return false if OOM.  Only fails on OOM.
static bool hsm_enclave_error_to_output(hsm_enclave_t* enclave, error_t err) {
  DLOG("hsm_enclave_error_to_output()");
  assert(err != err_SUCCESS);
  char errbuf[HSM_ENCLAVE_ERROR_CMDBUF_SIZE];
  memset(errbuf, 0, sizeof(errbuf));
  size_t written = DUMP_ERR(err, errbuf, sizeof(errbuf));
  assert(written > 0);
  DLOG("ERR returned to user: '%s'", errbuf);
  command_t* command;
  error_t my_err = command_new(
      &command, O2H_COMMAND_ERROR, 0, 0,
      written-1);  // since command is already delineated, no reason to write back trailing \x00
  if (my_err != err_SUCCESS) goto free_error;
  memcpy(command_extrabytes(command), errbuf, written-1);
  my_err = commandqueue_pushback(enclave->output_to_host, command);
  if (my_err != err_SUCCESS) goto free_command;
  return true;

free_command:
  command_free(command);
free_error:
  ERR_FREE(my_err);
  return false;
}

static error_t hsm_enclave_push_command_to_output(hsm_enclave_t* enclave, bool push_zero) {
  switch (enclave->output_from_command->n) {
    case 0:
      if (push_zero || enclave->output_to_host->n == 0) {
        return commandqueue_pushback(enclave->output_to_host, o2h_command_ZERO);
      } else {
        return err_SUCCESS;
      }
    case 1:
      commandqueue_concat_and_empty(enclave->output_to_host, enclave->output_from_command);
      return err_SUCCESS;
  }
  error_t err = err_SUCCESS;
  command_t* resp_msgs = NULL;
  if (err_SUCCESS != (err = command_new_uint32_userbytes(&resp_msgs, O2H_COMMAND_RESPONSE_MSGS, 0, 0, enclave->output_from_command->n))) goto clear_fromcommand;
  if (err_SUCCESS != (err = commandqueue_pushback(enclave->output_to_host, resp_msgs))) goto free_command;
  commandqueue_concat_and_empty(enclave->output_to_host, enclave->output_from_command);
  return err_SUCCESS;

free_command:
  free(resp_msgs);
clear_fromcommand:
  return err;
}

// PRECONDITION:  enclave->output_from_command is empty
command_t* hsm_enclave_handle_command(hsm_enclave_t* enclave, unsigned char* cmd_bytes, size_t cmd_length) {
  DLOG("#### hsm_enclave_handle_command() ####");
  command_t* cmd = (command_t*) cmd_bytes;
  command_t* response = NULL;
  error_t err = hsm_enclave_run_command(enclave, cmd, cmd_length);

  // Output from [output_from_process] to [output_from_command].
  if (err == err_SUCCESS) {
    err = hsm_enclave_process_channel_outputs_for_host(enclave);
  }
  commandqueue_clear(enclave->output_from_process);

  // Single command's output added to [output_to_host] queue.
  if (err == err_SUCCESS) {
    err = hsm_enclave_push_command_to_output(enclave, command_type(cmd) != H2O_COMMAND_POLL);
  }
  commandqueue_clear(enclave->output_from_command);

  // If we have an error of some sort, make sure we send a meaningful error
  if (err != err_SUCCESS) {
    if (!hsm_enclave_error_to_output(enclave, err)) {
      // We've run into a conundrum here... we don't have enough memory
      // to add an error to the output_to_host queue.  At this point,
      // we really want to tell the host "OMG, we're out of memory", but
      // there may be commands already in the queue that we want to send
      // up first.  We'd like to say "send an OOM error when you're done
      // sending what's in the queue", but that's by definition impossible.
      // So, we send a very specific, pre-allocated error message that says
      // "we're so out of memory that we can't do anything, and subsequent
      // responses may be out of sync with their associated requests".
      // The host, upon receipt of this, should probably send a RESET.
      response = o2h_command_OOM;
    } else {
      DLOG("queued error");
    }
    ERR_FREE(err);
  }
  if (response == NULL) {
    DLOG("requesting output_to_host command");
    response = commandqueue_popfront(enclave->output_to_host);
  }
  if (response == NULL) {
    response = o2h_command_ZERO;
    DLOG("- NO RESPONSE, THIS IS A BAD THING");
  } else {
    DLOG("- queued response");
  }
  DLOG("-> type=%08x,pid=%d,cid=%d,size=%d",
      command_type(response),
      command_process_id(response),
      command_channel_id(response),
      command_extrabytes_size(response));
  return response;
}
