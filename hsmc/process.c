/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "process.h"

#include "hsm_enclave.h"

void process_free(process_t* p) {
  DLOG("process_free(%p)", p);
  if (p->process_state != NULL) processstate_free(p->process_state);
  if (p->channels != NULL) {
    fixedmap_iter_t iter;
    fixedmap_iter_reset(&iter, p->channels);
    channel_t* c;
    while (fixedmap_iter_next(&iter, NULL, &c)) channel_free(c);
    fixedmap_free(p->channels);
  }
  free(p);
}

error_t process_new(process_t** p, processstate_t* ps) {
  ASSERT_ERR(p != NULL);
  ASSERT_ERR(ps != NULL);
  process_t* out = NULL;
  MALLOCZ_OR_RETURN_ERROR(out, process_t);
  DLOG("process_new(pid=%d) -> %p", ps->process_id, out);
  error_t err;
  if ((err = fixedmap_new(&out->channels, sizeof(uint32_t), sizeof(channel_t*))) != err_SUCCESS) goto process_new_free;
  out->process_state = ps;
  out->chanid_gen = 0;
  *p = out;
  return err_SUCCESS;

process_new_free:
  process_free(out);
  return err;
}

uint32_t process_id(const process_t* p) {
  return p->process_state->process_id;
}

static error_t process_try_to_finish_channel_initialization(process_t* p, channel_t* c) {
  if (!channel_initialization_complete(c)) {
    RETURN_IF_ERROR("handling initiation output",
        channel_output_initiation_message(c));
  }
  if (channel_initialization_complete(c)) {
    RETURN_IF_ERROR("giving channel to processstate",
        processstate_channel_add(p->process_state, c->channel_id, channel_lua_type(c)));
  }
  return err_SUCCESS;
}

error_t process_channel_add(process_t* p, channel_t* c) {
  DLOG("process_channel_add(pid=%d,cid=%d)", process_id(p), c->channel_id);
  if (fixedmap_get(p->channels, &c->channel_id, NULL)) return ERR("overwriting existing channel");
  RETURN_IF_ERROR("adding channel to process",
      fixedmap_upsert(p->channels, &c->channel_id, &c, NULL, NULL));
  error_t err = err_SUCCESS;
  if (err_SUCCESS != (err = process_try_to_finish_channel_initialization(p, c))) goto remove_channel;
  return err_SUCCESS;

remove_channel:
  fixedmap_remove(p->channels, &c->channel_id, NULL);
  return err;
}

error_t process_channel_remove(process_t* p, uint32_t channel_id) {
  DLOG("process_channel_remove(pid=%d,cid=%d)", process_id(p), channel_id);
  channel_t* c;
  if (!fixedmap_remove(p->channels, &channel_id, &c)) return ERR("channel not found");
  bool initialized = channel_initialization_complete(c);
  channel_free(c);
  if (initialized) {
    RETURN_IF_ERROR("giving channel to processstate",
        processstate_channel_remove(p->process_state, channel_id));
  }
  return err_SUCCESS;
}

error_t process_channel_message(process_t* p, uint32_t channel_id, void* msg, size_t size) {
  DLOG("process_channel_message(pid=%d,cid=%d,size=%ld)", process_id(p), channel_id, size);
  channel_t* c;
  if (!fixedmap_get(p->channels, &channel_id, &c)) return ERR("unknown channel id");
  if (channel_initialization_complete(c)) {
    void* pp_msg = NULL;
    size_t pp_size = 0;
    RETURN_IF_ERROR("preprocessing message in channel",
        channel_preprocess_incoming_process_message(c, msg, size, &pp_msg, &pp_size));
    ASSERT_ERR(pp_msg != NULL);
    error_t err = processstate_channel_message(p->process_state, channel_id, pp_msg, pp_size);
    if (msg != pp_msg) free(pp_msg);
    RETURN_IF_ERROR("processstate_channel_message", err);
  } else {
    RETURN_IF_ERROR("handling initiation message",
        channel_handle_initiation_message(c, msg, size));
    RETURN_IF_ERROR("finishing channel initiation",
        process_try_to_finish_channel_initialization(p, c));
  }
  return err_SUCCESS;
}

error_t process_create_channel_id(process_t* p, uint32_t* channel_id) {
  while (true) {
    ++p->chanid_gen;
    // This allows for a maximum of 2B channels open at once.
    // Since the HSM currently has ~2-2.5G of memory available to it,
    // and channels take up >1B of memory, we're guaranteed to OOM
    // before we reach that point.
    if (p->chanid_gen >= 0x8000000) p->chanid_gen = 1;
    uint32_t cid = p->chanid_gen;
    if (!fixedmap_get(p->channels, &cid, NULL)) {
      *channel_id = cid;
      return err_SUCCESS;
    }
  }
}

void process_free_channel(process_t* p, uint32_t cid) {
  channel_t* c = NULL;
  if (fixedmap_remove(p->channels, &cid, &c)) channel_free(c);
}
