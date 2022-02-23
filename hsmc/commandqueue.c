/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "commandqueue.h"

typedef struct commandqueue_entry_t {
  struct commandqueue_entry_t* next;
  command_t* command;  // owned
} commandqueue_entry_t;

void commandqueue_free(commandqueue_t* q) {
  DLOG("commandqueue_free(%p)", q);
  commandqueue_clear(q);
  free(q);
}

void commandqueue_clear(commandqueue_t* q) {
  DLOG("commandqueue_clear(%p)", q);
  while (q->front != NULL) {
    commandqueue_entry_t* e = q->front;
    q->front = e->next;
    command_free(e->command);
    free(e);
  }
  memset(q, 0, sizeof(commandqueue_t));
}

error_t commandqueue_new(commandqueue_t** q) {
  MALLOCZ_OR_RETURN_ERROR(*q, commandqueue_t);
  DLOG("commandqueue_new() -> %p", *q);
  return err_SUCCESS;
}

// takes ownership of [cmd].  Only fails on OOM.
error_t commandqueue_pushback(commandqueue_t* q, command_t* cmd) {
  DLOG("commandqueue_pushback(type=%08x,p=%d,c=%d,ebsz=%d)",
      command_type(cmd),
      command_process_id(cmd),
      command_channel_id(cmd),
      command_extrabytes_size(cmd));
  commandqueue_entry_t* entry;
  MALLOCZ_OR_RETURN_ERROR(entry, commandqueue_entry_t);
  entry->next = NULL;
  entry->command = cmd;
  if (q->back == NULL) {
    ASSERT_ERR(q->front == NULL);
    q->back = entry;
    q->front = entry;
  } else {
    ASSERT_ERR(q->front != NULL);
    q->back->next = entry;
    q->back = entry;
  }
  q->n++;
  return err_SUCCESS;
}

void commandqueue_concat_and_empty(commandqueue_t* q, commandqueue_t* to_append_and_empty) {
  if (q->n == 0) {
    *q = *to_append_and_empty;
  } else if (to_append_and_empty->n > 0) {
    q->n += to_append_and_empty->n;
    q->back->next = to_append_and_empty->front;
    q->back = to_append_and_empty->back;
  }
  // Empty out to_append_and_empty by zeroing the whole structure.
  memset(to_append_and_empty, 0, sizeof(commandqueue_t));
}

// relinquishes ownership of returned command.
command_t* commandqueue_popfront(commandqueue_t* q) {
  DLOG("commandqueue_popfront(n=%ld)", q->n);
  commandqueue_entry_t* front = q->front;
  if (front == NULL) {
    return NULL;
  }
  q->front = front->next;
  if (q->front == NULL) {
    q->back = NULL;
  }
  q->n--;
  command_t* cmd = front->command;
  DLOG("popping: type=%08x,c=%d,p=%d,ebsz=%d",
      command_type(cmd),
      command_channel_id(cmd),
      command_process_id(cmd),
      command_extrabytes_size(cmd));
  free(front);
  return cmd;
}
