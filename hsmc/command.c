/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "command.h"

#include <stdlib.h>
#include <string.h>

inline uint32_t bigendian_uint32_at(const unsigned char* p) {
  return (((uint32_t) p[0]) << 24) |
         (((uint32_t) p[1]) << 16) |
         (((uint32_t) p[2]) <<  8) |
         (((uint32_t) p[3]) <<  0);
}

inline void bigendian_uint32_write(unsigned char* p, uint32_t u) {
  p[0] = (u >> 24);
  p[1] = (u >> 16);
  p[2] = (u >>  8);
  p[3] = (u >>  0);
}

uint32_t command_type(command_t* command) {
  return bigendian_uint32_at(command + COMMAND_OFFSET_TYPE);
}

uint32_t command_process_id(command_t* command) {
  return bigendian_uint32_at(command + COMMAND_OFFSET_PID);
}

uint32_t command_channel_id(command_t* command) {
  return bigendian_uint32_at(command + COMMAND_OFFSET_CID);
}

uint32_t command_extrabytes_size(command_t* command) {
  return bigendian_uint32_at(command + COMMAND_OFFSET_EBSIZE);
}

size_t command_total_size(command_t* command) {
  return command_extrabytes_size(command) + COMMAND_HEADER_SIZE;
}

void* command_extrabytes(command_t* command) {
  return command + COMMAND_HEADER_SIZE;
}

error_t command_shrink_extrabytes(command_t* command, uint32_t size) {
  if (size > command_extrabytes_size(command)) return ERR("grows buffer");
  bigendian_uint32_write(command + COMMAND_OFFSET_EBSIZE, size);
  return err_SUCCESS;
}

// Pre-allocated because it's used very frequently.
command_t o2h_command_ZERO[] = {
  0,0,0x10,0,  // O2H_RESPONSE_MSGS
  0,0,0,0,  // PID
  0,0,0,0,  // CID
  0,0,0,4,  // EB_SIZE
  0,0,0,0}; // value=zero

// Pre-allocated in case we can't allocate it to report an OOM.
command_t o2h_command_OOM[] = {
  0,0,0x1f,0xff,  // O2H_OOM
  0,0,0,0,        // PID
  0,0,0,0,        // CID
  0,0,0,0};       // EB_SIZE

error_t command_new(command_t** out, uint32_t typ, uint32_t pid, uint32_t cid, uint32_t ebsize) {
  command_t* buf = calloc(ebsize + COMMAND_HEADER_SIZE, 1);
  if (buf == NULL) return err_OOM;
  DLOG("command_new(t=%08x,pid=%d,cid=%d,ebsz=%d) -> %p", typ, pid, cid, ebsize, buf);
  bigendian_uint32_write(buf + COMMAND_OFFSET_TYPE, typ);
  bigendian_uint32_write(buf + COMMAND_OFFSET_PID, pid);
  bigendian_uint32_write(buf + COMMAND_OFFSET_CID, cid);
  bigendian_uint32_write(buf + COMMAND_OFFSET_EBSIZE, ebsize);
  *out = buf;
  return err_SUCCESS;
}

error_t command_new_uint32_userbytes(command_t** out, uint32_t typ, uint32_t pid, uint32_t cid, uint32_t extrabytes_value) {
  unsigned char buf[4];
  bigendian_uint32_write(buf, extrabytes_value);
  RETURN_IF_ERROR("allocating command", command_new(out, typ, pid, cid, 4));
  memcpy(command_extrabytes(*out), buf, 4);
  return err_SUCCESS;
}

void command_free(command_t* command) {
  DLOG("command_free(%p)", command);
  if (command != o2h_command_ZERO && command != o2h_command_OOM) {
    free(command);
  }
}

