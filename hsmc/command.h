/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef _HSM_ENCLAVE_COMMAND_H
#define _HSM_ENCLAVE_COMMAND_H

#include <stdint.h>

#include "error.h"

////////////////////////////////////////////////////////////
// command_t
//   A command, passed either host to OS (H2O) or OS to host (O2H).
//   This is a singular buffer of at least size=16 and exactly
//   size=16+extrabytes_size.  Its format is purposefully extremely simple.
//
// We make a command be simply a set of bytes so that the buffer
// provided to the HsmEnclave can be cast to it zero-copy, with all subsequent
// validation happening within the HSM.  Returned values are again
// simply byte buffers, and thus able to be sent back to the host without
// any additional munging or copies.
typedef unsigned char command_t;

#define COMMAND_HEADER_SIZE 16
#define COMMAND_OFFSET_TYPE 0
#define COMMAND_OFFSET_PID 4
#define COMMAND_OFFSET_CID 8
#define COMMAND_OFFSET_EBSIZE 12

////////////////////////////////////////////////////////////
// Command Types:  Host -> OS
#define H2O_COMMAND_POLL                   0x00000000U
#define H2O_COMMAND_CHANNEL_MESSAGE        0x00000001U
#define H2O_COMMAND_CHANNEL_CLOSE          0x00000002U
#define H2O_COMMAND_PROCESS_CREATE         0x00000010U
#define H2O_COMMAND_PROCESS_DESTROY        0x00000011U
#define H2O_COMMAND_PROCESS_LIST           0x00000012U
// RAW channels do no encryption/decryption, and allow plaintext communication.
#define H2O_COMMAND_CHANNEL_CREATE_RAW     0x00000020U
// NoiseNK channels allow unauthenticated clients to do single-round-trip request/response pairs.
#define H2O_COMMAND_CHANNEL_CREATE_NOISENK 0x00000021U
// NoiseKK channels allow cross-HSM communication between the same code running on different processes.
// This can include the same code running on different HSMs, including on different hosts.
#define H2O_COMMAND_CHANNEL_CREATE_NOISEKK_INIT 0x00000022U
#define H2O_COMMAND_CHANNEL_CREATE_NOISEKK_RESP 0x00000023U
#define H2O_COMMAND_RESET_REQUEST          0x00000030U

////////////////////////////////////////////////////////////
// Command Types:  OS -> Host
#define O2H_COMMAND_RESPONSE_MSGS          0x00001000U
#define O2H_COMMAND_CHANNEL_MESSAGE        0x00001001U
#define O2H_COMMAND_NEW_ID                 0x00001002U
#define O2H_COMMAND_CHANNEL_CLOSE          0x00001003U
#define O2H_COMMAND_PROCESS_HASH           0x00001004U
#define O2H_COMMAND_ERROR                  0x0000100FU
#define O2H_COMMAND_RESET_COMPLETE         0x00001030U
#define O2H_COMMAND_OOM                    0x00001FFFU

/** utility function that reads 4 bytes from p[0..4] as a big-endian uint32. */
uint32_t bigendian_uint32_at(const unsigned char* p);
/** utility function that writes [u] to p[0..4] as a big-endian uint32. */
void bigendian_uint32_write(unsigned char* p, uint32_t u);

/** Returns the type of a command, one of O2H_COMMAND_* or H2O_COMMAND_*
 * \memberof command_t */
uint32_t command_type(command_t* command);
/** Returns the process ID from a command.
 * \memberof command_t */
uint32_t command_process_id(command_t* command);
/** Returns a channel ID from a command.
 * \memberof command_t */
uint32_t command_channel_id(command_t* command);
/** Returns the amount of extra bytes attached to this command.
 * \memberof command_t */
uint32_t command_extrabytes_size(command_t* command);
/** Returns the total size of a command, including header and extra bytes.
 * \memberof command_t */
size_t command_total_size(command_t* command);
/** Returns a pointer to the start of the extrabytes buffer in this command.
 * \memberof command_t */
void* command_extrabytes(command_t* command);

/** command_new allocates a new command.
 * \memberof command_t
 *
 * Args:
 *   *out:  On success, newly allocated command will be returned out of here.
 *   typ:  Command type
 *   pid:  Process ID
 *   cid:  Channel ID
 *   ebsize:  Size of the extrabytes buffer within this command.  extrabytes will be initialized to all zeros.
 *
 * Returns:
 *   err_SUCCESS:  A command was successfully allocated and initialized, and *out now points to it.
 *   err:  Command allocation/initialization failed, *out unchanged.
 */
error_t command_new(command_t** out, uint32_t typ, uint32_t pid, uint32_t cid, uint32_t ebsize);

/** command_new_uint32_userbytes is a convenience function to return a command whose
 *  userbytes contains a 4-byte big-endian unsigned integer.
 * \memberof command_t
 *
 * Args:
 *   *out:  On success, newly allocated command will be returned out of here.
 *   typ:  Command type
 *   pid:  Process ID
 *   cid:  Channel ID
 *   extrabytes_value:  uint32 that becomes the 4-byte extrabytes of this command.
 *
 * Returns:
 *   err_SUCCESS:  A command was successfully allocated and initialized, and *out now points to it.
 *   err:  Command allocation/initialization failed, *out unchanged.
 */
error_t command_new_uint32_userbytes(command_t** out, uint32_t typ, uint32_t pid, uint32_t cid, uint32_t extrabytes_value);

/** command_free deallocates a command allocated with command_new.
 * \memberof command_t */
void command_free(command_t* command);

/** command_shrink_extrabytes shrinks the size of the extrabytes buffer in [command].
 * \memberof command_t
 *
 * Args:
 *   command: this
 *   new_size:  Size to shrink command_extrabytes for [command].
 *
 * Returns:
 *   err_SUCCESS:  command_extrabytes_size(command) now equals new_size.
 *   err:  new_size was an invalid size (possibly larger than initial command_extrabytes_size(command).
 */
error_t command_shrink_extrabytes(command_t* command, uint32_t new_size);

/** Preallocated message of type O2H_COMMAND_OOM.
 * \memberof command_t */
extern command_t o2h_command_OOM[];
/** Preallocated message of type O2H_COMMAND_RESPONSE_MSGS with size==0
 * \memberof command_t */
extern command_t o2h_command_ZERO[];

#endif  // _HSM_ENCLAVE_COMMAND_H
