/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef _HSM_ENCLAVE_COMMANDQUEUE_H
#define _HSM_ENCLAVE_COMMANDQUEUE_H

#include "error.h"
#include "command.h"

////////////////////////////////////////////////////////////
// commandqueue_t
//   A simple FIFO queue, as a singly linked list.  New commands are pushed onto
//   the back of the queue and read from the front.
struct commandqueue_entry_t;
typedef struct {
  struct commandqueue_entry_t* front;
  struct commandqueue_entry_t* back;
  size_t n;
} commandqueue_t;

/** commandqueue_new allocates a new empty queue.
 * \memberof commandqueue_t
 *
 * Args:
 *   *q:  Written to upon success.
 *
 * Returns:
 *   err_SUCCESS:  *q contains a newly allocated, empty command queue.
 *   err:  allocation failed, *q unchanged.
 */
error_t commandqueue_new(commandqueue_t** q);

/** commandqueue_free deallocates a commandqueue created with commandqueue_new.
 * \memberof commandqueue_t */
void commandqueue_free(commandqueue_t* q);

/** commandqueue_clear empties a command queue, deallocating all commands currently owned within it.
 * \memberof commandqueue_t */
void commandqueue_clear(commandqueue_t* q);

/** commandqueue_pushback pushes a command onto [q].
 * \memberof commandqueue_t
 *
 * Args:
 *   q: this
 *   cmd:  Command to push
 *
 * Returns:
 *   err_SUCCESS:  [q] takes ownership of [cmd].
 *   err:  [cmd] ownership not taken, should be cleaned up by caller.
 */
error_t commandqueue_pushback(commandqueue_t* q, command_t* cmd);

/** commandqueue_popfront pops the next command off of [q] and returns it.
 * \memberof commandqueue_t
 *
 * Args:
 *   q: this
 *
 * Returns:
 *   NULL: q was empty, there is nothing to return
 *   cmd:  A command, now owned by the caller.
 */
command_t* commandqueue_popfront(commandqueue_t* q);

/** commandqueue_concat_and_empty concatenates the contents of [to_concat_and_empty]
 * \memberof commandqueue_t
 *     onto [q] and empties [to_concat_and_empty].  All commands previously owned/held
 *     by [to_concat_and_empty] are now owned/held by [q].  This command will always
 *     succeed and is constant-time.
 *
 * It's crucial to the correct error-handling of the HsmEnclave that
 * this command (concat_and_empty) not have the ability to fail
 * due to OOMs.  We use this to atomically add all commands from
 * a single run to the output queue, and doing so has to succeed
 * without exception.
 *
 * Args:
 *   q: Queue to concatenate commands onto
 *   to_concat_and_empty:  Queue to pull commands from and empty out
 */
void commandqueue_concat_and_empty(commandqueue_t* q, commandqueue_t* to_concat_and_empty);

#endif  // _HSM_ENCLAVE_COMMANDQUEUE_H
