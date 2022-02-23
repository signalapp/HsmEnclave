/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef _HSM_ENCLAVE_HSM_ENCLAVE_H
#define _HSM_ENCLAVE_HSM_ENCLAVE_H

#include <stdint.h>
#include <stdbool.h>

#include "error.h"
#include "command.h"
#include "commandqueue.h"
#include "fixedmap.h"
#include "noise.h"
#include "env.h"
#include "crypt.h"

////////////////////////////////////////////////////////////////////////////////
// HSM_ENCLAVE - a very small, simple, hopefully safe OS to run on an nCipher HSM.  //
////////////////////////////////////////////////////////////////////////////////
//
// This "OS" utilizes the SEEMachine concept native to certain nCipher HSMs.
// The nCipher HSM is a PCIe card attached to the motherboard of a host machine.
// The host's OS runs a userspace process, (hereafter the "Host" or "Host
// application"), which interacts with the HSM via the PCIe bus.
// The userspace host application can connect to the HSM, then submit jobs with
// NFastApp_Submit().  The HSM process receives those jobs via
// SEElib_AwaitJob(), performs some processing, then returns the result via
// SEElib_ReturnJob().  The userspace application then receives the result via
// NFastApp_Wait().
//
// Because of this processing scheme, HSM_ENCLAVE is built to work entirely
// reactively.  It only processes while it has a new message to process, and it
// falls dormant upon completion of that message.  Messages passed back and
// forth by HSM_ENCLAVE are called "command"s, and are either Host-to-OS (H2O) or
// OS-to-Host (O2H) directional.
//
// By its nature, the nCipher APIs assume a single request yields a single
// response, and its message encapsulation and transport behave accordingly.
// HSM_ENCLAVE, though, wants to allow for a single H2O message to generate multiple
// O2H messages, while still utilizing the encapsulation/transport that
// remove much of the potential complexity of handling streams or breakup of
// messages.  To do this, it follows a simple process:  upon receipt of a
// message, it generates N (possibly zero) output messages, and puts them on
// an output FIFO queue.  It then pops the first message on that queue off and
// hands it back to the host.
//
// When a request generates
// more than one response, it first adds a RESPONSE_MSGS(#) message to the
// queue, telling the host how many subsequent messages it should expect
// as the output from that request.  The host must be configured to request
// these additional responses via H2O_POLL.
//
// The host may have any number of outstanding messages to the OS.  At the
// moment, the OS handles all requests serially, thus replies will arrive
// in the order that messages are sent.  Due to the queuing nature of output,
// though, the reply received for a request may not be that request's reply.
// IE: if the Host sends requests R1 then R2, but R1 generates 2 responses,
// R2's "output" will be the second response for R1.  As mentioned above,
// the host must be aware of RESPONSE_MSGS(#) responses coming back and
// handle them appropriately.
//
// Objects are currently laid out as follows:
//   os (hsm_enclave_t): state for the entire HSM-side OS.
//   |- procid_gen: Generator for choosing process IDs of new processes
//   |- rand: Randomness source
//   |- base_state: Base DHState for terminating NoiseNK and NoiseKK connections
//   |- base_crypt: Base for doing Lua-to-host {en,de}cryption
//   |- output_from_process (commandqueue_t): output received from a process
//   |  |- ... command_t singly-linked list ...
//   |- output_from_command (commandqueue_t): output from a single command
//   |  |- ... command_t singly-linked list ...
//   |- output_to_host (commandqueue_t): output direct to host
//   |  |- ... command_t singly-linked list ...
//   |- processes (fixedmap_t):  pid->process map
//      |- procs: fixed-size map of 256 processes
//         |- [x] (process_t): state of a single process
//            |- channels (fixedmap_t): channels map in process
//            |  |- channels_vec: vector of channel_t
//            |  |  |- [x] (channel_t): state for single channel
//            |  |     |- ... channel-specific data ...
//            |  |- channel_zero (channel_t): special raw 'admin' channel
//            |- process_state (processstate_t): process internal state
//               |- output (commandqueue_t): queue for writing back to host
//                  |- ... command_t singly-linked list ...
//
// In short, the hsm_enclave_t contains a set of process_t processes, which within
// themselves each contain a processstate_t and a set of channel_t for
// communication.

////////////////////////////////////////////////////////////
// hsm_enclave_t
//   The root of the HSM OS.  Stores all processes (and by extension their state,
//   channels, etc), as well as output command queues.
typedef struct hsm_enclave_t {
  fixedmap_t* processes;
  uint32_t procid_gen;

  cryptfactory_t* base_crypt;
  NoiseRandState* rand;
  NoiseDHState* base_state;

  //// Output queues
  // We use a set of output queues to output values back out to the host.
  // In a perfect world with a higher-level language, we'd probably return
  // these from functions rather than having them up here.
  //
  // When a command is run, it will append to the [output_from_process] if it
  // is a command that runs a process function.  These commands must all be
  // O2H_COMMAND_CHANNEL_MESSAGE commands that have yet to be postprocessed
  // by their respective output channels.  All other commands should go directly
  // to the [output_from_command] channel.
  //
  // When the OS has finished a single command, it clears out both the
  // [output_from_process] and [output_from_command] queues, appending all
  // necessary values to the [output_to_host] queue, which persists
  // across multiple commands.
  //
  // === EXAMPLE ===
  //
  // Let's say that a command comes in to create a new raw channel CID=3,
  // and the creation of this channel causes messages to be sent to encrypted
  // channels CID=1 and CID=2.  Here's how this would look immediately after
  // the command has run:
  //
  //     output_from_process:
  //       O2H_COMMAND_CHANNEL_MESSAGE(CID=1, "foo")
  //       O2H_COMMAND_CHANNEL_MESSAGE(CID=2, "bar")
  //     output_from_command:
  //       O2H_COMMAND_NEW_ID(CID=3)
  //     output_to_host:
  //       <empty>
  //
  // The addition of the channel has created a NEW_ID command, which is added
  // directly to output_from_command, since it doesn't require postprocessing
  // (it isn't a channel message).  Now that the command is complete, the OS
  // first postprocesses [output_from_process] and appends the results to
  // [output_from_command], yielding this:
  //
  //     output_from_process:
  //       <empty>
  //     output_from_command:
  //       O2H_COMMAND_NEW_ID(CID=3)
  //       O2H_COMMAND_CHANNEL_MESSAGE(CID=1, "<encrypted:foo>")
  //       O2H_COMMAND_CHANNEL_MESSAGE(CID=2, "<encrypted:bar>")
  //     output_to_host:
  //       <empty>
  //
  // Finally, all commands in [output_from_command] are added to the persistent
  // [output_to_host], along with a O2H_COMMAND_RESPONSE_MSGS if necessary.
  // Since [output_from_command] has more than one command, it is necessary in
  // this example:
  //
  //     output_from_process:
  //       <empty>
  //     output_from_command:
  //       <empty>
  //     output_to_host:
  //       O2H_COMMAND_RESPONSE_MSGS(3)
  //       O2H_COMMAND_NEW_ID(CID=3)
  //       O2H_COMMAND_CHANNEL_MESSAGE(CID=1, "<encrypted:foo>")
  //       O2H_COMMAND_CHANNEL_MESSAGE(CID=2, "<encrypted:bar>")
  //
  // In the case where an error occurs anywhere in processing, the commands in
  // [output_from_process] and [output_from_command] are discarded, and a single
  // error message is appended to [output_to_host].  Here's what the final state
  // would look like if, for example, an error occurred encrypting for channel
  // CID=2:
  //
  //     output_from_process:
  //       <empty>
  //     output_from_command:
  //       <empty>
  //     output_to_host:
  //       O2H_COMMAND_ERROR("failed to encrypt for CID=2")
  //
  // Note that in this case, the NEW_ID(CID=3) command was also discarded,
  // and the channel was freed/removed from the process, due to error handling
  // as the error made its way up the stack.
  commandqueue_t* output_from_process;
  commandqueue_t* output_from_command;
  commandqueue_t* output_to_host;
} hsm_enclave_t;

/** Provide a command (received from a client) to [os] for processing.
 * \memberof hsm_enclave_t
 *
 * Args:
 *   os: this
 *   cmd:  Pointer to start of command buffer.  Does not take ownership of buffer.
 *   cmd_length:  Size of command buffer
 *
 * Returns:
 *   Command to return to client.  Guaranteed to always return a valid, correctly-sized
 *   and well-formed command.  Caller accepts ownership of returned value and should
 *   command_free it.
 */
command_t* hsm_enclave_handle_command(hsm_enclave_t* os, unsigned char* cmd, size_t cmd_length);

/** hsm_enclave_new allocates a new hsm_enclave_t.
 * \memberof hsm_enclave_t
 *
 * Must be initialized via a H2O_COMMAND_RESET_REQUEST before it's
 * capable of functioning fully.
 *
 * Args:
 *   *out:  output written here upon success.
 *
 * Returns:
 *   err_SUCCESS:  *out = new HsmEnclave object.
 *   err:  Allocation failed, *out unchanged.
 */
error_t hsm_enclave_new(hsm_enclave_t** out);

/** hsm_enclave_free deallocates a hsm_enclave_t allocated with hsm_enclave_new.
 * \memberof hsm_enclave_t */
void hsm_enclave_free(hsm_enclave_t* h);

#endif  // _HSM_ENCLAVE_HSM_ENCLAVE_H
