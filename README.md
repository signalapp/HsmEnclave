# HsmEnclave

This repository contains a system which allows for remote-attestable code
to be run from within an nCipher HSM.

**_Work in progress. Subject to change without notice. Use outside of Signal at your own risk._**

## Overview

HsmEnclave implements an HSM-resident remote-attestable enclave that runs
on nCipher Solo XC cards.  It includes an SEE (secure execution environment)
C executable which is uploaded and run on the nCipher HSM by a Java GRPC
server.  Remote clients make requests to the Java GRPC server, which translates
those request to nCipher `SEEJob` API calls and passes to the
`hardserver` (an nCipher-provided daemon/service), which handles pushing
the jobs across the PCIe bus to the correct HSM hardware.  Replies are received
by the `hardserver` and provided back to the Java GRPC server, which translates
them back to GRPC responses and sends them back to clients.

The HsmEnclave SEEMachine implements a simple set of API calls that allows
clients to:

* Create/destroy a _process_, a blob of Lua code and its associated state
* Create/destroy/utilize a _channel_, a communication medium for talking
  to a specific process
* Other meta-calls, to list current processes, reset the HSM's state, etc

The SEEMachine has the unique capability of utilizing a generated set of key
material in a manner that allows clients to remotely attest the Lua code they're
communicating with over channels.

## Subdirectories

* `service` : GRPC service that exposes the HsmEnclave's capabilities remotely
* `hsmc` : C implementation of HsmEnclave capabilities as an SEE machine
* `keys` : C implementation of nCipher API operations to generate necessary key material

## Building

### Host (Java) service

- enable annotation processing in IntelliJ
- `mvn mn:run` will build and run the service (with hot-reloading!)
- To run with support for physical HSMs (assuming the nfast SDK is installed): `mvn -Phsm mn:run`

With or without `-Phsm`, Java code will build and embed the `hsm_enclave_native`
binary, which runs as a local socket-connectable process and emulates HSM
behavior.

### HSM C Code


```sh
sudo apt-get install
    autoconf \
    automake \
    bison \
    build-essential \
    flex \
    libtool \
    m4 \
    python3

cd hsmc

make build/bin/hsm_enclave_native  # Build native-runnable emulation binary
make check                         # Run (native-runnable) tests/checks
make valgrind                      # Run valgrind against tests
make aflfuzz                       # Run against the AFL fuzzer
make aflfuzz_nolua                 # Run against the AFL fuzzer, with Lua disabled
make doxygen                       # Generate documentation
make coverage                      # Generate test coverage
make clean                         # Nuke everything from orbit

# The following HSM-native `make` targets require nCipher CodeSafe compiler/libaries.
make build/bin/hsm_enclave_onhsm        # Build HSM-native binary
make build/bin/hsm_enclave_onhsm_debug  # Build HSM-native binary, with debug logs turned on
make repeatable                         # Build HSM-native binaries in docker, fully repeatably
```

### Key-generation Code

```sh
cd keys
# Requires nCipher CodeSafe compiler/libaries.
make
```

### Building an application

Once running on an HSM, HsmEnclave is able to receive messages passed to it from
the host on which it runs.  The Java service exposes a GRPC mechanism for doing
this remotely that handles message ordering, etc correctly.

The host provides Lua code to create a *process* by calling the GRPC function
`ProcessCreate`.  The host may talk to a process by creating a *channel*,
a bidirectional communication mechanism with that process.

* Creating a process-specific channel for sending messages via the `Channel` method
* Sending any number of messages associated with that channel
* Closing the channel's bidirectional stream

While a channel is open, the Lua code may also write messages out to it, either
as a response to a message sent in on that channel or as a result of any other
action (creation or use of any other channel).

Lua applications written for HsmEnclave must provide three hooks, in the form
of global functions `HandleChannelCreate`, `HandleChannelMessage`, and
`HandleChannelClose`, each associated with part of a channel's lifecycle.
All of these functions return the same thing:  a (possibly empty) list of
messages to send to channels.

Let's look at an extremely simple example application:  a broadcast application
where any number of clients can connect, and where each message sent by a client
is received by each other connected client:

```
openChannels = {}  -- global, memory-persistent set of currently open channels

-- A new channel is being created.
function HandleChannelCreate(channelID, channelType)
  -- Add [channelID] to the set of currently open channels
  openChannels[channelID] = 1
  -- Don't send anything as output
  return {}
end

-- Clean up a closing channel.
function HandleChannelClose(channelID)
  -- Remove [channelID] from the set of currently open channels
  openChannels[channelID] = nil
  -- Don't send anything as output
  return {}
end

-- Handle receipt of a message on an established channel, in this case by
-- sending that message to all other currently-connected channels.
function HandleChannelMessage(channelID, msg)
  -- Create a new, empty list of messages to send as output
  local out = {}
  -- For each currently open channel...
  for recipientID, _ in pairs(openChannels) do
    -- ... that isn't the sender of this message ...
    if recipientID ~= channelID then
      -- ... append to output a fan-out message to that channel
      -- containing [msg].
      table.insert(out, {recipientID, msg})
    end
  done
  -- Request that all messages collected in [out] be sent.
  return out
end
```

When channels are created, they're passed a channel type.  This specifies
whether the channel is secure (encrypted/integrity-checked/etc), and whether
the other side of the channel is authenticated.  Currently, we support only
one authenticated identity:  the same application running on another
HsmEnclave.  Here's how that could be used, and some things we might use it for:

```
-- A new channel is being created.  channelType describes whether this channel
-- is from an unencrypted client, an external NoiseProtocol client, or this
-- application running on a separate HSM.
function HandleChannelCreate(channelID, channelType)
  -- We're treating all channel types the same in this example, but if we
  -- weren't, here's what we'd use each type for.
  if channelType == CHAN_CLIENT_NK then
    -- This is a new client connection, where the client is unauthenticated
    -- and the server is authenticated with our public/private key.
    -- This should be the connection type used for user-initiated connections.
    print("New encrypted client channel created: " .. channelID)
  elseif channelType == CHAN_SERVER_KK then
    -- This is a new server connection, connecting to this exact application
    -- on another HSM.  Both servers authenticate with each other, and both
    -- application fingerprints are checked and match.
    print("New encrypted server/server channel created: " .. channelID)
  elseif channelType == CHAN_UNENCRYPTED then
    -- This is an unencrypted connection.  The connection is unauthenticated,
    -- and the data passed over it is not securely protected in any way.
    -- This is generally used by the application owner to load data, etc.
    print("New unencrypted channel created: " .. channelID)
  else
    error("Invalid channel type " .. channelType)
  end
  -- Add [channelID] to the set of currently open channels
  openChannels[channelID] = 1
  -- Don't send anything as output
  return {}
end
```

By utilizing this simple message-passing framework, we're able to build up
complex and useful applications.  Given that channels may be established with
the HsmEnclave application from clients, from the host on which it's running, or
from other HSMs' applications, this simple paradigm even allows for distributed
computation.

### Handling network connections

When building a user-facing application around framework, we need to translate
client connections from across the internet into `CHAN_CLIENT_NK` connections.
This can be accomplished by a simple websocket handler, looking something
like the following pseudocode:

```
onWebsocketConnect(websocket_handle):
  this.websocket_handle = websocket_handle
  this.grpc_stream = grpc_backend.channel()
  this.grpc_stream.send(init{channel_type=CHANNEL_TYPE_CLIENT_NK})

onWebsocketClose():
  this.grpc_stream.close()

onWebsocketReceive(msg):
  this.grpc_stream.send(channel_message=msg)

onGrpcStreamClose():
  this.websocket_handle.close()

onGrpcStreamReceive(msg):
  this.websocket_handle.send(msg)
```
