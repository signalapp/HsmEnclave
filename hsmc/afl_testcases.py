#!/usr/bin/python3
#
# Copyright 2022 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#

"""Builds a set of test cases for the AFL fuzzer.

AFL (https://lcamtuf.coredump.cx/afl/) is a simple fuzzer.
This simple script generates initial test cases for it, one per
file, by concatenating sets of known/good commands.
"""

import sys
import struct
import random
import hashlib
import time

echo_code = b"""
function HandleChannelCreate(cid, name) end
function HandleChannelClose(cid) end
function HandleChannelMessage(cid, msg)
  return {{1,msg}}
end
"""

encdec_code = b"""
function HandleChannelCreate(cid, name) end
function HandleChannelClose(cid) end
function HandleChannelMessage(cid, msg)
  a = enclave.encrypt(msg)
  b = enclave.decrypt(a)
  return {{1,b}}
end
"""

fixedmap_code = b"""
function HandleChannelCreate(cid, name) end
function HandleChannelClose(cid) end
function HandleChannelMessage(cid, msg)
  m = enclave.fixedmap(4,4)
  m:upsert("abcd", "efgh")
  m:get("abcd")
  m:remove("abcd")
  return {{1,msg}}
end
"""

lua_functions = [
  b"enclave.encrypt",
  b"enclave.decrypt",
  b"enclave.sha256",
  b"enclave.fixedmap",
  b"error",
  b"print",
  b"setmetatable",
  b"getmetatable",
  b"assert",
  b"ipairs",
  b"next",
  b"pairs",
  b"pcall",
  b"select",
  b"tonumber",
  b"tostring",
  b"type",
  b"xpcall",
  b"coroutine.close",
  b"coroutine.create",
  b"coroutine.isyieldable",
  b"coroutine.resume",
  b"coroutine.running",
  b"coroutine.status",
  b"coroutine.wrap",
  b"coroutine.yield",
  b"string.byte",
  b"string.char",
  b"string.find",
  b"string.format",
  b"string.gmatch",
  b"string.gsub",
  b"string.len",
  b"string.lower",
  b"string.match",
  b"string.pack",
  b"string.packsize",
  b"string.rep",
  b"string.reverse",
  b"string.sub",
  b"string.unpack",
  b"string.upper",
  b"table.concat",
  b"table.insert",
  b"table.move",
  b"table.pack",
  b"table.remove",
  b"table.sort",
  b"table.unpack",
  b"math.abs",
  b"math.acos",
  b"math.asin",
  b"math.atan",
  b"math.ceil",
  b"math.cos",
  b"math.cosh",
  b"math.deg",
  b"math.exp",
  b"math.floor",
  b"math.fmod",
  b"math.huge",
  b"math.log",
  b"math.max",
  b"math.maxinteger",
  b"math.min",
  b"math.mininteger",
  b"math.modf",
  b"math.pi",
  b"math.rad",
  b"math.random",
  b"math.sin",
  b"math.sqrt",
  b"math.tan",
  b"math.tointeger",
  b"math.type",
  b"math.ult",
  b"utf8.char",
  b"utf8.charpattern",
  b"utf8.codes",
  b"utf8.codepoint",
  b"utf8.len",
  b"utf8.offset",
]

def be(i):
  return struct.pack('>I', i)

def command(typ, pid, cid, eb=b''):
  if not eb:
    eb = b''
  if isinstance(eb, str):
    eb = bytes(eb)
  return be(typ) + be(pid) + be(cid) + be(len(eb)) + eb


H2O_COMMAND_POLL                 = 0x00000000
H2O_COMMAND_CHANNEL_MESSAGE      = 0x00000001
H2O_COMMAND_CHANNEL_CLOSE        = 0x00000002
H2O_COMMAND_PROCESS_CREATE       = 0x00000010
H2O_COMMAND_PROCESS_DESTROY      = 0x00000011
H2O_COMMAND_CHANNEL_CREATE_RAW   = 0x00000020
H2O_COMMAND_CHANNEL_CREATE_NOISENK = 0x00000021
H2O_COMMAND_CHANNEL_CREATE_NOISEKK_INIT = 0x00000022
H2O_COMMAND_CHANNEL_CREATE_NOISEKK_RESP = 0x00000023
H2O_COMMAND_RESET_REQUEST       =   0x00000030

commands = [
  command(H2O_COMMAND_POLL, 0, 0),
  command(H2O_COMMAND_CHANNEL_MESSAGE, 1, 1, b'abc'),
  command(H2O_COMMAND_CHANNEL_CLOSE, 1, 1),
  command(H2O_COMMAND_PROCESS_CREATE, 0, 0, echo_code),
  command(H2O_COMMAND_PROCESS_CREATE, 0, 0, encdec_code),
  command(H2O_COMMAND_PROCESS_CREATE, 0, 0, fixedmap_code),
  command(H2O_COMMAND_PROCESS_DESTROY, 1, 0),
  command(H2O_COMMAND_CHANNEL_CREATE_RAW, 1, 0),
  command(H2O_COMMAND_RESET_REQUEST, 0, 0),
]

for f in lua_functions:
  commands.append(command(H2O_COMMAND_PROCESS_CREATE, 0, 0, b"%s()\n" % f))

def write_command_file(cmds, suffix):
  out = []
  for c in cmds:
    out.append(struct.pack('>H', len(c)))
    out.append(c)
  h = hashlib.sha256()
  to_write = b''.join(out)
  h.update(to_write)
  fname = h.hexdigest()
  print("Writing %s" % fname)
  with open("aflfuzz" + suffix + "/testcases/" + fname, 'wb') as f:
    f.write(to_write)

def main():
  suffix = len(sys.argv) > 1 and sys.argv[1] or ""
  for c in commands:
    write_command_file([c], suffix)
  random.seed(time.time())
  for i in range(500):
    n = random.randint(1, len(commands))
    write_command_file(random.sample(commands, n), suffix)
    

if __name__ == '__main__':
  main()
