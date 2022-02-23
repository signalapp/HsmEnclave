--
-- Copyright 2022 Signal Messenger, LLC
-- SPDX-License-Identifier: AGPL-3.0-only
--

-- Wrap OS and process handles in lambdas, then deref.
do
  local os = hsm_enclave_lua_enclave_handle
  local ps = hsm_enclave_lua_process_handle
  local enc = hsm_enclave_lua_encrypt
  local dec = hsm_enclave_lua_decrypt
  function hsm_enclave_encrypt_lambda(s, userkey)
    return enc(os, ps, s, userkey)
  end
  function hsm_enclave_decrypt_lambda(s, userkeys, keysize)
    return dec(ps, s, userkeys)
  end
end
hsm_enclave_lua_enclave_handle = nil
hsm_enclave_lua_process_handle = nil
hsm_enclave_lua_encrypt = nil
hsm_enclave_lua_decrypt = nil

--------------------------------------------------------------------------------
-- Patches modeled after https://gist.github.com/CaptainPRICE/bd19a8b92d9cb8a74329ba8b26d2e2c9
--------------------------------------------------------------------------------
do
    local _error = error
    error = nil
    function error_patched(message)
        assert(type(message) == 'string')
        -- Modified from CaptainPRICE patch to have level=1 (show current position) over level=0 (don't show position)
        return _error(message, 1)
    end
end
do
    local _getmetatable = getmetatable
    getmetatable = nil
    function getmetatable_patched(object)
        if type(object) == 'table' then
            return object.__metatable ~= nil and object.__metatable or _getmetatable(object)
        end
        return nil
    end
end
do
    local _setmetatable = setmetatable
    setmetatable = nil
    function setmetatable_patched(tbl, metatable)
        assert(type(tbl) == 'table' and ((metatable) == nil or type(metatable) == 'table'))
        if tbl.__metatable ~= nil then
            return error('cannot change a protected metatable')
        end
        return _setmetatable(tbl, metatable)
    end
end


sandbox_env = {
  -- enclave-specific functions
  enclave = {
    encrypt = hsm_enclave_encrypt_lambda,
    decrypt = hsm_enclave_decrypt_lambda,
    sha256 = hsm_enclave_lua_sha256,
    fixedmap = hsm_enclave_lua_fixedmap,
    timestamp_micros = hsm_enclave_lua_timestamp_micros,
  },

  -- patched functions
  error = error_patched,
  print = hsm_enclave_lua_print,
  setmetatable = setmetatable_patched,
  getmetatable = getmetatable_patched,

  -- copied-over functions
  assert = assert,
  ipairs = ipairs,
  next = next,
  pairs = pairs,
  pcall = pcall,
  select = select,
  tonumber = tonumber,
  tostring = tostring,
  type = type,
  _VERSION = _VERSION,
  xpcall = xpcall,
  coroutine = {
    close = coroutine.close,
    create = coroutine.create,
    isyieldable = coroutine.isyieldable,
    resume = coroutine.resume,
    running = coroutine.running,
    status = coroutine.status,
    wrap = coroutine.wrap,
    yield = coroutine.yield,
  },
  string = {
    byte = string.byte,
    char = string.char,
    find = string.find,
    format = string.format,
    gmatch = string.gmatch,
    gsub = string.gsub,
    len = string.len,
    lower = string.lower,
    match = string.match,
    pack = string.pack,
    packsize = string.packsize,
    rep = string.rep,
    reverse = string.reverse,
    sub = string.sub,
    unpack = string.unpack,
    upper = string.upper,
  },
  table = {
    concat = table.concat,
    insert = table.insert,
    move = table.move,
    pack = table.pack,
    remove = table.remove,
    sort = table.sort,
    unpack = table.unpack,
  },
  math = {
    abs = math.abs,
    acos = math.acos,
    asin = math.asin,
    atan = math.atan,
    ceil = math.ceil,
    cos = math.cos,
    cosh = math.cosh,
    deg = math.deg,
    exp = math.exp,
    floor = math.floor,
    fmod = math.fmod,
    huge = math.huge,
    log = math.log,
    max = math.max,
    maxinteger = math.maxinteger,
    min = math.min,
    mininteger = math.mininteger,
    modf = math.modf,
    pi = math.pi,
    rad = math.rad,
    random = math.random,
    sin = math.sin,
    sqrt = math.sqrt,
    tan = math.tan,
    tointeger = math.tointeger,
    type = math.type,
    ult = math.ult,
  },
  utf8 = {
    char = utf8.char,
    charpattern = utf8.charpattern,
    codes = utf8.codes,
    codepoint = utf8.codepoint,
    len = utf8.len,
    offset = utf8.offset,
  },
}
sandbox_env['_G'] = sandbox_env

hsm_enclave_lua_print = nil
hsm_enclave_lua_fixedmap = nil
