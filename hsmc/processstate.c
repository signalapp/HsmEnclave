/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "processstate.h"

#include <sha2/sha256.h>
#include <sys/time.h>
#include <lauxlib.h>
#include <lualib.h>
#include <lua.h>

#include "hsm_enclave.h"
#include "hmac_sha2.h"
#include "fixedmap.h"
#include "channel.h"
#include "sandbox.h"

static unsigned char userkey_empty_bytes[CRYPT_USERKEY_BYTES] = {0};
bool processstate_run_lua = true;

/** Lua function called to encrypt a single string.
 *
 * Lua arguments (stack position, type):
 *  plaintext       (1, string)
 *  hsm_enclave_t*        (2, light userdata)
 *  processstate_t* (3, light userdata)
 * Lua return values:
 *  ciphertext (string)
 */
static int hsm_enclave_lua_encrypt(lua_State* s) {
  DLOG("hsm_enclave_lua_encrypt()");
  size_t size;
  hsm_enclave_t* enclave = lua_touserdata(s, 1);
  processstate_t* ps = lua_touserdata(s, 2);
  const unsigned char* data = (const unsigned char*) luaL_checklstring(s, 3, &size);
  size_t userkey_size = CRYPT_USERKEY_BYTES;
  const unsigned char* userkey = (const unsigned char*) luaL_optlstring(s, 4, NULL, &userkey_size); 
  if (userkey == NULL || userkey_size == 0) {
    userkey = userkey_empty_bytes;
    userkey_size = sizeof(userkey_empty_bytes);
  } else if (userkey_size != CRYPT_USERKEY_BYTES) {
    return luaL_error(s, "userkey invalid size");
  }

  luaL_Buffer buf;
  size_t bufsize = size + CRYPT_OVERHEAD;
  unsigned char* bufptr = (unsigned char*) luaL_buffinitsize(s, &buf, bufsize);
  error_t err = crypt_encrypt(ps->crypt, enclave->rand, data, size, userkey, bufptr, &bufsize);
  if (err != err_SUCCESS) {
    DLOG_ERR(err);
    ERR_FREE(err);
    return luaL_error(s, "encrypt failed");
  }
  luaL_pushresultsize(&buf, bufsize);
  return 1;
}

/** Lua function called to decrypt a single string.
 *
 * Lua arguments (stack position, type):
 *  ciphertext      (1, string)
 *  hsm_enclave_t*        (2, light userdata)
 *  processstate_t* (3, light userdata)
 * Lua return values:
 *  plaintext (string)
 */
static int hsm_enclave_lua_decrypt(lua_State* s) {
  DLOG("hsm_enclave_lua_decrypt()");
  processstate_t* ps = lua_touserdata(s, 1);
  size_t size;
  unsigned const char* data = (unsigned const char*) luaL_checklstring(s, 2, &size);
  size_t userkeys_size = 1;
  unsigned const char* userkeys = (unsigned const char*) luaL_optlstring(s, 3, NULL, &userkeys_size);
  if (userkeys == NULL || userkeys_size == 0) {
    userkeys = userkey_empty_bytes;
    userkeys_size = sizeof(userkey_empty_bytes);
  }

  luaL_Buffer buf;
  size_t bufsize = size;
  unsigned char* bufptr = (unsigned char*) luaL_buffinitsize(s, &buf, bufsize);
  error_t err = crypt_decrypt(ps->crypt, (const unsigned char*) data, size, userkeys, userkeys_size, bufptr, &bufsize);
  if (err != err_SUCCESS) {
    DLOG_ERR(err);
    ERR_FREE(err);
    return luaL_error(s, "decrypt failed");
  }
  luaL_pushresultsize(&buf, bufsize);
  return 1;
}

// hash_bytes writes a hash into hash[0..32].
static void hash_bytes(const unsigned char* bytes, size_t bytes_length, unsigned char* hash) {
  sha256_context_t s;
  sha256_reset(&s);
  sha256_update(&s, bytes, bytes_length);
  sha256_finish(&s, hash);
}

/** Lua function called to compute the SHA256 hash of a single string.
 *
 * Lua arguments (stack position, type):
 *  data (1-N (variadic), string)
 * Lua return values:
 *  hash (string)
 */
static int hsm_enclave_lua_sha256(lua_State* s) {
  DLOG("hsm_enclave_lua_sha256()");
  sha256_context_t h;
  sha256_reset(&h);
  int top = lua_gettop(s);
  int i;
  for (i = 1; i <= top; i++) {
    size_t size;
    const char* data = luaL_checklstring(s, i, &size);
    sha256_update(&h, data, size);
  }
  unsigned char sha_data[32];
  sha256_finish(&h, sha_data);
  lua_pushlstring(s, (char*) sha_data, sizeof(sha_data));
  return 1;
}

/** Lua function called to (possibly) print debug information.
 *
 * Lua arguments (stack position, type):
 *  logline (1, string)
 */
static int hsm_enclave_lua_print(lua_State* s) {
  DLOG("LUA: %s", luaL_checkstring(s, 1));
  return 0;
}

/** Lua function called to (possibly) print log information.
 *
 * Lua arguments (stack position, type):
 *  logline (1, string)
 */
static int hsm_enclave_lua_log(lua_State* s) {
  LOG("LUA: %s", luaL_checkstring(s, 1));
  return 0;
}

/** Lua function called to get the current timestamp in epoch microseconds
 *
 * Lua return value:
 *   timestamp (Lua Integer (long long))
 */
static int hsm_enclave_lua_timestamp_micros(lua_State* s) {
  struct timeval tv;
  gettimeofday(&tv, NULL);

  lua_pushinteger(s, ((uint64_t)(tv.tv_sec)) * 1000000ULL + tv.tv_usec);

  return 1;
}

void processstate_free(processstate_t* p) {
  DLOG("processstate_free(%p)", p);
  if (p->L != NULL) lua_close(p->L);
  if (p->crypt != NULL) crypt_free(p->crypt);
  free(p);
}

static const luaL_Reg processstate_libstoload[] = {
  {LUA_GNAME, luaopen_base},
  // {LUA_LOADLIBNAME, luaopen_package},
  {LUA_COLIBNAME, luaopen_coroutine},
  {LUA_TABLIBNAME, luaopen_table},
  // {LUA_IOLIBNAME, luaopen_io},
  // {LUA_OSLIBNAME, luaopen_os},
  {LUA_STRLIBNAME, luaopen_string},
  {LUA_MATHLIBNAME, luaopen_math},
  {LUA_UTF8LIBNAME, luaopen_utf8},
  // {LUA_DBLIBNAME, luaopen_debug},
  {"fixedmap", luaopen_fixedmap},
  {NULL, NULL}
};

static void processstate_init_lua(processstate_t* p) {
  const luaL_Reg *lib;
  for (lib = processstate_libstoload; lib->func; lib++) {
    luaL_requiref(p->L, lib->name, lib->func, 1);
    lua_pop(p->L, 1);
  }
}

/** Called when we've done a lua_pcall, with the result code passed in. */
static error_t hsm_enclave_lua_error(lua_State* L, int lua_result) {
  switch (lua_result) {
  case LUA_OK:
    // On an OK, pcall has pushed the results of the function onto the stack.
    // We ignore those (the caller wants them) and return success without
    // modifying the stack at all.
    return err_SUCCESS;
  case LUA_ERRMEM:
    // On a non-OK, pcall has pushed an error message onto the stack.  In
    // the case of an OOM, we ignore it and return err_OOM, but we do want
    // to remove it from the stack, hence the pop().
    lua_pop(L, 1);
    return err_OOM;
  }
  // For non-OOM errors, there should be a string on the stack that provides
  // error details.  We try to grab it.
  error_t err;
  if (lua_isstring(L, -1)) {
    const char* errmsg = lua_tostring(L, -1);
    err = ERR_COPYSTR(errmsg);
  } else {
    err = ERR("unknown; non-string at error stack position");
  }
  // Regardless of whether we were successful in gathering a string from the
  // stack, pcall has guaranteed that it pushed _something_ onto the stack,
  // so it's up to us to remove it.
  lua_pop(L, 1);

  switch (lua_result) {
  case LUA_ERRSYNTAX:
    return ERR_CTX(err, "LUA_ERRSYNTAX");
  case LUA_ERRRUN:
    return ERR_CTX(err, "LUA_ERRRUN");
  case LUA_ERRERR:
    return ERR_CTX(err, "LUA_ERRERR");
  case LUA_YIELD:
    return ERR_CTX(err, "LUA_YIELD");
  default:
    return ERR_CTX(err, "unknown error type");
  }
}

static error_t luahelper_pcall(lua_State* s, int args, int ret) {
  DLOG("luahelper_pcall(args=%d,ret=%d)", args, ret);
  /* POP args+1 */
  /* On success, PUSH ret */
  /* On failure, stack empty */
  return hsm_enclave_lua_error(s, lua_pcall(s, args, ret, 0));
}

static int luahelper_pushstring_in_pcall(lua_State* s) {
  char* buf = (char*) lua_touserdata(s, 1);
  size_t size = luaL_checkinteger(s, 2);
  // Within this function, we're protected by a lua_pcall wrapper, so this lua_pushlstring's potential
  // failure due to OOM is protected correctly.
  lua_pushlstring(s, buf, size);
  return 1;
}

/** Helper function to push a C buffer onto the Lua stack. */
static error_t luahelper_pushstring(lua_State* s, const unsigned char* buf, size_t size) {
  DLOG("luahelper_pushstring(size=%lu)", size);
  ASSERT_ERR(lua_checkstack(s, 3));
  /* PUSH 1, STACK=1 */ lua_pushcfunction(s, &luahelper_pushstring_in_pcall);
  /* PUSH 1, STACK=2 */ lua_pushlightuserdata(s, (char*) buf);
  /* PUSH 1, STACK=3 */ lua_pushinteger(s, size);
  /* On success:
       POP 3, PUSH 1, STACK=1
     On failure:
       POP 3, STACK=0
  */
  return luahelper_pcall(s, 2, 1);
}

/** Push a "global" function onto the stack.  Note that "global" here
 *  actually means "within the sandbox env". */
static error_t processstate_push_global_function(processstate_t* p, const char* global) {
  ASSERT_ERR(lua_checkstack(p->L, 2));  // aim a little high
  /* PUSH 1, STACK=1 */ RETURN_IF_ERROR("pushing global name", luahelper_pushstring(p->L, (unsigned char*) global, strlen(global)));
  /* POP 1, PUSH 1, STACK=1 */ int typ = lua_gettable(p->L, p->sandbox_env);
  if (typ != LUA_TFUNCTION) {
    lua_pop(p->L, 1);
    return ERR_CTX(ERR_COPYSTR(global), "global function missing");
  }
  /* STACK=1 */
  return err_SUCCESS;
}

struct luafunction_t {
  const char* name;
  lua_CFunction func;
};

static struct luafunction_t lua_funcs[] = {
  {.name = "hsm_enclave_lua_encrypt", .func = hsm_enclave_lua_encrypt},
  {.name = "hsm_enclave_lua_decrypt", .func = hsm_enclave_lua_decrypt},
  {.name = "hsm_enclave_lua_sha256", .func = hsm_enclave_lua_sha256},
  {.name = "hsm_enclave_lua_print", .func = hsm_enclave_lua_print},
  {.name = "hsm_enclave_lua_log", .func = hsm_enclave_lua_log},
  {.name = "hsm_enclave_lua_timestamp_micros", .func = hsm_enclave_lua_timestamp_micros},
  {.name = NULL, .func = NULL}
};

struct luaenum_t {
  const char* name;
  lua_Integer value;
};

static struct luaenum_t lua_enums[] = {
  // Channel types
  {.name = "CHAN_UNENCRYPTED", .value = LUA_CHANNELTYPE_UNENCRYPTED},
  {.name = "CHAN_CLIENT_NK", .value = LUA_CHANNELTYPE_CLIENTNK},
  {.name = "CHAN_SERVER_KK", .value = LUA_CHANNELTYPE_SERVERKK},

  // Channel closure status (should match GRPC status values)
  {.name = "STATUS_OK", .value = 0},
  {.name = "STATUS_CANCELLED", .value = 1},
  {.name = "STATUS_UNKNOWN", .value = 2},
  {.name = "STATUS_INVALID_ARGUMENT", .value = 3},
  {.name = "STATUS_DEADLINE_EXCEEDED", .value = 4},
  {.name = "STATUS_NOT_FOUND", .value = 5},
  {.name = "STATUS_ALREADY_EXISTS", .value = 6},
  {.name = "STATUS_PERMISSION_DENIED", .value = 7},
  {.name = "STATUS_RESOURCE_EXHAUSTED", .value = 8},
  {.name = "STATUS_FAILED_PRECONDITION", .value = 9},
  {.name = "STATUS_ABORTED", .value = 10},
  {.name = "STATUS_OUT_OF_RANGE", .value = 11},
  {.name = "STATUS_UNIMPLEMENTED", .value = 12},
  {.name = "STATUS_INTERNAL", .value = 13},
  {.name = "STATUS_UNAVAILABLE", .value = 14},
  {.name = "STATUS_DATA_LOSS", .value = 15},
  {.name = "STATUS_UNAUTHENTICATED", .value = 16},

  {.name = NULL, .value = 0}
};

static const char* hsm_enclave_lua_enclave_handle = "hsm_enclave_lua_enclave_handle";
static const char* hsm_enclave_lua_process_handle = "hsm_enclave_lua_process_handle";

error_t processstate_new(processstate_t** out, const void* code, size_t code_size, uint32_t process_id, hsm_enclave_t* enclave_ref) {
  ASSERT_ERR(code_size > 0);
  processstate_t* ps;
  MALLOCZ_OR_RETURN_ERROR(ps, processstate_t);
  DLOG("processstate_new() -> %p", ps);
  error_t err = err_SUCCESS;
  ps->process_id = process_id;
  ps->L = luaL_newstate();
  ps->enclave_ref = enclave_ref;
  if (ps->L == NULL) {
    err = err_OOM;
    goto free_processstate;
  }

  processstate_init_lua(ps);
  if (!lua_checkstack(ps->L, 3)) {
    err = ERR("unable to check Lua stack in _new");
    goto free_processstate;
  }

  /* PUSH 1, STACK=1 */ lua_pushlightuserdata(ps->L, enclave_ref);
  /* POP  1, STACK=0 */ lua_setglobal(ps->L, hsm_enclave_lua_enclave_handle);
  /* PUSH 1, STACK=1 */ lua_pushlightuserdata(ps->L, ps);
  /* POP  1, STACK=0 */ lua_setglobal(ps->L, hsm_enclave_lua_process_handle);
  int i;
  for (i = 0; lua_funcs[i].func != NULL; i++) {
    /* PUSH 1, STACK=1 */ lua_pushcfunction(ps->L, lua_funcs[i].func);
    /* POP  1, STACK=0 */ lua_setglobal(ps->L, lua_funcs[i].name);
  }

  // Load and run sandbox code to hide things we want hidden.
  DLOG("  sandbox buffer loading");
  /* PUSH 1, STACK=1 */ if (err_SUCCESS != (err = ERR_CTX(hsm_enclave_lua_error(ps->L, luaL_loadbufferx(ps->L, sandbox_code, strlen(sandbox_code), "sandbox", "t")), "sandbox"))) goto free_processstate;
  DLOG("  sandbox buffer loaded");
  /* POP  1, STACK=0 */ if (err_SUCCESS != (err = ERR_CTX(luahelper_pcall(ps->L, 0, LUA_MULTRET), "pcall sandbox"))) goto free_processstate;
  DLOG("  sandbox buffer executed");
  /* PUSH 1, STACK=1 */ if (LUA_TTABLE != lua_getglobal(ps->L, "sandbox_env")) {
    err = ERR("missing sandbox_env table");
    goto free_processstate;
  }
  ps->sandbox_env = lua_gettop(ps->L);

  // Set globals for channel
  for (i = 0; lua_enums[i].name != NULL; i++) {
    /* PUSH 1, STACK=2 */ if (err_SUCCESS != (err = luahelper_pushstring(ps->L, (unsigned char*) lua_enums[i].name, strlen(lua_enums[i].name)))) goto free_processstate;
    /* PUSH 1, STACK=3 */ lua_pushinteger(ps->L, lua_enums[i].value);
    /* POP  2, STACK=1 */ lua_settable(ps->L, ps->sandbox_env);
  }

  // We must set up crypt before we load the supplied buffer, since that buffer may
  // call enclave.encrypt/decrypt.
  if (err_SUCCESS != (err = cryptfactory_derive(enclave_ref->base_crypt, ps->codehash, &ps->crypt))) {
    err = ERR_CTX(err, "cryptfactory_derive");
    goto free_processstate;
  }

  // Load and run user code.
  hash_bytes(code, code_size, ps->codehash);

  if (processstate_run_lua) {
    DLOG("  lua buffer loading");
    /* PUSH 1, STACK=2 */ if (err_SUCCESS != (err = ERR_CTX(hsm_enclave_lua_error(ps->L, luaL_loadbufferx(ps->L, code, code_size, "process", "t")), "loadbuffer"))) goto free_processstate;
    DLOG("  lua buffer loaded");
    /* PUSH 1, STACK=3 */ if (LUA_TTABLE != lua_getglobal(ps->L, "sandbox_env")) {
      err = ERR("missing sandbox_env table");
      goto free_processstate;
    }
    /* POP  1, STACK=2 */ lua_setupvalue(ps->L, -2, 1);
    DLOG("  sandbox upvalue set");
    /* POP  1, STACK=1 */ if (err_SUCCESS != (err = ERR_CTX(luahelper_pcall(ps->L, 0, LUA_MULTRET), "pcall buffer"))) goto free_processstate;
    DLOG("  lua buffer executed");

    // These 3 pushes just check that the associated functions exist.
    /* PUSH 1, STACK=2 */ if (err_SUCCESS != (err = processstate_push_global_function(ps, "HandleChannelCreate"))) goto free_processstate;
    ps->handle_channel_create = lua_gettop(ps->L);
    /* PUSH 1, STACK=3 */ if (err_SUCCESS != (err = processstate_push_global_function(ps, "HandleChannelClose"))) goto free_processstate;
    ps->handle_channel_close = lua_gettop(ps->L);
    /* PUSH 1, STACK=4 */ if (err_SUCCESS != (err = processstate_push_global_function(ps, "HandleChannelMessage"))) goto free_processstate;
    ps->handle_channel_message = lua_gettop(ps->L);
    DLOG("  lua globals found");
  }

  // NOTE: sandbox_env continues to exist at index 1, pushed onto the stack and
  // pointed to by ps->sandbox_env.

  *out = ps;
  return err_SUCCESS;

free_processstate:
  processstate_free(ps);
  return err;
}

#define LUA_ERR_POP(L, n, e) do { \
  error_t _lua_e_ = (e); \
  if (_lua_e_ != err_SUCCESS) { \
    lua_pop(L, n); \
    return _lua_e_; \
  } \
} while (0)

#define LUA_ERR_ASSERT(L, n, b, ctx) LUA_ERR_POP(L, n, ((b) ? err_SUCCESS : ERR_CTX(ERR(#b), ctx)))

/** Process a single entry of the return list from a HandleChannelX function.
 *  That entry should be the current top of the stack.
 *  Does not pop the tuple we're processing from the stack, but pops everything
 *  it pushes onto the stack during processing.
 */
static error_t processstate_lua_command_tuple(processstate_t* p) {
  DLOG("- processstate_lua_command_tuple(pid=%d)", p->process_id);
  ASSERT_ERR(lua_checkstack(p->L, 1));

  // CID
  /* PUSH 1, STACK=1 */ LUA_ERR_ASSERT(p->L, 1, LUA_TNUMBER == lua_rawgeti(p->L, -1, 1), "getting channel ID");
  lua_Number cidL = lua_tonumber(p->L, -1);
  /* POP  1, STACK=0 */ lua_pop(p->L, 1);

  // Bytes
  size_t size = 0;
  const char* bytes = NULL;
  uint32_t close_status = 0;
  bool have_close_status = false;
  /* PUSH 1, STACK=1 */ switch (lua_rawgeti(p->L, -1, 2)) {
    case LUA_TNUMBER: {
      lua_Number n = lua_tonumber(p->L, -1);
      lua_numbertointeger(n, &close_status);
      have_close_status = true;
      break;
    }
    case LUA_TSTRING:
      bytes = lua_tolstring(p->L, -1, &size);
      break;
    default:
      /* POP  1, STACK=0 */ lua_pop(p->L, 1);
      return ERR("bytes invalid type");
  }

  uint32_t cid = 0;
  lua_numbertointeger(cidL, &cid);

  command_t* cmd = NULL;
  error_t err = err_SUCCESS;
  if (have_close_status) {
    DLOG("  - command close cid=%d status=%d", cid, close_status);
    err = command_new_uint32_userbytes(&cmd, O2H_COMMAND_CHANNEL_CLOSE, p->process_id, cid, close_status);
  } else if (err_SUCCESS == (err = command_new(&cmd, O2H_COMMAND_CHANNEL_MESSAGE, p->process_id, cid, size))) {
    DLOG("  - command message cid=%d ebsz=%ld", cid, size);
    memcpy(command_extrabytes(cmd), bytes, size);
  }
  if (err != err_SUCCESS) goto luapop;
  if (err_SUCCESS != (err = commandqueue_pushback(p->enclave_ref->output_from_process, cmd))) {
    command_free(cmd);
  }

luapop:
  /* POP  1, STACK=0 */ lua_pop(p->L, 1);
  return err;
}

static error_t processstate_lua_command_tuple_list(processstate_t* p) {
  DLOG("processstate_lua_command_tuple_list(pid=%d)", p->process_id);
  if (lua_isnoneornil(p->L, -1)) return err_SUCCESS;  // allow nil to be treated as empty list
  if (!lua_istable(p->L, -1)) {
    return ERR("HandleChannelMessage didn't return table");
  }
  // We assert 2 here since processstate_lua_command_tuple
  // will need 1 additional beyond our use of 1
  ASSERT_ERR(lua_checkstack(p->L, 2));
  int i;
  bool done = false;
  error_t err = err_SUCCESS;
  for (i = 1 /* lua is 1-indexed */; !done; i++) {
    // Iterate up until we don't find something.
    /* PUSH 1, STACK=1 */ switch (lua_rawgeti(p->L, -1, i)) {
      case LUA_TNONE:
      case LUA_TNIL:
        done = true;
        break;
      case LUA_TTABLE:
        // We found a command tuple, process it on the stack.
        err = processstate_lua_command_tuple(p);
        break;
      default:
        err = ERR("unexpected lua type");
    }
    /* POP 1, STACK=0 */ lua_pop(p->L, 1);
    if (err_SUCCESS != err) {
      break;
    }
  }
  return err;
}

error_t processstate_channel_message(processstate_t* p, uint32_t channel_id, const unsigned char* msg, size_t size) {
  DLOG("processstate_channel_message(pid=%d,cid=%d,size=%ld)", p->process_id, channel_id, size);
  error_t err = err_SUCCESS;
  if (processstate_run_lua) {
    ASSERT_ERR(lua_checkstack(p->L, 8));  // aim a little high
    /* PUSH 1, STACK=1 */ lua_pushvalue(p->L, p->handle_channel_message);
    /* PUSH 1, STACK=2 */ lua_pushnumber(p->L, channel_id);

    // At this point in the code, we're not within a lua_pcall, so we're not protected from any sort of
    // errors that Lua might run into when performing operations.  We want to push the 'msg' string
    // onto the stack, but if we call lua_pushlstring directly, there's a chance that Lua could OOM,
    // and being outside of a pcall we'd panic and be unable to handle it, hard-crashing the system.
    // To get around that, we call our lua_pushl_string helper, which safely pushes pointers to the buffer
    // onto the stack (safe because we lua_checkstack it'll work, and we're pushing word-sized values
    // rather than a non-fixed-sized buffer), then call a helper C function (lua_push_string_helper)
    // within a pcall which does our actual lua_pushlstring operation safely wrapped.

    /* PUSH 1, STACK=3 */ if (err_SUCCESS != (err = luahelper_pushstring(p->L, msg, size))) {
      // If the push of the string fails, we've already pushed the function and channel ID, so
      // before we return, we need to clean them off the stack.
      lua_pop(p->L, 2);
      return err;
    }
    /* POP 3, PUSH 1, STACK=1 */ RETURN_IF_ERROR(
        "running HandleChannelMessage",
        luahelper_pcall(p->L, 2 /*nargs*/, 1 /*nret*/));
    err = processstate_lua_command_tuple_list(p);
    /* POP 1, STACK=0 */ lua_pop(p->L, 1);
  }
  return ERR_CTX(err, "postprocessing HandleChannelMessage");
}

error_t processstate_channel_add(processstate_t* p, uint32_t channel_id, int lua_channel_type) {
  DLOG("processstate_channel_add(pid=%d,cid=%d)", p->process_id, channel_id);
  error_t err = err_SUCCESS;
  if (processstate_run_lua) {
    ASSERT_ERR(lua_checkstack(p->L, 8));  // aim a little high
    /* PUSH 1, STACK=1 */ lua_pushvalue(p->L, p->handle_channel_create);
    /* PUSH 1, STACK=2 */ lua_pushnumber(p->L, channel_id);
    /* PUSH 1, STACK=3 */ lua_pushnumber(p->L, lua_channel_type);
    /* POP 3, PUSH 1, STACK=1 */ RETURN_IF_ERROR(
        "running HandleChannelCreate",
        luahelper_pcall(p->L, 2 /*nargs*/, 1 /*nret*/));
    err = processstate_lua_command_tuple_list(p);
    /* POP 1, STACK=0 */ lua_pop(p->L, 1);
  }
  return ERR_CTX(err, "postprocessing HandleChannelCreate");
}

error_t processstate_channel_remove(processstate_t* p, uint32_t channel_id) {
  DLOG("processstate_channel_remove(pid=%d,cid=%d)", p->process_id, channel_id);
  error_t err = err_SUCCESS;
  if (processstate_run_lua) {
    ASSERT_ERR(lua_checkstack(p->L, 8));  // aim a little high
    /* PUSH 1, STACK=1 */ lua_pushvalue(p->L, p->handle_channel_close);
    /* PUSH 1, STACK=2 */ lua_pushnumber(p->L, channel_id);
    /* POP 2, PUSH 1, STACK=1 */ RETURN_IF_ERROR(
        "running HandleChannelClose",
        luahelper_pcall(p->L, 1 /*nargs*/, 1 /*nret*/));
    err = processstate_lua_command_tuple_list(p);
    /* POP 1, STACK=0 */ lua_pop(p->L, 1);
  }
  return ERR_CTX(err, "postprocessing HandleChannelClose");
}
