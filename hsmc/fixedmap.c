/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "fixedmap.h"
#include "error.h"
#include "dlog.h"
#include "noise.h"
#include <lauxlib.h>
#include <math.h>
#include <halfsiphash.h>

static unsigned char* fixedmap_halfsiphash_key;
static unsigned char fixedmap_halfsiphash_key_buffer[8];

static error_t fixedmap_init(void) {
  // Allow multiple serial calls.  Does not protect against parallel execution.
  if (fixedmap_halfsiphash_key != NULL) return err_SUCCESS;

  if (NOISE_ERROR_NONE != noise_randstate_generate_simple(fixedmap_halfsiphash_key_buffer, sizeof(fixedmap_halfsiphash_key_buffer))) {
    return ERR("generating random state for fixedmap failed");
  }
  // Set to non-null as a marker that initiation has completed.
  fixedmap_halfsiphash_key = fixedmap_halfsiphash_key_buffer;
  return err_SUCCESS;
}

struct fixedmap_t {
  // This block contains all entries in a single contiguous memory space.
  // You can think of it as containing a repeated set of [jump][key][value]
  // entries concatenated together.
  unsigned char* block;
  // This block is the size of [ksize]+[vsize], and is utilized during
  // upserts where we need temporary storage to copy key/value pairs around
  // while keeping our RobinHood jumps correctly ordered/handled.
  unsigned char* tmpkv;

  size_t ksize;    // Exact size of each key, in bytes
  size_t vsize;    // Exact size of each value, in bytes
  size_t cap;      // Number of entries in [block]
  size_t size;     // Number of set entries in [block]

  // [maxjump] is a small optimization that stores the maximum [jump] value
  // across all entries in the current map.  When calling _get on a key,
  // we only have to look up to this many entries into the map before we
  // know that the key doesn't exist.
  size_t maxjump;
};

typedef struct {
  // This entry is stored at index [hash(key)+jump] in the map.
  // [jump] will be non-zero if the entry contains a key/value pair,
  // or zero if the entry is empty.
  uint32_t jump;
  // Pointer to the start of the key/value pair stored in this entry.
  // Key stored at [kv], Value stored at [kv+h->ksize].
  unsigned char kv[0];
} fixedmap_entry_t;

#define FNV_START 2166136261
#define FNV_PRIME 16777619

// Simple fast hashing algorithm.
// https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
static size_t fnv1a(const unsigned char* k, size_t size) {
  size_t i;
  size_t out = FNV_START;
  for (i = 0; i < size; i++) {
    out ^= k[i];
    out *= FNV_PRIME;
  }
  return out;
}

// Hash a key within the given map.
static inline size_t khash(fixedmap_t* h, const unsigned char* k) {
  size_t out = 0;
  halfsiphash(k, h->ksize, fixedmap_halfsiphash_key, (unsigned char*) &out, sizeof(out));
  return out;
}

// Return whether two keys [a] and [b] are equal.
static bool keq(fixedmap_t* h, const unsigned char* a, const unsigned char* b) {
  return 0 == memcmp(a, b, h->ksize);
}

// Swap the data contained within two memory regions [a] and [b],
// both of size [s].
static void memswap(unsigned char* a, unsigned char* b, size_t s) {
  unsigned char buf[64];
  while (s > 0) {
    size_t to_copy = sizeof(buf) > s ? s : sizeof(buf);
    memcpy(buf, a, to_copy);
    memcpy(a, b, to_copy);
    memcpy(b, buf, to_copy);
    s -= to_copy;
  }
}

// Compute the total size in bytes of a fixedmap_entry_t, including
// its associated key and value.
static size_t fixedmap_entry_size(fixedmap_t* h) {
  return h->ksize + h->vsize + sizeof(fixedmap_entry_t);
}

// Return a pointer to an entry within the fixedmap.  Note that [i]
// may be outside the range of [0,h->cap); this function will perform
// the correct modulo arithmetic to get a valid pointer.
static fixedmap_entry_t* fixedmap_entry_n(fixedmap_t* h, size_t i) {
  return (fixedmap_entry_t*) (h->block + (i % h->cap) * fixedmap_entry_size(h));
}

error_t fixedmap_new(fixedmap_t** out, size_t ksize, size_t vsize) {
  RETURN_IF_ERROR("fixedmap_init", fixedmap_init());
  fixedmap_t* h;
  MALLOCZ_OR_RETURN_ERROR(h, fixedmap_t);
  h->ksize = ksize;
  h->vsize = vsize;
  h->size = 0;
  h->maxjump = 0;
  h->cap = 32;
  h->block = (unsigned char*) calloc(h->cap, fixedmap_entry_size(h));
  if (h->block == NULL) goto oom;

  // When upserting, we sometimes need to swap around key/value pairs, and
  // we'd like to not have to malloc space for that within the upsert call.
  // So, we create a single key/value-sized buffer within the fixedmap_t that
  // we utilize for this purpose.
  h->tmpkv = (unsigned char*) calloc(h->ksize + h->vsize, 1);
  if (h->tmpkv == NULL) goto oom;
  *out = h;
  return err_SUCCESS;

oom:
  fixedmap_free(h);
  return err_OOM;
}

void fixedmap_free(fixedmap_t* h) {
  if (h->block) free(h->block);
  if (h->tmpkv) free(h->tmpkv);
  free(h);
}

// Increase the size of a fixedmap to [newcap].
// We generate a brand new memory space, then copy all entries
// from the old space into the new one.  This is an expensive operation
// at O(n).
static error_t fixedmap_resize(fixedmap_t* h, size_t newcap) {
  DLOG("fixedmap_resize(%p, %ld->%ld)", h, h->cap, newcap);
  ASSERT_ERR(newcap > h->cap);
  fixedmap_t old = *h;
  error_t err = err_OOM;
  h->block = (unsigned char*) calloc(newcap, fixedmap_entry_size(h));
  if (h->block == NULL) goto rollback;
  h->cap = newcap;
  h->size = 0;
  h->maxjump = 0;
  for (int i = 0; i < old.cap; i++) {
    fixedmap_entry_t* e = fixedmap_entry_n(&old, i);
    if (e->jump) {
      if (err_SUCCESS != (err = fixedmap_upsert(h, e->kv, e->kv + h->ksize, NULL, NULL))) goto freenew;
    }
  }
  free(old.block);
  return err_SUCCESS;

 freenew:
  free(h->block);
 rollback:
  *h = old;
  return err;
}

// Update [h->maxjump] with [jump].
static void fixedmap_maybe_set_max_jump(fixedmap_t* h, size_t jump) {
  if (jump > h->maxjump) {
    DLOG("fixedmap maxjump = %ld in size %ld/%ld", jump, h->size, h->cap);
    h->maxjump = jump;
  }
}

// Find a given key within the map, returning both the index at which
// it was found (in [*idx]) and a pointer to the entry that houses
// it (in [*out]).  If not found, sets [*out] to NULL and returns false.
static bool fixedmap_find(fixedmap_t* h, const unsigned char* k, size_t* idx, fixedmap_entry_t** out) {
  size_t hash = khash(h, k);
  size_t jump;
  for (jump = 1; jump <= h->maxjump; jump++) {
    fixedmap_entry_t* e = fixedmap_entry_n(h, hash + jump);
    if (e->jump == 0) {
      break;
    } else if (e->jump != jump) {
      // If the jumps don't match, then the hashes don't match, so the keys don't match.
      // Skip the need for checking keq().
      continue;
    } else if (keq(h, k, e->kv)) {
      *idx = hash + jump;
      *out = e;
      return true;
    }
  }
  *out = NULL;
  return false;
}

error_t fixedmap_upsert(fixedmap_t* h, const void* k_void, const void* v_void, void* old_v_void, bool* replaced) {
  const unsigned char* k = (const unsigned char*) k_void;
  const unsigned char* v = (const unsigned char*) v_void;
  unsigned char* old_v = (unsigned char*) old_v_void;
  // We resize when we are 8/9 full (~88%).  Because we use RobinHood
  // hashing, the _get calls for this high a level of saturation is
  // still quite good.
  size_t captest = h->size + h->size/8;
  if (captest > h->cap) {
    // See the Lua use of NUM_BLOCKS for why the following makes sense:
    //
    // When we grow, we grow randomly by somewhere between 25% and 75%.
    // This randomness makes a big difference when keys are uniformly
    // distributed between blocks, as it avoids having all blocks grow
    // at once.  If, for example, we grew by 1/2 all the time, all blocks
    // would grow at about the same time, dropping our memory utilization
    // from 8/9 -> 16/27 (88% -> 59%).  By making blocks be different
    // sizes, we tend to allow a more consistent memory utilization.
    size_t new_cap = h->cap + h->cap / 4 + rand() % (h->cap / 2);

    // This set of resizing computations (deciding when to resize and what
    // to resize to) in practice provides roughly a 70% utilization of
    // the hash.
    RETURN_IF_ERROR("upsert resize", fixedmap_resize(h, new_cap));
  }
  fixedmap_entry_t* e;
  size_t idx = 0;
  if (fixedmap_find(h, k, &idx, &e)) {
    if (old_v) memcpy(old_v, e->kv + h->ksize, h->vsize);
    if (replaced) *replaced = true;
    memcpy(e->kv + h->ksize, v, h->vsize);
    return err_SUCCESS;
  }

  // This loop is the core of our RobinHood hashing, modeled on
  // https://programming.guide/robin-hood-hashing.html.  As we insert, we
  // find a place for our own key, potentially dislodging other keys
  // in the process.  Every time we dislodge a key, we then continue
  // to find a place for it.  We end when we insert a key/value pair into
  // an _empty_ part of the hashmap.
  size_t hash = khash(h, k);
  size_t jump;
  for (jump = 1; ; jump++) {
    fixedmap_entry_t* e = fixedmap_entry_n(h, hash + jump);
    if (e->jump == 0) {
      // We've found an empty slot.  Insert the current key/value,
      // and we're done.
      e->jump = jump;
      memcpy(e->kv, k, h->ksize);
      memcpy(e->kv + h->ksize, v, h->vsize);
      if (replaced) *replaced = false;
      h->size++;
      fixedmap_maybe_set_max_jump(h, jump);
      return err_SUCCESS;
    } else if (e->jump < jump) {
      // We've found an entry with a lower jump than us.
      // Do the RobinHood thing:
      //   - take that spot
      //   - then look for a new spot for the new key/value
      hash = hash + jump - e->jump;
      size_t tmpjump = e->jump;
      e->jump = jump;
      fixedmap_maybe_set_max_jump(h, jump);
      jump = tmpjump;
      // The passed-in key/value are const pointers, so we can't copy
      // the data from the key/value we found in the map into them.
      // Rather than doing that, copy the passed-in key/value into
      // our tmpkv storage, then utilize that from now on for memswaps.
      if (k != h->tmpkv) {
        memcpy(h->tmpkv, k, h->ksize);
        memcpy(h->tmpkv + h->ksize, v, h->vsize);
        k = h->tmpkv;
        v = h->tmpkv + h->ksize;
      }
      memswap(e->kv, h->tmpkv, h->ksize + h->vsize);
    }
  }
}

bool fixedmap_get(fixedmap_t* h, const void* k_void, void* curr_v_void) {
  const unsigned char* k = (const unsigned char*) k_void;
  unsigned char* curr_v = (unsigned char*) curr_v_void;
  fixedmap_entry_t* e;
  size_t idx = 0;
  if (fixedmap_find(h, k, &idx, &e)) {
    if (curr_v) memcpy(curr_v, e->kv + h->ksize, h->vsize);
    return true;
  }
  return false;
}

bool fixedmap_remove(fixedmap_t* h, const void* k_void, void* old_v_void) {
  const unsigned char* k = (const unsigned char*) k_void;
  unsigned char* old_v = (unsigned char*) old_v_void;
  fixedmap_entry_t* e;
  uintptr_t idx;
  if (!fixedmap_find(h, k, &idx, &e)) return false;
  if (old_v) memcpy(old_v, e->kv + h->ksize, h->vsize);

  h->size--;
  size_t i;
  for (i = 1; ; i++) {
    fixedmap_entry_t* next = fixedmap_entry_n(h, idx+i);
    if (next->jump < 2) break;
    memcpy(e->kv, next->kv, h->ksize + h->vsize);
    e->jump = next->jump - 1;
    e = next;
  }
  e->jump = 0;
  return true;
}

size_t fixedmap_size(fixedmap_t* h) {
  return h->size;
}

size_t fixedmap_capacity(fixedmap_t* h) {
  return h->cap;
}

void fixedmap_clear(fixedmap_t* h) {
  memset(h->block, 0, h->cap * fixedmap_entry_size(h));
  h->size = 0;
}

//// ITERATOR IMPLEMENTATION

void fixedmap_iter_reset(fixedmap_iter_t* f, fixedmap_t* m) {
  f->m = m;
  f->i = 0-1;
}

bool fixedmap_iter_next(fixedmap_iter_t* f, void* k, void* v) {
  for (f->i++; f->i < f->m->cap && fixedmap_entry_n(f->m, f->i)->jump == 0; f->i++) {}
  if (f->i >= f->m->cap) return false;
  fixedmap_entry_t* e = fixedmap_entry_n(f->m, f->i);
  if (k) memcpy(k, e->kv, f->m->ksize);
  if (v) memcpy(v, e->kv + f->m->ksize, f->m->vsize);
  return true;
}

//// LUA IMPLEMENTATION BELOW THIS POINT
//
// In our C code, we're generally utilizing this fixedmap for relatively
// small sets, where resizing up to the next size is not too onerous.
// In Lua, however, this type is generally used for extremely large
// datasets, and resizing with allocate-then-copy can cause large spikes
// in memory.
//
// Increasing the size of a hashtable generally requires creating a new
// table that's larger, then copying over.  For some time, then, both
// the larger and smaller table must be in memory.  This limits the total
// size of the table to where SIZE+SIZE_INCREASED must be less than total
// RAM.  There's probably really tricky ways around this, but here's a
// super simple one:  we actually just keep 16 hash tables, each of which
// is entirely independent.  We use the [block_index] function to
// deterministically place each key in one of these 16 for all operations.
// When one resizes, then, it temporarily grows the memory by 1/5, then
// settles down to a consistent growth of 1/9, since:
//   - each table is ~1/16 of initial space
//   - during growth, a new table of size 2/16 is created, and
//     (2/16 + 16/16) = 1.125, a 1/8 growth
//   - once the old table is discarded, we're back to (2/16 + 15/16), or
//     a final growth of 1/16.
// We can pretty arbitrarily choose the NUM_BLOCKS, but 8 or 16 seems
// the simplest.  We use 16 since it can be contained in a nibble (4-bit
// int), and that allows us to XOR all the nibbles for our key hash
// together into a nicely mixed block index (see [block_index] impl).
//
// In short, the userdata we store in Lua isn't a fixedmap_t*, it's
// a fixedmap_t*[NUM_BLOCKS], and rather than doing fixedmap_op(h, key),
// we redirect all ops to fixedmap_op(hs[block_index(key)], key).
const int NUM_BLOCKS = 16;  // If you change this, change block_index

static unsigned char block_index(const unsigned char* k, size_t s) {
  size_t fnv = fnv1a(k, s);
  // Mix all nibbles together with XOR.
  return (fnv
          ^ (fnv >> 4)
          ^ (fnv >> 8)
          ^ (fnv >> 12)
          ^ (fnv >> 16)
          ^ (fnv >> 20)
          ^ (fnv >> 24)
          ^ (fnv >> 28)
          ) & 0x0F;
}

/** Lua function to garbage collect our userdata, attached via a "__gc"
 *  reference on our metatable. */
static int fixedmapL_gc(lua_State* L) {
  fixedmap_t** h = (fixedmap_t**) lua_touserdata(L, 1);
  int i;
  for (i = 0; i < NUM_BLOCKS; i++) {
    if (h[i]) fixedmap_free(h[i]);
  }
  return 0;
}

/** Lua function to build a new map, by creating an array of NUM_BLOCKS
 *  fixedmap_t hashmaps with the user-provided key/value sizes.
 *  @param (ksize, vsize) Key and value sizes for map.
 *  @return newly constructed map.
 */
static int fixedmapL_new(lua_State* L) {
  DLOG("Creating lua fixedmap");
  lua_Integer ksize = luaL_checkinteger(L, 1);
  if (ksize < 0 || ksize > 4<<20) {
    return luaL_error(L, "key size out of range: 0 < %d <= %d", ksize, 4<<20);
  }
  lua_Integer vsize = luaL_checkinteger(L, 2);
  if (vsize < 0 || vsize > 4<<20) {
    return luaL_error(L, "value size out of range: 0 < %d <= %d", vsize, 4<<20);
  }
  fixedmap_t** hs = (fixedmap_t**) lua_newuserdata(L, sizeof(fixedmap_t*) * NUM_BLOCKS);
  memset(hs, 0, sizeof(fixedmap_t*) * NUM_BLOCKS);

  // These two calls attach the type 'fixedmap' (created in luaopen_fixedmap)
  // to the userdata object we've just created.  Importantly, from this point
  // on, our [hs] object will now be correctly garbage-collected via a call
  // to fixedmapL_gc, even if something further in this function fails.
  luaL_getmetatable(L, "fixedmap");
  lua_setmetatable(L, -2);

  error_t err = err_SUCCESS;
  int i;
  for (i = 0; i < NUM_BLOCKS; i++) {
    if (err_SUCCESS != (err = fixedmap_new(hs+i, ksize, vsize))) {
      DLOG_ERR(err);
      ERR_FREE(err);
      // blocks will be free'd by Lua, since __gc is already set by setmetatable.
      return luaL_error(L, "setup of block %d failed", i);
    }
  }
  return 1;
}

/** Lua function to _upsert.
 *  @param (key, value) Key and value to upsert
 *  @return "" if key didn't already exist in map, or previous value if it did.
 */
static int fixedmapL_upsert(lua_State* L) {
  fixedmap_t** hs = (fixedmap_t**) lua_touserdata(L, 1);
  size_t ksize;
  size_t vsize;
  const unsigned char* k = (const unsigned char*) luaL_checklstring(L, 2, &ksize);
  const unsigned char* v = (const unsigned char*) luaL_checklstring(L, 3, &vsize);
  fixedmap_t* h = hs[block_index(k, ksize)];
  if (h->ksize != ksize) {
    return luaL_error(L, "key size must be %d, was %d", h->ksize, ksize);
  }
  if (h->vsize != vsize) {
    return luaL_error(L, "value size must be %d, was %d", h->vsize, vsize);
  }

  luaL_Buffer b;
  luaL_buffinit(L, &b);
  unsigned char* old_v = (unsigned char*) luaL_prepbuffsize(&b, h->vsize);
  bool found = false;
  error_t err = fixedmap_upsert(h, k, v, old_v, &found);
  if (err != err_SUCCESS) {
    DLOG_ERR(err);
    ERR_FREE(err);
    return luaL_error(L, "upsert failed");
  }
  if (found) {
    luaL_addsize(&b, h->vsize);
  }
  luaL_pushresult(&b);
  return 1;
}

/** Lua function to _get.
 *  @param (key) Key to look up.
 *  @return "" if key didn't already exist in map, or value if it does.
 */
static int fixedmapL_get(lua_State* L) {
  fixedmap_t** hs = (fixedmap_t**) lua_touserdata(L, 1);
  size_t ksize;
  const unsigned char* k = (const unsigned char*) luaL_checklstring(L, 2, &ksize);
  fixedmap_t* h = hs[block_index(k, ksize)];
  if (h->ksize != ksize) {
    return luaL_error(L, "key size must be %d, was %d", h->ksize, ksize);
  }
  luaL_Buffer b;
  luaL_buffinit(L, &b);
  unsigned char* v = (unsigned char*) luaL_prepbuffsize(&b, h->vsize);
  if (fixedmap_get(h, k, v)) {
    luaL_addsize(&b, h->vsize);
  }
  luaL_pushresult(&b);
  return 1;
}

/** Lua function to _remove.
 *  @param (key) Key to look remove.
 *  @return "" if key didn't already exist in map, or value if there was one we removed.
 */
static int fixedmapL_remove(lua_State* L) {
  fixedmap_t** hs = (fixedmap_t**) lua_touserdata(L, 1);
  size_t ksize;
  const unsigned char* k = (const unsigned char*) luaL_checklstring(L, 2, &ksize);
  fixedmap_t* h = hs[block_index(k, ksize)];
  if (h->ksize != ksize) {
    return luaL_error(L, "key size must be %d, was %d", h->ksize, ksize);
  }
  luaL_Buffer b;
  luaL_buffinit(L, &b);
  unsigned char* v = (unsigned char*) luaL_prepbuffsize(&b, h->vsize);
  if (fixedmap_remove(h, k, v)) {
    luaL_addsize(&b, h->vsize);
  }
  luaL_pushresult(&b);
  return 1;
}

/** Attach the ability to use our fixedmap to Lua.
 *
 * Creates the global function "hsm_enclave_lua_fixedmap" to generate a new map,
 * which has the methods "upsert", "get", and "remove".
 */
int luaopen_fixedmap(lua_State* L) {
  // Create a 'type' via a metatable.
  luaL_newmetatable(L, "fixedmap");

  // Allow for myinstance:method() calls on the metatable via "__index".
  lua_pushliteral(L, "__index");
  lua_pushvalue(L, -2);
  lua_rawset(L, -3);

  // Attach garbage collection logic via "__gc".
  lua_pushstring(L, "__gc");
  lua_pushcfunction(L, fixedmapL_gc);
  lua_settable(L, -3);

  // Attach our three functions.

  lua_pushstring(L, "upsert");
  lua_pushcfunction(L, fixedmapL_upsert);
  lua_settable(L, -3);

  lua_pushstring(L, "get");
  lua_pushcfunction(L, fixedmapL_get);
  lua_settable(L, -3);

  lua_pushstring(L, "remove");
  lua_pushcfunction(L, fixedmapL_remove);
  lua_settable(L, -3);

  // Attach the global function to instantiate these objects.
  lua_pushcfunction(L, fixedmapL_new);
  lua_setglobal(L, "hsm_enclave_lua_fixedmap");

  return 0;
}
