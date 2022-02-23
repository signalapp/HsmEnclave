/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef _HSM_ENCLAVE_FIXEDMAP_H
#define _HSM_ENCLAVE_FIXEDMAP_H

#include "error.h"
#include <stdbool.h>
#include <lua.h>

/** fixedmap_t is a hashmap where keys and values are both fixed-sized byte strings.
 *
 * We implement this as a growing-only RobinHood hash with FNV1a hashing on the bytes.
 * Entries take up 4 + ksize + vsize bytes.  Writes should be relatively fast, but
 * we're mostly optimizing for reads here.  The table resizes up at ~88% utilization.
 *
 * fixedmap_t copies its keys/values into internal storage:
 *
 *   fixedmap_t* m;
 *   uint32_t k = 1;
 *   uint32_t v = 12345;
 *   fixedmap_new(&m, sizeof(k), sizeof(v));
 *   fixedmap_upsert(m, &k, &v, NULL, NULL);
 *
 *   // [k] has been copied in, and can be modified locally
 *
 *   k = 2;
 *   bool found;
 *   fixedmap_get(m, &k, NULL, &found);
 *   assert(!found);
 *   
 *   k = 1;
 *   v = 0;
 *   fixedmap_get(m, &k, &v, &found);
 *   assert(found);
 *   assert(v == 12345);
 */
struct fixedmap_t;
typedef struct fixedmap_t fixedmap_t;

/** Creates a new fixedmap.
 * \memberof fixedmap_t
 *
 * Args:
 *  @param *h Output will be written here on successful allocation/creation.
 *  @param ksize Size of each key
 *  @param vsize Size of each value
 *
 * @return
 *  err_SUCCESS: *h contains a new, usable fixedmap.
 *  err: *h unchanged, nothing allocated, error during creation.
 */
error_t fixedmap_new(fixedmap_t** h, size_t ksize, size_t vsize);

/** Deallocate a fixedmap.
 * \memberof fixedmap_t
 *
 * Args:
 *  @param h Object to free/deallocate.
 */
void fixedmap_free(fixedmap_t* h);

/** Clear all entries from the map.
 * \memberof fixedmap_t */
void fixedmap_clear(fixedmap_t* h);

/** Insert or replace the value at key [k] with the new value at [v].
 * \memberof fixedmap_t
 *
 * Args:
 *  @param h Map to upsert into
 *  @param k Pointer to key (of size ksize)
 *  @param v Pointer to new value to write (of size vsize)
 *  @param old_v If non-null and a value existed within the map at [k],
 *      that value is copied into [old_v]
 *  @param replaced If non-null, set to true or false depending on whether
 *      [k] already had an entry in the map that was replaced with this call
 *
 * @return
 *  err_SUCCESS:  h[k] now equals [v], and if [old_v] and/or [replaced] are
 *      non-NULL, they've been set.
 *  err:  [h], [old_v], and [replaced] unchanged
 */
error_t fixedmap_upsert(fixedmap_t* h, const void* k, const void* v, void* old_v, bool* replaced);

/** Get the value at key [k] within a map.
 * \memberof fixedmap_t
 *
 * Args:
 *  @param h Map to read from
 *  @param k Pointer to key (of size ksize)
 *  @param curr_v If non-null and a value existed within the map at [k],
 *      that value is copied into [curr_v]
 *
 * @return
 *  true: [k] was found in the map.
 *  false: [k] was not found in the map.
 */
bool fixedmap_get(fixedmap_t* h, const void* k, void* curr_v);

/** Remove the value at key [k] from the map.
 * \memberof fixedmap_t
 *
 * Args:
 *  @param h Map to remove from
 *  @param k Pointer to key (of size ksize)
 *  @param old_v If non-null and a value existed within the map at [k],
 *      that value is copied into [old_v]
 *
 * @return
 *  true: [k]'s entry was found and removed.
 *  false: [k] has no entry in the map.
 */
bool fixedmap_remove(fixedmap_t* h, const void* k, void* old_v);

/** Return the size (number of set keys) in the given map [h]
 * \memberof fixedmap_t */
size_t fixedmap_size(fixedmap_t* h);

/** Return the capacity (number of spaces) in the given map [h]
 * \memberof fixedmap_t */
size_t fixedmap_capacity(fixedmap_t* h);

/** Simple iterator for fixedmap.
 *
 * Usage:
 *
 *   fixedmap_iter_t iter;
 *   // Point iterator at beginning of map [m]
 *   fixedmap_iter_reset(&iter, m);
 *   // Iterate over all k/v pairs in [m]:
 *   int k, v;
 *   while (fixedmap_iter_next(&iter, &k, &v)) {
 *     printf("k=%d v=%d\n", k, v);
 *   }
 */
typedef struct {
  fixedmap_t* m;
  size_t i;
} fixedmap_iter_t;

/** Reset iterator [f] to point at the beginning of [m].
 * \memberof fixedmap_iter_t. */
void fixedmap_iter_reset(fixedmap_iter_t* f, fixedmap_t* m);

/** Set k/v to the next entry in the map if there is one.
 * \memberof fixedmap_iter_t.
 *
 * Args:
 *   @param k Key will be written here, NULL to not get keys
 *   @param v Value will be written here, NULL to not get values
 *
 * @return
 *   true: [k] and [v] are set to the next value in the map
 *   false: end of map reached.
 */
bool fixedmap_iter_next(fixedmap_iter_t* f, void* k, void* v);

/** luaopen_fixedmap adds the ability to use the hsm_enclave_lua_fixedmap() function
 *  in Lua to create fixedmaps and use them.
 *
 * Lua's implementation is built on top of fixedmap_t, but not entirely
 * the same.  It's designed for large datasets, using 16 underlying fixedmap_t
 * objects to allow for resizing without doubling total memory usage,
 * and it operates only on fixed-length strings.
 */
int luaopen_fixedmap(lua_State* L);

#endif  // _HSM_ENCLAVE_FIXEDMAP_H
