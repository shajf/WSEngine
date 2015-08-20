/*shajf*/
#ifndef NGX_HASH2_H
#define NGX_HASH2_H

/**
 * @file ngx_hash.h
 * @brief NGX Hash Tables
 */

#include <ngx_config.h>
#include <ngx_core.h>

/**
 * @defgroup ngx_hash Hash Tables
 * @ingroup NGX 
 * @{
 */

/**
 * When passing a key to ngx_hash_set or ngx_hash2_get, this value can be
 * passed to indicate a string-valued key, and have ngx_hash compute the
 * length automatically.
 *
 * @remark ngx_hash will use strlen(key) for the length. The NUL terminator
 *         is not included in the hash value (why throw a constant in?).
 *         Since the hash table merely references the provided key (rather
 *         than copying it), ngx_hash2_this() will return the NUL-term'd key.
 */
#define NGX_HASH_KEY_STRING     (-1)

/**
 * Abstract type for hash tables.
 */
typedef struct ngx_hash2_t ngx_hash2_t;

/**
 * Abstract type for scanning hash tables.
 */
typedef struct ngx_hash2_index_t ngx_hash2_index_t;

/**
 * Callback functions for calculating hash values.
 * @param key The key.
 * @param klen The length of the key, or NGX_HASH_KEY_STRING to use the string 
 *             length. If NGX_HASH_KEY_STRING then returns the actual key length.
 */
typedef unsigned int (*ngx_hashfunc_t)(const u_char *key, ssize_t *klen);

/**
 * The default hash function.
 */
unsigned int ngx_hashfunc_default(const u_char *key, ssize_t *klen);

/**
 * Create a hash table.
 * @param pool The pool to allocate the hash table out of
 * @return The hash table just created
  */
ngx_hash2_t * ngx_hash2_make(ngx_pool_t *pool);

/**
 * Create a hash table with a custom hash function
 * @param pool The pool to allocate the hash table out of
 * @param hash_func A custom hash function.
 * @return The hash table just created
  */
ngx_hash2_t * ngx_hash2_make_custom(ngx_pool_t *pool, ngx_hashfunc_t hash_func);

/**
 * Make a copy of a hash table
 * @param pool The pool from which to allocate the new hash table
 * @param h The hash table to clone
 * @return The hash table just created
 * @remark Makes a shallow copy
 */
ngx_hash2_t * ngx_hash2_copy(ngx_pool_t *pool,const ngx_hash2_t *h);

/**
 * Associate a value with a key in a hash table.
 * @param ht The hash table
 * @param key Pointer to the key
 * @param klen Length of the key. Can be NGX_HASH_KEY_STRING to use the string length.
 * @param val Value to associate with the key
 * @remark If the value is NULL the hash entry is deleted.
 */
void ngx_hash2_set(ngx_hash2_t *ht, const void *key,ssize_t klen, const void *val);

/**
 * Look up the value associated with a key in a hash table.
 * @param ht The hash table
 * @param key Pointer to the key
 * @param klen Length of the key. Can be NGX_HASH_KEY_STRING to use the string length.
 * @return Returns NULL if the key is not present.
 */
void * ngx_hash2_get(ngx_hash2_t *ht, const void *key,ssize_t klen);

/**
 * Start iterating over the entries in a hash table.
 * @param p The pool to allocate the ngx_hash2_index_t iterator. If this
 *          pool is NULL, then an internal, non-thread-safe iterator is used.
 * @param ht The hash table
 * @return The iteration state
 * @remark  There is no restriction on adding or deleting hash entries during
 * an iteration (although the results may be unpredictable unless all you do
 * is delete the current entry) and multiple iterations can be in
 * progress at the same time.
 *
 * @par Example:
 *
 * @code
 * int sum_values(ngx_pool_t *p, ngx_hash2_t *ht)
 * {
 *     ngx_hash2_index_t *hi;
 *     void *val;
 *     int sum = 0;
 *     for (hi = ngx_hash_first(p, ht); hi; hi = ngx_hash_next(hi)) {
 *         ngx_hash2_this(hi, NULL, NULL, &val);
 *         sum += *(int *)val;
 *     }
 *     return sum;
 * }
 * @endcode
 */
ngx_hash2_index_t * ngx_hash2_first(ngx_pool_t *p, ngx_hash2_t *ht);

/**
 * Continue iterating over the entries in a hash table.
 * @param hi The iteration state
 * @return a pointer to the updated iteration state.  NULL if there are no more  
 *         entries.
 */
ngx_hash2_index_t * ngx_hash2_next(ngx_hash2_index_t *hi);

/**
 * Get the current entry's details from the iteration state.
 * @param hi The iteration state
 * @param key Return pointer for the pointer to the key.
 * @param klen Return pointer for the key length.
 * @param val Return pointer for the associated value.
 * @remark The return pointers should point to a variable that will be set to the
 *         corresponding data, or they may be NULL if the data isn't interesting.
 */
void ngx_hash2_this(ngx_hash2_index_t *hi, const void **key, ssize_t *klen, void **val);

/**
 * Get the number of key/value pairs in the hash table.
 * @param ht The hash table
 * @return The number of key/value pairs in the hash table.
 */
unsigned int ngx_hash2_count(ngx_hash2_t *ht);

/**
 * Clear any key/value pairs in the hash table.
 * @param ht The hash table
 */
void ngx_hash2_clear(ngx_hash2_t *ht);

/**
 * Merge two hash tables into one new hash table. The values of the overlay
 * hash override the values of the base if both have the same key.  Both
 * hash tables must use the same hash function.
 * @param p The pool to use for the new hash table
 * @param overlay The table to add to the initial table
 * @param base The table that represents the initial values of the new table
 * @return A new hash table containing all of the data from the two passed in
 */
ngx_hash2_t * ngx_hash2_overlay(ngx_pool_t *p,const ngx_hash2_t *overlay, const ngx_hash2_t *base);

/**
 * Merge two hash tables into one new hash table. If the same key
 * is present in both tables, call the supplied merge function to
 * produce a merged value for the key in the new table.  Both
 * hash tables must use the same hash function.
 * @param p The pool to use for the new hash table
 * @param h1 The first of the tables to merge
 * @param h2 The second of the tables to merge
 * @param merger A callback function to merge values, or NULL to
 *  make values from h1 override values from h2 (same semantics as
 *  ngx_hash_overlay())
 * @param data Client data to pass to the merger function
 * @return A new hash table containing all of the data from the two passed in
 */
ngx_hash2_t * ngx_hash2_merge(ngx_pool_t *p,
                                         const ngx_hash2_t *h1,
                                         const ngx_hash2_t *h2,
                                         void * (*merger)(ngx_pool_t *p,
                                                     const void *key,
                                                     ssize_t klen,
                                                     const void *h1_val,
                                                     const void *h2_val,
                                                     const void *data),
                                         const void *data);

/**
 * Declaration prototype for the iterator callback function of ngx_hash_do().
 *
 * @param rec The data passed as the first argument to ngx_hash_[v]do()
 * @param key The key from this iteration of the hash table
 * @param klen The key length from this iteration of the hash table
 * @param value The value from this iteration of the hash table
 * @remark Iteration continues while this callback function returns non-zero.
 * To export the callback function for ngx_hash_do() it must be declared 
 * in the _NONSTD convention.
 */
typedef int (ngx_hash_do_callback_fn_t)(void *rec, const void *key,
                                                   ssize_t klen,
                                                   const void *value);

/** 
 * Iterate over a hash table running the provided function once for every
 * element in the hash table. The @param comp function will be invoked for
 * every element in the hash table.
 *
 * @param comp The function to run
 * @param rec The data to pass as the first argument to the function
 * @param ht The hash table to iterate over
 * @return FALSE if one of the comp() iterations returned zero; TRUE if all
 *            iterations returned non-zero
 * @see ngx_hash_do_callback_fn_t
 */
int ngx_hash2_do(ngx_hash_do_callback_fn_t *comp,
                             void *rec, const ngx_hash2_t *ht);

#endif	/* !NGX_HASH_H */
