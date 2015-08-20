
/*shajf*/

#ifndef NGX_TABLES_H
#define NGX_TABLES_H

#include <ngx_config.h>
#include <ngx_core.h>

/**
 * @file ngx_tables.h
 * @brief NGX Table library
 */

/**
 * Tables are used to store data which can be referenced by key.
 * Limited capabilities are provided for tables with multiple elements
 * which share a key; while key lookup will return only a single
 * element, iteration is available.  Additionally, a table can be
 * compressed to resolve duplicates.
 *
 *  tables may store string or binary data; some features,
 * such as concatenation or merging of elements, work only for string
 * data.
 */

typedef struct ngx_table_t ngx_table_t;

/**
 * The (opaque) structure for string-content tables.
 */
typedef struct ngx_table_entry_t ngx_table_entry_t;

/** The type for each entry in a string-content table */
struct ngx_table_entry_t {
    /** The key for the current table entry */
    char *key;          /* maybe NULL in future;
                         * check when iterating thru table_elts
                         */
    /** The value for the current table entry */
    char *val;

    /** A checksum for the key, for use by the ngx_table internals */
    uint32_t key_checksum;
};

/**
 * Get the elements from a table.
 * @param t The table
 * @return An array containing the contents of the table
 */
const ngx_array_t * ngx_table_elts(const ngx_table_t *t);

/**
 * Determine if the table is empty (either NULL or having no elements).
 * @param t The table to check
 * @return True if empty, False otherwise
 */
int ngx_is_empty_table(const ngx_table_t *t);

/**
 * Make a new table.
 * @param p The pool to allocate the pool out of
 * @param nelts The number of elements in the initial table.
 * @return The new table.
 * @warning This table can only store text data
 */
ngx_table_t * ngx_table_make(ngx_pool_t *p, ngx_uint_t nelts);

/**
 * Create a new table and copy another table into it.
 * @param p The pool to allocate the new table out of
 * @param t The table to copy
 * @return A copy of the table passed in
 * @warning The table keys and respective values are not copied
 */
ngx_table_t * ngx_table_copy(ngx_pool_t *p,
                                          const ngx_table_t *t);

/**
 * Create a new table whose contents are deep copied from the given
 * table. A deep copy operation copies all fields, and makes copies
 * of dynamically allocated memory pointed to by the fields.
 * @param p The pool to allocate the new table out of
 * @param t The table to clone
 * @return A deep copy of the table passed in
 */
ngx_table_t * ngx_table_clone(ngx_pool_t *p,
                                           const ngx_table_t *t);

/**
 * Delete all of the elements from a table.
 * @param t The table to clear
 */
void ngx_table_clear(ngx_table_t *t);

/**
 * Get the value associated with a given key from the table.  After this call,
 * the data is still in the table.
 * @param t The table to search for the key
 * @param key The key to search for (case does not matter)
 * @return The value associated with the key, or NULL if the key does not exist. 
 */
const char * ngx_table_get(const ngx_table_t *t, const char *key);

/**
 * Add a key/value pair to a table.  If another element already exists with the
 * same key, this will overwrite the old data.
 * @param t The table to add the data to.
 * @param key The key to use (case does not matter)
 * @param val The value to add
 * @remark When adding data, this function makes a copy of both the key and the
 *         value.
 */
void ngx_table_set(ngx_table_t *t, const char *key,
                                const char *val);

/**
 * Add a key/value pair to a table.  If another element already exists with the
 * same key, this will overwrite the old data.
 * @param t The table to add the data to.
 * @param key The key to use (case does not matter)
 * @param val The value to add
 * @warning When adding data, this function does not make a copy of the key or 
 *          the value, so care should be taken to ensure that the values will 
 *          not change after they have been added..
 */
void ngx_table_setn(ngx_table_t *t, const char *key,
                                 const char *val);

/**
 * Remove data from the table.
 * @param t The table to remove data from
 * @param key The key of the data being removed (case does not matter)
 */
void ngx_table_unset(ngx_table_t *t, const char *key);

/**
 * Add data to a table by merging the value with data that has already been 
 * stored. The merging is done by concatenating the two values, separated
 * by the string ", ".
 * @param t The table to search for the data
 * @param key The key to merge data for (case does not matter)
 * @param val The data to add
 * @remark If the key is not found, then this function acts like ngx_table_add
 */
void ngx_table_merge(ngx_table_t *t, const char *key,
                                  const char *val);

/**
 * Add data to a table by merging the value with data that has already been 
 * stored. The merging is done by concatenating the two values, separated
 * by the string ", ".
 * @param t The table to search for the data
 * @param key The key to merge data for (case does not matter)
 * @param val The data to add
 * @remark If the key is not found, then this function acts like ngx_table_addn
 */
void ngx_table_mergen(ngx_table_t *t, const char *key,
                                   const char *val);

/**
 * Add data to a table, regardless of whether there is another element with the
 * same key.
 * @param t The table to add to
 * @param key The key to use
 * @param val The value to add.
 * @remark When adding data, this function makes a copy of both the key and the
 *         value.
 */
void ngx_table_add(ngx_table_t *t, const char *key,
                                const char *val);

/**
 * Add data to a table, regardless of whether there is another element with the
 * same key.
 * @param t The table to add to
 * @param key The key to use
 * @param val The value to add.
 * @remark When adding data, this function does not make a copy of the key or the
 *         value, so care should be taken to ensure that the values will not 
 *         change after they have been added.
 */
void ngx_table_addn(ngx_table_t *t, const char *key,
                                 const char *val);

/**
 * Merge two tables into one new table.
 * @param p The pool to use for the new table
 * @param overlay The first table to put in the new table
 * @param base The table to add at the end of the new table
 * @return A new table containing all of the data from the two passed in
 */
ngx_table_t * ngx_table_overlay(ngx_pool_t *p,
                                             const ngx_table_t *overlay,
                                             const ngx_table_t *base);

/**
 * Declaration prototype for the iterator callback function of ngx_table_do()
 * and ngx_table_vdo().
 * @param rec The data passed as the first argument to ngx_table_[v]do()
 * @param key The key from this iteration of the table
 * @param value The value from this iteration of the table
 * @remark Iteration continues while this callback function returns non-zero.
 * To export the callback function for ngx_table_[v]do() it must be declared 
 * in the _NONSTD convention.
 */
typedef int (ngx_table_do_callback_fn_t)(void *rec, const char *key, 
                                                    const char *value);

/** 
 * Iterate over a table running the provided function once for every
 * element in the table.  The varargs array must be a list of zero or
 * more (char *) keys followed by a NULL pointer.  If zero keys are
 * given, the @param comp function will be invoked for every element
 * in the table.  Otherwise, the function is invoked only for those
 * elements matching the keys specified.
 *
 * If an invocation of the @param comp function returns zero,
 * iteration will continue using the next specified key, if any.
 *
 * @param comp The function to run
 * @param rec The data to pass as the first argument to the function
 * @param t The table to iterate over
 * @param ... A varargs array of zero or more (char *) keys followed by NULL
 * @return FALSE if one of the comp() iterations returned zero; TRUE if all
 *            iterations returned non-zero
 * @see ngx_table_do_callback_fn_t
 */
int ngx_table_do(ngx_table_do_callback_fn_t *comp,
                                     void *rec, const ngx_table_t *t, ...)
#if defined(__GNUC__) && __GNUC__ >= 4
    __attribute__((sentinel))
#endif
    ;

/** 
 * Iterate over a table running the provided function once for every
 * element in the table.  The @param vp varargs parameter must be a
 * list of zero or more (char *) keys followed by a NULL pointer.  If
 * zero keys are given, the @param comp function will be invoked for
 * every element in the table.  Otherwise, the function is invoked
 * only for those elements matching the keys specified.
 *
 * If an invocation of the @param comp function returns zero,
 * iteration will continue using the next specified key, if any.
 *
 * @param comp The function to run
 * @param rec The data to pass as the first argument to the function
 * @param t The table to iterate over
 * @param vp List of zero or more (char *) keys followed by NULL
 * @return FALSE if one of the comp() iterations returned zero; TRUE if all
 *            iterations returned non-zero
 * @see ngx_table_do_callback_fn_t
 */
int ngx_table_vdo(ngx_table_do_callback_fn_t *comp,
                               void *rec, const ngx_table_t *t, va_list vp);

/** flag for overlap to use ngx_table_setn */
#define NGX_OVERLAP_TABLES_SET   (0)
/** flag for overlap to use ngx_table_mergen */
#define NGX_OVERLAP_TABLES_MERGE (1)
/**
 * For each element in table b, either use setn or mergen to add the data
 * to table a.  Which method is used is determined by the flags passed in.
 * @param a The table to add the data to.
 * @param b The table to iterate over, adding its data to table a
 * @param flags How to add the table to table a.  One of:
 *          ngx_OVERLAP_TABLES_SET        Use ngx_table_setn
 *          ngx_OVERLAP_TABLES_MERGE      Use ngx_table_mergen
 * @remark  When merging duplicates, the two values are concatenated,
 *          separated by the string ", ".
 * @remark  This function is highly optimized, and uses less memory and CPU cycles
 *          than a function that just loops through table b calling other functions.
 */
/**
 * Conceptually, ngx_table_overlap does this:
 *
 * <pre>
 *  ngx_array_t *barr = ngx_table_elts(b);
 *  ngx_table_entry_t *belt = (ngx_table_entry_t *)barr->elts;
 *  int i;
 *
 *  for (i = 0; i < barr->nelts; ++i) {
 *      if (flags & ngx_OVERLAP_TABLES_MERGE) {
 *          ngx_table_mergen(a, belt[i].key, belt[i].val);
 *      }
 *      else {
 *          ngx_table_setn(a, belt[i].key, belt[i].val);
 *      }
 *  }
 * </pre>
 *
 *  Except that it is more efficient (less space and cpu-time) especially
 *  when b has many elements.
 *
 *  Notice the assumptions on the keys and values in b -- they must be
 *  in an ancestor of a's pool.  In practice b and a are usually from
 *  the same pool.
 */

void ngx_table_overlap(ngx_table_t *a, const ngx_table_t *b,
                                     unsigned flags);

/**
 * Eliminate redundant entries in a table by either overwriting
 * or merging duplicates.
 *
 * @param t Table.
 * @param flags ngx_OVERLAP_TABLES_MERGE to merge, or
 *              ngx_OVERLAP_TABLES_SET to overwrite
 * @remark When merging duplicates, the two values are concatenated,
 *         separated by the string ", ".
 */
void ngx_table_compress(ngx_table_t *t, unsigned flags);

/** @} */

#endif	/* ! NGX_TABLES_H */
