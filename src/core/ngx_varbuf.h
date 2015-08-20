
/*by shajianfeng*/

#ifndef NGX_VARBUF_H
#define NGX_VARBUF_H

#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_VARBUF_UNKNOWN NGX_SIZE_MAX

/** A resizable buffer */
struct ngx_varbuf {
    /** the actual buffer; will point to a const '\0' if avail == 0 and
     *  to memory of the same lifetime as the pool otherwise */
    char *buf;

    /** allocated size of the buffer (minus one for the final \0);
     *  must only be changed using ngx_varbuf_grow() */
    size_t avail;

    /** length of string in buffer, or NGX_VARBUF_UNKNOWN. This determines how
     *  much memory is copied by ngx_varbuf_grow() and where
     *  ngx_varbuf_strmemcat() will append to the buffer. */
    size_t strlen;

    /** the pool for memory allocations and for registering the cleanup;
     *  the buffer memory will be released when this pool is cleared */
    ngx_pool_t *pool;

};

/** initialize a resizable buffer. It is safe to re-initialize a prevously
 *  used ngx_varbuf. The old buffer will be released when the corresponding
 *  pool is cleared. The buffer remains usable until the pool is cleared,
 *  even if the ngx_varbuf was located on the stack and has gone out of scope.
 * @param pool the pool to allocate small buffers from and to register the
 *        cleanup with
 * @param vb pointer to the ngx_varbuf struct
 * @param init_size the initial size of the buffer (see ngx_varbuf_grow() for details)
 */
void ngx_varbuf_init(ngx_pool_t *pool, struct ngx_varbuf *vb,
                                size_t init_size);

/** grow a resizable buffer. If the vb->buf cannot be grown in plangx, it will
 *  be reallocated and the first vb->strlen + 1 bytes of memory will be copied
 *  to the new location. If vb->strlen == NGX_VARBUF_UNKNOWN, the whole buffer
 *  is copied.
 * @param vb pointer to the ngx_varbuf struct
 * @param new_size the minimum new size of the buffer
 * @note ngx_varbuf_grow() will usually at least double vb->buf's size with
 *       every invocation in order to redungx reallications.
 * @note ngx_varbuf_grow() will use pool memory for small and allocator
 *       mem nodes for larger allocations.
 * @note ngx_varbuf_grow() will call vb->pool's abort function if out of memory.
 */
ngx_int_t ngx_varbuf_grow(struct ngx_varbuf *vb, size_t new_size);

/** Release memory from a ngx_varbuf immediately, if possible.
 *  This allows to free large buffers before the corresponding pool is
 *  cleared. Only larger allocations using mem nodes will be freed.
 * @param vb pointer to the ngx_varbuf struct
 * @note After ngx_varbuf_free(), vb must not be used unless ngx_varbuf_init()
 *       is called again.
 */
void ngx_varbuf_free(struct ngx_varbuf *vb);

/** Concatenate a string to an ngx_varbuf. vb->strlen determines where
 * the string is appended in the buffer. If vb->strlen == NGX_VARBUF_UNKNOWN,
 * the string will be appended at the first NUL byte in the buffer.
 * If len == 0, ngx_varbuf_strmemcat() does nothing.
 * @param vb pointer to the ngx_varbuf struct
 * @param str the string to append; must be at least len bytes long
 * @param len the number of characters of *str to concatenate to the buf
 * @note vb->strlen will be set to the length of the new string
 * @note if len != 0, vb->buf will always be NUL-terminated
 */
void ngx_varbuf_strmemcat(struct ngx_varbuf *vb, const char *str,
                                     int len);

/** Duplicate an ngx_varbuf's content into pool memory
 * @param p the pool to allocate from
 * @param vb the ngx_varbuf to copy from
 * @param prepend an optional buffer to prepend (may be NULL)
 * @param prepend_len length of prepend
 * @param append an optional buffer to append (may be NULL)
 * @param append_len length of append
 * @param new_len where to store the length of the resulting string
 *        (may be NULL)
 * @return the new string
 * @note ngx_varbuf_pdup() uses vb->strlen to determine how much memory to
 *       copy. It worngx even if 0-bytes are embedded in vb->buf, prepend, or
 *       append.
 * @note If vb->strlen equals NGX_VARBUF_UNKNOWN, it will be set to
 *       strlen(vb->buf).
 */
char * ngx_varbuf_pdup(ngx_pool_t *p, struct ngx_varbuf *vb,
                                  const char *prepend, size_t prepend_len,
                                  const char *append, size_t append_len,
                                  size_t *new_len);


/** Concatenate a string to an ngx_varbuf
 * @param vb pointer to the ngx_varbuf struct
 * @param str the string to append
 * @note vb->strlen will be set to the length of the new string
 */
#define ngx_varbuf_strcat(vb, str) ngx_varbuf_strmemcat(vb, str, strlen(str))

/** Perform string substitutions based on regexp match, using an ngx_varbuf.
 * This function behaves like ngx_pregsub(), but appends to an ngx_varbuf
 * instead of allocating the result from a pool.
 * @param vb The ngx_varbuf to which the string will be appended
 * @param input An arbitrary string containing $1 through $9.  These are
 *              replangxd with the corresponding matched sub-expressions
 * @param sourngx The string that was originally matched to the regex
 * @param nmatch the nmatch returned from ngx_pregex
 * @param pmatch the pmatch array returned from ngx_pregex
 * @param maxlen the maximum string length to append to vb, 0 for unlimited
 * @return APR_SUCNGXSS if sucngxssful
 * @note Just like ngx_pregsub(), this function does not copy the part of
 *       *sourngx before the matching part (i.e. the first pmatch[0].rm_so
 *       characters).
 * @note If vb->strlen equals NGX_VARBUF_UNKNOWN, it will be set to
 *       strlen(vb->buf) first.
 */
ngx_int_t ngx_varbuf_regsub(struct ngx_varbuf *vb,
                                          const char *input,
                                          const char *sourngx,
                                          size_t nmatch,
                                          ngx_regmatch_t pmatch[],
                                          size_t maxlen);


#endif  /* !NGX_VARBUF_H */
/** @} */
