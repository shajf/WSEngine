/* shajf */

#ifndef NGX_STRMATCH_H
#define NGX_STRMATCH_H

#include <ngx_config.h>
#include <ngx_core.h>

/**
 * @file ngx_strmatch.h
 * @brief NGX-UTIL string matching routines
 */

/**
 * @defgroup NGX_Util_StrMatch String matching routines
 * @ingroup NGX_Util
 * @{
 */

/** @see ngx_strmatch_pattern */
typedef struct ngx_strmatch_pattern ngx_strmatch_pattern;

/**
 * Precompiled search pattern
 */
struct ngx_strmatch_pattern {
    /** Function called to compare */
    const char *(*compare)(const ngx_strmatch_pattern *this_pattern,
                           const char *s, size_t slen);
    const char *pattern;    /**< Current pattern */
    size_t length;      /**< Current length */
    void *context;          /**< hook to add precomputed metadata */
};

#if defined(DOXYGEN)
/**
 * Search for a precompiled pattern within a string
 * @param pattern The pattern
 * @param s The string in which to search for the pattern
 * @param slen The length of s (excluding null terminator)
 * @return A pointer to the first instance of the pattern in s, or
 *         NULL if not found
 */
const char * ngx_strmatch(const ngx_strmatch_pattern *pattern,
                                       const char *s, size_t slen);
#else
#define ngx_strmatch(pattern, s, slen) (*((pattern)->compare))((pattern), (s), (slen))
#endif

/**
 * Precompile a pattern for matching using the Boyer-Moore-Horspool algorithm
 * @param p The pool from which to allocate the pattern
 * @param s The pattern string
 * @param case_sensitive Whether the matching should be case-sensitive
 * @return a pointer to the compiled pattern, or NULL if compilation fails
 */
const ngx_strmatch_pattern * ngx_strmatch_precompile(ngx_pool_t *p, const char *s, int case_sensitive);

#endif	/* !NGX_STRMATCH_H */
