/* 
 * shajf
 */

#include "ngx_strmatch.h"

#define NUM_CHARS  256

/*
 * String searching functions
 */
static const char *match_no_op(const ngx_strmatch_pattern *this_pattern,
                               const char *s, size_t slen)
{
    return s;
}

static const char *match_boyer_moore_horspool(
                               const ngx_strmatch_pattern *this_pattern,
                               const char *s, size_t slen)
{
    const char *s_end = s + slen;
    size_t *shift = (size_t *)(this_pattern->context);
    const char *s_next = s + this_pattern->length - 1;
    const char *p_start = this_pattern->pattern;
    const char *p_end = p_start + this_pattern->length - 1;
    while (s_next < s_end) {
        const char *s_tmp = s_next;
        const char *p_tmp = p_end;
        while (*s_tmp == *p_tmp) {
            p_tmp--;
            if (p_tmp < p_start) {
                return s_tmp;
            }
            s_tmp--;
        }
        s_next += shift[(int)*((const char *)s_next)];
    }
    return NULL;
}

static const char *match_boyer_moore_horspool_nocase(
                               const ngx_strmatch_pattern *this_pattern,
                               const char *s, size_t slen)
{
    const char *s_end = s + slen;
    size_t *shift = (size_t *)(this_pattern->context);
    const char *s_next = s + this_pattern->length - 1;
    const char *p_start = this_pattern->pattern;
    const char *p_end = p_start + this_pattern->length - 1;
    while (s_next < s_end) {
        const char *s_tmp = s_next;
        const char *p_tmp = p_end;
        while (ngx_tolower(*s_tmp) == ngx_tolower(*p_tmp)) {
            p_tmp--;
            if (p_tmp < p_start) {
                return s_tmp;
            }
            s_tmp--;
        }
        s_next += shift[(unsigned char)ngx_tolower(*s_next)];
    }
    return NULL;
}

const ngx_strmatch_pattern * ngx_strmatch_precompile(
                                              ngx_pool_t *p, const char *s,
                                              int case_sensitive)
{
    ngx_strmatch_pattern *pattern;
    size_t i;
    size_t *shift;

    pattern = (ngx_strmatch_pattern*)ngx_palloc(p, sizeof(*pattern));
    pattern->pattern = s;
    pattern->length = ngx_strlen(s);

    if (pattern->length == 0) {
        pattern->compare = match_no_op;
        pattern->context = NULL;
        return pattern;
    }

    shift = (size_t *)ngx_palloc(p, sizeof(size_t) * NUM_CHARS);
    for (i = 0; i < NUM_CHARS; i++) {
        shift[i] = pattern->length;
    }
    if (case_sensitive) {
        pattern->compare = match_boyer_moore_horspool;
        for (i = 0; i < pattern->length - 1; i++) {
            shift[(unsigned char)s[i]] = pattern->length - i - 1;
        }
    }
    else {
        pattern->compare = match_boyer_moore_horspool_nocase;
        for (i = 0; i < pattern->length - 1; i++) {
            shift[(unsigned char)ngx_tolower(s[i])] = pattern->length - i - 1;
        }
    }
    pattern->context = shift;

    return pattern;
}
