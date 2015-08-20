/*
* shajf
*/

#ifndef _MSC_PCRE_H_
#define _MSC_PCRE_H_

typedef struct msc_regex_t msc_regex_t;

#include <ngx_config.h>
#include <ngx_core.h>
#include <pcre.h>

#ifndef PCRE_ERROR_MATCHLIMIT
/* Define for compile, but not valid in this version of PCRE. */
#define PCRE_ERROR_MATCHLIMIT (-8)
#endif /* PCRE_ERROR_MATCHLIMIT */

#ifndef PCRE_ERROR_RECURSIONLIMIT
/* Define for compile, but not valid in this version of PCRE. */
#define PCRE_ERROR_RECURSIONLIMIT (-21)
#endif /* PCRE_ERROR_RECURSIONLIMIT */

#include "modsecurity.h"

struct msc_regex_t {
    void            *re;
    void            *pe;
    const char      *pattern;
};

void  *msc_pregcomp_ex(ngx_pool_t *pool, const char *pattern, int options,
                               const char **_errptr, int *_erroffset,
                               int match_limit, int match_limit_recursion);

void  *msc_pregcomp(ngx_pool_t *pool, const char *pattern, int options,
                            const char **_errptr, int *_erroffset);

int  msc_regexec_ex(msc_regex_t *regex, const char *s,
                            unsigned int slen, int startoffset, int options,
                            int *ovector, int ovecsize, char **error_msg);

int  msc_regexec_capture(msc_regex_t *regex, const char *s,
                                 unsigned int slen, int *ovector,
                                 int ovecsize, char **error_msg);

int  msc_regexec(msc_regex_t *regex, const char *s,
                         unsigned int slen, char **error_msg);

int  msc_fullinfo(msc_regex_t *regex, int what, void *where);

#endif
