/*
* shajf
*/

#include "msc_pcre.h"

void *(*old_pcre_malloc)(size_t);
void  (*old_pcre_free)(void *);

static ngx_pool_t *msc_pcre_pool = NULL;

static void *msc_pcre_malloc(size_t size){
    
    return ngx_palloc(msc_pcre_pool,size); 
}

static void msc_pcre_free(void *data){
    
    data = data;

}

static inline void msc_pcre_start(ngx_pool_t *p){
    
    old_pcre_malloc = pcre_malloc;
    old_pcre_free = pcre_free;
    pcre_malloc = msc_pcre_malloc;
    pcre_free = msc_pcre_free;
    msc_pcre_pool = p;
}

static inline void msc_pcre_end(){
    
    pcre_malloc = old_pcre_malloc;
    pcre_free = old_pcre_free;
    msc_pcre_pool = NULL;
}


/**
 * Compiles the provided regular expression pattern. The _err*
 * parameters are optional, but if they are provided and an error
 * occurs they will contain the error message and the offset in
 * the pattern where the offending part of the pattern begins. The
 * match_limit* parameters are optional and if >0, then will set
 * match limits.
 */
void *msc_pregcomp_ex(ngx_pool_t *pool, const char *pattern, int options,
                      const char **_errptr, int *_erroffset,
                      int match_limit, int match_limit_recursion)
{
    const char *errptr = NULL;
    int erroffset;
    msc_regex_t *regex;
    pcre_extra *pe = NULL;

    regex = (msc_regex_t*)ngx_pcalloc(pool, sizeof(msc_regex_t));
    if (regex == NULL) return NULL;
    regex->pattern = pattern;
    
    msc_pcre_start(pool);

    if ((_errptr == NULL)||(_erroffset == NULL)) {
        regex->re = pcre_compile(pattern, options, &errptr, &erroffset, NULL);
    } else {
        regex->re = pcre_compile(pattern, options, _errptr, _erroffset, NULL);
    }
    
    if (regex->re == NULL) {
        msc_pcre_end();
        return NULL;
    }

    #ifdef WITH_PCRE_STUDY
        #ifdef WITH_PCRE_JIT
                pe = pcre_study(regex->re, PCRE_STUDY_JIT_COMPILE, &errptr);
        #else
                pe = pcre_study(regex->re, 0, &errptr);
        #endif
    #endif

    /* Setup the pcre_extra record if pcre_study did not already do it */
    if (pe == NULL) {
        pe = pcre_malloc(sizeof(pcre_extra));
        if (pe == NULL) {
            msc_pcre_end();
            return NULL;
        }
        memset(pe, 0, sizeof(pcre_extra));
    }

#ifdef PCRE_EXTRA_MATCH_LIMIT
    /* If match limit is available, then use it */

    /* Use ModSecurity runtime defaults */
    if (match_limit > 0) {
        pe->match_limit = match_limit;
        pe->flags |= PCRE_EXTRA_MATCH_LIMIT;
    }
#ifdef MODSEC_PCRE_MATCH_LIMIT
    /* Default to ModSecurity compiled defaults */
    else {
        pe->match_limit = MODSEC_PCRE_MATCH_LIMIT;
        pe->flags |= PCRE_EXTRA_MATCH_LIMIT;
    }
#endif /* MODSEC_PCRE_MATCH_LIMIT */
#else
#pragma message ( "This PCRE version does not support match limits!  Upgrade to at least PCRE v6.5." )
#endif /* PCRE_EXTRA_MATCH_LIMIT */

#ifdef PCRE_EXTRA_MATCH_LIMIT_RECURSION
    /* If match limit recursion is available, then use it */

    /* Use ModSecurity runtime defaults */
    if (match_limit_recursion > 0) {
        pe->match_limit_recursion = match_limit_recursion;
        pe->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
    }
#ifdef MODSEC_PCRE_MATCH_LIMIT_RECURSION
    /* Default to ModSecurity compiled defaults */
    else {
        pe->match_limit_recursion = MODSEC_PCRE_MATCH_LIMIT_RECURSION;
        pe->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
    }
#endif /* MODSEC_PCRE_MATCH_LIMIT_RECURSION */
#else
#pragma message ( "This PCRE version does not support match recursion limits!  Upgrade to at least PCRE v6.5." )
#endif /* PCRE_EXTRA_MATCH_LIMIT_RECURSION */
    

    regex->pe = pe;
    msc_pcre_end();
	
    return regex;
}

/**
 * Compiles the provided regular expression pattern.  Calls msc_pregcomp_ex()
 * with default limits.
 */
void *msc_pregcomp(ngx_pool_t *pool, const char *pattern, int options,
                   const char **_errptr, int *_erroffset)
{
    return msc_pregcomp_ex(pool, pattern, options, _errptr, _erroffset, 0, 0);
}

/**
 * Executes regular expression with extended options.
 * Returns PCRE_ERROR_NOMATCH when there is no match, error code < -1
 * on errors, and a value > 0 when there is a match.
 */
int msc_regexec_ex(msc_regex_t *regex, const char *s, unsigned int slen,
    int startoffset, int options, int *ovector, int ovecsize, char **error_msg)
{
    if (error_msg == NULL) return -1000; /* To differentiate from PCRE as it already uses -1. */
    *error_msg = NULL;

    return pcre_exec(regex->re, regex->pe, s, slen, startoffset, options, ovector, ovecsize);
}

/**
 * Executes regular expression, capturing subexpressions in the given
 * vector. Returns PCRE_ERROR_NOMATCH when there is no match, error code < -1
 * on errors, and a value > 0 when there is a match.
 */
int msc_regexec_capture(msc_regex_t *regex, const char *s, unsigned int slen,
    int *ovector, int ovecsize, char **error_msg)
{
    if (error_msg == NULL) return -1000; /* To differentiate from PCRE as it already uses -1. */
    *error_msg = NULL;

    return msc_regexec_ex(regex, s, slen, 0, 0, ovector, ovecsize, error_msg);
}

/**
 * Executes regular expression but ignores any of the subexpression
 * captures. See above for the return codes.
 */
int msc_regexec(msc_regex_t *regex, const char *s, unsigned int slen,
    char **error_msg)
{
    if (error_msg == NULL) return -1000; /* To differentiate from PCRE as it already uses -1. */
    *error_msg = NULL;

    return msc_regexec_ex(regex, s, slen, 0, 0, NULL, 0, error_msg);
}

/**
 * Gets info on a compiled regex.
 */
int msc_fullinfo(msc_regex_t *regex, int what, void *where)
{
    return pcre_fullinfo(regex->re, regex->pe, what, where);
}

