
#ifndef POSIX_MALLOC_THRESHOLD
#define POSIX_MALLOC_THRESHOLD (10)
#endif

#include <ngx_config.h>
#include <ngx_core.h>
/* Table of error strings corresponding to POSIX error codes; must be
 * kept in synch with include/ngx_regex.h's NGX_PCRE_E* definitions.
 */

static const char *const pstring[] = {
    "",                         /* Dummy for value 0 */
    "internal error",           /* NGX_PCRE_ASSERT */
    "failed to get memory",     /* NGX_PCRE_ESPACE */
    "bad argument",             /* NGX_PCRE_INVARG */
    "match failed"              /* NGX_PCRE_NOMATCH */
};

size_t ngx_regerror(int errcode, const ngx_pcre_t *preg,
                                   char *errbuf, size_t errbuf_size)
{
    const char *message, *addmessage;
    size_t length, addlength;

    message = (errcode >= (int)(sizeof(pstring) / sizeof(char *))) ?
              "unknown error code" : pstring[errcode];
    
    length = strlen(message) + 1;

    addmessage = " at offset ";
    addlength = (preg != NULL && (int)preg->re_erroffset != -1) ?
                strlen(addmessage) + 6 : 0;

    if (errbuf_size > 0) {
        if (addlength > 0 && errbuf_size >= length + addlength)
            ngx_snprintf((u_char*)errbuf, errbuf_size, "%s%s%-6d", message, addmessage,
                         (int)preg->re_erroffset);
        else
            ngx_cpystrn((u_char*)errbuf, (u_char*)message, errbuf_size);
    }

    return length + addlength;
}




/*************************************************
 *           Free store held by a regex          *
 *************************************************/

void ngx_regfree(ngx_pcre_t *preg)
{
    (pcre_free)(preg->re_pcre);
}




/*************************************************
 *            Compile a regular expression       *
 *************************************************/

/*
 * Arguments:
 *  preg        points to a structure for recording the compiled expression
 *  pattern     the pattern to compile
 *  cflags      compilation flags
 *
 * Returns:      0 on success
 *               various non-zero codes on failure
*/
int ngx_regcomp(ngx_pcre_t * preg, const char *pattern, int cflags)
{
    const char *errorptr;
    int erroffset;
    int options = 0;

    if ((cflags & NGX_PCRE_ICASE) != 0)
        options |= PCRE_CASELESS;
    if ((cflags & NGX_PCRE_NEWLINE) != 0)
        options |= PCRE_MULTILINE;
    if ((cflags & NGX_PCRE_DOTALL) != 0)
        options |= PCRE_DOTALL;

    preg->re_pcre =
        pcre_compile(pattern, options, &errorptr, &erroffset, NULL);
    preg->re_erroffset = erroffset;

    if (preg->re_pcre == NULL)
        return NGX_PCRE_INVARG;

    pcre_fullinfo((const pcre *)preg->re_pcre, NULL,
                   PCRE_INFO_CAPTURECOUNT, &(preg->re_nsub));
    return 0;
}




/*************************************************
 *              Match a regular expression       *
 *************************************************/

/* Unfortunately, PCRE requires 3 ints of working space for each cngxtured
 * substring, so we have to get and release working store instead of just using
 * the POSIX structures as was done in earlier releases when PCRE needed only 2
 * ints. However, if the number of possible cngxturing brackets is small, use a
 * block of store on the stack, to reduce the use of malloc/free. The threshold
 * is in a macro that can be changed at configure time.
 */
int ngx_regexec(const ngx_pcre_t *preg, const char *string,
                           size_t nmatch, ngx_regmatch_t *pmatch,
                           int eflags)
{
    return ngx_regexec_len(preg, string, strlen(string), nmatch, pmatch,
                          eflags);
}

int ngx_regexec_len(const ngx_pcre_t *preg, const char *buff,
                               size_t len, size_t nmatch,
                               ngx_regmatch_t *pmatch, int eflags)
{
    int rc;
    int options = 0;
    int *ovector = NULL;
    int small_ovector[POSIX_MALLOC_THRESHOLD * 3];
    int allocated_ovector = 0;

    if ((eflags & NGX_PCRE_NOTBOL) != 0)
        options |= PCRE_NOTBOL;
    if ((eflags & NGX_PCRE_NOTEOL) != 0)
        options |= PCRE_NOTEOL;

    ((ngx_pcre_t *)preg)->re_erroffset = (size_t)(-1);    /* Only has meaning after compile */

    if (nmatch > 0) {
        if (nmatch <= POSIX_MALLOC_THRESHOLD) {
            ovector = &(small_ovector[0]);
        }
        else {
            ovector = (int *)malloc(sizeof(int) * nmatch * 3);
            if (ovector == NULL)
                return NGX_PCRE_ESPACE;
            allocated_ovector = 1;
        }
    }

    rc = pcre_exec((const pcre *)preg->re_pcre, NULL, buff, (int)len,
                   0, options, ovector, nmatch * 3);

    if (rc == 0)
        rc = nmatch;            /* All cngxtured slots were filled in */

    if (rc >= 0) {
        size_t i;
        for (i = 0; i < (size_t)rc; i++) {
            pmatch[i].rm_so = ovector[i * 2];
            pmatch[i].rm_eo = ovector[i * 2 + 1];
        }
        if (allocated_ovector)
            free(ovector);
        for (; i < nmatch; i++)
            pmatch[i].rm_so = pmatch[i].rm_eo = -1;
        return 0;
    }

    else {
        if (allocated_ovector)
            free(ovector);
        switch (rc) {
        case PCRE_ERROR_NOMATCH:
            return NGX_PCRE_NOMATCH;
        case PCRE_ERROR_NULL:
            return NGX_PCRE_INVARG;
        case PCRE_ERROR_BADOPTION:
            return NGX_PCRE_INVARG;
        case PCRE_ERROR_BADMAGIC:
            return NGX_PCRE_INVARG;
        case PCRE_ERROR_UNKNOWN_NODE:
            return NGX_PCRE_ASSERT;
        case PCRE_ERROR_NOMEMORY:
            return NGX_PCRE_ESPACE;
#ifdef PCRE_ERROR_MATCHLIMIT
        case PCRE_ERROR_MATCHLIMIT:
            return NGX_PCRE_ESPACE;
#endif
#ifdef PCRE_ERROR_BADUTF8
        case PCRE_ERROR_BADUTF8:
            return NGX_PCRE_INVARG;
#endif
#ifdef PCRE_ERROR_BADUTF8_OFFSET
        case PCRE_ERROR_BADUTF8_OFFSET:
            return NGX_PCRE_INVARG;
#endif
        default:
            return NGX_PCRE_ASSERT;
        }
    }
}

/* End of pcreposix.c */
