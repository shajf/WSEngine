
/**
 * shajf
 */

#ifndef NGX_PCRE_H
#define NGX_PCRE_H

#define NGX_MAX_REG_MATCH 10
/* Options for ngx_regcomp, ngx_regexec, and ngx_rxplus versions: */

#define NGX_PCRE_ICASE    0x01 /** use a case-insensitive match */
#define NGX_PCRE_NEWLINE  0x02 /** don't match newlines against '.' etc */
#define NGX_PCRE_NOTBOL   0x04 /** ^ will not match against start-of-string */
#define NGX_PCRE_NOTEOL   0x08 /** $ will not match against end-of-string */

#define NGX_PCRE_EXTENDED (0)  /** unused */
#define NGX_PCRE_NOSUB    (0)  /** unused */

#define NGX_PCRE_MULTI 0x10    /* perl's /g (needs fixing) */
#define NGX_PCRE_NOMEM 0x20    /* nomem in our code */
#define NGX_PCRE_DOTALL 0x40   /* perl's /s flag */

/* Error values: */
enum {
  NGX_PCRE_ASSERT = 1,  /** internal error ? */
  NGX_PCRE_ESPACE,      /** failed to get memory */
  NGX_PCRE_INVARG,      /** invalid argument */
  NGX_PCRE_NOMATCH      /** match failed */
};

/* The structure representing a compiled regular expression. */
typedef struct {
    void *re_pcre;
    int re_nsub;
    size_t re_erroffset;
} ngx_pcre_t;

/* The structure in which a cngxtured offset is returned. */
typedef struct {
    int rm_so;
    int rm_eo;
} ngx_regmatch_t;

/* The functions */

/**
 * Compile a regular expression.
 * @param preg Returned compiled regex
 * @param regex The regular expression string
 * @param cflags Bitwise OR of NGX_PCRE_* flags (ICASE and NEWLINE supported,
 *                                             other flags are ignored)
 * @return Zero on success or non-zero on error
 */
int ngx_regcomp(ngx_pcre_t *preg, const char *regex, int cflags);

/**
 * Match a NUL-terminated string against a pre-compiled regex.
 * @param preg The pre-compiled regex
 * @param string The string to match
 * @param nmatch Provide information regarding the location of any matches
 * @param pmatch Provide information regarding the location of any matches
 * @param eflags Bitwise OR of NGX_PCRE_* flags (NOTBOL and NOTEOL supported,
 *                                             other flags are ignored)
 * @return 0 for successful match, \p NGX_PCRE_NOMATCH otherwise
 */
int ngx_regexec(const ngx_pcre_t *preg, const char *string,
                           size_t nmatch, ngx_regmatch_t *pmatch, int eflags);

/**
 * Match a string with given length against a pre-compiled regex. The string
 * does not need to be NUL-terminated.
 * @param preg The pre-compiled regex
 * @param buff The string to match
 * @param len Length of the string to match
 * @param nmatch Provide information regarding the location of any matches
 * @param pmatch Provide information regarding the location of any matches
 * @param eflags Bitwise OR of NGX_PCRE_* flags (NOTBOL and NOTEOL supported,
 *                                             other flags are ignored)
 * @return 0 for successful match, NGX_PCRE_NOMATCH otherwise
 */
int ngx_regexec_len(const ngx_pcre_t *preg, const char *buff,
                               size_t len, size_t nmatch,
                               ngx_regmatch_t *pmatch, int eflags);

/**
 * Return the error code returned by regcomp or regexec into error messages
 * @param errcode the error code returned by regexec or regcomp
 * @param preg The precompiled regex
 * @param errbuf A buffer to store the error in
 * @param errbuf_size The size of the buffer
 */
size_t ngx_regerror(int errcode, const ngx_pcre_t *preg,
                                   char *errbuf, size_t errbuf_size);

/** Destroy a pre-compiled regex.
 * @param preg The pre-compiled regex to free.
 */
void ngx_regfree(ngx_pcre_t *preg);

#endif /* NGX_PCREEX_T */

