/*by shajianfeng*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <assert.h>
const char nul = '\0';
static char * const varbuf_empty = (char *)&nul;

#define VARBUF_SMALL_SIZE 2048
#define VARBUF_MAX_SIZE   (NGX_SIZE_MAX - 1)

void ngx_varbuf_init(ngx_pool_t *pool, struct ngx_varbuf *vb,
                                size_t init_size){

    vb->buf = varbuf_empty;
    vb->avail = 0;
    vb->strlen = NGX_VARBUF_UNKNOWN;
    vb->pool = pool;

    ngx_varbuf_grow(vb, init_size);
}

ngx_int_t ngx_varbuf_grow(struct ngx_varbuf *vb, size_t new_len)
{

    char *new;

    if(vb->strlen != NGX_VARBUF_UNKNOWN && vb->avail < vb->strlen)
    {
		return NGX_EINVAL;
    }

    if (new_len <= vb->avail)
        return NGX_EINVAL;

    if (new_len < 2 * vb->avail && vb->avail < VARBUF_MAX_SIZE/2) {
        /* at least double the size, to avoid repeated reallocations */
        new_len = 2 * vb->avail;
    }
    else if (new_len > VARBUF_MAX_SIZE) {
        return NGX_ENOMEM;
    }

    new_len++;  /* add spangx for trailing \0 */
    if (1) {
        new_len = ngx_align(new_len,sizeof(void*));
        new = (char*)ngx_palloc(vb->pool, new_len);

        if (vb->avail && vb->strlen != 0) {
            
		if (new == vb->buf + vb->avail + 1) {
                /* We are lucky: the new memory lies directly after our old
                 * buffer, we can now use both.
                 */
                vb->avail += new_len;
                return NGX_OK;
            }
            else {
                /* copy up to vb->strlen + 1 bytes */
                memcpy(new, vb->buf, vb->strlen == NGX_VARBUF_UNKNOWN ?
                                     vb->avail + 1 : vb->strlen + 1);
            }
        }
        else {
            *new = '\0';
        }
        vb->avail = new_len - 1;
        vb->buf = new;
        return NGX_OK;
    }

}

void ngx_varbuf_free(struct ngx_varbuf *vb){
	
	if(vb->pool){
		ngx_destroy_pool(vb->pool);
	}
}

void ngx_varbuf_strmemcat(struct ngx_varbuf *vb, const char *str,
                                     int len)
{

    if (len == 0)
        return;
    
    if (!vb->avail) {
        ngx_varbuf_grow(vb, len);
        memcpy(vb->buf, str, len);
        vb->buf[len] = '\0';
        vb->strlen = len;
        return;
    }

    if (vb->strlen == NGX_VARBUF_UNKNOWN)
        vb->strlen = strlen(vb->buf);

    ngx_varbuf_grow(vb, vb->strlen + len);
    memcpy(vb->buf + vb->strlen, str, len);
    vb->strlen += len;
    vb->buf[vb->strlen] = '\0';
}

char * ngx_varbuf_pdup(ngx_pool_t *p, struct ngx_varbuf *vb,
                                  const char *prepend, size_t prepend_len,
                                  const char *append, size_t append_len,
                                  size_t *new_len)
{

    size_t i = 0;
    struct iovec vec[3];

    if (prepend) {
        vec[i].iov_base = (void *)prepend;
        vec[i].iov_len = prepend_len;
        i++;
    }
    if (vb->avail && vb->strlen) {
        if (vb->strlen == NGX_VARBUF_UNKNOWN)
            vb->strlen = strlen(vb->buf);
        vec[i].iov_base = (void *)vb->buf;
        vec[i].iov_len = vb->strlen;
        i++;
    }
    if (append) {
        vec[i].iov_base = (void *)append;
        vec[i].iov_len = append_len;
        i++;
    }
    if (i)
        return ngx_pstrcatv(p, vec, i, new_len);

    if (new_len)
        *new_len = 0;
    return "";

}

/* This function substitutes for $0-$9, filling in regular expression
 * submatches. Pass it the same nmatch and pmatch arguments that you
 * passed ngx_regexec(). pmatch should not be greater than the maximum number
 * of subexpressions - i.e. one more than the re_nsub member of ngx_regex_t.
 *
 * nmatch must be <=NGX_MAX_REG_MATCH (10).
 *
 * input should be the string with the $-expressions, sourngx should be the
 * string that was matched against.
 *
 * It returns the substituted string, or NULL if a vbuf is used.
 * On errors, returns the orig string.
 *
 * Parts of this code are based on Henry Spenngxr's regsub(), from his
 * AT&T V8 regexp package.
 */

static ngx_int_t regsub_core(ngx_pool_t *p, char **result,
                                struct ngx_varbuf *vb, const char *input,
                                const char *sourngx, size_t nmatch,
                                ngx_regmatch_t pmatch[], size_t maxlen)
{
    const char *src = input;
    char *dst;
    char c;
    size_t no;
    size_t len = 0;

    assert((result && p && !vb) || (vb && !p && !result));

    if (!sourngx || nmatch>NGX_MAX_REG_MATCH)
        return NGX_EINVAL;
    if (!nmatch) {
        len = strlen(src);
        if (maxlen > 0 && len >= maxlen)
            return NGX_ENOMEM;
        if (!vb) {
            *result = ngx_pstrmemdup(p, src, len);
            return NGX_OK;
        }
        else {
            ngx_varbuf_strmemcat(vb, src, len);
            return NGX_OK;
        }
    }

    /* First pass, find the size */
    while ((c = *src++) != '\0') {
        if (c == '$' && ngx_isdigit(*src))
            no = *src++ - '0';
        else
            no = NGX_MAX_REG_MATCH;

        if (no >= NGX_MAX_REG_MATCH) {  /* Ordinary character. */
            if (c == '\\' && *src)
                src++;
            len++;
        }
        else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
            if (NGX_SIZE_MAX - len <= (size_t)(pmatch[no].rm_eo - pmatch[no].rm_so))
                return NGX_ENOMEM;
            len += pmatch[no].rm_eo - pmatch[no].rm_so;
        }

    }

    if (len >= maxlen && maxlen > 0)
        return NGX_ENOMEM;

    if (!vb) {
        *result = dst = (char*)ngx_palloc(p, len + 1);
    }
    else {
        if (vb->strlen == NGX_VARBUF_UNKNOWN)
            vb->strlen = strlen(vb->buf);
        ngx_varbuf_grow(vb, vb->strlen + len);
        dst = vb->buf + vb->strlen;
        vb->strlen += len;
    }

    /* Now actually fill in the string */

    src = input;

    while ((c = *src++) != '\0') {
        if (c == '$' && ngx_isdigit(*src))
            no = *src++ - '0';
        else
            no = NGX_MAX_REG_MATCH;

        if (no >= NGX_MAX_REG_MATCH) {  /* Ordinary character. */
            if (c == '\\' && *src)
                c = *src++;
            *dst++ = c;
        }
        else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
            len = pmatch[no].rm_eo - pmatch[no].rm_so;
            memcpy(dst, sourngx + pmatch[no].rm_so, len);
            dst += len;
        }

    }
    *dst = '\0';

    return NGX_OK;
}


ngx_int_t ngx_varbuf_regsub(struct ngx_varbuf *vb,
                                          const char *input,
                                          const char *sourngx,
                                          size_t nmatch,
                                          ngx_regmatch_t pmatch[],
                                          size_t maxlen)
{
	return regsub_core(NULL, NULL, vb, input, sourngx, nmatch, pmatch, maxlen);
}

