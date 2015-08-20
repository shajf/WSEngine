/*
* by shajianfeng
*/

#include <ngx_config.h>
#include <ngx_core.h>

int ngx_cfg_closefile(ngx_configfile_t *cfp){

    return (cfp->close == NULL) ? 0 : cfp->close(cfp->param);
}

static ngx_int_t cfg_close(void *param)
{
    ngx_file_t *file = (ngx_file_t*)param;

    return ngx_close_file(file->fd);
}

static ngx_int_t cfg_getch(char *ch, void *param)
{
    ngx_file_t *file = (ngx_file_t*)param;
    
	return ngx_file_getc(ch, file);
}

static ngx_int_t cfg_getstr(void *buf, size_t bufsiz, void *param)
{
    ngx_file_t *file = (ngx_file_t*)param;
    return ngx_file_gets((char*)buf,bufsiz,file);
}

ngx_int_t ngx_pcfg_openfile(ngx_configfile_t **ret_cfg,ngx_pool_t *p, const char *name)
{
    ngx_configfile_t *new_cfg;
    ngx_file_t *file = NULL;

    if (name == NULL) {
        return NGX_ERROR;
    }
	
	file = ngx_open_file_read(p,name);

    if(file == NULL){
		return NGX_ERROR;
    }

    if (!ngx_is_file(&file->info) &&
        strcmp(name, "/dev/null") != 0) {
        ngx_close_file(file->fd);
        return NGX_ERROR;
    }

    new_cfg = (ngx_configfile_t*)ngx_palloc(p, sizeof(ngx_configfile_t));
    new_cfg->param = (void*)file;
    new_cfg->name = ngx_pstrndup(p, name);
    new_cfg->getch = cfg_getch;
    new_cfg->getstr = cfg_getstr;
    new_cfg->close = cfg_close;
    new_cfg->line_number = 0;
    *ret_cfg = new_cfg;
    return NGX_OK;
}

/* Allocate a ngx_configfile_t handle with user defined functions and params */
ngx_configfile_t * ngx_pcfg_open_custom(
            ngx_pool_t *p, const char *descr, void *param,
            ngx_int_t (*getc_func) (char *ch, void *param),
            ngx_int_t (*gets_func) (void *buf, size_t bufsize, void *param),
            ngx_int_t (*close_func) (void *param))
{
    ngx_configfile_t *new_cfg = (ngx_configfile_t*)ngx_palloc(p, sizeof(*new_cfg));
    new_cfg->param = param;
    new_cfg->name = descr;
    new_cfg->getch = getc_func;
    new_cfg->getstr = gets_func;
    new_cfg->close = close_func;
    new_cfg->line_number = 0;
    return new_cfg;
}

ngx_int_t ngx_cfg_getc(char *ch, ngx_configfile_t *cfp){

    ngx_int_t rc = cfp->getch(ch, cfp->param);
    if (rc !=NGX_ERROR && *ch == '\n')
        ++cfp->line_number;
    return rc;
}
/* Read one line from open ngx_configfile_t, strip LF, increase line number */
/* If custom handler does not define a getstr() function, read char by char */
static ngx_int_t ngx_cfg_getline_core(char *buf, size_t bufsize,
                                        ngx_configfile_t *cfp)
{
    ssize_t rc;
    /* If a "get string" function is defined, use it */
    if (cfp->getstr != NULL) {
        char *cp;
        char *cbuf = buf;
        size_t cbufsize = bufsize;

        while (1) {
            ++cfp->line_number;
            rc = cfp->getstr(cbuf, cbufsize, cfp->param);
            if (rc == NGX_EOF) {
                if (cbuf != buf) {
                    *cbuf = '\0';
                    break;
                }

                else {
                    return NGX_EOF;
                }
            }
            if (rc != NGX_OK) {
                return rc;
            }

            /*
             *  check for line continuation,
             *  i.e. match [^\\]\\[\r]\n only
             */
            cp = cbuf;
            cp += strlen(cp);
            if (cp > cbuf && cp[-1] == '\n') {
                cp--;
                if (cp > cbuf && cp[-1] == '\r')
                    cp--;
                if (cp > cbuf && cp[-1] == '\\') {
                    cp--;
                    /*
                     * line continuation requested -
                     * then remove bacngxlash and continue
                     */
                    cbufsize -= (cp-cbuf);
                    cbuf = cp;
                    continue;
                }
            }
            else if ((size_t)(cp - buf) >= bufsize - 1) {
                return NGX_ENOSPC;
            }
            break;
        }
    } else {
        /* No "get string" function defined; read character by character */
        size_t i = 0;

        if (bufsize < 2) {
            /* too small, assume caller is crazy */
            return NGX_EINVAL;
        }
        buf[0] = '\0';

        while (1) {
            char c;
            rc = cfp->getch(&c, cfp->param);
            if (rc == NGX_EOF) {
                if (i > 0)
                    break;
                else
                    return NGX_EOF;
            }
            if (rc != NGX_OK)
                return rc;
            if (c == '\n') {
                ++cfp->line_number;
                /* check for line continuation */
                if (i > 0 && buf[i-1] == '\\') {
                    i--;
                    continue;
                }
                else {
                    break;
                }
            }
            else if (i >= bufsize - 2) {
                return NGX_ENOSPC;
            }
            buf[i] = c;
            ++i;
        }
        buf[i] = '\0';
    }
    return NGX_OK;
}

static int cfg_trim_line(char *buf)
{
    char *start, *end;
    /*
     * Leading and trailing white spangx is eliminated completely
     */
    start = buf;
    while (ngx_isspace(*start))
        ++start;
    /* blast trailing whitespangx */
    end = &start[strlen(start)];
    while (--end >= start && ngx_isspace(*end))
        *end = '\0';
    /* Zap leading whitespangx by shifting */
    if (start != buf)
        memmove(buf, start, end - start + 2);
    return end - start + 1;
}

/* Read one line from open ngx_configfile_t, strip LF, increase line number */
/* If custom handler does not define a getstr() function, read char by char */
ngx_int_t ngx_cfg_getline(char *buf, size_t bufsize,
                                        ngx_configfile_t *cfp)
{
    ngx_int_t rc = ngx_cfg_getline_core(buf, bufsize, cfp);
    if (rc == NGX_OK)
        cfg_trim_line(buf);
    return rc;
}

ngx_int_t ngx_varbuf_cfg_getline(struct ngx_varbuf *vb,
                                               ngx_configfile_t *cfp,
                                               size_t max_len)
{
    ngx_int_t rc;
    size_t new_len;
    vb->strlen = 0;
    *vb->buf = '\0';

    if (vb->strlen == NGX_VARBUF_UNKNOWN)
        vb->strlen = strlen(vb->buf);
    if (vb->avail - vb->strlen < 3) {
        new_len = vb->avail * 2;
        if (new_len > max_len)
            new_len = max_len;
        else if (new_len < 3)
            new_len = 3;
        ngx_varbuf_grow(vb, new_len);
    }

    for (;;) {
        rc = ngx_cfg_getline_core(vb->buf + vb->strlen, vb->avail - vb->strlen, cfp);
        if (rc == NGX_ENOSPC || rc == NGX_OK)
            vb->strlen += strlen(vb->buf + vb->strlen);
        if (rc != NGX_ENOSPC)
            break;
        if (vb->avail >= max_len)
            return NGX_ENOSPC;
        new_len = vb->avail * 2;
        if (new_len > max_len)
            new_len = max_len;
        ngx_varbuf_grow(vb, new_len);
        --cfp->line_number;
    }
    if (vb->strlen > max_len)
        return NGX_ENOSPC;
    if (rc == NGX_OK)
        vb->strlen = cfg_trim_line(vb->buf);
    return rc;
}

static char *substring_conf(ngx_pool_t *p, const char *start, int len,
                            char quote)
{
    char *result = (char*)ngx_palloc(p, len + 2);
    char *resp = result;
    int i;

    for (i = 0; i < len; ++i) {
        if (start[i] == '\\' && (start[i + 1] == '\\'
                                 || (quote && start[i + 1] == quote)))
            *resp++ = start[++i];
        else
            *resp++ = start[i];
    }

    *resp++ = '\0';
    return result;
}

const char * ngx_resolve_env(ngx_pool_t *p, const char * word)
{
# define SMALL_EXPANSION 5
    struct sll {
        struct sll *next;
        const char *string;
        size_t len;
    } *result, *current, sresult[SMALL_EXPANSION];
    char *res_buf, *cp;
    const char *s, *e, *ep;
    unsigned spc;
    size_t outlen;

    s = ngx_strchr(word, '$');
    if (!s) {
        return word;
    }

    /* well, actually something to do */
    ep = word + strlen(word);
    spc = 0;
    result = current = &(sresult[spc++]);
    current->next = NULL;
    current->string = word;
    current->len = s - word;
    outlen = current->len;

    do {
        /* prepare next entry */
        if (current->len) {
            current->next = (spc < SMALL_EXPANSION)
                            ? &(sresult[spc++])
                            : (struct sll *)ngx_palloc(p,
                                                       sizeof(*current->next));
            current = current->next;
            current->next = NULL;
            current->len = 0;
        }

        if (*s == '$') {
            if (s[1] == '{' && (e = ngx_strchr(s, '}'))) {
                char *name = ngx_pstrmemdup(p, s+2, e-s-2);
                word = NULL;
				word = getenv(name);
                
				if (word) {
                    current->string = word;
                    current->len = strlen(word);
                    outlen += current->len;
                }
                
				else {
                    if (ngx_strchr(name, ':') == 0)
                    current->string = s;
                    current->len = e - s + 1;
                    outlen += current->len;
                }
                s = e + 1;
            }
            else {
                current->string = s++;
                current->len = 1;
                ++outlen;
            }
        }
        else {
            word = s;
            s = ngx_strchr(s, '$');
            current->string = word;
            current->len = s ? s - word : ep - word;
            outlen += current->len;
        }
    } while (s && *s);

    /* assemble result */
    res_buf = cp = (char*)ngx_palloc(p, outlen + 1);
    do {
        if (result->len) {
            memcpy(cp, result->string, result->len);
            cp += result->len;
        }
        result = result->next;
    } while (result);
    res_buf[outlen] = '\0';

    return res_buf;
}

char * ngx_getword_conf(ngx_pool_t *p, const char **line)
{
    const char *str = *line, *strend;
    char *res;
    char quote;

    while (*str && ngx_isspace(*str))
        ++str;

    if (!*str) {
        *line = str;
        return "";
    }

    if ((quote = *str) == '"' || quote == '\'') {
        strend = str + 1;
        while (*strend && *strend != quote) {
            if (*strend == '\\' && strend[1] &&
                (strend[1] == quote || strend[1] == '\\')) {
                strend += 2;
            }
            else {
                ++strend;
            }
        }
        res = substring_conf(p, str + 1, strend - str - 1, quote);

        if (*strend == quote)
            ++strend;
    }
    else {
        strend = str;
        while (*strend && !ngx_isspace(*strend))
            ++strend;

        res = substring_conf(p, str, strend - str, 0);
    }

    while (*strend && ngx_isspace(*strend))
        ++strend;
    *line = strend;
    return res;
}
