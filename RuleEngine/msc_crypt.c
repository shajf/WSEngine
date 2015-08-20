/*
 * shajf
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_sha1.h>
#include <ngx_base64.h>

#include "msc_crypt.h"
#include "msc_util.h"
#include "acmp.h"
#include "libxml/HTMLtree.h"
#include "libxml/uri.h"
#include "msc_http_var.h"
#include "msc_log.h"
#include "nginx_io.h"

/**
 * \brief Normalize path in URI
 *
 * \param msr ModSecurity transaction resource
 * \param input The URI to be normalized
 *
 * \retval input normalized input
 * \retval NULL on fail
 */
char *normalize_path(modsec_rec *msr, char *input) {
    xmlURI *uri = NULL;
    char *parsed_content = NULL;
    char *content = NULL;

    if(msr == NULL) return NULL;

    if(input == NULL) return NULL;

    uri = xmlParseURI(input);

    if(uri != NULL && uri->path)    {
        if(uri->scheme) {
            content = ngx_psprintf(msr->mp, ngx_strlen("uri->scheme")+5,"%s://", uri->scheme);
            parsed_content = ngx_pstrcat(msr->mp, content, NULL);
        }

        if(uri->server) {
            content = ngx_pstrndup(msr->mp,uri->server);
            if(parsed_content)
                parsed_content = ngx_pstrcat(msr->mp, parsed_content, content, NULL);
            else
                parsed_content = ngx_pstrcat(msr->mp, content, NULL);
        }

        if(uri->port)   {
            content = ngx_psprintf(msr->mp, NGX_INT64_LEN+2,":%d", uri->port);
            if(parsed_content)
                parsed_content = ngx_pstrcat(msr->mp, parsed_content, content, NULL);
            else
                parsed_content = ngx_pstrcat(msr->mp, content, NULL);
        }

        if(uri->path)   {
            char *Uri = NULL;
            /*int i;*/
            char *relative_link = NULL;
            char *filename = NULL;
            char *relative_path = NULL;
            char *relative_uri = NULL;

            filename = file_basename_str(msr->mp, &msr->r->uri);

            if(filename == NULL || (msr->r->uri.len<(size_t)ngx_strlen(filename)))
                return NULL;

            relative_path = ngx_pstrmemdup(msr->mp, (const char*)msr->r->uri.data,msr->r->uri.len - ngx_strlen(filename));
            relative_uri = ngx_pstrcat(msr->mp, relative_path, uri->path, NULL);

            relative_link = ngx_pstrndup(msr->mp, relative_uri);

            xmlNormalizeURIPath(relative_link);

            Uri = ngx_pstrndup(msr->mp, relative_link);

/*
            for(i = 0; i < (int)strlen(Uri); i++)    {
                if(Uri[i] != '.' && Uri[i] != '/')  {
                    if (i - 1 < 0)
                        i = 0;
                    else
                        i--;
                    if(Uri[i] == '/')
                        --bytes;
                    break;
                }   else    {
                    bytes++;
                }
            }

            if(bytes >= (int)strlen(uri->path))
                return NULL;
*/

            content = ngx_pstrndup(msr->mp, Uri);

            if(parsed_content)
                parsed_content = ngx_pstrcat(msr->mp, parsed_content, content, NULL);
            else
                parsed_content = ngx_pstrcat(msr->mp, content, NULL);

        }

        if(uri->query_raw)  {
            content = ngx_pstrcat(msr->mp, "?", uri->query_raw,NULL);
            if(parsed_content)
                parsed_content = ngx_pstrcat(msr->mp, parsed_content, content, NULL);
            else
                parsed_content = ngx_pstrcat(msr->mp, content, NULL);
        }

        if(uri->fragment)   {
            content = ngx_pstrcat(msr->mp, "#", uri->fragment,NULL);
            if(parsed_content)
                parsed_content = ngx_pstrcat(msr->mp, parsed_content, content, NULL);
            else
                parsed_content = ngx_pstrcat(msr->mp, content, NULL);
        }
        xmlFreeURI(uri);
        return ngx_pstrndup(msr->mp, parsed_content);
    }

    if(uri != NULL) xmlFreeURI(uri);
    return ngx_pstrndup(msr->mp, input);
}

/**
 * \brief Create a random password
 *
 * \param mp ModSecurity transaction memory pool
 *
 * \retval key random key
 */
char *getkey(ngx_pool_t *mp) {
    unsigned char digest[NGX_SHA1_DIGESTSIZE];
    char *sig, *key, *value;
    ngx_sha1_t ctx;
    char salt[64];

    generate_random_bytes(salt, sizeof(salt));
    key = ngx_psprintf(mp,64,"%s",salt);

    ngx_sha1_init (&ctx);
    ngx_sha1_update (&ctx, key, ngx_strlen(key));
    ngx_sha1_update (&ctx, "\0", 1);

    generate_random_bytes(salt, sizeof(salt));
    value = ngx_psprintf(mp,64,"%s",salt);

    ngx_sha1_update (&ctx, value, ngx_strlen (value));
    ngx_sha1_final (digest, &ctx);

    sig = (char*)ngx_pcalloc (mp, ngx_base64_encode_len (sizeof (digest)));
    ngx_base64_encode (sig, (const char*)digest, sizeof (digest));

    return sig;
}


/**
 * \brief Generate the MAC for a given message
 *
 * \param msr ModSecurity transaction resource
 * \param key The key used within HMAC
 * \param key_len Key length
 * \param msg The message to generate the MAC
 * \param msglen The message length
 *
 * \retval hex_digest The MAC
 */
char *hmac(modsec_rec *msr, const char *key, int key_len,
        unsigned char *msg, int msglen) {
    ngx_sha1_t ctx;
    unsigned char digest[NGX_SHA1_DIGESTSIZE];
    unsigned char hmac_ipad[HMAC_PAD_SIZE], hmac_opad[HMAC_PAD_SIZE];
    unsigned char nkey[NGX_SHA1_DIGESTSIZE];
    unsigned char *hmac_key = (unsigned char *) key;
    unsigned char hex_digest[NGX_SHA1_DIGESTSIZE * 2], *hmac_digest;
    const char hex[] = "0123456789abcdef";
    int i;

    if (key_len > HMAC_PAD_SIZE-1) {
        hmac_key = nkey;
        key_len = NGX_SHA1_DIGESTSIZE;
    }

    memset ((void *) hmac_ipad, 0, sizeof (hmac_ipad));
    memset ((void *) hmac_opad, 0, sizeof (hmac_opad));
    memmove (hmac_ipad, hmac_key, key_len);
    memmove (hmac_opad, hmac_key, key_len);

    for (i = 0; i < HMAC_PAD_SIZE-1; i++)  {
        hmac_ipad[i] ^= 0x36;
        hmac_opad[i] ^= 0x5c;
    }

    ngx_sha1_init (&ctx);
    ngx_sha1_update(&ctx, hmac_ipad, HMAC_PAD_SIZE-1);
    ngx_sha1_update(&ctx, (const char *) msg, msglen);
    ngx_sha1_final (digest, &ctx);

    ngx_sha1_init (&ctx);
    ngx_sha1_update(&ctx, hmac_opad, HMAC_PAD_SIZE-1);
    ngx_sha1_update(&ctx, digest, sizeof (digest));
    ngx_sha1_final (digest, &ctx);

    hmac_digest = hex_digest;
    for (i = 0; i < (int)(sizeof (digest)); i++) {
        *hmac_digest++ = hex[digest[i] >> 4];
        *hmac_digest++ = hex[digest[i] & 0xF];
    }

    *hmac_digest = '\0';

    return ngx_pstrndup (msr->mp, (const char*)hex_digest);
}


/**
 * \brief Init html response body parser
 *
 * \param msr ModSecurity transaction resource
 *
 * \retval 1 on success
 * \retval -1 on fail
 */
int init_response_body_html_parser(modsec_rec *msr)   {
    char *charset = NULL;
    char *final_charset = NULL;
    char sep=0;

    if(msr == NULL||msr->r == NULL) return -1;

    const char *content_type =  msc_http_var_content_type(msr);

    if(content_type == NULL) return -1;

    if(msr->crypto_html_tree != NULL){
        xmlFreeDoc(msr->crypto_html_tree);
        msr->crypto_html_tree = NULL;
    }

    if((strncmp("text/html",content_type,  9) != 0)){
        if (msr->txcfg->debuglog_level >= 4)
            msr_log(msr, 4,
                    "init_response_body_html_parser: skipping html_tree generation for Content[%s].", content_type);
        if(msr->crypto_html_tree != NULL){
            xmlFreeDoc(msr->crypto_html_tree);
            msr->crypto_html_tree = NULL;
        }
        return -1;
    }

    if (msr->resbody_length == 0) {
        if (msr->txcfg->debuglog_level >= 4)
            msr_log(msr, 4, "init_response_body_html_parser: skipping html_tree generation for zero length respomse body.");
        msr->crypto_html_tree = NULL;
        return 0;
    }

    if((msr->r->headers_out.content_encoding==NULL)){
        charset=m_strcasestr(content_type,"charset=");
        if(charset == NULL){
            if (msr->txcfg->debuglog_level >= 4)
                msr_log(msr, 4, "init_response_body_html_parser: assuming ISO-8859-1.");
            msr->crypto_html_tree = htmlReadMemory(msr->resbody_data, msr->resbody_length, NULL,
                    "ISO-8859-1", HTML_PARSE_RECOVER | HTML_PARSE_NOBLANKS | HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING);
            htmlSetMetaEncoding ((htmlDocPtr) msr->crypto_html_tree, (const xmlChar *) "ISO-8859-1");
        }
        else{
            charset+=8;
            final_charset=strchr(charset,' ');
            if(final_charset == NULL) final_charset = strchr(charset,';');
            if(final_charset != NULL) {
                sep = *final_charset;
                *final_charset = '\0';
            }

            if (msr->txcfg->debuglog_level >= 4)
                msr_log(msr, 4,
                        "init_response_body_html_parser: Charset[%s]",charset);
            msr->crypto_html_tree = htmlReadMemory(msr->resbody_data, msr->resbody_length, NULL,
                    charset, HTML_PARSE_RECOVER| HTML_PARSE_NOBLANKS | HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING);
            htmlSetMetaEncoding ((htmlDocPtr) msr->crypto_html_tree, (const xmlChar *)charset);
            if(final_charset != NULL) *final_charset=sep;
        }

    }
    else{
        char *ce = (char*)ngx_pstrdup(msr->mp,&msr->r->headers_out.content_encoding->value);

        if (msr->txcfg->debuglog_level >= 4)
            msr_log(msr, 4,"init_response_body_html_parser: Enconding[%s].",ce);
        msr->crypto_html_tree = htmlReadMemory(msr->resbody_data, msr->resbody_length, NULL,
                ce, HTML_PARSE_RECOVER | HTML_PARSE_NOBLANKS | HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING);
        htmlSetMetaEncoding ((htmlDocPtr) msr->crypto_html_tree, (const xmlChar *)ce);
    }
    if(msr->crypto_html_tree == NULL){
        if (msr->txcfg->debuglog_level >= 4)
            msr_log(msr, 4,
                    "init_response_body_html_parser: Failed to parse response body.");
        return -1;
    }
    else {
        if (msr->txcfg->debuglog_level >= 4)
            msr_log(msr, 4,
                    "init_response_body_html_parser: Successfully html parser generated.");
        return 1;
    }

    return 1;
}

/**
 * \brief Execute all hash methods
 *
 * \param msr ModSecurity transaction resource
 * \param link The html attr value to be checked
 * \param type The hash method type
 *
 * \retval 1 Match
 * \retval 0 No Match
 * \retval -1 on fail
 */
int do_hash_method(modsec_rec *msr, char *link, int type)   {
    hash_method **em = NULL;
    ngx_uint_t i = 0;
    char *error_msg = NULL;
    char *my_error_msg = NULL;
    int ovector[33];
    int rc;

    if(msr == NULL) return -1;

    em = (hash_method **)msr->txcfg->hash_method->elts;

    if(msr->txcfg->hash_method->nelts == 0)
        return 1;

    for (i = 0; i < msr->txcfg->hash_method->nelts; i++) {

        if(em[i] != NULL && em[i]->param_data != NULL){

            switch(type)    {
                case HASH_URL_HREF_HASH_PM:
                    if(em[i]->type == HASH_URL_HREF_HASH_PM)   {
                        const char *match = NULL;
                        ngx_int_t rc = 0;
                        ACMPT pt;

                        pt.parser = (ACMP *)em[i]->param_data;
                        pt.ptr = NULL;

                        rc = acmp_process_quick(&pt, &match, link, strlen(link));

                        if (rc) {
                            return 1;
                        } else  {
                            return 0;
                        }
                    }
                    break;
                case HASH_URL_HREF_HASH_RX:
                    if(em[i]->type == HASH_URL_HREF_HASH_RX)   {
                        rc = msc_regexec_capture(em[i]->param_data, link, strlen(link), ovector, 30, &my_error_msg);
                        if ((rc == PCRE_ERROR_MATCHLIMIT) || (rc == PCRE_ERROR_RECURSIONLIMIT)) {
                            msc_string *s = (msc_string *)ngx_pcalloc(msr->mp, sizeof(msc_string));

                            if (s == NULL) return -1;
                            s->name = ngx_pstrndup(msr->mp, "MSC_PCRE_LIMITS_EXCEEDED");
                            if (s->name == NULL) return -1;
                            s->name_len = strlen(s->name);
                            s->value = ngx_pstrndup(msr->mp, "1");
                            if (s->value == NULL) return -1;
                            s->value_len = 1;
                            ngx_table_setn(msr->tx_vars, s->name, (void *)s);

                            error_msg = ngx_psprintf(msr->mp,
                                    ngx_strlen("Execution error - PCRE limits exceeded for Hash regex [%s] (%d): %s")+ngx_strlen(em[i]->param)+ngx_strlen(my_error_msg)+NGX_INT64_LEN+2,
                                    "Execution error - PCRE limits exceeded for Hash regex [%s] (%d): %s",
                                    em[i]->param,rc, my_error_msg);

                            if (msr->txcfg->debuglog_level >= 4)
                                msr_log(msr, 4, "%s.", error_msg);

                            return 0; /* No match. */
                        }
                        else if (rc < -1) {
                            error_msg = ngx_psprintf(msr->mp, 
                                    ngx_strlen("Regex execution failed (%d): %s")+ngx_strlen(my_error_msg)+NGX_INT64_LEN+2,
                                    "Regex execution failed (%d): %s",
                                    rc, my_error_msg);

                            if (msr->txcfg->debuglog_level >= 4)
                                msr_log(msr, 4, "%s.", error_msg);
                            return -1;
                        }
                        if (rc != PCRE_ERROR_NOMATCH) { /* Match. */
                            return 1;
                        }
                    }
                    break;
                case HASH_URL_FACTION_HASH_PM:
                    if(em[i]->type == HASH_URL_FACTION_HASH_PM)   {
                       const char *match = NULL;
                        ngx_int_t rc = 0;
                        ACMPT pt;

                        pt.parser = (ACMP *)em[i]->param_data;
                        pt.ptr = NULL;

                        rc = acmp_process_quick(&pt, &match, link, strlen(link));

                        if (rc) {
                            return 1;
                        } else  {
                            return 0;
                        }
                    }
                    break;
                case HASH_URL_FACTION_HASH_RX:
                    if(em[i]->type == HASH_URL_FACTION_HASH_RX)   {
                        rc = msc_regexec_capture(em[i]->param_data, link, strlen(link), ovector, 30, &my_error_msg);
                        if ((rc == PCRE_ERROR_MATCHLIMIT) || (rc == PCRE_ERROR_RECURSIONLIMIT)) {
                            msc_string *s = (msc_string *)ngx_pcalloc(msr->mp, sizeof(msc_string));

                            if (s == NULL) return -1;
                            s->name = ngx_pstrndup(msr->mp, "MSC_PCRE_LIMITS_EXCEEDED");
                            if (s->name == NULL) return -1;
                            s->name_len = strlen(s->name);
                            s->value = ngx_pstrndup(msr->mp, "1");
                            if (s->value == NULL) return -1;
                            s->value_len = 1;
                            ngx_table_setn(msr->tx_vars, s->name, (void *)s);

                            error_msg = ngx_psprintf(msr->mp,
                                    ngx_strlen("Execution error - PCRE limits exceeded for Hash regex [%s] (%d): %s")+ngx_strlen(em[i]->param)+ngx_strlen(my_error_msg)+NGX_INT64_LEN+2,
                                    "Execution error - PCRE limits exceeded for Hash regex [%s] (%d): %s",
                                    em[i]->param,rc, my_error_msg);

                            if (msr->txcfg->debuglog_level >= 4)
                                msr_log(msr, 4, "%s.", error_msg);

                            return 0; /* No match. */
                        }
                        else if (rc < -1) {
                            error_msg = ngx_psprintf(msr->mp, ngx_strlen("Regex execution failed (%d): %s")+ngx_strlen(my_error_msg)+NGX_INT64_LEN+2,
                                    "Regex execution failed (%d): %s",
                                    rc, my_error_msg);
                            if (msr->txcfg->debuglog_level >= 4)
                                msr_log(msr, 4, "%s.", error_msg);
                            return -1;
                        }
                        if (rc != PCRE_ERROR_NOMATCH) { /* Match. */
                            return 1;
                        }
                    }
                    break;
                case HASH_URL_LOCATION_HASH_PM:
                    if(em[i]->type == HASH_URL_LOCATION_HASH_PM)   {
                       const char *match = NULL;
                        ngx_int_t rc = 0;
                        ACMPT pt;

                        pt.parser = (ACMP *)em[i]->param_data;
                        pt.ptr = NULL;

                        rc = acmp_process_quick(&pt, &match, link, strlen(link));

                        if (rc) {
                            return 1;
                        } else  {
                            return 0;
                        }
                    }
                    break;
                case HASH_URL_LOCATION_HASH_RX:
                    if(em[i]->type == HASH_URL_LOCATION_HASH_RX)   {
                        rc = msc_regexec_capture(em[i]->param_data, link, strlen(link), ovector, 30, &my_error_msg);
                        if ((rc == PCRE_ERROR_MATCHLIMIT) || (rc == PCRE_ERROR_RECURSIONLIMIT)) {
                            msc_string *s = (msc_string *)ngx_pcalloc(msr->mp, sizeof(msc_string));

                            if (s == NULL) return -1;
                            s->name = ngx_pstrndup(msr->mp, "MSC_PCRE_LIMITS_EXCEEDED");
                            if (s->name == NULL) return -1;
                            s->name_len = strlen(s->name);
                            s->value = ngx_pstrndup(msr->mp, "1");
                            if (s->value == NULL) return -1;
                            s->value_len = 1;
                            ngx_table_setn(msr->tx_vars, s->name, (void *)s);

                            error_msg = ngx_psprintf(msr->mp,
                                    ngx_strlen("Execution error - PCRE limits exceeded for Hash regex [%s] (%d): %s")+ngx_strlen(em[i]->param)+ngx_strlen(my_error_msg)+NGX_INT64_LEN+2,
                                    "Execution error - PCRE limits exceeded for Hash regex [%s] (%d): %s",
                                    em[i]->param,rc, my_error_msg);

                            if (msr->txcfg->debuglog_level >= 4)
                                msr_log(msr, 4, "%s.", error_msg);

                            return 0; /* No match. */
                        }
                        else if (rc < -1) {
                            error_msg = ngx_psprintf(msr->mp, 
                                    ngx_strlen("Regex execution failed (%d): %s")+ngx_strlen(my_error_msg)+NGX_INT64_LEN+2,
                                    "Regex execution failed (%d): %s",
                                    rc, my_error_msg);
                            if (msr->txcfg->debuglog_level >= 4)
                                msr_log(msr, 4, "%s.", error_msg);
                            return -1;
                        }
                        if (rc != PCRE_ERROR_NOMATCH) { /* Match. */
                            return 1;
                        }
                    }
                    break;
                case HASH_URL_IFRAMESRC_HASH_PM:
                    if(em[i]->type == HASH_URL_IFRAMESRC_HASH_PM)   {
                       const char *match = NULL;
                        ngx_int_t rc = 0;
                        ACMPT pt;

                        pt.parser = (ACMP *)em[i]->param_data;
                        pt.ptr = NULL;

                        rc = acmp_process_quick(&pt, &match, link, strlen(link));

                        if (rc) {
                            return 1;
                        } else  {
                            return 0;
                        }
                    }
                    break;
                case HASH_URL_IFRAMESRC_HASH_RX:
                    if(em[i]->type == HASH_URL_IFRAMESRC_HASH_RX)   {
                        rc = msc_regexec_capture(em[i]->param_data, link, strlen(link), ovector, 30, &my_error_msg);
                        if ((rc == PCRE_ERROR_MATCHLIMIT) || (rc == PCRE_ERROR_RECURSIONLIMIT)) {
                            msc_string *s = (msc_string *)ngx_pcalloc(msr->mp, sizeof(msc_string));

                            if (s == NULL) return -1;
                            s->name = ngx_pstrndup(msr->mp, "MSC_PCRE_LIMITS_EXCEEDED");
                            if (s->name == NULL) return -1;
                            s->name_len = strlen(s->name);
                            s->value = ngx_pstrndup(msr->mp, "1");
                            if (s->value == NULL) return -1;
                            s->value_len = 1;
                            ngx_table_setn(msr->tx_vars, s->name, (void *)s);

                            error_msg = ngx_psprintf(msr->mp,
                                     ngx_strlen("Execution error - PCRE limits exceeded for Hash regex [%s] (%d): %s")+ngx_strlen(em[i]->param)+ngx_strlen(my_error_msg)+NGX_INT64_LEN+2,
                                    "Execution error - PCRE limits exceeded for Hash regex [%s] (%d): %s",
                                    em[i]->param,rc, my_error_msg);

                            if (msr->txcfg->debuglog_level >= 4)
                                msr_log(msr, 4, "%s.", error_msg);

                            return 0; /* No match. */
                        }
                        else if (rc < -1) {
                            error_msg = ngx_psprintf(msr->mp, 
                                    ngx_strlen("Regex execution failed (%d): %s")+ngx_strlen(my_error_msg)+NGX_INT64_LEN+2,
                                    "Regex execution failed (%d): %s",
                                    rc, my_error_msg);

                            if (msr->txcfg->debuglog_level >= 4)
                                msr_log(msr, 4, "%s.", error_msg);
                            return -1;
                        }
                        if (rc != PCRE_ERROR_NOMATCH) { /* Match. */
                            return 1;
                        }
                    }
                    break;
                case HASH_URL_FRAMESRC_HASH_PM:
                    if(em[i]->type == HASH_URL_FRAMESRC_HASH_PM)   {
                       const char *match = NULL;
                        ngx_int_t rc = 0;
                        ACMPT pt;

                        pt.parser = (ACMP *)em[i]->param_data;
                        pt.ptr = NULL;

                        rc = acmp_process_quick(&pt, &match, link, strlen(link));

                        if (rc) {
                            return 1;
                        } else  {
                            return 0;
                        }
                    }
                    break;
                case HASH_URL_FRAMESRC_HASH_RX:
                    if(em[i]->type == HASH_URL_FRAMESRC_HASH_RX)   {
                        rc = msc_regexec_capture(em[i]->param_data, link, strlen(link), ovector, 30, &my_error_msg);
                        if ((rc == PCRE_ERROR_MATCHLIMIT) || (rc == PCRE_ERROR_RECURSIONLIMIT)) {
                            msc_string *s = (msc_string *)ngx_pcalloc(msr->mp, sizeof(msc_string));

                            if (s == NULL) return -1;
                            s->name = ngx_pstrndup(msr->mp, "MSC_PCRE_LIMITS_EXCEEDED");
                            if (s->name == NULL) return -1;
                            s->name_len = strlen(s->name);
                            s->value = ngx_pstrndup(msr->mp, "1");
                            if (s->value == NULL) return -1;
                            s->value_len = 1;
                            ngx_table_setn(msr->tx_vars, s->name, (void *)s);

                            error_msg = ngx_psprintf(msr->mp,
                                    ngx_strlen("Execution error - PCRE limits exceeded for Hash regex [%s] (%d): %s")+ngx_strlen(em[i]->param)+ngx_strlen(my_error_msg)+NGX_INT64_LEN+2,
                                    "Execution error - PCRE limits exceeded for Hash regex [%s] (%d): %s",
                                    em[i]->param,rc, my_error_msg);

                            if (msr->txcfg->debuglog_level >= 4)
                                msr_log(msr, 4, "%s.", error_msg);

                            return 0; /* No match. */
                        }
                        else if (rc < -1) {
                            error_msg = ngx_psprintf(msr->mp, 
                                    ngx_strlen("Regex execution failed (%d): %s")+ngx_strlen(my_error_msg)+NGX_INT64_LEN+2,
                                    "Regex execution failed (%d): %s",
                                    rc, my_error_msg);
                            if (msr->txcfg->debuglog_level >= 4)
                                msr_log(msr, 4, "%s.", error_msg);
                            return -1;
                        }
                        if (rc != PCRE_ERROR_NOMATCH) { /* Match. */
                            return 1;
                        }
                    }
                    break;
            }
        }

    }
    return 0;
}

/**
 * \brief Hash the html elements
 *
 * \param msr ModSecurity transaction resource
 *
 * \retval 1 On success
 * \retval 0 No element was changed
 * \retval -1 On fail
 */
int hash_response_body_links(modsec_rec *msr)   {
    int lsize = 0, fsize = 0, lcount = 0, fcount = 0, i;
    int isize = 0, icount = 0, frsize = 0, frcount = 0;
    int bytes = 0;
    xmlXPathContextPtr  xpathCtx = NULL;
    xmlXPathObjectPtr   xpathObj = NULL;
    xmlChar *content_option = NULL;
    char *mac_link = NULL;
    int rc, elts = 0;

    if(msr == NULL)
        return -1;

    if (msr->crypto_html_tree == NULL) {
        if (msr->txcfg->debuglog_level >= 4)
            msr_log(msr, 4, "hash_response_body_links: Cannot parse NULL html tree");
        return -1;
    }

    if(msr->txcfg->crypto_hash_href_rx == 0 && msr->txcfg->crypto_hash_href_pm == 0
            && msr->txcfg->crypto_hash_faction_rx == 0 && msr->txcfg->crypto_hash_faction_pm == 0
            && msr->txcfg->crypto_hash_iframesrc_rx == 0 && msr->txcfg->crypto_hash_iframesrc_pm == 0
            && msr->txcfg->crypto_hash_framesrc_rx == 0 && msr->txcfg->crypto_hash_framesrc_pm == 0)
        return -1;

    xpathCtx = xmlXPathNewContext(msr->crypto_html_tree);
    if(xpathCtx == NULL) {
        if (msr->txcfg->debuglog_level >= 4)
            msr_log(msr, 4, "hash_response_body_links: Unable to create Xpath context.");
        goto ctx_error;
    }

    lcount=fcount=0;

    if(msr->txcfg->crypto_hash_href_rx == 1 || msr->txcfg->crypto_hash_href_pm == 1)    {

        xpathObj = xmlXPathEvalExpression((xmlChar*)"//*[@href]", xpathCtx);
        if(xpathObj == NULL) {
            if (msr->txcfg->debuglog_level >= 4)
                msr_log(msr, 4,
                        "hash_response_body_links: Unable to evaluate xpath expression.");
            goto obj_error;
        }

        lsize = (xpathObj->nodesetval) ? xpathObj->nodesetval->nodeNr : 0;
        for(i = lsize - 1; i >=0; i--) {
            register xmlNodePtr cur;

            cur = xpathObj->nodesetval->nodeTab[i];
            if(cur != NULL){
                xmlChar *href = xmlGetProp(cur, (const xmlChar *) "href");
                char *content_href = normalize_path(msr, (char *)href);

                if(content_href != NULL && strstr(content_href,msr->txcfg->crypto_param_name) == NULL) {
                    if(msr->txcfg->crypto_hash_href_rx == 1)    {
                        rc = do_hash_method(msr, (char *)content_href, HASH_URL_HREF_HASH_RX);
                        if(rc > 0)  {
                            mac_link = NULL;
                            mac_link = do_hash_link(msr, (char *)content_href, FULL_LINK);
                            if(mac_link != NULL) {
                                xmlSetProp(cur, (const xmlChar *) "href", (const xmlChar *) mac_link);
                                lcount++;
                                bytes += strlen(mac_link);
                                msr->of_stream_changed = 1;
                            }
                            mac_link = NULL;
                            if(href != NULL)
                                xmlFree(href);
                            continue;
                        }
                    }
                    if(msr->txcfg->crypto_hash_href_pm == 1)    {
                        rc = do_hash_method(msr, (char *)content_href, HASH_URL_HREF_HASH_PM);
                        if(rc > 0)  {
                            mac_link = NULL;
                            mac_link = do_hash_link(msr, (char *)content_href, FULL_LINK);
                            if(mac_link != NULL) {
                                xmlSetProp(cur, (const xmlChar *) "href", (const xmlChar *) mac_link);
                                lcount++;
                                bytes += strlen(mac_link);
                                msr->of_stream_changed = 1;
                            }
                            mac_link = NULL;
                            if(href != NULL)
                                xmlFree(href);
                            continue;
                        }
                    }
                }

                if(href != NULL)    {
                    xmlFree(href);
                    href = NULL;
                }
            }
        }

        if(xpathObj != NULL)
            xmlXPathFreeObject(xpathObj);
    }

    if(msr->txcfg->crypto_hash_faction_rx == 1 || msr->txcfg->crypto_hash_faction_pm == 1) {
        xpathObj = xmlXPathEvalExpression((xmlChar*)"//form", xpathCtx);
        if(xpathObj == NULL) {
            if (msr->txcfg->debuglog_level >= 4)
                msr_log(msr, 4,
                        "hash_response_body_links: Unable to evaluate xpath expression.");
            goto obj_error;
        }

        fsize = (xpathObj->nodesetval) ? xpathObj->nodesetval->nodeNr : 0;
        for(i = fsize - 1; i >=0; i--) {
            register xmlNodePtr cur;

            cur = xpathObj->nodesetval->nodeTab[i];
            if((cur != NULL)){
                xmlChar *action = NULL;
                char *content_action = NULL;

                if(content_option)
                    xmlFree(content_option);

                action = xmlGetProp(cur, (const xmlChar *) "action");
                content_action = normalize_path(msr, (char *)action);
                content_option = xmlGetProp(cur, (const xmlChar *) "option");

                if(content_action != NULL && content_option == NULL && strstr(content_action,msr->txcfg->crypto_param_name) == NULL) {
                    if(msr->txcfg->crypto_hash_faction_rx == 1) {
                        rc = do_hash_method(msr, (char *)content_action, HASH_URL_FACTION_HASH_RX);
                        if(rc > 0)  {
                            mac_link = NULL;
                            mac_link = do_hash_link(msr, (char *)content_action, FULL_LINK);
                            if(mac_link != NULL) {
                                xmlSetProp(cur, (const xmlChar *) "action", (const xmlChar *) mac_link);
                                fcount++;
                                bytes += strlen(mac_link);
                                msr->of_stream_changed = 1;
                            }
                            mac_link = NULL;
                            if(action != NULL)
                                xmlFree(action);
                            continue;
                        }
                    }
                    if(msr->txcfg->crypto_hash_faction_pm == 1) {
                        rc = do_hash_method(msr, (char *)content_action, HASH_URL_FACTION_HASH_PM);
                        if(rc > 0)  {
                            mac_link = NULL;
                            mac_link = do_hash_link(msr, (char *)content_action, FULL_LINK);
                            if(mac_link != NULL) {
                                xmlSetProp(cur, (const xmlChar *) "action", (const xmlChar *) mac_link);
                                fcount++;
                                bytes += strlen(mac_link);
                                msr->of_stream_changed = 1;
                            }
                            mac_link = NULL;
                            if(action != NULL)
                                xmlFree(action);
                            continue;
                        }
                    }
                }

                if(action != NULL)  {
                    xmlFree(action);
                    action = NULL;
                }

                if(content_option)  {
                    xmlFree(content_option);
                    content_option = NULL;
                }
            }
        }

        if(xpathObj != NULL)
            xmlXPathFreeObject(xpathObj);
    }

    if(msr->txcfg->crypto_hash_iframesrc_rx == 1 || msr->txcfg->crypto_hash_iframesrc_pm == 1) {
        xpathObj = xmlXPathEvalExpression((xmlChar*)"//iframe", xpathCtx);
        if(xpathObj == NULL) {
            if (msr->txcfg->debuglog_level >= 4)
                msr_log(msr, 4,
                        "hash_response_body_links: Unable to evaluate xpath expression.");
            goto obj_error;
        }

        isize = (xpathObj->nodesetval) ? xpathObj->nodesetval->nodeNr : 0;
        for(i = isize - 1; i >=0; i--) {
            register xmlNodePtr cur;

            cur = xpathObj->nodesetval->nodeTab[i];
            if((cur != NULL)){

                xmlChar *src = xmlGetProp(cur, (const xmlChar *) "src");
                char *content_src = normalize_path(msr, (char *)src);

                if(content_src != NULL && strstr(content_src,msr->txcfg->crypto_param_name) == NULL) {
                    if(msr->txcfg->crypto_hash_iframesrc_rx == 1) {
                        rc = do_hash_method(msr, (char *)content_src, HASH_URL_IFRAMESRC_HASH_RX);
                        if(rc > 0)  {
                            mac_link = NULL;
                            mac_link = do_hash_link(msr, (char *)content_src, FULL_LINK);
                            if(mac_link != NULL) {
                                xmlSetProp(cur, (const xmlChar *) "src", (const xmlChar *) mac_link);
                                icount++;
                                bytes += strlen(mac_link);
                                msr->of_stream_changed = 1;
                            }
                            mac_link = NULL;
                            if(src != NULL)
                                xmlFree(src);
                            continue;
                        }
                    }
                    if(msr->txcfg->crypto_hash_iframesrc_pm == 1) {
                        rc = do_hash_method(msr, (char *)content_src, HASH_URL_IFRAMESRC_HASH_PM);
                        if(rc > 0)  {
                            mac_link = NULL;
                            mac_link = do_hash_link(msr, (char *)content_src, FULL_LINK);
                            if(mac_link != NULL) {
                                xmlSetProp(cur, (const xmlChar *) "src", (const xmlChar *) mac_link);
                                icount++;
                                bytes += strlen(mac_link);
                                msr->of_stream_changed = 1;
                            }
                            mac_link = NULL;
                            if(src != NULL)
                                xmlFree(src);
                            continue;
                        }
                    }
                }

                if(src != NULL) {
                    xmlFree(src);
                    src = NULL;
                }
            }
        }

        if(xpathObj != NULL)
            xmlXPathFreeObject(xpathObj);
    }

    if(msr->txcfg->crypto_hash_framesrc_rx == 1 || msr->txcfg->crypto_hash_framesrc_pm == 1) {
        xpathObj = xmlXPathEvalExpression((xmlChar*)"//frame", xpathCtx);
        if(xpathObj == NULL) {
            if (msr->txcfg->debuglog_level >= 4)
                msr_log(msr, 4,
                        "hash_response_body_links: Unable to evaluate xpath expression.");
            goto obj_error;
        }

        frsize = (xpathObj->nodesetval) ? xpathObj->nodesetval->nodeNr : 0;
        for(i = frsize - 1; i >=0; i--) {
            register xmlNodePtr cur;

            cur = xpathObj->nodesetval->nodeTab[i];
            if((cur != NULL)){

                xmlChar *src = xmlGetProp(cur, (const xmlChar *) "src");
                char *content_src = normalize_path(msr, (char *)src);

                if(content_src != NULL && strstr(content_src,msr->txcfg->crypto_param_name) == NULL) {
                    if(msr->txcfg->crypto_hash_framesrc_rx == 1) {
                        rc = do_hash_method(msr, (char *)content_src, HASH_URL_FRAMESRC_HASH_RX);
                        if(rc > 0)  {
                            mac_link = NULL;
                            mac_link = do_hash_link(msr, (char *)content_src, FULL_LINK);
                            if(mac_link != NULL) {
                                xmlSetProp(cur, (const xmlChar *) "src", (const xmlChar *) mac_link);
                                frcount++;
                                bytes += strlen(mac_link);
                                msr->of_stream_changed = 1;
                            }
                            mac_link = NULL;
                            if(src != NULL)
                                xmlFree(src);
                            continue;
                        }
                    }
                    if(msr->txcfg->crypto_hash_framesrc_pm == 1) {
                        rc = do_hash_method(msr, (char *)content_src, HASH_URL_FRAMESRC_HASH_PM);
                        if(rc > 0)  {
                            mac_link = NULL;
                            mac_link = do_hash_link(msr, (char *)content_src, FULL_LINK);
                            if(mac_link != NULL) {
                                xmlSetProp(cur, (const xmlChar *) "src", (const xmlChar *) mac_link);
                                frcount++;
                                bytes += strlen(mac_link);
                                msr->of_stream_changed = 1;
                            }
                            mac_link = NULL;
                            if(src != NULL)
                                xmlFree(src);
                            continue;
                        }
                    }
                }

                if(src != NULL) {
                    xmlFree(src);
                    src = NULL;
                }
            }
        }

        if(xpathObj != NULL)
            xmlXPathFreeObject(xpathObj);
    }

    if(xpathCtx != NULL)
        xmlXPathFreeContext(xpathCtx);

    if (msr->txcfg->debuglog_level >= 4)    {
        msr_log(msr, 4, "hash_response_body_links: Processed [%d] iframe src, [%d] hashed.",isize, icount);
        msr_log(msr, 4, "hash_response_body_links: Processed [%d] frame src, [%d] hashed.",frsize, frcount);
        msr_log(msr, 4, "hash_response_body_links: Processed [%d] form actions, [%d] hashed.",fsize, fcount);
        msr_log(msr, 4, "hash_response_body_links: Processed [%d] links, [%d] hashed.",lsize, lcount);
    }

    if(msr->of_stream_changed == 0) {
        if(msr->crypto_html_tree != NULL)   {
            xmlFreeDoc(msr->crypto_html_tree);
            msr->crypto_html_tree = NULL;
        }
        return 0;
    }

    elts = (icount+frcount+fcount+lcount);

    if((elts >= INT32_MAX) || (elts < 0))
        return 0;

    return bytes;

obj_error:
    if(xpathCtx != NULL)
    xmlXPathFreeContext(xpathCtx);
ctx_error:
    return -1;
}

/**
 * \brief Inject the new response body
 *
 * \param msr ModSecurity transaction resource
 * \param elts Number of hashed elements
 *
 * \retval 1 On success
 * \retval -1 On fail
 */
int inject_hashed_response_body(modsec_rec *msr, int elts) {
    xmlOutputBufferPtr output_buf = NULL;
    xmlCharEncodingHandlerPtr  handler = NULL;
    char *p = NULL;
    const char *ctype = NULL;
    const char *encoding = NULL;
    char *content_value = NULL;

    if(msr == NULL) return -1;

    if(msr->r == NULL) return -1;

    if (msr->crypto_html_tree == NULL) {
        if (msr->txcfg->debuglog_level >= 4)
            msr_log(msr, 4, "inject_hashed_response_body: Cannot parse NULL html tree");
        return -1;
    }
    
    ctype = msc_http_var_content_type(msr);

    encoding = (const char *) htmlGetMetaEncoding(msr->crypto_html_tree);

    if (ctype && encoding == NULL) {
        if (ctype && (p = m_strcasestr(ctype, "charset=") , p != NULL)) {
            p += 8 ;
            if (encoding = ngx_pstrmemdup(msr->mp, p, strcspn(p, " ;") ), encoding) {
                xmlCharEncoding enc;
                enc = xmlParseCharEncoding(encoding);
                enc = enc;

                handler = xmlFindCharEncodingHandler(encoding);
            }
        }
    } else  {
        if(encoding != NULL)    {
            xmlCharEncoding enc;
            enc = xmlParseCharEncoding(encoding);
            enc = enc;
            handler = xmlFindCharEncodingHandler(encoding);
        }
    }

    if (msr->txcfg->debuglog_level >= 4)
        msr_log(msr, 4, "inject_hashed_response_body: Detected encoding type [%s].", encoding);

    if (handler == NULL)
        handler = xmlFindCharEncodingHandler("UTF-8");
    if (handler == NULL)
        handler = xmlFindCharEncodingHandler("ISO-8859-1");
    if (handler == NULL)
        handler = xmlFindCharEncodingHandler("HTML");
    if (handler == NULL)
        handler = xmlFindCharEncodingHandler("ascii");

    if(handler == NULL) {
        xmlFreeDoc(msr->crypto_html_tree);
        return -1;
    }



    if (msr->txcfg->debuglog_level >= 4)
        msr_log(msr, 4, "inject_hashed_response_body: Using content-type [%s].", handler->name);

    output_buf = xmlAllocOutputBuffer(handler);
    if (output_buf == NULL) {
        if (msr->txcfg->debuglog_level >= 4)
            msr_log(msr, 4, "inject_hashed_response_body: Unable to allocate memory buffer.");
        xmlFreeDoc(msr->crypto_html_tree);
        return -1;
    }

    htmlDocContentDumpFormatOutput(output_buf, msr->crypto_html_tree, NULL, 0);
    xmlOutputBufferFlush(output_buf);

#ifdef  LIBXML2_NEW_BUFFER

    if (output_buf->conv == NULL || (output_buf->conv && xmlOutputBufferGetSize(output_buf) == 0)) {

        if(output_buf->buffer == NULL || xmlOutputBufferGetSize(output_buf) == 0)  {
            xmlOutputBufferClose(output_buf);
            xmlFreeDoc(msr->crypto_html_tree);
            msr->of_stream_changed = 0;
            return -1;
        }

        if(msr->stream_output_data != NULL) {
            free(msr->stream_output_data);
            msr->stream_output_data =  NULL;
        }

        msr->stream_output_length = xmlOutputBufferGetSize(output_buf);
        msr->stream_output_data = (char *)malloc(msr->stream_output_length+1);

        if (msr->stream_output_data == NULL) {
            xmlOutputBufferClose(output_buf);
            xmlFreeDoc(msr->crypto_html_tree);
            return -1;
        }

        memset(msr->stream_output_data, 0x0, msr->stream_output_length+1);
        memcpy(msr->stream_output_data, xmlOutputBufferGetContent(output_buf), msr->stream_output_length);

        if (msr->txcfg->debuglog_level >= 4)
            msr_log(msr, 4, "inject_hashed_response_body: Copying XML tree from CONTENT to stream buffer [%zu] bytes.", xmlOutputBufferGetSize(output_buf));

    } else {

        if(output_buf->conv == NULL || xmlOutputBufferGetSize(output_buf) == 0)  {
            xmlOutputBufferClose(output_buf);
            xmlFreeDoc(msr->crypto_html_tree);
            msr->of_stream_changed = 0;
            return -1;
        }

        if(msr->stream_output_data != NULL) {
            free(msr->stream_output_data);
            msr->stream_output_data =  NULL;
        }

        msr->stream_output_length = xmlOutputBufferGetSize(output_buf);
        msr->stream_output_data = (char *)malloc(msr->stream_output_length+1);

        if (msr->stream_output_data == NULL) {
            xmlOutputBufferClose(output_buf);
            xmlFreeDoc(msr->crypto_html_tree);
            return -1;
        }

        memset(msr->stream_output_data, 0x0, msr->stream_output_length+1);
        memcpy(msr->stream_output_data, xmlOutputBufferGetContent(output_buf), msr->stream_output_length);

        if (msr->txcfg->debuglog_level >= 4)
            msr_log(msr, 4, "inject_hashed_response_body: Copying XML tree from CONV to stream buffer [%zu] bytes.", xmlOutputBufferGetSize(output_buf));

    }

#else

    if (output_buf->conv == NULL || (output_buf->conv && output_buf->conv->use == 0)) {

        if(output_buf->buffer == NULL || output_buf->buffer->use == 0)  {
            xmlOutputBufferClose(output_buf);
            xmlFreeDoc(msr->crypto_html_tree);
            msr->of_stream_changed = 0;
            return -1;
        }

        if(msr->stream_output_data != NULL) {
            free(msr->stream_output_data);
            msr->stream_output_data =  NULL;
        }

        msr->stream_output_length = output_buf->buffer->use;
        msr->stream_output_data = (char *)malloc(msr->stream_output_length+1);

        if (msr->stream_output_data == NULL) {
            xmlOutputBufferClose(output_buf);
            xmlFreeDoc(msr->crypto_html_tree);
            return -1;
        }

        memset(msr->stream_output_data, 0x0, msr->stream_output_length+1);
        memcpy(msr->stream_output_data, (char *)xmlBufferContent(output_buf->buffer), msr->stream_output_length);
        //memcpy(msr->stream_output_data, output_buf->buffer->content, msr->stream_output_length);

        if (msr->txcfg->debuglog_level >= 4)
            msr_log(msr, 4, "inject_hashed_response_body: Copying XML tree from CONTENT to stream buffer [%d] bytes.", msr->stream_output_length);

    } else {

        if(output_buf->conv == NULL || output_buf->conv->use == 0)  {
            xmlOutputBufferClose(output_buf);
            xmlFreeDoc(msr->crypto_html_tree);
            msr->of_stream_changed = 0;
            return -1;
        }

        if(msr->stream_output_data != NULL) {
            free(msr->stream_output_data);
            msr->stream_output_data =  NULL;
        }

        msr->stream_output_length = output_buf->conv->use;
        msr->stream_output_data = (char *)malloc(msr->stream_output_length+1);

        if (msr->stream_output_data == NULL) {
            xmlOutputBufferClose(output_buf);
            xmlFreeDoc(msr->crypto_html_tree);
            return -1;
        }

        memset(msr->stream_output_data, 0x0, msr->stream_output_length+1);
        memcpy(msr->stream_output_data, (char *)xmlBufferContent(output_buf->conv), msr->stream_output_length);
        //memcpy(msr->stream_output_data, output_buf->conv->content, msr->stream_output_length);

        if (msr->txcfg->debuglog_level >= 4)
            msr_log(msr, 4, "inject_hashed_response_body: Copying XML tree from CONV to stream buffer [%d] bytes.", msr->stream_output_length);

    }

#endif

    xmlOutputBufferClose(output_buf);

    content_value = ngx_psprintf(msr->mp, NGX_INT64_LEN+2,"%z", msr->stream_output_length);

    if (msr->txcfg->debuglog_level >= 4)
        msr_log(msr, 4, "inject_hashed_response_body: Setting new content value %s", content_value);
    add_http_response_header(msr,"Content-Length",content_value,&msr->r->headers_out.content_length);
    xmlFreeDoc(msr->crypto_html_tree);

    if (msr->txcfg->debuglog_level >= 4)
        msr_log(msr, 4, "inject_hashed_response_body: Stream buffer [%z]. Done",msr->stream_output_length);

    return 1;
}

/**
 * \brief Parse and MAC html elements
 *
 * \param msr ModSecurity transaction resource
 * \param link The html attr value to be checked
 * \param type The hash method type
 *
 * \retval mac_link MACed link
 * \retval NULL on fail
 */
char *do_hash_link(modsec_rec *msr, char *link, int type)  {
    char  *mac_link = NULL;
    char *path_chunk = NULL;
    char *hash_value = NULL;
    char *qm = NULL;

    if(msr == NULL) return NULL;

    if(strlen(link) > 7 && strncmp("http:",(char*)link,5)==0){
        path_chunk = strchr(link+7,'/');
        if(path_chunk != NULL)  {
            if (msr->txcfg->debuglog_level >= 4)    {
                msr_log(msr, 4, "Signing data [%s]", path_chunk+1);
                }

            if(msr->txcfg->crypto_key_add == HASH_KEYONLY)
                hash_value =  hmac(msr, msr->txcfg->crypto_key, msr->txcfg->crypto_key_len, (unsigned char *) path_chunk+1, strlen((char*)path_chunk)-1);

            if(msr->txcfg->crypto_key_add == HASH_SESSIONID)  {
                if(msr->sessionid == NULL || strlen(msr->sessionid) == 0)   {
                    
                    const char *new_pwd = ngx_pstrcat(msr->mp,msr->txcfg->crypto_key,msc_http_var_remote_addr(msr),NULL);
                    
                    if (msr->txcfg->debuglog_level >= 4)
                        msr_log(msr, 4, "Session id is empty. Using REMOTE_IP");
                    msr->txcfg->crypto_key_len = strlen(new_pwd);
                    hash_value = hmac(msr, new_pwd, msr->txcfg->crypto_key_len, (unsigned char *) path_chunk+1, strlen((char*)path_chunk)-1);
                } else {
                    const char *new_pwd = ngx_pstrcat(msr->mp,msr->txcfg->crypto_key, msr->sessionid,NULL);
                    if (msr->txcfg->debuglog_level >= 4)
                        msr_log(msr, 4, "Using session id [%s]", msr->sessionid);
                    msr->txcfg->crypto_key_len = strlen(new_pwd);
                    hash_value = hmac(msr, new_pwd, msr->txcfg->crypto_key_len, (unsigned char *) path_chunk+1, strlen((char*)path_chunk)-1);
                }
            }

            if(msr->txcfg->crypto_key_add == HASH_REMOTEIP)   {
                const char *new_pwd = ngx_pstrcat(msr->mp, msr->txcfg->crypto_key, msc_http_var_remote_addr(msr),NULL);
                msr->txcfg->crypto_key_len = strlen(new_pwd);
                hash_value = hmac(msr, new_pwd, msr->txcfg->crypto_key_len, (unsigned char *) path_chunk+1, strlen((char*)path_chunk)-1);
            }
        } else  {
            return NULL;
        }
    } else
        if(strlen(link) > 8 && strncmp("https",(char*)link,5)==0){
            path_chunk = strchr(link+8,'/');
            if(path_chunk != NULL)  {
                if (msr->txcfg->debuglog_level >= 4)    {
                    msr_log(msr, 4, "Signing data [%s]", path_chunk+1);
                }

                if(msr->txcfg->crypto_key_add == HASH_KEYONLY)
                    hash_value =  hmac(msr, msr->txcfg->crypto_key, msr->txcfg->crypto_key_len, (unsigned char *) path_chunk+1, strlen((char*)path_chunk)-1);

                if(msr->txcfg->crypto_key_add == HASH_SESSIONID)  {
                    if(msr->sessionid == NULL || strlen(msr->sessionid) == 0)   {
                        const char *new_pwd = ngx_pstrcat(msr->mp, msr->txcfg->crypto_key,msc_http_var_remote_addr(msr),NULL);
                        if (msr->txcfg->debuglog_level >= 4)
                            msr_log(msr, 4, "Session id is empty. Using REMOTE_IP");
                        msr->txcfg->crypto_key_len = strlen(new_pwd);
                        hash_value = hmac(msr, new_pwd, msr->txcfg->crypto_key_len, (unsigned char *) path_chunk+1, strlen((char*)path_chunk)-1);
                    } else {
                        const char *new_pwd = ngx_pstrcat(msr->mp, msr->txcfg->crypto_key, msr->sessionid,NULL);
                        if (msr->txcfg->debuglog_level >= 4)
                            msr_log(msr, 4, "Using session id [%s]", msr->sessionid);
                        msr->txcfg->crypto_key_len = strlen(new_pwd);
                        hash_value = hmac(msr, new_pwd, msr->txcfg->crypto_key_len, (unsigned char *) path_chunk+1, strlen((char*)path_chunk)-1);
                    }
                }

                if(msr->txcfg->crypto_key_add == HASH_REMOTEIP)   {
                    const char *new_pwd = ngx_pstrcat(msr->mp, msr->txcfg->crypto_key,msc_http_var_remote_addr(msr),NULL);
                    msr->txcfg->crypto_key_len = strlen(new_pwd);
                    hash_value = hmac(msr, new_pwd, msr->txcfg->crypto_key_len, (unsigned char *) path_chunk+1, strlen((char*)path_chunk)-1);
                }
            } else  {
                return NULL;
            }
        }
        else if(*link=='/'){
            if (msr->txcfg->debuglog_level >= 4)    {
                msr_log(msr, 4, "Signing data [%s]", link+1);
                }

            if(msr->txcfg->crypto_key_add == HASH_KEYONLY)
                hash_value = hmac(msr, msr->txcfg->crypto_key, msr->txcfg->crypto_key_len, (unsigned char *) link+1, strlen((char*)link)-1);

            if(msr->txcfg->crypto_key_add == HASH_SESSIONID)  {
                if(msr->sessionid == NULL || strlen(msr->sessionid) == 0)   {
                    const char *new_pwd = ngx_pstrcat(msr->mp, msr->txcfg->crypto_key,msc_http_var_remote_addr(msr),NULL);
                    if (msr->txcfg->debuglog_level >= 4)
                        msr_log(msr, 4, "Session id is empty. Using REMOTE_IP");
                    msr->txcfg->crypto_key_len = strlen(new_pwd);
                    hash_value = hmac(msr, new_pwd, msr->txcfg->crypto_key_len, (unsigned char *) link+1, strlen((char*)link)-1);
                } else  {
                    const char *new_pwd = ngx_pstrcat(msr->mp, msr->txcfg->crypto_key, msr->sessionid,NULL);
                    if (msr->txcfg->debuglog_level >= 4)
                        msr_log(msr, 4, "Using session id [%s]", msr->sessionid);
                    msr->txcfg->crypto_key_len = strlen(new_pwd);
                    hash_value = hmac(msr, new_pwd, msr->txcfg->crypto_key_len, (unsigned char *) link+1, strlen((char*)link)-1);
                }
            }

            if(msr->txcfg->crypto_key_add == HASH_REMOTEIP)   {
                const char *new_pwd = ngx_pstrcat(msr->mp, msr->txcfg->crypto_key,msc_http_var_remote_addr(msr),NULL);

                msr->txcfg->crypto_key_len = strlen(new_pwd);
                
                hash_value = hmac(msr, new_pwd, msr->txcfg->crypto_key_len, (unsigned char *) link+1, strlen((char*)link)-1);
            }

        }
        else {
            char *relative_link = NULL;
            char *filename = NULL;
            char *relative_path = NULL;
            char *relative_uri = NULL;

            filename = file_basename(msr->mp, msr->parsed_uri.path);

            if(filename == NULL || (strlen(msr->parsed_uri.path)<strlen(filename)))
                return NULL;

            relative_path = ngx_pstrmemdup(msr->mp, msr->parsed_uri.path, strlen(msr->parsed_uri.path) - strlen(filename));
            relative_uri = ngx_pstrcat(msr->mp, relative_path, link, NULL);

            relative_link = relative_uri+1;

            if (msr->txcfg->debuglog_level >= 4)    {
                msr_log(msr, 4, "Signing data [%s] size %zu", relative_link, strlen(relative_link));
                }

            if(msr->txcfg->crypto_key_add == HASH_KEYONLY)
                hash_value = hmac(msr, msr->txcfg->crypto_key, msr->txcfg->crypto_key_len, (unsigned char *) relative_link, strlen((char*)relative_link));

            if(msr->txcfg->crypto_key_add == HASH_SESSIONID)  {
                if(msr->sessionid == NULL || strlen(msr->sessionid) == 0)   {
                    const char *new_pwd = ngx_pstrcat(msr->mp, msr->txcfg->crypto_key, msc_http_var_remote_addr(msr),NULL); 
                    
                    if (msr->txcfg->debuglog_level >= 4)
                        msr_log(msr, 4, "Session id is empty. Using REMOTE_IP");
                    msr->txcfg->crypto_key_len = strlen(new_pwd);
                    hash_value = hmac(msr, new_pwd, msr->txcfg->crypto_key_len, (unsigned char *) relative_link, strlen((char*)relative_link));
                } else {
                    const char *new_pwd = ngx_pstrcat(msr->mp, msr->txcfg->crypto_key, msr->sessionid,NULL);
                    if (msr->txcfg->debuglog_level >= 4)
                        msr_log(msr, 4, "Using session id [%s]", msr->sessionid);
                    msr->txcfg->crypto_key_len = strlen(new_pwd);
                    hash_value = hmac(msr, new_pwd, msr->txcfg->crypto_key_len, (unsigned char *) relative_link, strlen((char*)relative_link));
                }
            }

            if(msr->txcfg->crypto_key_add == HASH_REMOTEIP)   {
                const char *new_pwd = ngx_pstrcat(msr->mp, msr->txcfg->crypto_key, msc_http_var_remote_addr(msr),NULL);
                msr->txcfg->crypto_key_len = strlen(new_pwd);
                hash_value = hmac(msr, new_pwd, msr->txcfg->crypto_key_len, (unsigned char *) relative_link, strlen((char*)relative_link));
            }

        link = relative_uri;

        }

    if(hash_value == NULL) return NULL;

    if(type == HASH_ONLY)
        return hash_value;

    qm = strchr((char*)link,'?');
    if(qm == NULL){
        mac_link= (char*)ngx_pstrcat(msr->mp, link,"?",msr->txcfg->crypto_param_name,"=",(char *)hash_value,NULL);
    }
    else{
        mac_link= (char*)ngx_pstrcat(msr->mp, link,"&",msr->txcfg->crypto_param_name,"=",(char *)hash_value,NULL);
    }

    return mac_link;
}

/**
 * \brief Modify Location in case of status 302 and 301
 *
 * \param msr ModSecurity transaction resource
 *
 * \retval 1 On Success
 * \retval 0 on fail
 */
int modify_response_header(modsec_rec *msr) {
    
    char *mac_link = NULL;
    int rc = 0;
    ngx_http_variable_value_t location;
    ngx_str_t var = ngx_string("location");
    char *location_str;

    if(msr == NULL) return 0;

    if (msr->txcfg->debuglog_level >= 9)
        msr_log(msr, 4, "HTTP status (%d)", msr->response_status);

    if(msr->response_status != NGX_HTTP_MOVED_TEMPORARILY &&
            msr->response_status != NGX_HTTP_MOVED_PERMANENTLY)    {
        if (msr->txcfg->debuglog_level >= 9)
            msr_log(msr, 4, "Skipping status other than 302 an 301");
        return 0;
    }

    ngx_http_get_out_header(msr->r,&var,&location);

    if(location.not_found)
        return 0;
    
    location_str = (char*)ngx_http_pvdup(msr->mp,&location);

    if (msr->txcfg->debuglog_level >= 9)
        msr_log(msr, 4, "Processing reponse header location [%s]",location_str);

    if(msr->txcfg->crypto_hash_location_rx == 1) {
        rc = do_hash_method(msr, location_str, HASH_URL_LOCATION_HASH_RX);

        if(rc > 0)  {
            mac_link = NULL;
            mac_link = do_hash_link(msr, location_str, FULL_LINK);
        }   else    {
            return 0;
        }

    } else if(msr->txcfg->crypto_hash_location_pm == 1) {
        rc = do_hash_method(msr, location_str, HASH_URL_LOCATION_HASH_PM);

        if(rc > 0)  {
            mac_link = NULL;
            mac_link = do_hash_link(msr, location_str, FULL_LINK);
        }   else    {
            return 0;
        }

    }

    if(mac_link == NULL)
        return 0;

    if (msr->txcfg->debuglog_level >= 9)
        msr_log(msr, 4, "Setting new reponse header location [%s]", mac_link);

    if(rc > 0)  {

        add_http_response_header(msr,"Location",(const char*)ngx_pstrndup(msr->mp, mac_link),&msr->r->headers_out.location);
    }

    return 1;
}
