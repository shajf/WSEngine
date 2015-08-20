/*
* ModSecurity for Apache 2.x, http://www.modsecurity.org/
* Copyright (c) 2004-2013 Trustwave Holdings, Inc. (http://www.trustwave.com/)
*
* You may not use this file except in compliance with
* the License.  You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* If any of the files related to licensing are missing or if you have any
* other questions related to licensing please contact Trustwave Holdings, Inc.
* directly using the email address security@modsecurity.org.
*/

#ifndef _UTIL_H_
#define _UTIL_H_

#include <ngx_config.h>
#include <ngx_core.h>

#include "modsecurity.h"
#include "re.h"
#include "msc_tree.h"

#define NGX_USETID      0x8000 /**< Set user id */
#define NGX_GSETID      0x4000 /**< Set group id */
#define NGX_WSTICKY     0x2000 /**< Sticky bit */


#define UNICODE_ERROR_CHARACTERS_MISSING    -1
#define UNICODE_ERROR_INVALID_ENCODING      -2
#define UNICODE_ERROR_OVERLONG_CHARACTER    -3
#define UNICODE_ERROR_RESTRICTED_CHARACTER  -4
#define UNICODE_ERROR_DECODING_ERROR        -5

char  *utf8_unicode_inplace_ex(ngx_pool_t *mp, unsigned char *input, long int input_len, int *changed);

char  *m_strcasestr(const char *haystack, const char *needle);

int  normalize_path_inplace(unsigned char *input, int len, int win, int *changed);

int  parse_boolean(const char *input);

char  *remove_quotes(ngx_pool_t *mptmp, const char *input, int input_len);

char  *parse_pm_content(const char *op_parm, unsigned short int op_len, msre_rule *rule, char **error_msg);

char  *remove_escape(ngx_pool_t *mptmp, const char *input, int input_len);

int  parse_name_eq_value(ngx_pool_t *mp, const char *input, char **name, char **value);

char  *url_encode(ngx_pool_t *mp, char *input, unsigned int input_len, int *changed);

char  *strnurlencat(char *destination, char *source, unsigned int maxlen);

char  *file_dirname(ngx_pool_t *p, const char *filename);

char  *file_basename(ngx_pool_t *p, const char *filename);

char  *file_basename_str(ngx_pool_t *p, ngx_str_t *filename);

int  sql_hex2bytes_inplace(unsigned char *data, int len);

int  hex2bytes_inplace(unsigned char *data, int len);

char  *bytes2hex(ngx_pool_t *pool,unsigned char *data, int len);

int  is_token_char(unsigned char c);

int  remove_lf_crlf_inplace(char *text);

char  *guess_tmp_dir(ngx_pool_t *p);

char  *current_logtime(ngx_pool_t *mp);

char  *current_filetime(ngx_pool_t *mp);

int  msc_mkstemp_ex(char *templat, int mode);

int  msc_mkstemp(char *templat);

char  *strtolower_inplace(unsigned char *str);

char  *log_escape_re(ngx_pool_t *p, const char *text);

char  *log_escape(ngx_pool_t *p, const char *text);

char  *log_escape_nq(ngx_pool_t *p, const char *text);

char  *log_escape_ex(ngx_pool_t *p, const char *text, unsigned long int text_length);

char  *log_escape_nq_ex(ngx_pool_t *p, const char *text, unsigned long int text_length);

char  *log_escape_hex(ngx_pool_t *mp, const unsigned char *text, unsigned long int text_length);

char  *log_escape_raw(ngx_pool_t *mp, const  unsigned char *text, unsigned long int text_length);

char  *log_escape_nul(ngx_pool_t *mp, const unsigned char *text,unsigned long int text_length);

int  decode_base64_ext(char *plain_text, const unsigned char *input, int input_len);

int  convert_to_int(const char c);

int  set_match_to_tx(modsec_rec *msr, int capture, const char *match, int tx_n);

int  js_decode_nonstrict_inplace(unsigned char *input, long int input_len);

int  urldecode_uni_nonstrict_inplace_ex(unsigned char *input, long int input_length, int * changed);

int  urldecode_nonstrict_inplace_ex(unsigned char *input, long int input_length, int *invalid_count, int *changed);

int  html_entities_decode_inplace(ngx_pool_t *mp,unsigned char *input, int len);

int  ansi_c_sequences_decode_inplace(unsigned char *input, int len);


int  is_empty_string(const char *string);

char  *resolve_relative_path(ngx_pool_t *pool, const char *parent_filename, const char *filename);

int  css_decode_inplace(unsigned char *input, long int input_len);

char  *construct_single_var(modsec_rec *msr, char *name);

char  *format_all_performance_variables(modsec_rec *msr, ngx_pool_t *mp);

unsigned char  is_netmask_v4(char *ip_strv4);

unsigned char  is_netmask_v6(char *ip_strv6);

int  msc_headers_to_buffer(const ngx_array_t *arr, char *buffer, int max_length);

int  ip_tree_from_file(TreeRoot **rtree, char *uri,
    ngx_pool_t *mp, char **error_msg);

int  tree_contains_ip(ngx_pool_t *mp, TreeRoot *rtree,
    const char *value, modsec_rec *msr, char **error_msg);

int  ip_tree_from_param(ngx_pool_t *pool,
    char *param, TreeRoot **rtree, char **error_msg);

int read_line(char *buff, int size, FILE *fp);

int ip_check(const char* ip);

int generate_random_bytes(char *buf,size_t length);

ngx_pcre_t * ngx_pregcomp(ngx_pool_t *p, const char *pattern,int cflags);
#endif
