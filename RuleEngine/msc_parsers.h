
/*
* shajf
*/

#ifndef _MSC_PARSERS_H_
#define _MSC_PARSERS_H_

#include "modsecurity.h"

int  parse_cookies_v0(modsec_rec *msr, char *_cookie_header, ngx_table_t *cookies,
    const char *delim);

int  parse_cookies_v1(modsec_rec *msr, char *_cookie_header, ngx_table_t *cookies);

int  parse_arguments(modsec_rec *msr, const char *s, size_t inputlength,
    int argument_separator, const char *origin, ngx_table_t *arguments, int *invalid_count);

void  add_argument(modsec_rec *msr, ngx_table_t *arguments, msc_arg *arg);

#endif
