/*
* shajf
*/

#ifndef _MSC_CRYPT_H_
#define _MSC_CRYPT_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "modsecurity.h"
#include <libxml/HTMLparser.h>
#include <libxml/xpath.h>

#define HMAC_PAD_SIZE 65
#define HASH_ONLY 0
#define FULL_LINK 1

#ifndef INT32_MAX
#define INT32_MAX      (2147483647)
#endif

char  *hmac(modsec_rec *msr, const char *key, int key_len,unsigned char *msg, int msglen);

char  *do_hash_link(modsec_rec *msr, char *link,int type);

char  *getkey(ngx_pool_t *mp);

int  init_response_body_html_parser(modsec_rec *msr);
int  hash_response_body_links(modsec_rec *msr);
int  inject_hashed_response_body(modsec_rec *msr, int elts);
int  do_hash_method(modsec_rec *msr, char *link, int type);
int  modify_response_header(modsec_rec *msr);
char  *normalize_path(modsec_rec *msr, char *input);
#endif
