#ifndef NGINX_IO_H
#define NGINX_IO_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "modsecurity.h"

ngx_int_t read_http_request_body(modsec_rec *msr,char **error_msg);

ngx_int_t add_http_request_header(modsec_rec *msr,const char *key,const char *val,ngx_table_elt_t **elt_hash);
ngx_int_t add_http_response_header(modsec_rec *msr,const char *key,const char *val,ngx_table_elt_t **elt_hash);

#endif /*NGINX_IO_H*/
