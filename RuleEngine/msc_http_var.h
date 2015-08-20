

#ifndef MSC_HTTP_VAR_H
#define MSC_HTTP_VAR_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "modsecurity.h"

const char *msc_http_var_remote_addr(modsec_rec *msr);

const char *msc_http_var_local_addr(modsec_rec *msr);

ngx_uint_t msc_http_var_remote_port(modsec_rec *msr);

ngx_uint_t msc_http_var_local_port(modsec_rec *msr);

const char *msc_http_var_request_line(modsec_rec *msr);

const char *msc_http_var_request_uri(modsec_rec *msr);
const char *msc_http_var_query_string(modsec_rec *msr);

const char *msc_http_var_request_method(modsec_rec *msr);


const char *msc_http_var_request_protocol(modsec_rec *msr);

const char *msc_http_var_hostname(modsec_rec *msr);

ngx_table_t *msc_http_var_request_headers(modsec_rec *msr);

ngx_uint_t msc_http_var_response_status(modsec_rec *msr);

const char *msc_http_var_status_line(modsec_rec *msr);

const char *msc_http_var_response_protocol(modsec_rec *msr);

ngx_table_t *msc_http_var_response_headers(modsec_rec *msr);

const char *msc_http_var_content_type(modsec_rec *msr);

ngx_uint_t msc_http_var_content_length(modsec_rec *msr,int req);

const char *msc_http_var_remote_user(modsec_rec *msr);
#endif /*MSC_HTTP_VAR_H*/
