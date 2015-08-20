/*
* shajf
*/

#ifndef _MSC_JSON_H_
#define _MSC_JSON_H_

typedef struct json_data json_data;


#include <ngx_config.h>
#include <ngx_core.h>
#include "modsecurity.h"

#include <yajl/yajl_parse.h>
//#ifdef WITH_YAJL
//#else


#include "modsecurity.h"

/* Structures */
struct json_data {
    /* yajl configuration and parser state */
    yajl_handle handle;
    yajl_status status;

    /* error reporting and JSON array flag */
    unsigned char *yajl_error;

    /* prefix is used to create data hierarchy (i.e., 'parent.child.value') */
    unsigned char *prefix;
    unsigned char *current_key;
};

/* Functions */

int  json_init(modsec_rec *msr, char **error_msg);

int  json_process(modsec_rec *msr, const char *buf,
    unsigned int size, char **error_msg);

int  json_complete(modsec_rec *msr, char **error_msg);

ngx_int_t json_cleanup(modsec_rec *msr);

int  json_process_chunk(modsec_rec *msr, const char *buf,
		unsigned int size, char **error_msg);

#endif
