/*
* shajf
*/

#ifndef _MSC_XML_H_
#define _MSC_XML_H_

typedef struct xml_data xml_data;

#include <ngx_config.h>
#include <ngx_core.h>
#include "modsecurity.h"
#include <libxml/xmlschemas.h>
#include <libxml/xpath.h>

/* Structures */

struct xml_data {
    xmlSAXHandler           *sax_handler;
    xmlParserCtxtPtr        parsing_ctx;
    xmlDocPtr               doc;

    unsigned int            well_formed;
};

/* Functions */

int  xml_init(modsec_rec *msr, char **error_msg);

int  xml_process_chunk(modsec_rec *msr, const char *buf,
    unsigned int size, char **error_msg);

int  xml_complete(modsec_rec *msr, char **error_msg);

ngx_int_t  xml_cleanup(modsec_rec *msr);

#endif
