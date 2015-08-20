/*
* shajf
*/

#ifndef _MSC_GSB_H_
#define _MSC_GSB_H_

typedef struct gsb_db gsb_db;

#include <ngx_config.h>
#include <ngx_core.h>
#include "modsecurity.h"
#include "msc_config.h"

struct gsb_db {
    ngx_file_t *db;
    const char *dbfn;
    ngx_hash2_t *gsb_table;
};

int gsb_db_init(directory_config *dcfg, const char *dbfn, char **error_msg);

#endif
