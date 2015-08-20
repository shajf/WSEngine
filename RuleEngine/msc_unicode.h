/*shajf*/
#ifndef _MSC_UNICODE_H_
#define _MSC_UNICODE_H_

typedef struct unicode_map unicode_map;

#include <ngx_config.h>
#include <ngx_core.h>
#include "modsecurity.h"
#include "msc_config.h"

struct unicode_map {
    ngx_file_t *map;
    const char *mapfn;
};

int unicode_map_init(directory_config *dcfg, const char *mapfn, char **error_msg);

#endif
