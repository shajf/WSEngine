/*
*shajf
*/

#ifndef _MSC_GEO_H_
#define _MSC_GEO_H_

typedef struct geo_rec geo_rec;
typedef struct geo_db geo_db;

#include <ngx_config.h>
#include <ngx_core.h>
#include <GeoIP.h>
#include <GeoIPCity.h>
#include "modsecurity.h"
#include "msc_config.h"

/* Structures */

struct geo_rec {
    const char *country_code;
    const char *country_code3;
    const char *country_name;
    const char *country_continent;
    const char *region;
    const char *city;
    const char *postal_code;
    float       latitude;
    float       longitude;
    int         dma_code;
    int         area_code;
};

struct geo_db {
    GeoIP *gi;
    const char *dbfn;
};

/* Functions */

int  geo_init(directory_config *dcfg, const char *dbfn, char **error_msg);

int  geo_lookup(modsec_rec *msr, geo_rec *rec, const char *target, char **error_msg);

#endif
