/*
* shajf
*/

#include "msc_geo.h"
#include "msc_log.h"

#define GEO_STR_DEFAULT (const char*)"--"

static void geo_cleanup(void *data){

    geo_db *geo = (geo_db*)data;

    GeoIP_delete(geo->gi);
}

/**
 * Initialise Geo data structure
 */
int geo_init(directory_config *dcfg, const char *dbfn, char **error_msg)
{
    ngx_pool_cleanup_t *clp = NULL;

    *error_msg = NULL;

    if ((dcfg->geo == NULL) || (dcfg->geo == NGX_CONF_UNSET_PTR)) {
        dcfg->geo = (geo_db*)ngx_pcalloc(dcfg->mp, sizeof(geo_db));
    }

    dcfg->geo->gi = GeoIP_open(dbfn, GEOIP_MMAP_CACHE);

    if(dcfg->geo->gi==NULL){
        *error_msg = ngx_psprintf(dcfg->mp,ngx_strlen("could not open geoip db:")+ngx_strlen(dbfn)+2,
                "could not open geoip db:%s",dbfn);

        return 0;
    }

    dcfg->geo->dbfn = ngx_pstrndup(dcfg->mp, dbfn);
    clp = ngx_pool_cleanup_add(dcfg->mp,0);

    if(clp == NULL){
        
        *error_msg = ngx_pstrndup(dcfg->mp,"init geoip cleanup failed!");
        return 0;
    }

    clp->handler = geo_cleanup;
    clp->data = (void*)dcfg->geo;

    return 1;
}


/**
 * Perform geographical lookup on target.
 */
int geo_lookup(modsec_rec *msr, geo_rec *georec, const char *ip, char **error_msg)
{
    GeoIPRecord *gir = NULL;
    geo_db *geo = msr->txcfg->geo;
    *error_msg = NULL;
    
    if(ip_check(ip) == 0){
        
        *error_msg = ngx_psprintf(msr->mp,ngx_strlen("Geo ip lookup failed,invalid ip:")+ngx_strlen(ip)+2,
                "Geo ip lookup failed,invalid ip:%s",ip);
        
        msr_log(msr,4,"%s",*error_msg);

        return 0;
    }

    /* init */
    georec->country_code = GEO_STR_DEFAULT;
    georec->country_code3 = GEO_STR_DEFAULT;
    georec->country_name = GEO_STR_DEFAULT;
    georec->country_continent = GEO_STR_DEFAULT;
    georec->region = GEO_STR_DEFAULT;
    georec->city = GEO_STR_DEFAULT;
    georec->postal_code = GEO_STR_DEFAULT;
    georec->latitude = 0;
    georec->longitude = 0;
    georec->dma_code = -1;
    georec->area_code = -1;

    if (msr->txcfg->debuglog_level >= 9) {
        msr_log(msr, 9, "GEO: Looking up \"%s\".", ip);
    }
    
    gir = GeoIP_record_by_addr(geo->gi,ip);
    
    /*found*/
    if(gir){
        
        if(gir->country_code) georec->country_code = ngx_pstrndup(msr->mp,(const char*)gir->country_code);

        if(gir->country_code3) georec->country_code3 = ngx_pstrndup(msr->mp,(const char*)gir->country_code3);

        if(gir->country_name) georec->country_name = ngx_pstrndup(msr->mp,(const char*)gir->country_name);

        if(gir->continent_code) georec->country_continent = ngx_pstrndup(msr->mp,(const char*)gir->continent_code);

        if(gir->region) georec->region = ngx_pstrndup(msr->mp,(const char*)gir->region);

        if(gir->city) georec->country_code = ngx_pstrndup(msr->mp,(const char*)gir->city);

        if(gir->postal_code) georec->postal_code = ngx_pstrndup(msr->mp,(const char*)gir->postal_code);

        georec->latitude = gir->latitude;
        
        georec->longitude = gir->longitude;
        
        georec->dma_code = gir->dma_code;
        
        georec->area_code = gir->area_code;
       
        GeoIPRecord_delete(gir);
    }
    
    return 1;
}


