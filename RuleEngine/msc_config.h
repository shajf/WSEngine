
/*
 * shajf
 * */

#ifndef MSC_CONFIG_H
#define MSC_CONFIG_H

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct directory_config directory_config;
#include "msc_gsb.h"
#include "msc_unicode.h"
#include "modsecurity.h"
#include "kvstore/kvstore.h"
#include "re.h"

struct directory_config {
    ngx_pool_t          *mp;

    msre_ruleset        *ruleset;

    int                  is_enabled;
    int                  reqbody_access;
    int                  reqintercept_oe;
    int                  reqbody_buffering;
    long int             reqbody_inmemory_limit;
    long int             reqbody_limit;
    long int             reqbody_no_files_limit;
    int                  resbody_access;

    long int             of_limit;
    ngx_table_t         *of_mime_types;
    int                  of_mime_types_cleared;
    int                  of_limit_action;
    int                  if_limit_action;

    const char          *debuglog_name;
    int                  debuglog_level;
    ngx_file_t          *debuglog_fd;

    int                  cookie_format;
    int                  argument_separator;
    const char           *cookiev0_separator;

    int                  rule_inheritance;
    ngx_array_t  *rule_exceptions;


    /* -- Audit log -- */

    /* Max rule time */
    int                  max_rule_time;

    /* Upload */
    const char          *tmp_dir;
    const char          *upload_dir;
    int                  upload_keep_files;
    int                  upload_validates_files;
    int                  upload_filemode; /* int only so NGX_CONF_UNSET works */
    int                  upload_file_limit;

    /* Used only in the configuration phase. */
    msre_rule           *tmp_chain_starter;
    msre_actionset      *tmp_default_actionset;
    ngx_table_t         *tmp_rule_placeholders;

    /* Misc */
    kvstore_t           *persistdb;
    const char          *webappid;
    const char          *sensor_id;
    const char          *httpBlkey;

    /* Content injection. */
    int                  content_injection_enabled;

    /* Stream Inspection */
    int                 stream_inbody_inspection;
    int                 stream_outbody_inspection;

    /* Geo Lookup */
    geo_db              *geo;

    /* Gsb Lookup */
    gsb_db              *gsb;

    /* Unicode map */
    unicode_map         *u_map;

    /* Cache */
    int                  cache_trans;
    int                  cache_trans_incremental;
    size_t           cache_trans_min;
    size_t           cache_trans_max;
    size_t           cache_trans_maxitems;

    /* Array to hold signatures of components, which will
     * appear in the ModSecurity signature in the audit log.
     */
    ngx_array_t  *component_signatures;

    /* Request character encoding. */
    const char          *request_encoding;

    int disable_backend_compression;

    /* Collection timeout */
    int col_timeout;

    /* hash of ids */
    ngx_hash2_t          *rule_id_htab;

    /* Hash */
    ngx_array_t  *hash_method;
    const char          *crypto_key;
    int                 crypto_key_len;
    const char          *crypto_param_name;
    int                 hash_is_enabled;
    int                 hash_enforcement;
    int                 crypto_key_add;
    int                 crypto_hash_href_rx;
    int                 crypto_hash_faction_rx;
    int                 crypto_hash_location_rx;
    int                 crypto_hash_iframesrc_rx;
    int                 crypto_hash_framesrc_rx;
    int                 crypto_hash_href_pm;
    int                 crypto_hash_faction_pm;
    int                 crypto_hash_location_pm;
    int                 crypto_hash_iframesrc_pm;
    int                 crypto_hash_framesrc_pm;

    /* xml */
    int                 xml_external_entity;
};

void  *create_directory_config(ngx_pool_t *mp,char *path);

void  *merge_directory_configs(ngx_pool_t *mp, void *_parent, void *_child);

void  init_directory_config(directory_config *dcfg);

#endif /*MSC_CONFIG_H*/
