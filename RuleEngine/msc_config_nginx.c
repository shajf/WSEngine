/*
 * =====================================================================================
 *      Copyright (C) 2014 jianfeng sha
 *
 *      Filename:  msc_config_nginx.c
 *
 *      Description:  
 *
 *      Created:  02/05/15 11:24:53
 *
 *      Author:  jianfeng sha , csp001314@163.com
 *
 * =====================================================================================
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "modsecurity.h"
#include "msc_util.h"
#include "acmp.h"
#include "msc_crypt.h"

#if defined(WITH_LUA)
#include "msc_lua.h"
#endif

#define doc_config(conf) (((modsec_loc_conf_t*)(conf))->config)
#define arg_check(arg) if((arg)!=NGX_CONF_UNSET) return "is a duplicate"
#define arg_check_ptr(arg) if((arg)!=NGX_CONF_UNSET_PTR) return "is a duplicate"  

static int strtoflag(char *p){

    if(strcasecmp(p,"on") == 0) return 1;
    else if(strcasecmp(p,"off") == 0) return 0;
    else if(strcasecmp(p,"true") == 0) return 1;
    else if(strcasecmp(p,"false") == 0) return 0;
    else return -1;
}

static void set_arg_ptr(ngx_conf_t *cf,char** arg,ngx_uint_t index){
    
    ngx_str_t *value;
    if(index>=cf->args->nelts){
        *arg = NULL;
    }

    value = cf->args->elts;
    *arg = (char*)value[index].data;
}

void *create_directory_config(ngx_pool_t *mp)
{
    directory_config *dcfg = (directory_config *)ngx_pcalloc(mp, sizeof(directory_config));
    if (dcfg == NULL) return NULL;

    dcfg->mp = mp;
    dcfg->is_enabled = NGX_CONF_UNSET;

    dcfg->reqbody_access = NGX_CONF_UNSET;
    dcfg->reqintercept_oe = NGX_CONF_UNSET;
    dcfg->reqbody_buffering = NGX_CONF_UNSET;
    dcfg->reqbody_inmemory_limit = NGX_CONF_UNSET;
    dcfg->reqbody_limit = NGX_CONF_UNSET;
    dcfg->reqbody_no_files_limit = NGX_CONF_UNSET;
    dcfg->resbody_access = NGX_CONF_UNSET;

    dcfg->debuglog_name = NGX_CONF_UNSET_PTR;
    dcfg->debuglog_level = NGX_CONF_UNSET;
    dcfg->debuglog_fd = NGX_CONF_UNSET_PTR;

    dcfg->of_limit = NGX_CONF_UNSET;
    dcfg->if_limit_action = NGX_CONF_UNSET;
    dcfg->of_limit_action = NGX_CONF_UNSET;
    dcfg->of_mime_types = NGX_CONF_UNSET_PTR;
    dcfg->of_mime_types_cleared = NGX_CONF_UNSET;

    dcfg->cookie_format = NGX_CONF_UNSET;
    dcfg->argument_separator = NGX_CONF_UNSET;
    dcfg->cookiev0_separator = NGX_CONF_UNSET_PTR;

    dcfg->rule_inheritance = NGX_CONF_UNSET;
    dcfg->rule_exceptions = ngx_array_create(mp, 16, sizeof(rule_exception *));
    dcfg->hash_method = ngx_array_create(mp, 16, sizeof(hash_method *));

    dcfg->max_rule_time = NGX_CONF_UNSET;

    dcfg->ruleset = NULL;

    /* Upload */
    dcfg->tmp_dir = NGX_CONF_UNSET_PTR;
    dcfg->upload_dir = NGX_CONF_UNSET_PTR;
    dcfg->upload_keep_files = NGX_CONF_UNSET;
    dcfg->upload_validates_files = NGX_CONF_UNSET;
    dcfg->upload_filemode = NGX_CONF_UNSET;
    dcfg->upload_file_limit = NGX_CONF_UNSET;

    /* These are only used during the configuration process. */
    dcfg->tmp_chain_starter = NULL;
    dcfg->tmp_default_actionset = NULL;
    dcfg->tmp_rule_placeholders = NULL;

    /* Misc */
    dcfg->persistdb = NGX_CONF_UNSET_PTR;
    dcfg->webappid = NGX_CONF_UNSET_PTR;
    dcfg->sensor_id = NGX_CONF_UNSET_PTR;
    dcfg->httpBlkey = NGX_CONF_UNSET_PTR;

    /* Content injection. */
    dcfg->content_injection_enabled = NGX_CONF_UNSET;

    /* Stream inspection */
    dcfg->stream_inbody_inspection = NGX_CONF_UNSET;
    dcfg->stream_outbody_inspection = NGX_CONF_UNSET;

    /* Geo Lookups */
    dcfg->geo = NGX_CONF_UNSET_PTR;

    /* Gsb Lookups */
    dcfg->gsb = NGX_CONF_UNSET_PTR;

    /* Unicode Map */
    dcfg->u_map = NGX_CONF_UNSET_PTR;

    /* Cache */
    dcfg->cache_trans = NGX_CONF_UNSET;
    dcfg->cache_trans_incremental = NGX_CONF_UNSET;
    dcfg->cache_trans_min = NGX_CONF_UNSET;
    dcfg->cache_trans_max = NGX_CONF_UNSET;
    dcfg->cache_trans_maxitems = NGX_CONF_UNSET;

    /* Rule ids */
    dcfg->rule_id_htab = ngx_hash2_make(mp);
    dcfg->component_signatures = ngx_array_create(mp, 16, sizeof(char *));

    dcfg->request_encoding = NGX_CONF_UNSET_PTR;
    dcfg->disable_backend_compression = NGX_CONF_UNSET;

    /* Collection timeout */
    dcfg->col_timeout = NGX_CONF_UNSET;

    dcfg->crypto_key = NGX_CONF_UNSET_PTR;
    dcfg->crypto_key_len = NGX_CONF_UNSET;
    dcfg->crypto_key_add = NGX_CONF_UNSET;
    dcfg->crypto_param_name = NGX_CONF_UNSET_PTR;
    dcfg->hash_is_enabled = NGX_CONF_UNSET;
    dcfg->hash_enforcement = NGX_CONF_UNSET;
    dcfg->crypto_hash_href_rx = NGX_CONF_UNSET;
    dcfg->crypto_hash_faction_rx = NGX_CONF_UNSET;
    dcfg->crypto_hash_location_rx = NGX_CONF_UNSET;
    dcfg->crypto_hash_iframesrc_rx = NGX_CONF_UNSET;
    dcfg->crypto_hash_framesrc_rx = NGX_CONF_UNSET;
    dcfg->crypto_hash_href_pm = NGX_CONF_UNSET;
    dcfg->crypto_hash_faction_pm = NGX_CONF_UNSET;
    dcfg->crypto_hash_location_pm = NGX_CONF_UNSET;
    dcfg->crypto_hash_iframesrc_pm = NGX_CONF_UNSET;
    dcfg->crypto_hash_framesrc_pm = NGX_CONF_UNSET;


    /* xml external entity */
    dcfg->xml_external_entity = NGX_CONF_UNSET;

    return dcfg;
}

/**
 * Copies rules between one phase of two configuration contexts,
 * taking exceptions into account.
 */
static void copy_rules_phase(ngx_pool_t *mp,
                             ngx_array_t *parent_phase_arr,
                             ngx_array_t *child_phase_arr,
                             ngx_array_t *exceptions_arr)
{
    rule_exception **exceptions;
    msre_rule **rules;
    ngx_uint_t i, j;
    int mode = 0;

    rules = (msre_rule **)parent_phase_arr->elts;
    for(i = 0; i < parent_phase_arr->nelts; i++) {
        msre_rule *rule = (msre_rule *)rules[i];
        int copy = 1;

        if (mode == 0) {
            /* First rule in the chain. */
            exceptions = (rule_exception **)exceptions_arr->elts;
            for(j = 0; j < exceptions_arr->nelts; j++) {

                /* Process exceptions. */
                switch(exceptions[j]->type) {
                    case RULE_EXCEPTION_REMOVE_ID :
                        if ((rule->actionset != NULL)&&(rule->actionset->id != NULL)) {
                            int ruleid = atoi(rule->actionset->id);
                            if (rule_id_in_range(ruleid, exceptions[j]->param)) copy--;
                        }
                        break;
                    case RULE_EXCEPTION_REMOVE_MSG :
                        if ((rule->actionset != NULL)&&(rule->actionset->msg != NULL)) {
                            char *my_error_msg = NULL;

                            int rc = msc_regexec(exceptions[j]->param_data,
                                    rule->actionset->msg, strlen(rule->actionset->msg),
                                    &my_error_msg);
                            if (rc >= 0) copy--;
                        }
                        break;
                    case RULE_EXCEPTION_REMOVE_TAG :
                        if ((rule->actionset != NULL)&&(ngx_is_empty_table(rule->actionset->actions) == 0)) {
                            char *my_error_msg = NULL;
                            const ngx_array_t *tarr = NULL;
                            const ngx_table_entry_t *telts = NULL;
                            ngx_uint_t c;

                            tarr = ngx_table_elts(rule->actionset->actions);
                            telts = (const ngx_table_entry_t*)tarr->elts;

                            for (c = 0; c < tarr->nelts; c++) {
                                msre_action *action = (msre_action *)telts[c].val;
                                if(strcmp("tag", action->metadata->name) == 0)  {

                                    int rc = msc_regexec(exceptions[j]->param_data,
                                            action->param, strlen(action->param),
                                            &my_error_msg);
                                    if (rc >= 0) copy--;
                                }
                            }
                        }
                        break;
                }
            }

            if (copy > 0) {

                /* Copy the rule. */
                *(msre_rule **)ngx_array_push(child_phase_arr) = rule;
                if (rule->actionset->is_chained) mode = 2;
            } else {
                if (rule->actionset->is_chained) mode = 1;
            }
        } else {
            if (mode == 2) {

                /* Copy the rule (it belongs to the chain we want to include. */
                *(msre_rule **)ngx_array_push(child_phase_arr) = rule;
            }

            if ((rule->actionset == NULL)||(rule->actionset->is_chained == 0)) mode = 0;
        }
    }
}

static int copy_rules(ngx_pool_t *mp, msre_ruleset *parent_ruleset,
                      msre_ruleset *child_ruleset,
                      ngx_array_t *exceptions_arr)
{
    int ret = 0;

    if (parent_ruleset == NULL || child_ruleset == NULL ||
            exceptions_arr == NULL) {
        ret = -1;
        goto failed;
    }

    copy_rules_phase(mp, parent_ruleset->phase_request_headers,
        child_ruleset->phase_request_headers, exceptions_arr);
    copy_rules_phase(mp, parent_ruleset->phase_request_body,
        child_ruleset->phase_request_body, exceptions_arr);
    copy_rules_phase(mp, parent_ruleset->phase_response_headers,
        child_ruleset->phase_response_headers, exceptions_arr);
    copy_rules_phase(mp, parent_ruleset->phase_response_body,
        child_ruleset->phase_response_body, exceptions_arr);
    copy_rules_phase(mp, parent_ruleset->phase_logging,
        child_ruleset->phase_logging, exceptions_arr);

failed:
    return ret;
}

/**
 * Merges two directory configurations.
 */
void *merge_directory_configs(ngx_pool_t *mp, void *_parent, void *_child)
{
    directory_config *parent = (directory_config *)_parent;
    directory_config *child = (directory_config *)_child;
    directory_config *merged = create_directory_config(mp);

    if (merged == NULL) return NULL;

    /* Use values from the child configuration where possible,
     * otherwise use the parent's.
     */

    merged->is_enabled = (child->is_enabled == NGX_CONF_UNSET
        ? parent->is_enabled : child->is_enabled);

    /* IO parameters */
    merged->reqbody_access = (child->reqbody_access == NGX_CONF_UNSET
        ? parent->reqbody_access : child->reqbody_access);

    merged->reqbody_buffering = (child->reqbody_buffering == NGX_CONF_UNSET
        ? parent->reqbody_buffering : child->reqbody_buffering);
    
    merged->reqbody_inmemory_limit = (child->reqbody_inmemory_limit == NGX_CONF_UNSET
        ? parent->reqbody_inmemory_limit : child->reqbody_inmemory_limit);
    
    merged->reqbody_limit = (child->reqbody_limit == NGX_CONF_UNSET
        ? parent->reqbody_limit : child->reqbody_limit);
    
    merged->reqbody_no_files_limit = (child->reqbody_no_files_limit == NGX_CONF_UNSET
        ? parent->reqbody_no_files_limit : child->reqbody_no_files_limit);
    
    merged->resbody_access = (child->resbody_access == NGX_CONF_UNSET
        ? parent->resbody_access : child->resbody_access);

    merged->of_limit = (child->of_limit == NGX_CONF_UNSET
        ? parent->of_limit : child->of_limit);
    
    merged->if_limit_action = (child->if_limit_action == NGX_CONF_UNSET
        ? parent->if_limit_action : child->if_limit_action);
    
    merged->of_limit_action = (child->of_limit_action == NGX_CONF_UNSET
        ? parent->of_limit_action : child->of_limit_action);
    
    merged->reqintercept_oe = (child->reqintercept_oe == NGX_CONF_UNSET
        ? parent->reqintercept_oe : child->reqintercept_oe);

    if (child->of_mime_types != NGX_CONF_UNSET_PTR) {
        /* Child added to the table */

        if (child->of_mime_types_cleared == 1) {
            /* The list of MIME types was cleared in the child,
             * which means the parent's MIME types went away and
             * we should not take them into consideration here.
             */
            merged->of_mime_types = child->of_mime_types;
            merged->of_mime_types_cleared = 1;
        } else {
            /* Add MIME types defined in the child to those
             * defined in the parent context.
             */
            if (parent->of_mime_types == NGX_CONF_UNSET_PTR) {
                merged->of_mime_types = child->of_mime_types;
                merged->of_mime_types_cleared = NGX_CONF_UNSET;
            } else {
                merged->of_mime_types = ngx_table_overlay(mp, parent->of_mime_types,
                    child->of_mime_types);
                if (merged->of_mime_types == NULL) return NULL;
            }
        }
    } else {
        /* Child did not add to the table */

        if (child->of_mime_types_cleared == 1) {
            merged->of_mime_types_cleared = 1;
        } else {
            merged->of_mime_types = parent->of_mime_types;
            merged->of_mime_types_cleared = parent->of_mime_types_cleared;
        }
    }

    /* debug log */
    if (child->debuglog_fd == NGX_CONF_UNSET_PTR) {
        merged->debuglog_name = parent->debuglog_name;
        merged->debuglog_fd = parent->debuglog_fd;
    } else {
        merged->debuglog_name = child->debuglog_name;
        merged->debuglog_fd = child->debuglog_fd;
    }

    merged->debuglog_level = (child->debuglog_level == NGX_CONF_UNSET
        ? parent->debuglog_level : child->debuglog_level);

    merged->cookie_format = (child->cookie_format == NGX_CONF_UNSET
        ? parent->cookie_format : child->cookie_format);
    
    merged->argument_separator = (child->argument_separator == NGX_CONF_UNSET
        ? parent->argument_separator : child->argument_separator);
    
    merged->cookiev0_separator = (child->cookiev0_separator == NGX_CONF_UNSET_PTR
        ? parent->cookiev0_separator : child->cookiev0_separator);


    /* rule inheritance */
    if ((child->rule_inheritance == NGX_CONF_UNSET)||(child->rule_inheritance == 1)) {
        merged->rule_inheritance = parent->rule_inheritance;
        if ((child->ruleset == NULL)&&(parent->ruleset == NULL)) {

            /* Do nothing, there are no rules in either context. */
        } else
        if (child->ruleset == NULL) {

            /* Copy the rules from the parent context. */
            merged->ruleset = msre_ruleset_create(parent->ruleset->engine, mp);
            /* TODO: copy_rules return code should be taken into consideration. */
            copy_rules(mp, parent->ruleset, merged->ruleset, child->rule_exceptions);
        } else
        if (parent->ruleset == NULL) {

            /* Copy child rules. */
            merged->ruleset = msre_ruleset_create(child->ruleset->engine, mp);
            merged->ruleset->phase_request_headers = ngx_array_copy(mp,
                child->ruleset->phase_request_headers);
            merged->ruleset->phase_request_body = ngx_array_copy(mp,
                child->ruleset->phase_request_body);
            merged->ruleset->phase_response_headers = ngx_array_copy(mp,
                child->ruleset->phase_response_headers);
            merged->ruleset->phase_response_body = ngx_array_copy(mp,
                child->ruleset->phase_response_body);
            merged->ruleset->phase_logging = ngx_array_copy(mp,
                child->ruleset->phase_logging);
        } else {

            /* Copy parent rules, then add child rules to it. */
            merged->ruleset = msre_ruleset_create(parent->ruleset->engine, mp);
            /* TODO: copy_rules return code should be taken into consideration. */
            copy_rules(mp, parent->ruleset, merged->ruleset, child->rule_exceptions);

            ngx_array_cat(merged->ruleset->phase_request_headers,
                child->ruleset->phase_request_headers);
            ngx_array_cat(merged->ruleset->phase_request_body,
                child->ruleset->phase_request_body);
            ngx_array_cat(merged->ruleset->phase_response_headers,
                child->ruleset->phase_response_headers);
            ngx_array_cat(merged->ruleset->phase_response_body,
                child->ruleset->phase_response_body);
            ngx_array_cat(merged->ruleset->phase_logging,
                child->ruleset->phase_logging);
        }
    } else {
        merged->rule_inheritance = 0;
        if (child->ruleset != NULL) {
            /* Copy child rules. */
            merged->ruleset = msre_ruleset_create(child->ruleset->engine, mp);
            merged->ruleset->phase_request_headers = ngx_array_copy(mp,
                child->ruleset->phase_request_headers);
            merged->ruleset->phase_request_body = ngx_array_copy(mp,
                child->ruleset->phase_request_body);
            merged->ruleset->phase_response_headers = ngx_array_copy(mp,
                child->ruleset->phase_response_headers);
            merged->ruleset->phase_response_body = ngx_array_copy(mp,
                child->ruleset->phase_response_body);
            merged->ruleset->phase_logging = ngx_array_copy(mp,
                child->ruleset->phase_logging);
        }
    }

    /* Merge rule exceptions. */
    merged->rule_exceptions = ngx_array_append(mp, parent->rule_exceptions,
        child->rule_exceptions);

    merged->hash_method = ngx_array_append(mp, parent->hash_method,
        child->hash_method);

    merged->max_rule_time = (child->max_rule_time == NGX_CONF_UNSET
        ? parent->max_rule_time : child->max_rule_time);

    /* Upload */
    merged->tmp_dir = (child->tmp_dir == NGX_CONF_UNSET_PTR
        ? parent->tmp_dir : child->tmp_dir);
    merged->upload_dir = (child->upload_dir == NGX_CONF_UNSET_PTR
        ? parent->upload_dir : child->upload_dir);
    merged->upload_keep_files = (child->upload_keep_files == NGX_CONF_UNSET
        ? parent->upload_keep_files : child->upload_keep_files);
    merged->upload_validates_files = (child->upload_validates_files == NGX_CONF_UNSET
        ? parent->upload_validates_files : child->upload_validates_files);
    merged->upload_filemode = (child->upload_filemode == NGX_CONF_UNSET
        ? parent->upload_filemode : child->upload_filemode);
    merged->upload_file_limit = (child->upload_file_limit == NGX_CONF_UNSET
        ? parent->upload_file_limit : child->upload_file_limit);

    /* Misc */
    merged->persistdb = (child->persistdb == NGX_CONF_UNSET_PTR
        ? parent->persistdb : child->persistdb);
    merged->webappid = (child->webappid == NGX_CONF_UNSET_PTR
        ? parent->webappid : child->webappid);
    merged->sensor_id = (child->sensor_id == NGX_CONF_UNSET_PTR
        ? parent->sensor_id : child->sensor_id);
    merged->httpBlkey = (child->httpBlkey == NGX_CONF_UNSET_PTR
        ? parent->httpBlkey : child->httpBlkey);

    /* Content injection. */
    merged->content_injection_enabled = (child->content_injection_enabled == NGX_CONF_UNSET
        ? parent->content_injection_enabled : child->content_injection_enabled);

    /* Stream inspection */
    merged->stream_inbody_inspection = (child->stream_inbody_inspection == NGX_CONF_UNSET
        ? parent->stream_inbody_inspection : child->stream_inbody_inspection);
    merged->stream_outbody_inspection = (child->stream_outbody_inspection == NGX_CONF_UNSET
        ? parent->stream_outbody_inspection : child->stream_outbody_inspection);

    /* Geo Lookup */
    merged->geo = (child->geo == NGX_CONF_UNSET_PTR
        ? parent->geo : child->geo);

    /* Gsb Lookup */
    merged->gsb = (child->gsb == NGX_CONF_UNSET_PTR
        ? parent->gsb : child->gsb);

    /* Unicode Map */
    merged->u_map = (child->u_map == NGX_CONF_UNSET_PTR
        ? parent->u_map : child->u_map);

    /* Cache */
    merged->cache_trans = (child->cache_trans == NGX_CONF_UNSET
        ? parent->cache_trans : child->cache_trans);
    merged->cache_trans_incremental = (child->cache_trans_incremental == NGX_CONF_UNSET
        ? parent->cache_trans_incremental : child->cache_trans_incremental);
    merged->cache_trans_min = (child->cache_trans_min == (size_t)NGX_CONF_UNSET
        ? parent->cache_trans_min : child->cache_trans_min);
    merged->cache_trans_max = (child->cache_trans_max == (size_t)NGX_CONF_UNSET
        ? parent->cache_trans_max : child->cache_trans_max);
    merged->cache_trans_maxitems = (child->cache_trans_maxitems == (size_t)NGX_CONF_UNSET
        ? parent->cache_trans_maxitems : child->cache_trans_maxitems);

    /* Merge component signatures. */
    merged->component_signatures = ngx_array_append(mp, parent->component_signatures,
        child->component_signatures);

    merged->request_encoding = (child->request_encoding == NGX_CONF_UNSET_PTR
        ? parent->request_encoding : child->request_encoding);

    merged->disable_backend_compression = (child->disable_backend_compression == NGX_CONF_UNSET
        ? parent->disable_backend_compression : child->disable_backend_compression);

    merged->col_timeout = (child->col_timeout == NGX_CONF_UNSET
        ? parent->col_timeout : child->col_timeout);

    /* Hash */
    merged->crypto_key = (child->crypto_key == NGX_CONF_UNSET_PTR
        ? parent->crypto_key : child->crypto_key);
    merged->crypto_key_len = (child->crypto_key_len == NGX_CONF_UNSET
        ? parent->crypto_key_len : child->crypto_key_len);
    merged->crypto_key_add = (child->crypto_key_add == NGX_CONF_UNSET
        ? parent->crypto_key_add : child->crypto_key_add);
    merged->crypto_param_name = (child->crypto_param_name == NGX_CONF_UNSET_PTR
        ? parent->crypto_param_name : child->crypto_param_name);
    merged->hash_is_enabled = (child->hash_is_enabled == NGX_CONF_UNSET
        ? parent->hash_is_enabled : child->hash_is_enabled);
    merged->hash_enforcement = (child->hash_enforcement == NGX_CONF_UNSET
        ? parent->hash_enforcement : child->hash_enforcement);
    merged->crypto_hash_href_rx = (child->crypto_hash_href_rx == NGX_CONF_UNSET
        ? parent->crypto_hash_href_rx : child->crypto_hash_href_rx);
    merged->crypto_hash_faction_rx = (child->crypto_hash_faction_rx == NGX_CONF_UNSET
        ? parent->crypto_hash_faction_rx : child->crypto_hash_faction_rx);
    merged->crypto_hash_location_rx = (child->crypto_hash_location_rx == NGX_CONF_UNSET
        ? parent->crypto_hash_location_rx : child->crypto_hash_location_rx);
    merged->crypto_hash_iframesrc_rx = (child->crypto_hash_iframesrc_rx == NGX_CONF_UNSET
        ? parent->crypto_hash_iframesrc_rx : child->crypto_hash_iframesrc_rx);
    merged->crypto_hash_framesrc_rx = (child->crypto_hash_framesrc_rx == NGX_CONF_UNSET
        ? parent->crypto_hash_framesrc_rx : child->crypto_hash_framesrc_rx);
    merged->crypto_hash_href_pm = (child->crypto_hash_href_pm == NGX_CONF_UNSET
        ? parent->crypto_hash_href_pm : child->crypto_hash_href_pm);
    merged->crypto_hash_faction_pm = (child->crypto_hash_faction_pm == NGX_CONF_UNSET
        ? parent->crypto_hash_faction_pm : child->crypto_hash_faction_pm);
    merged->crypto_hash_location_pm = (child->crypto_hash_location_pm == NGX_CONF_UNSET
        ? parent->crypto_hash_location_pm : child->crypto_hash_location_pm);
    merged->crypto_hash_iframesrc_pm = (child->crypto_hash_iframesrc_pm == NGX_CONF_UNSET
        ? parent->crypto_hash_iframesrc_pm : child->crypto_hash_iframesrc_pm);
    merged->crypto_hash_framesrc_pm = (child->crypto_hash_framesrc_pm == NGX_CONF_UNSET
        ? parent->crypto_hash_framesrc_pm : child->crypto_hash_framesrc_pm);

    /* xml external entity */
    merged->xml_external_entity = (child->xml_external_entity == NGX_CONF_UNSET
        ? parent->xml_external_entity : child->xml_external_entity);

    return merged;
}

/**
 * Initialise directory configuration. This function is *not* meant
 * to be called for directory configuration instances created during
 * the configuration phase. It can only be called on copies of those
 * (created fresh for every transaction).
 */
void init_directory_config(directory_config *dcfg)
{
    if (dcfg == NULL) return;

    if (dcfg->is_enabled == NGX_CONF_UNSET) dcfg->is_enabled = 0;

    if (dcfg->reqbody_access == NGX_CONF_UNSET) dcfg->reqbody_access = 0;
    if (dcfg->reqintercept_oe == NGX_CONF_UNSET) dcfg->reqintercept_oe = 0;
    if (dcfg->reqbody_buffering == NGX_CONF_UNSET) dcfg->reqbody_buffering = REQUEST_BODY_FORCEBUF_OFF;
    if (dcfg->reqbody_inmemory_limit == NGX_CONF_UNSET)
        dcfg->reqbody_inmemory_limit = REQUEST_BODY_DEFAULT_INMEMORY_LIMIT;
    if (dcfg->reqbody_limit == NGX_CONF_UNSET) dcfg->reqbody_limit = REQUEST_BODY_DEFAULT_LIMIT;
    if (dcfg->reqbody_no_files_limit == NGX_CONF_UNSET) dcfg->reqbody_no_files_limit = REQUEST_BODY_NO_FILES_DEFAULT_LIMIT;
    if (dcfg->resbody_access == NGX_CONF_UNSET) dcfg->resbody_access = 0;
    if (dcfg->of_limit == NGX_CONF_UNSET) dcfg->of_limit = RESPONSE_BODY_DEFAULT_LIMIT;
    if (dcfg->if_limit_action == NGX_CONF_UNSET) dcfg->if_limit_action = REQUEST_BODY_LIMIT_ACTION_REJECT;
    if (dcfg->of_limit_action == NGX_CONF_UNSET) dcfg->of_limit_action = RESPONSE_BODY_LIMIT_ACTION_REJECT;

    if (dcfg->of_mime_types == NGX_CONF_UNSET_PTR) {
        dcfg->of_mime_types = ngx_table_make(dcfg->mp, 3);
        if (dcfg->of_mime_types_cleared != 1) {
            ngx_table_setn(dcfg->of_mime_types, "text/plain", "1");
            ngx_table_setn(dcfg->of_mime_types, "text/html", "1");
        }
    }

    if (dcfg->debuglog_fd == NGX_CONF_UNSET_PTR) dcfg->debuglog_fd = NULL;
    if (dcfg->debuglog_name == NGX_CONF_UNSET_PTR) dcfg->debuglog_name = NULL;
    if (dcfg->debuglog_level == NGX_CONF_UNSET) dcfg->debuglog_level = 0;

    if (dcfg->cookie_format == NGX_CONF_UNSET) dcfg->cookie_format = 0;
    if (dcfg->argument_separator == NGX_CONF_UNSET) dcfg->argument_separator = '&';
    if (dcfg->cookiev0_separator == NGX_CONF_UNSET_PTR) dcfg->cookiev0_separator = NULL;

    if (dcfg->rule_inheritance == NGX_CONF_UNSET) dcfg->rule_inheritance = 1;

    if (dcfg->max_rule_time == NGX_CONF_UNSET) dcfg->max_rule_time = 0;

    /* Upload */
    if (dcfg->tmp_dir == NGX_CONF_UNSET_PTR) dcfg->tmp_dir = guess_tmp_dir(dcfg->mp);
    if (dcfg->upload_dir == NGX_CONF_UNSET_PTR) dcfg->upload_dir = NULL;
    if (dcfg->upload_keep_files == NGX_CONF_UNSET) dcfg->upload_keep_files = KEEP_FILES_OFF;
    if (dcfg->upload_validates_files == NGX_CONF_UNSET) dcfg->upload_validates_files = 0;
    if (dcfg->upload_filemode == NGX_CONF_UNSET) dcfg->upload_filemode = 0600;
    if (dcfg->upload_file_limit == NGX_CONF_UNSET) dcfg->upload_file_limit = 100;

    /* Misc */
    if (dcfg->persistdb == NGX_CONF_UNSET_PTR) dcfg->persistdb = NULL;
    if (dcfg->webappid == NGX_CONF_UNSET_PTR) dcfg->webappid = "default";
    if (dcfg->sensor_id == NGX_CONF_UNSET_PTR) dcfg->sensor_id = "default";
    if (dcfg->httpBlkey == NGX_CONF_UNSET_PTR) dcfg->httpBlkey = NULL;

    /* Content injection. */
    if (dcfg->content_injection_enabled == NGX_CONF_UNSET) dcfg->content_injection_enabled = 0;

    /* Stream inspection */
    if (dcfg->stream_inbody_inspection == NGX_CONF_UNSET) dcfg->stream_inbody_inspection = 0;
    if (dcfg->stream_outbody_inspection == NGX_CONF_UNSET) dcfg->stream_outbody_inspection = 0;

    /* Geo Lookup */
    if (dcfg->geo == NGX_CONF_UNSET_PTR) dcfg->geo = NULL;

    /* Gsb Lookup */
    if (dcfg->gsb == NGX_CONF_UNSET_PTR) dcfg->gsb = NULL;

    /* Unicode Map */
    if (dcfg->u_map == NGX_CONF_UNSET_PTR) dcfg->u_map = NULL;

    /* Cache */
    if (dcfg->cache_trans == NGX_CONF_UNSET) dcfg->cache_trans = MODSEC_CACHE_DISABLED;
    if (dcfg->cache_trans_incremental == NGX_CONF_UNSET) dcfg->cache_trans_incremental = 0;
    if (dcfg->cache_trans_min == (size_t)NGX_CONF_UNSET) dcfg->cache_trans_min = 32;
    if (dcfg->cache_trans_max == (size_t)NGX_CONF_UNSET) dcfg->cache_trans_max = 1024;
    if (dcfg->cache_trans_maxitems == (size_t)NGX_CONF_UNSET) dcfg->cache_trans_maxitems = 512;

    if (dcfg->request_encoding == NGX_CONF_UNSET_PTR) dcfg->request_encoding = NULL;

    if (dcfg->disable_backend_compression == NGX_CONF_UNSET) dcfg->disable_backend_compression = 0;

    if (dcfg->col_timeout == NGX_CONF_UNSET) dcfg->col_timeout = 3600;

    /* Hash */
    if (dcfg->crypto_key == NGX_CONF_UNSET_PTR) dcfg->crypto_key = getkey(dcfg->mp);
    if (dcfg->crypto_key_len == NGX_CONF_UNSET) dcfg->crypto_key_len = strlen(dcfg->crypto_key);
    if (dcfg->crypto_key_add == NGX_CONF_UNSET) dcfg->crypto_key_add = HASH_KEYONLY;
    if (dcfg->crypto_param_name == NGX_CONF_UNSET_PTR) dcfg->crypto_param_name = "crypt";
    if (dcfg->hash_is_enabled == NGX_CONF_UNSET) dcfg->hash_is_enabled = HASH_DISABLED;
    if (dcfg->hash_enforcement == NGX_CONF_UNSET) dcfg->hash_enforcement = HASH_DISABLED;
    if (dcfg->crypto_hash_href_rx == NGX_CONF_UNSET) dcfg->crypto_hash_href_rx = 0;
    if (dcfg->crypto_hash_faction_rx == NGX_CONF_UNSET) dcfg->crypto_hash_faction_rx = 0;
    if (dcfg->crypto_hash_location_rx == NGX_CONF_UNSET) dcfg->crypto_hash_location_rx = 0;
    if (dcfg->crypto_hash_iframesrc_rx == NGX_CONF_UNSET) dcfg->crypto_hash_iframesrc_rx = 0;
    if (dcfg->crypto_hash_framesrc_rx == NGX_CONF_UNSET) dcfg->crypto_hash_framesrc_rx = 0;
    if (dcfg->crypto_hash_href_pm == NGX_CONF_UNSET) dcfg->crypto_hash_href_pm = 0;
    if (dcfg->crypto_hash_faction_pm == NGX_CONF_UNSET) dcfg->crypto_hash_faction_pm = 0;
    if (dcfg->crypto_hash_location_pm == NGX_CONF_UNSET) dcfg->crypto_hash_location_pm = 0;
    if (dcfg->crypto_hash_iframesrc_pm == NGX_CONF_UNSET) dcfg->crypto_hash_iframesrc_pm = 0;
    if (dcfg->crypto_hash_framesrc_pm == NGX_CONF_UNSET) dcfg->crypto_hash_framesrc_pm = 0;

    /* xml external entity */
    if (dcfg->xml_external_entity == NGX_CONF_UNSET) dcfg->xml_external_entity = 0;

}

static char *add_rule(ngx_conf_t *cf, directory_config *dcfg, int type,
                            const char *p1, const char *p2, const char *p3)
{
    char *my_error_msg = NULL;
    //msre_rule *rule = NULL, *tmp_rule = NULL;
    char *rid = NULL;
    msre_rule *rule = NULL;
    extern msc_engine *modsecurity;

    /* Create a ruleset if one does not exist. */
    if ((dcfg->ruleset == NULL)||(dcfg->ruleset == NGX_CONF_UNSET_PTR)) {
        dcfg->ruleset = msre_ruleset_create(modsecurity->msre, dcfg->mp);
        if (dcfg->ruleset == NULL) return FATAL_ERROR;
    }

    /* Create the rule now. */
    switch(type) {
        #if defined(WITH_LUA)
        case RULE_TYPE_LUA :
            rule = msre_rule_lua_create(dcfg->ruleset, conf_file_name(cf),
                conf_file_line(cf), p1, p2, &my_error_msg);
            break;
        #endif
        default :
            rule = msre_rule_create(dcfg->ruleset, type, conf_file_name(cf),
                conf_file_line(cf), p1, p2, p3, &my_error_msg);
            break;
    }

    if (rule == NULL) {
        return my_error_msg;
    }
    
    #if 0
    /* Rules must have uniq ID */
    if ((dcfg->tmp_chain_starter == NULL)&&rule->actionset == NULL)
        return "ModSecurity: Rules must have at least id action";
    #endif

    if(rule->actionset != NULL && (dcfg->tmp_chain_starter == NULL))    {
        
        #if 0
        if(rule->actionset->id == NGX_CONF_UNSET_PTR)
            return "ModSecurity: No action id present within the rule";
        #endif

        if(rule->actionset->id != NGX_CONF_UNSET_PTR){
            
            rid = ngx_hash2_get(dcfg->rule_id_htab, rule->actionset->id, NGX_HASH_KEY_STRING);
            if(rid != NULL) {
                return ngx_pstrcat(dcfg->mp,"ModSecurity: Found another rule with the same id:",rule->actionset->id,NULL);
            } else    {
                ngx_hash2_set(dcfg->rule_id_htab, ngx_pstrndup(dcfg->mp, rule->actionset->id), NGX_HASH_KEY_STRING, ngx_pstrndup(dcfg->mp, "1"));
            }
        
        }
    }

    /* Create default actionset if one does not already exist. */
    if (dcfg->tmp_default_actionset == NULL) {
        dcfg->tmp_default_actionset = msre_actionset_create_default(modsecurity->msre);
        if (dcfg->tmp_default_actionset == NULL) return FATAL_ERROR;
    }

    /* Check some cases prior to merging so we know where it came from */

    /* Check syntax for chained rules */
    if ((rule->actionset != NULL) && (dcfg->tmp_chain_starter != NULL)) {
        /* Must NOT specify a disruptive action. */
        if (rule->actionset->intercept_action != NGX_CONF_UNSET) {
            return ngx_pstrndup(dcfg->mp, "ModSecurity: Disruptive actions can only "
                "be specified by chain starter rules.");
        }

        /* Must NOT specify a skipafter action. */
        if (rule->actionset->skip_after != NGX_CONF_UNSET_PTR) {
            return ngx_pstrndup(dcfg->mp, "ModSecurity: SkipAfter actions can only "
                "be specified by chain starter rules.");
        }

        /* Must NOT specify a phase. */
        if (rule->actionset->phase != NGX_CONF_UNSET) {
            return ngx_pstrndup(dcfg->mp, "ModSecurity: Execution phases can only be "
                "specified by chain starter rules.");
        }

        /* Must NOT use metadata actions. */
        /* ENH: loop through to check for tags */
        if ((rule->actionset->id != NGX_CONF_UNSET_PTR)
            ||(rule->actionset->rev != NGX_CONF_UNSET_PTR)
            ||(rule->actionset->msg != NGX_CONF_UNSET_PTR)
            ||(rule->actionset->severity != NGX_CONF_UNSET)
            ||(rule->actionset->version != NGX_CONF_UNSET_PTR)
            ||(rule->actionset->accuracy != NGX_CONF_UNSET)
            ||(rule->actionset->maturity != NGX_CONF_UNSET)
            ||(rule->actionset->logdata != NGX_CONF_UNSET_PTR))
        {
            return ngx_pstrndup(dcfg->mp, "ModSecurity: Metadata actions (id, rev, msg, tag, severity, ver, accuracy, maturity, logdata) "
                " can only be specified by chain starter rules.");
        }

        /* Must NOT use skip. */
        if (rule->actionset->skip_count != NGX_CONF_UNSET) {
            return ngx_pstrndup(dcfg->mp, "ModSecurity: The skip action can only be used "
                " by chain starter rules. ");
        }
    }

    /* Merge actions with the parent.
     *
     * ENH Probably do not want this done fully for chained rules.
     */
    rule->actionset = msre_actionset_merge(modsecurity->msre, dcfg->mp, dcfg->tmp_default_actionset,
        rule->actionset, 1);

    /* Keep track of the parent action for "block" */
    rule->actionset->parent_intercept_action_rec = dcfg->tmp_default_actionset->intercept_action_rec;
    rule->actionset->parent_intercept_action = dcfg->tmp_default_actionset->intercept_action;

    /* Must NOT specify a disruptive action in logging phase. */
    if ((rule->actionset != NULL)
        && (rule->actionset->phase == PHASE_LOGGING)
        && (rule->actionset->intercept_action != ACTION_ALLOW)
        && (rule->actionset->intercept_action != ACTION_ALLOW_REQUEST)
        && (rule->actionset->intercept_action != ACTION_NONE)
    ) {
        return ngx_pstrndup(dcfg->mp, "ModSecurity: Disruptive actions "
            "cannot be specified in the logging phase.");
    }

    if (dcfg->tmp_chain_starter != NULL) {
        rule->chain_starter = dcfg->tmp_chain_starter;
        rule->actionset->phase = rule->chain_starter->actionset->phase;
    }

    if (rule->actionset->is_chained != 1) {
        /* If this rule is part of the chain but does
         * not want more rules to follow in the chain
         * then cut it (the chain).
         */
        dcfg->tmp_chain_starter = NULL;
    } else {
        /* On the other hand, if this rule wants other
         * rules to follow it, then start a new chain
         * if there isn't one already.
         */
        if (dcfg->tmp_chain_starter == NULL) {
            dcfg->tmp_chain_starter = rule;
        }
    }

    /* Create skip table if one does not already exist. */
    if (dcfg->tmp_rule_placeholders == NULL) {
        dcfg->tmp_rule_placeholders = ngx_table_make(dcfg->mp, 10);
        if (dcfg->tmp_rule_placeholders == NULL) return FATAL_ERROR;
    }

    /* Keep track of any rule IDs we need to skip after */
    if (rule->actionset->skip_after != NGX_CONF_UNSET_PTR) {
        char *tmp_id = ngx_pstrndup(dcfg->mp, rule->actionset->skip_after);
        ngx_table_setn(dcfg->tmp_rule_placeholders, tmp_id, tmp_id);

    }

    /* Add rule to the recipe. */
    if (msre_ruleset_rule_add(dcfg->ruleset, rule, rule->actionset->phase) < 0) {
        return "Internal Error: Failed to add rule to the ruleset.";
    }

    /* Add an additional placeholder if this rule ID is on the list */
    if ((rule->actionset->id != NULL) && ngx_table_get(dcfg->tmp_rule_placeholders, rule->actionset->id)) {
        msre_rule *phrule = (msre_rule*)ngx_palloc(rule->ruleset->mp, sizeof(msre_rule));
        if (phrule == NULL) {
            return FATAL_ERROR;
        }

        /* shallow copy of original rule with placeholder marked as target */
        memcpy(phrule, rule, sizeof(msre_rule));
        phrule->placeholder = RULE_PH_SKIPAFTER;

        /* Add placeholder. */
        if (msre_ruleset_rule_add(dcfg->ruleset, phrule, phrule->actionset->phase) < 0) {
            return "Internal Error: Failed to add placeholder to the ruleset.";
        }

        /* No longer need to search for the ID */
        ngx_table_unset(dcfg->tmp_rule_placeholders, rule->actionset->id);
    }

    /* Update the unparsed rule */
    rule->unparsed = msre_rule_generate_unparsed(dcfg->ruleset->mp, rule, NULL, NULL, NULL);

    return NULL;
}

static char* ngx_conf_set_cmd_action(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
   
    directory_config *dcfg = doc_config(conf);
    char *p1;
    set_arg_ptr(cf,&p1,1);

    return add_rule(cf,dcfg, RULE_TYPE_ACTION, SECACTION_TARGETS, SECACTION_ARGS, (const char*)p1);
}

static char* ngx_conf_set_cmd_argument_separator(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
   
    directory_config *dcfg = doc_config(conf);
    char *p1;
    arg_check(dcfg->argument_separator);
    
    set_arg_ptr(cf,&p1,1);
    

    if (strlen(p1) != 1) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid argument separator: ", p1,NULL);
    }
    
    dcfg->argument_separator = p1[0];

    return NULL;
}

static char* ngx_conf_set_cmd_cookiev0_separator(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
   
    directory_config *dcfg = doc_config(conf);
    char *p1;
    arg_check_ptr(dcfg->cookiev0_separator);
    
    set_arg_ptr(cf,&p1,1);
    

    if (strlen(p1) != 1) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid cookie v0 separator: ", p1,NULL);
    }
    
    dcfg->cookiev0_separator = p1;

    return NULL;
}

static char* ngx_conf_set_cmd_cache_transformations(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
   
    directory_config *dcfg = doc_config(conf);
    char *p1,*p2;
    arg_check(dcfg->cache_trans);
    
    set_arg_ptr(cf,&p1,1);
    set_arg_ptr(cf,&p2,2);
    

    if (strcasecmp(p1, "on") == 0)
        dcfg->cache_trans = MODSEC_CACHE_ENABLED;
    else if (strcasecmp(p1, "off") == 0)
        dcfg->cache_trans = MODSEC_CACHE_DISABLED;
    else
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for SecCacheTransformations: ", p1,NULL);

    /* Process options */
    if (p2 != NULL) {
        ngx_table_t *vartable = ngx_table_make(dcfg->mp, 4);
        ngx_int_t rc;
        char *error_msg = NULL;
        const char *charval = NULL;
        int64_t intval = 0;

        if (vartable == NULL) {
            return ngx_pstrndup(dcfg->mp, "ModSecurity: Unable to process options for SecCacheTransformations");
        }
        rc = msre_parse_generic(dcfg->mp, p2, vartable, &error_msg);
        if (rc < 0) {
            return ngx_pstrcat(dcfg->mp, "ModSecurity: Unable to parse options for SecCacheTransformations: ", error_msg,NULL);
        }

        /* incremental */
        charval = ngx_table_get(vartable, "incremental");
        if (charval != NULL) {
            if (strcasecmp(charval, "on") == 0)
                dcfg->cache_trans_incremental = 1;
            else if (strcasecmp(charval, "off") == 0)
                dcfg->cache_trans_incremental = 0;
            else
                return ngx_pstrcat(dcfg->mp, "ModSecurity: SecCacheTransformations invalid incremental value: ", charval,NULL);
        }

        /* minlen */
        charval = ngx_table_get(vartable, "minlen");
        if (charval != NULL) {
            intval = ngx_atoi64(charval);
            if (errno == ERANGE) {
                return ngx_pstrcat(dcfg->mp, "ModSecurity: SecCacheTransformations minlen out of range: ", charval,NULL);
            }
            if (intval < 0) {
                return ngx_pstrcat(dcfg->mp, "ModSecurity: SecCacheTransformations minlen must be positive: ", charval,NULL);
            }

            /* The NGX_CONF_UNSET indicator is -1, a signed long, and therfore
             * we cannot be >= the unsigned value of NGX_CONF_UNSET.
             */
            if ((unsigned long)intval >= (unsigned long)NGX_CONF_UNSET) {
                return ngx_psprintf(dcfg->mp,
                        NGX_INT64_LEN+ngx_strlen("ModSecurity: SecCacheTransformations minlen must be less than: %ul")+2,
                        "ModSecurity: SecCacheTransformations minlen must be less than: %ul", (unsigned long)NGX_CONF_UNSET);
            }
            dcfg->cache_trans_min = (size_t)intval;
        }

        /* maxlen */
        charval = ngx_table_get(vartable, "maxlen");
        if (charval != NULL) {
            intval = ngx_atoi64(charval);
            if (errno == ERANGE) {
                return ngx_pstrcat(dcfg->mp, "ModSecurity: SecCacheTransformations maxlen out of range: ", charval,NULL);
            }
            if (intval < 0) {
                return ngx_pstrcat(dcfg->mp, "ModSecurity: SecCacheTransformations maxlen must be positive: ", charval,NULL);
            }

            /* The NGX_CONF_UNSET indicator is -1, a signed long, and therfore
             * we cannot be >= the unsigned value of NGX_CONF_UNSET.
             */
            if ((unsigned long)intval >= (unsigned long)NGX_CONF_UNSET) {
                return ngx_psprintf(dcfg->mp,
                        ngx_strlen("ModSecurity: SecCacheTransformations maxlen must be less than: %ul")+NGX_INT64_LEN+2,
                        "ModSecurity: SecCacheTransformations maxlen must be less than: %ul", (unsigned long)NGX_CONF_UNSET);
            }

            if ((intval != 0) && ((size_t)intval < dcfg->cache_trans_min)) {
                return ngx_psprintf(dcfg->mp,
                        ngx_strlen("ModSecurity: SecCacheTransformations maxlen must not be less than minlen: %ul < %z")+NGX_INT64_LEN*2+2,
                        "ModSecurity: SecCacheTransformations maxlen must not be less than minlen: %ul < %z",
                        (unsigned long)intval, dcfg->cache_trans_min);
            }
            dcfg->cache_trans_max = (size_t)intval;

        }

        /* maxitems */
        charval = ngx_table_get(vartable, "maxitems");
        if (charval != NULL) {
            intval = ngx_atoi64(charval);
            if (errno == ERANGE) {
                return ngx_pstrcat(dcfg->mp, "ModSecurity: SecCacheTransformations maxitems out of range: ", charval,NULL);
            }
            if (intval < 0) {
                return ngx_pstrcat(dcfg->mp, "ModSecurity: SecCacheTransformations maxitems must be positive: ", charval,NULL);
            }
            dcfg->cache_trans_maxitems = (size_t)intval;
        }
    }

    return NULL;

}

static char* ngx_conf_set_cmd_component_signature(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
   
    directory_config *dcfg = doc_config(conf);
    char *p1;
    set_arg_ptr(cf,&p1,1);
    
    /* ENH Enforce "Name/VersionX.Y.Z (comment)" format. */
    *(char **)ngx_array_push(dcfg->component_signatures) = (char *)p1;

    return NULL;
}

static char* ngx_conf_set_cmd_content_injection(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){


    directory_config *dcfg = doc_config(conf);
    char *p1;
    int flag;

    arg_check(dcfg->content_injection_enabled);
    
    set_arg_ptr(cf,&p1,1);

    flag  = strtoflag(p1);

    if(flag==-1) return "must be on or off";
    
    dcfg->content_injection_enabled = flag;

    return NULL;
}

static char* ngx_conf_set_cmd_stream_outbody_inspection(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){


    directory_config *dcfg = doc_config(conf);
    char *p1;
    int flag;

    arg_check(dcfg->stream_outbody_inspection);
    
    set_arg_ptr(cf,&p1,1);

    flag  = strtoflag(p1);

    if(flag ==-1) return "must be on or off";
    
    dcfg->stream_outbody_inspection = flag;

    return NULL;
}

static char* ngx_conf_set_cmd_stream_inbody_inspection(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){


    directory_config *dcfg = doc_config(conf);
    char *p1;
    int flag;

    arg_check(dcfg->stream_inbody_inspection);
    
    set_arg_ptr(cf,&p1,1);

    flag  = strtoflag(p1);

    if(flag==-1) return "must be on or off";
    
    dcfg->stream_inbody_inspection = flag;

    return NULL;
}

static char* ngx_conf_set_cmd_cookie_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){


    directory_config *dcfg = doc_config(conf);
    char *p1;

    arg_check(dcfg->cookie_format);
    
    set_arg_ptr(cf,&p1,1);
    
    if (strcmp(p1, "0") == 0) dcfg->cookie_format = COOKIES_V0;
    else if (strcmp(p1, "1") == 0) dcfg->cookie_format = COOKIES_V1;
    else {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid cookie format: ", p1,NULL);
    }

    return NULL;
}

static char* ngx_conf_set_cmd_persistdb(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){


    directory_config *dcfg = doc_config(conf);
    char *p1;
    char *errmsg;

    arg_check_ptr(dcfg->persistdb);
    
    set_arg_ptr(cf,&p1,1);
    

    dcfg->persistdb = do_open_kvstore(dcfg->mp,p1,&errmsg);
    
    if(dcfg->persistdb== NULL) return errmsg;

    return NULL;

}

static char* ngx_conf_set_cmd_debug_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){


    directory_config *dcfg = doc_config(conf);
    char *p1;

    arg_check_ptr(dcfg->debuglog_name);
    
    set_arg_ptr(cf,&p1,1);
    
    dcfg->debuglog_name = p1;
    
    dcfg->debuglog_fd = ngx_open_file_log(dcfg->mp,dcfg->debuglog_name);

    if (dcfg->debuglog_fd == NULL) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Failed to open debug log file: ",
            dcfg->debuglog_name,NULL);
    }

    return NULL;
}

static char* ngx_conf_set_cmd_debug_log_level(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){


    directory_config *dcfg = doc_config(conf);
    char *p1;

    arg_check(dcfg->debuglog_level);
    
    set_arg_ptr(cf,&p1,1);
    
    dcfg->debuglog_level = atoi(p1);
    if ((dcfg->debuglog_level >= 0)&&(dcfg->debuglog_level <= 9)) return NULL;

    return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for SecDebugLogLevel: ", p1,NULL);
}

static char* ngx_conf_set_cmd_collection_timeout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){


    directory_config *dcfg = doc_config(conf);
    char *p1;

    arg_check(dcfg->col_timeout);
    
    set_arg_ptr(cf,&p1,1);
    
    dcfg->col_timeout = atoi(p1);
    /* max 30 days */
    if ((dcfg->col_timeout >= 0)&&(dcfg->col_timeout <= 2592000)) return NULL;

    return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for SecCollectionTimeout: ", p1,NULL);
}

static char* ngx_conf_set_cmd_default_action(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){


    char *p1;
    char *my_error_msg = NULL;
    extern msc_engine *modsecurity;
    directory_config *dcfg = doc_config(conf);
    
    set_arg_ptr(cf,&p1,1);

    dcfg->tmp_default_actionset = msre_actionset_create(modsecurity->msre, dcfg->mp, p1, &my_error_msg);
    if (dcfg->tmp_default_actionset == NULL) {
        if (my_error_msg != NULL) return my_error_msg;
        else return FATAL_ERROR;
    }

    /* Must specify a disruptive action. */
    /* ENH: Remove this requirement? */
    if (dcfg->tmp_default_actionset->intercept_action == NGX_CONF_UNSET) {
        return ngx_pstrndup(dcfg->mp, "ModSecurity: SecDefaultAction must specify a disruptive action.");
    }

    /* Must specify a phase. */
    /* ENH: Remove this requirement? */
    if (dcfg->tmp_default_actionset->phase == NGX_CONF_UNSET) {
        return ngx_pstrndup(dcfg->mp, "ModSecurity: SecDefaultAction must specify a phase.");
    }

    /* Must not use metadata actions. */
    /* ENH: loop through to check for tags */
    if ((dcfg->tmp_default_actionset->id != NGX_CONF_UNSET_PTR)
        ||(dcfg->tmp_default_actionset->rev != NGX_CONF_UNSET_PTR)
        ||(dcfg->tmp_default_actionset->version != NGX_CONF_UNSET_PTR)
        ||(dcfg->tmp_default_actionset->maturity != NGX_CONF_UNSET)
        ||(dcfg->tmp_default_actionset->accuracy != NGX_CONF_UNSET)
        ||(dcfg->tmp_default_actionset->msg != NGX_CONF_UNSET_PTR))
    {
        return ngx_pstrndup(dcfg->mp, "ModSecurity: SecDefaultAction must not "
            "contain any metadata actions (id, rev, msg, tag, severity, ver, accuracy, maturity, logdata).");
    }

    /* Must not use chain. */
    if (dcfg->tmp_default_actionset->is_chained != NGX_CONF_UNSET) {
        return ngx_pstrndup(dcfg->mp, "ModSecurity: SecDefaultAction must not "
            "contain a chain action.");
    }

    /* Must not use skip. */
    if (dcfg->tmp_default_actionset->skip_count != NGX_CONF_UNSET) {
        return ngx_pstrndup(dcfg->mp, "ModSecurity: SecDefaultAction must not "
            "contain a skip action.");
    }

    /* Must not use skipAfter. */
    if (dcfg->tmp_default_actionset->skip_after != NGX_CONF_UNSET_PTR) {
        return ngx_pstrndup(dcfg->mp, "ModSecurity: SecDefaultAction must not "
            "contain a skipAfter action.");
    }

    return NULL;
}

static char* ngx_conf_set_cmd_disable_backend_compression(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){


    directory_config *dcfg = doc_config(conf);
    char *p1;
    int flag;

    arg_check(dcfg->disable_backend_compression);
    
    set_arg_ptr(cf,&p1,1);

    flag  = strtoflag(p1);

    if(flag==-1) return "must be on or off";
    
    dcfg->disable_backend_compression = flag;

    return NULL;
}

static char* ngx_conf_set_cmd_gsb_lookup_db(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){


    char *error_msg;
    char *p1;
    
    directory_config *dcfg = doc_config(conf);
    
    set_arg_ptr(cf,&p1,1);


    if (gsb_db_init(dcfg, p1, &error_msg) <= 0) {
        return error_msg;
    }

    return NULL;
}

static char* ngx_conf_set_cmd_unicode_codepage(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;
    long val;
    
    directory_config *dcfg = doc_config(conf);
    
    set_arg_ptr(cf,&p1,1);

    val = atol(p1);
    if (val <= 0) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid setting for "
                                       "SecUnicodeCodePage: ", p1,NULL);
    }

    unicode_codepage = (unsigned long int)val;

    return NULL;
}

static char* ngx_conf_set_cmd_unicode_map(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *error_msg;
    char *p1,*p2;
    long val = 0;
    
    directory_config *dcfg = doc_config(conf);
    
    set_arg_ptr(cf,&p1,1);
    set_arg_ptr(cf,&p2,2);

    if(p2 != NULL)  {
        val = atol(p2);
        if (val <= 0) {
            return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid setting for "
                    "SecUnicodeMapFile: ", p2,NULL);
        }

        unicode_codepage = (unsigned long int)val;
    }

    if (unicode_map_init(dcfg, p1, &error_msg) <= 0) {
        return error_msg;
    }

    return NULL;
}

static char* ngx_conf_set_cmd_geo_lookup_db(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;
    char *error_msg;
    
    directory_config *dcfg = doc_config(conf);
    
    set_arg_ptr(cf,&p1,1);

    if (geo_init(dcfg, p1, &error_msg) <= 0) {
        return error_msg;
    }

    return NULL;
}

static char *add_marker(ngx_conf_t *cf, directory_config *dcfg,
                              const char *p1, const char *p2, const char *p3)
{
    char *my_error_msg = NULL;
    msre_rule *rule = NULL;
    extern msc_engine *modsecurity;
    int p;

    /* Create a ruleset if one does not exist. */
    if ((dcfg->ruleset == NULL)||(dcfg->ruleset == NGX_CONF_UNSET_PTR)) {
        dcfg->ruleset = msre_ruleset_create(modsecurity->msre, dcfg->mp);
        if (dcfg->ruleset == NULL) return FATAL_ERROR;
    }

    /* Create the rule now. */
    rule = msre_rule_create(dcfg->ruleset, RULE_TYPE_MARKER, conf_file_name(cf),conf_file_line(cf), p1, p2, p3, &my_error_msg);
    if (rule == NULL) {
        return my_error_msg;
    }

    /* This is a marker */
    rule->placeholder = RULE_PH_MARKER;

    /* Add placeholder to each phase */
    for (p = PHASE_FIRST; p <= PHASE_LAST; p++) {

        if (msre_ruleset_rule_add(dcfg->ruleset, rule, p) < 0) {
            return "Internal Error: Failed to add marker to the ruleset.";
        }
    }

    /* No longer need to search for the ID */
    if (dcfg->tmp_rule_placeholders != NULL) {
        ngx_table_unset(dcfg->tmp_rule_placeholders, rule->actionset->id);
    }

    return NULL;
}

static char* ngx_conf_set_cmd_marker(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;
    
    directory_config *dcfg = doc_config(conf);
    
    set_arg_ptr(cf,&p1,1);

    const char *action = ngx_pstrcat(dcfg->mp, SECMARKER_BASE_ACTIONS, p1, NULL);
    
    return add_marker(cf, dcfg, SECMARKER_TARGETS, SECMARKER_ARGS, action);
}

static char* ngx_conf_set_cmd_pcre_match_limit(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    long val;
    char *p1;
    
    directory_config *dcfg = doc_config(conf);
    
    set_arg_ptr(cf,&p1,1);

    val = atol(p1);
    if (val <= 0) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid setting for "
                "SecPcreMatchLimit: ", p1,NULL);
    }
    
    msc_pcre_match_limit = (unsigned long int)val;

    return NULL;
}

static char* ngx_conf_set_cmd_pcre_match_limit_recursion(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    long val;
    char *p1;
    
    directory_config *dcfg = doc_config(conf);
    
    set_arg_ptr(cf,&p1,1);

    val = atol(p1);
    if (val <= 0) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid setting for "
                "SecPcreMatchLimitRecursion: ", p1,NULL);
    }
    msc_pcre_match_limit_recursion = (unsigned long int)val;

    return NULL;
}

static char* ngx_conf_set_cmd_request_body_access(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;
    int flag;

    directory_config *dcfg = doc_config(conf);

    arg_check(dcfg->reqbody_access);

    set_arg_ptr(cf,&p1,1);
    
    flag = strtoflag(p1);

    if(flag == -1){
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for SecRequestBodyAccess: ", p1,NULL);
    }

    dcfg->reqbody_access = flag;
    
    return NULL;
}    

static char* ngx_conf_set_cmd_request_intercept_on_error(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;
    int flag;

    directory_config *dcfg = doc_config(conf);

    arg_check(dcfg->reqintercept_oe);

    set_arg_ptr(cf,&p1,1);
    
    flag = strtoflag(p1);

    if(flag == -1){
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for SecInterceptOnError: ", p1,NULL);
    }

    dcfg->reqintercept_oe = flag;
    
    return NULL;
}    

static char* ngx_conf_set_cmd_rule_perf_time(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;
    long int limit;

    directory_config *dcfg = doc_config(conf);

    arg_check(dcfg->max_rule_time);

    set_arg_ptr(cf,&p1,1);

    limit = strtol(p1, NULL, 10);
    if ((limit == LONG_MAX)||(limit == LONG_MIN)||(limit <= 0)) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for SecRulePerfTime: ", p1,NULL);
    }

    dcfg->max_rule_time = limit;

    return NULL;
}

static char* ngx_conf_set_cmd_request_body_inmemory_limit(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;
    long int limit;

    directory_config *dcfg = doc_config(conf);

    arg_check(dcfg->reqbody_inmemory_limit);

    set_arg_ptr(cf,&p1,1);

    limit = strtol(p1, NULL, 10);
    if ((limit == LONG_MAX)||(limit == LONG_MIN)||(limit <= 0)) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for SecRequestBodyInMemoryLimit: ", p1,NULL);
    }

    dcfg->reqbody_inmemory_limit = limit;

    return NULL;
}

static char* ngx_conf_set_cmd_request_body_limit(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;
    long int limit;

    directory_config *dcfg = doc_config(conf);

    arg_check(dcfg->reqbody_limit);

    set_arg_ptr(cf,&p1,1);

    limit = strtol(p1, NULL, 10);
    if ((limit == LONG_MAX)||(limit == LONG_MIN)||(limit <= 0)) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for SecRequestBodyLimit: ", p1,NULL);
    }

    dcfg->reqbody_limit = limit;

    return NULL;
}
    
static char* ngx_conf_set_cmd_request_body_no_files_limit(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;
    long int limit;

    directory_config *dcfg = doc_config(conf);

    arg_check(dcfg->reqbody_no_files_limit);

    set_arg_ptr(cf,&p1,1);

    limit = strtol(p1, NULL, 10);
    if ((limit == LONG_MAX)||(limit == LONG_MIN)||(limit <= 0)) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for SecRequestBodyNoFilesLimit: ", p1,NULL);
    }

    dcfg->reqbody_no_files_limit = limit;

    return NULL;
}

static char* ngx_conf_set_cmd_request_encoding(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;

    directory_config *dcfg = doc_config(conf);

    arg_check_ptr(dcfg->request_encoding);

    set_arg_ptr(cf,&p1,1);

    /* ENH Validate encoding */
    dcfg->request_encoding = p1;

    return NULL;
}

static char* ngx_conf_set_cmd_response_body_access(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;
    int flag;

    directory_config *dcfg = doc_config(conf);

    arg_check(dcfg->resbody_access);

    set_arg_ptr(cf,&p1,1);

    flag = strtoflag(p1);

    if(flag == -1){
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for SecResponseBodyAccess: ", p1,NULL);
    }

    dcfg->resbody_access = flag;

    return NULL;
}

static char* ngx_conf_set_cmd_response_body_limit(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    long int limit;
    char *p1;

    directory_config *dcfg = doc_config(conf);

    arg_check(dcfg->of_limit);

    set_arg_ptr(cf,&p1,1);


    limit = strtol(p1, NULL, 10);
    if ((limit == LONG_MAX)||(limit == LONG_MIN)||(limit <= 0)) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for SecResponseBodyLimit: ", p1,NULL);
    }

    if (limit > RESPONSE_BODY_HARD_LIMIT) {
        return ngx_psprintf(dcfg->mp, NGX_INT64_LEN+ngx_strlen("ModSecurity: Response size limit can not exceed the hard limit: %li")+2,
                "ModSecurity: Response size limit can not exceed the hard limit: %l", RESPONSE_BODY_HARD_LIMIT);
    }

    dcfg->of_limit = limit;

    return NULL;
}

static char* ngx_conf_set_cmd_cmd_resquest_body_limit_action(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;

    directory_config *dcfg = doc_config(conf);

    arg_check(dcfg->if_limit_action);

    set_arg_ptr(cf,&p1,1);
    
    if (dcfg->is_enabled == MODSEC_DETECTION_ONLY)  {
        dcfg->if_limit_action = REQUEST_BODY_LIMIT_ACTION_PARTIAL;
        return NULL;
    }

    if (strcasecmp(p1, "ProcessPartial") == 0) dcfg->if_limit_action = REQUEST_BODY_LIMIT_ACTION_PARTIAL;
    else if (strcasecmp(p1, "Reject") == 0) dcfg->if_limit_action = REQUEST_BODY_LIMIT_ACTION_REJECT;
    else
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for SecRequestBodyLimitAction: ", p1,NULL);

    return NULL;

}

static char* ngx_conf_set_cmd_response_body_mime_type(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *_p1;

    directory_config *dcfg = doc_config(conf);

    set_arg_ptr(cf,&_p1,1);

    char *p1 = ngx_pstrndup(dcfg->mp, _p1);

    /* TODO check whether the parameter is a valid MIME type of "???" */

    if ((dcfg->of_mime_types == NULL)||(dcfg->of_mime_types == NGX_CONF_UNSET_PTR)) {
        dcfg->of_mime_types = ngx_table_make(dcfg->mp, 10);
    }

    strtolower_inplace((unsigned char *)p1);
    ngx_table_setn(dcfg->of_mime_types, p1, "1");

    return NULL;
}

static char* ngx_conf_set_cmd_response_body_mime_types_clear(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    directory_config *dcfg = doc_config(conf);

    dcfg->of_mime_types_cleared = 1;

    if ((dcfg->of_mime_types != NULL)&&(dcfg->of_mime_types != NGX_CONF_UNSET_PTR)) {
        ngx_table_clear(dcfg->of_mime_types);
    }

    return NULL;
}


static char* ngx_conf_set_cmd_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1,*p2,*p3;

    directory_config *dcfg = doc_config(conf);

    set_arg_ptr(cf,&p1,1);
    set_arg_ptr(cf,&p2,2);
    set_arg_ptr(cf,&p3,3);

    return add_rule(cf,dcfg, RULE_TYPE_NORMAL, p1, p2, p3);
}

static char* ngx_conf_set_cmd_rule_engine(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;

    directory_config *dcfg = doc_config(conf);
    arg_check(dcfg->is_enabled);
    set_arg_ptr(cf,&p1,1);

    if (strcasecmp(p1, "on") == 0)
    {
        dcfg->is_enabled = MODSEC_ENABLED;
    }
    else if (strcasecmp(p1, "off") == 0)
    {
        dcfg->is_enabled = MODSEC_DISABLED;
    }
    else if (strcasecmp(p1, "detectiononly") == 0)
    {
        dcfg->is_enabled = MODSEC_DETECTION_ONLY;
        dcfg->of_limit_action = RESPONSE_BODY_LIMIT_ACTION_PARTIAL;
        dcfg->if_limit_action = REQUEST_BODY_LIMIT_ACTION_PARTIAL;
    }
    else
    {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for " \
                "SecRuleEngine: ", p1,NULL);
    }

    return NULL;
}

static char* ngx_conf_set_cmd_xml_external_entity(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;
    int flag;

    directory_config *dcfg = doc_config(conf);

    arg_check(dcfg->xml_external_entity);

    set_arg_ptr(cf,&p1,1);

    flag = strtoflag(p1);

    if(flag == -1){
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for SecXmlExternalEntity: ", p1,NULL);
    }

    dcfg->xml_external_entity = flag;

    return NULL;
}


static char* ngx_conf_set_cmd_rule_inheritance(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;
    int flag;

    directory_config *dcfg = doc_config(conf);

    arg_check(dcfg->rule_inheritance);

    set_arg_ptr(cf,&p1,1);

    flag = strtoflag(p1);

    if(flag == -1){
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for SecRuleInheritance: ", p1,NULL);
    }

    dcfg->rule_inheritance = flag;

    return NULL;
}

static char* ngx_conf_set_cmd_rule_script(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    #if defined(WITH_LUA)
    char *p1,*p2;

    directory_config *dcfg = doc_config(conf);

    set_arg_ptr(cf,&p1,1);
    set_arg_ptr(cf,&p2,2);

    return add_rule(cf,dcfg, RULE_TYPE_LUA, p1, p2, NULL);
    #else
    return NULL;
    #endif
}

static char* ngx_conf_set_cmd_rule_remove_by_id(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;

    directory_config *dcfg = doc_config(conf);

    set_arg_ptr(cf,&p1,1);
    
    rule_exception *re = (rule_exception*)ngx_pcalloc(dcfg->mp, sizeof(rule_exception));

    re->type = RULE_EXCEPTION_REMOVE_ID;
    re->param = p1;
    *(rule_exception **)ngx_array_push(dcfg->rule_exceptions) = re;

    /* Remove the corresponding rules from the context straight away. */
    msre_ruleset_rule_remove_with_exception(dcfg->ruleset, re);

    return NULL;

}

static char* ngx_conf_set_cmd_rule_remove_by_tag(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;

    directory_config *dcfg = doc_config(conf);

    set_arg_ptr(cf,&p1,1);

    rule_exception *re = (rule_exception*)ngx_pcalloc(dcfg->mp, sizeof(rule_exception));

    re->type = RULE_EXCEPTION_REMOVE_TAG;
    re->param = p1;
    re->param_data = msc_pregcomp(dcfg->mp, p1, 0, NULL, NULL);
    if (re->param_data == NULL) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid regular expression: ", p1,NULL);
    }
    *(rule_exception **)ngx_array_push(dcfg->rule_exceptions) = re;

    /* Remove the corresponding rules from the context straight away. */
    msre_ruleset_rule_remove_with_exception(dcfg->ruleset, re);


    return NULL;
}   

static char* ngx_conf_set_cmd_rule_remove_by_msg(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;

    directory_config *dcfg = doc_config(conf);

    set_arg_ptr(cf,&p1,1);

    rule_exception *re = (rule_exception*)ngx_pcalloc(dcfg->mp, sizeof(rule_exception));

    re->type = RULE_EXCEPTION_REMOVE_MSG;
    re->param = p1;
    re->param_data = msc_pregcomp(dcfg->mp, p1, 0, NULL, NULL);
    if (re->param_data == NULL) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid regular expression: ", p1,NULL);
    }
    *(rule_exception **)ngx_array_push(dcfg->rule_exceptions) = re;

    /* Remove the corresponding rules from the context straight away. */
    msre_ruleset_rule_remove_with_exception(dcfg->ruleset, re);


    return NULL;
}


static char* ngx_conf_set_cmd_hash_method_pm(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1,*p2;

    directory_config *dcfg = doc_config(conf);

    set_arg_ptr(cf,&p1,1);
    set_arg_ptr(cf,&p2,2);
    
    rule_exception *re = (rule_exception*)ngx_pcalloc(dcfg->mp, sizeof(hash_method));
    
    const char *_p2 = ngx_pstrndup(dcfg->mp, p2);
    ACMP *p = NULL;
    const char *phrase = NULL;
    const char *next = NULL;

    if (dcfg == NULL) return NULL;

    p = acmp_create(0, dcfg->mp);
    if (p == NULL) return NULL;

    if(phrase == NULL)
        phrase = ngx_pstrndup(dcfg->mp, _p2);

    for (;;) {
        while((ngx_isspace(*phrase) != 0) && (*phrase != '\0')) phrase++;
        if (*phrase == '\0') break;
        next = phrase;
        while((ngx_isspace(*next) == 0) && (*next != 0)) next++;
        acmp_add_pattern(p, phrase, NULL, NULL, next - phrase);
        phrase = next;
    }

    acmp_prepare(p);

    if (strcasecmp(p1, "HashHref") == 0) {
        re->type = HASH_URL_HREF_HASH_PM;
        re->param = _p2;
        re->param_data = (void *)p;
        if (re->param_data == NULL) {
            return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid pattern: ", p2,NULL);
        }
        dcfg->crypto_hash_href_pm = 1;
    }
    else if (strcasecmp(p1, "HashFormAction") == 0) {
        re->type = HASH_URL_FACTION_HASH_PM;
        re->param = _p2;
        re->param_data = (void *)p;
        if (re->param_data == NULL) {
            return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid pattern: ", p2,NULL);
        }
        dcfg->crypto_hash_faction_pm = 1;
    }
    else if (strcasecmp(p1, "HashLocation") == 0) {
        re->type = HASH_URL_LOCATION_HASH_PM;
        re->param = _p2;
        re->param_data = (void *)p;
        if (re->param_data == NULL) {
            return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid pattern: ", p2,NULL);
        }
        dcfg->crypto_hash_location_pm = 1;
    }
    else if (strcasecmp(p1, "HashIframeSrc") == 0) {
        re->type = HASH_URL_IFRAMESRC_HASH_PM;
        re->param = _p2;
        re->param_data = (void *)p;
        if (re->param_data == NULL) {
            return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid pattern: ", p2,NULL);
        }
        dcfg->crypto_hash_iframesrc_pm = 1;
    }
    else if (strcasecmp(p1, "HashFrameSrc") == 0) {
        re->type = HASH_URL_FRAMESRC_HASH_PM;
        re->param = _p2;
        re->param_data = (void *)p;
        if (re->param_data == NULL) {
            return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid pattern: ", p2,NULL);
        }
        dcfg->crypto_hash_framesrc_pm = 1;
    }

    *(hash_method **)ngx_array_push(dcfg->hash_method) = re;

    return NULL;

}

static char* ngx_conf_set_cmd_hash_method_rx(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1,*p2;

    directory_config *dcfg = doc_config(conf);

    set_arg_ptr(cf,&p1,1);
    set_arg_ptr(cf,&p2,2);

    rule_exception *re = (rule_exception*)ngx_pcalloc(dcfg->mp, sizeof(hash_method));
    const char *_p2 = ngx_pstrndup(dcfg->mp, p2);
    if (dcfg == NULL) return NULL;

    if (strcasecmp(p1, "HashHref") == 0) {
        re->type = HASH_URL_HREF_HASH_RX;
        re->param = _p2;
        re->param_data = msc_pregcomp(dcfg->mp, p2, 0, NULL, NULL);
        if (re->param_data == NULL) {
            return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid regular expression: ", p2,NULL);
        }
        dcfg->crypto_hash_href_rx = 1;
    }
    else if (strcasecmp(p1, "HashFormAction") == 0) {
        re->type = HASH_URL_FACTION_HASH_RX;
        re->param = _p2;
        re->param_data = msc_pregcomp(dcfg->mp, p2, 0, NULL, NULL);
        if (re->param_data == NULL) {
            return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid regular expression: ", p2,NULL);
        }
        dcfg->crypto_hash_faction_rx = 1;
    }
    else if (strcasecmp(p1, "HashLocation") == 0) {
        re->type = HASH_URL_LOCATION_HASH_RX;
        re->param = _p2;
        re->param_data = msc_pregcomp(dcfg->mp, p2, 0, NULL, NULL);
        if (re->param_data == NULL) {
            return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid regular expression: ", p2,NULL);
        }
        dcfg->crypto_hash_location_rx = 1;
    }
    else if (strcasecmp(p1, "HashIframeSrc") == 0) {
        re->type = HASH_URL_IFRAMESRC_HASH_RX;
        re->param = _p2;
        re->param_data = msc_pregcomp(dcfg->mp, p2, 0, NULL, NULL);
        if (re->param_data == NULL) {
            return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid regular expression: ", p2,NULL);
        }
        dcfg->crypto_hash_iframesrc_rx = 1;
    }
    else if (strcasecmp(p1, "HashFrameSrc") == 0) {
        re->type = HASH_URL_FRAMESRC_HASH_RX;
        re->param = _p2;
        re->param_data = msc_pregcomp(dcfg->mp, p2, 0, NULL, NULL);
        if (re->param_data == NULL) {
            return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid regular expression: ", p2,NULL);
        }
        dcfg->crypto_hash_framesrc_rx = 1;
    }

    *(hash_method **)ngx_array_push(dcfg->hash_method) = re;

    return NULL;
}

static char *update_rule_action(ngx_conf_t  *cf, directory_config *dcfg,
                                      const char *p1, const char *p2, int offset)
{
    char *my_error_msg = NULL;
    msre_rule *rule = NULL;
    msre_actionset *new_actionset = NULL;
    msre_ruleset *ruleset = dcfg->ruleset;
    extern msc_engine *modsecurity;

    /* Get the ruleset if one exists */
    if ((ruleset == NULL)||(ruleset == NGX_CONF_UNSET_PTR)) {
        return NULL;
    }

    /* Fetch the rule */
    rule = msre_ruleset_fetch_rule(ruleset, p1, offset);
    if (rule == NULL) {
        return NULL;
    }

    /* Check the rule actionset */
    /* ENH: Can this happen? */
    if (rule->actionset == NULL) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Attempt to update action for rule \"",p1,"\" failed: Rule does not have an actionset.", NULL);
    }

    /* Create a new actionset */
    new_actionset = msre_actionset_create(modsecurity->msre, dcfg->mp, p2, &my_error_msg);
    if (new_actionset == NULL) return FATAL_ERROR;
    if (my_error_msg != NULL) return my_error_msg;

    /* Must NOT change an id */
    if ((new_actionset->id != NGX_CONF_UNSET_PTR) && (rule->actionset->id != NULL) && (strcmp(rule->actionset->id, new_actionset->id) != 0)) {
        return ngx_pstrndup(dcfg->mp, "ModSecurity: Rule IDs cannot be updated via SecRuleUpdateActionById.");
    }

    /* Must NOT alter the phase */
    if ((new_actionset->phase != NGX_CONF_UNSET) && (rule->actionset->phase != new_actionset->phase)) {
        return ngx_pstrndup(dcfg->mp, "ModSecurity: Rule phases cannot be updated via SecRuleUpdateActionById.");
    }

    /* Merge new actions with the rule */
    /* ENH: Will this leak the old actionset? */
    rule->actionset = msre_actionset_merge(modsecurity->msre, dcfg->mp, rule->actionset,
        new_actionset, 1);
    msre_actionset_set_defaults(rule->actionset);

    /* Update the unparsed rule */
    rule->unparsed = msre_rule_generate_unparsed(ruleset->mp, rule, NULL, NULL, NULL);

    return NULL;
}

static char* ngx_conf_set_cmd_rule_update_action_by_id(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1,*p2;

    directory_config *dcfg = doc_config(conf);

    set_arg_ptr(cf,&p1,1);
    set_arg_ptr(cf,&p2,2);

    int offset = 0, rule_id = atoi(p1);
    char *opt = strchr(p1,':');
    char *savedptr = NULL;
    char *param = ngx_pstrndup(dcfg->mp, p1);

    if (rule_id <= 0) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for ID for update action: ", p1,NULL);
    }

    if(opt != NULL) {
        opt++;
        offset = atoi(opt);
        opt = ngx_strtok(param,":", &savedptr);
        return update_rule_action(cf, dcfg, (const char *)opt, p2, offset);
    }

    return update_rule_action(cf, dcfg, p1, p2, offset);
}

static char* ngx_conf_set_cmd_rule_update_target_by_id(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1,*p2,*p3;

    directory_config *dcfg = doc_config(conf);

    set_arg_ptr(cf,&p1,1);
    set_arg_ptr(cf,&p2,2);
    set_arg_ptr(cf,&p3,3);

    rule_exception *re = (rule_exception*)ngx_pcalloc(dcfg->mp, sizeof(rule_exception));

    if(p1 == NULL)  {
        return ngx_pstrndup(dcfg->mp, "Updating target by ID with no ID");
    }

    re->type = RULE_EXCEPTION_REMOVE_ID;
    /* TODO: Validate the range here, while we can still tell the user if it's invalid */
    re->param = p1;

    if(dcfg->ruleset == NULL) {
        return ngx_pstrndup(dcfg->mp, "Updating target by ID with no ruleset in this context");
    }

    return msre_ruleset_rule_update_target_matching_exception(NULL, dcfg->ruleset, re, p2, p3);
}

static char* ngx_conf_set_cmd_rule_update_target_by_tag(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1,*p2,*p3;

    directory_config *dcfg = doc_config(conf);

    set_arg_ptr(cf,&p1,1);
    set_arg_ptr(cf,&p2,2);
    set_arg_ptr(cf,&p3,3);

    rule_exception *re = ngx_pcalloc(dcfg->mp, sizeof(rule_exception));

    if(p1 == NULL)  {
        return ngx_pstrndup(dcfg->mp, "Updating target by tag with no tag");
    }

    re->type = RULE_EXCEPTION_REMOVE_TAG;
    re->param = p1;
    re->param_data = msc_pregcomp(dcfg->mp, p1, 0, NULL, NULL);
    if (re->param_data == NULL) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid regular expression: ", p1,NULL);
    }

    return msre_ruleset_rule_update_target_matching_exception(NULL, dcfg->ruleset, re, p2, p3);

}

static char* ngx_conf_set_cmd_rule_update_target_by_msg(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1,*p2,*p3;

    directory_config *dcfg = doc_config(conf);

    set_arg_ptr(cf,&p1,1);
    set_arg_ptr(cf,&p2,2);
    set_arg_ptr(cf,&p3,3);

    rule_exception *re = (rule_exception*)ngx_pcalloc(dcfg->mp, sizeof(rule_exception));

    if(p1 == NULL)  {
        return ngx_pstrndup(dcfg->mp, "Updating target by message with no message");
    }

    re->type = RULE_EXCEPTION_REMOVE_MSG;
    re->param = p1;
    re->param_data = msc_pregcomp(dcfg->mp, p1, 0, NULL, NULL);
    if (re->param_data == NULL) {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid regular expression: ", p1,NULL);
    }

    return msre_ruleset_rule_update_target_matching_exception(NULL, dcfg->ruleset, re, p2, p3);
}

static char* ngx_conf_set_cmd_tmp_dir(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;

    directory_config *dcfg = doc_config(conf);

    arg_check_ptr(dcfg->tmp_dir);
    set_arg_ptr(cf,&p1,1);

    if (strcasecmp(p1, "none") == 0) dcfg->tmp_dir = NULL;
    else dcfg->tmp_dir = p1;

    return NULL;
}

static char* ngx_conf_set_cmd_upload_dir(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;

    directory_config *dcfg = doc_config(conf);
    arg_check_ptr(dcfg->upload_dir);

    set_arg_ptr(cf,&p1,1);
    
    if (strcasecmp(p1, "none") == 0) dcfg->upload_dir = NULL;
    else dcfg->upload_dir =  p1;

    return NULL;

}

static char* ngx_conf_set_cmd_upload_file_limit(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;

    directory_config *dcfg = doc_config(conf);
    arg_check(dcfg->upload_file_limit);
    set_arg_ptr(cf,&p1,1);
    
    if (strcasecmp(p1, "default") == 0) {
        dcfg->upload_file_limit = NGX_CONF_UNSET;
    }
    else {
        dcfg->upload_file_limit = atoi(p1);
    }

    return NULL;
}

static char* ngx_conf_set_cmd_upload_filemode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;

    directory_config *dcfg = doc_config(conf);
    arg_check(dcfg->upload_filemode);
    set_arg_ptr(cf,&p1,1);

    if (strcasecmp(p1, "default") == 0) {
        dcfg->upload_filemode = NGX_CONF_UNSET;
    }
    else {
        long int mode = strtol(p1, NULL, 8); /* expects octal mode */
        if ((mode == LONG_MAX)||(mode == LONG_MIN)||(mode <= 0)||(mode > 07777)) {
            return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for SecUploadFileMode: ", p1,NULL);
        }

        dcfg->upload_filemode = (int)mode;
    }

    return NULL;
}

static char* ngx_conf_set_cmd_upload_keep_files(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;

    directory_config *dcfg = doc_config(conf);
    arg_check(dcfg->upload_keep_files);
    set_arg_ptr(cf,&p1,1);

    if (strcasecmp(p1, "on") == 0) {
        dcfg->upload_keep_files = KEEP_FILES_ON;
    } else
    if (strcasecmp(p1, "off") == 0) {
        dcfg->upload_keep_files = KEEP_FILES_OFF;
    } else
    if (strcasecmp(p1, "relevantonly") == 0) {
        dcfg->upload_keep_files = KEEP_FILES_RELEVANT_ONLY;
    } else {
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid setting for SecUploadKeepFiles: ",
            p1,NULL);
    }
    return NULL;
}   

static char* ngx_conf_set_cmd_upload_save_tmp_files(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;
    int flag;

    directory_config *dcfg = doc_config(conf);
    arg_check(dcfg->upload_validates_files);
    set_arg_ptr(cf,&p1,1);

    flag = strtoflag(p1);

    if(flag == -1){
    
        return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid setting for SecTmpSaveUploadedFiles: ",
            p1,NULL);
    }

    dcfg->upload_validates_files = flag;

    return NULL;
}

static char* ngx_conf_set_cmd_web_app_id(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;

    directory_config *dcfg = doc_config(conf);
    arg_check_ptr(dcfg->webappid);
    set_arg_ptr(cf,&p1,1);

    dcfg->webappid = p1;
    return NULL;
}

static char* ngx_conf_set_cmd_sensor_id(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;

    directory_config *dcfg = doc_config(conf);
    arg_check_ptr(dcfg->sensor_id);
    set_arg_ptr(cf,&p1,1);

    dcfg->sensor_id = p1;
    return NULL;
}

static char* ngx_conf_set_cmd_httpBl_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;

    directory_config *dcfg = doc_config(conf);
    arg_check_ptr(dcfg->httpBlkey);
    set_arg_ptr(cf,&p1,1);

    dcfg->httpBlkey = p1;
    return NULL;
}

static char* ngx_conf_set_cmd_hash_engine(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;

    directory_config *dcfg = doc_config(conf);
    arg_check(dcfg->hash_is_enabled);
    set_arg_ptr(cf,&p1,1);

    if (strcasecmp(p1, "on") == 0)  {
        dcfg->hash_is_enabled = HASH_ENABLED;
        dcfg->hash_enforcement = HASH_ENABLED;
    }
    else if (strcasecmp(p1, "off") == 0)    {
        dcfg->hash_is_enabled = HASH_DISABLED;
        dcfg->hash_enforcement = HASH_DISABLED;
    }
    else return ngx_pstrcat(dcfg->mp, "ModSecurity: Invalid value for SecHashEngine: ", p1,NULL);

    return NULL;
}

static char* ngx_conf_set_cmd_hash_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *_p1,*_p2;
    char *p1 = NULL;

    directory_config *dcfg = doc_config(conf);
    set_arg_ptr(cf,&_p1,1);
    set_arg_ptr(cf,&_p2,2);

    if (strcasecmp(_p1, "Rand") == 0)    {
        p1 = ngx_pstrndup(dcfg->mp, getkey(dcfg->mp));
        dcfg->crypto_key = p1;
        dcfg->crypto_key_len = strlen(dcfg->crypto_key);
    } else    {
        p1 = ngx_pstrndup(dcfg->mp, _p1);
        dcfg->crypto_key = p1;
        dcfg->crypto_key_len = strlen(p1);
    }

    if(_p2 == NULL)  {
        return NULL;
    } else    {
        if (strcasecmp(_p2, "KeyOnly") == 0)
            dcfg->crypto_key_add = HASH_KEYONLY;
        else if (strcasecmp(_p2, "SessionID") == 0)
            dcfg->crypto_key_add = HASH_SESSIONID;
        else if (strcasecmp(_p2, "RemoteIP") == 0)
            dcfg->crypto_key_add = HASH_REMOTEIP;
    }
    return NULL;
}

static char* ngx_conf_set_cmd_hash_param(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    
    char *p1;

    directory_config *dcfg = doc_config(conf);
    arg_check_ptr(dcfg->crypto_param_name);
    set_arg_ptr(cf,&p1,1);

    dcfg->crypto_param_name = p1;

    return NULL;
}
    
/* -- Configuration directives definitions -- */
ngx_command_t module_directives[] = {


    { ngx_string("SecAction"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_action,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecArgumentSeparator"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_argument_separator,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      
    { ngx_string("SecCookiev0Separator"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_cookiev0_separator,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecCacheTransformations"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_conf_set_cmd_cache_transformations,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecComponentSignature"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_component_signature,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecContentInjection"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_content_injection,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecStreamOutBodyInspection"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_stream_outbody_inspection,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecStreamInBodyInspection"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_stream_inbody_inspection,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},
    
    { ngx_string("SecCookieFormat"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_cookie_format,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecPersistdb"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_persistdb,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecDebugLog"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_debug_log,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecDebugLogLevel"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_debug_log_level,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecCollectionTimeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_collection_timeout,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},
    
    
    { ngx_string("SecDefaultAction"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_default_action,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecDisableBackendCompression"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_disable_backend_compression,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecGsbLookupDB"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_gsb_lookup_db,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecUnicodeCodePage"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_unicode_codepage,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},
    
    { ngx_string("SecUnicodeMapFile"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_conf_set_cmd_unicode_map,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},
    
    { ngx_string("SecGeoLookupDB"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_geo_lookup_db,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecMarker"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_marker,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecPcreMatchLimit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_pcre_match_limit,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecPcreMatchLimitRecursion"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_pcre_match_limit_recursion,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecRequestBodyAccess"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_request_body_access,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},
    
    
    { ngx_string("SecInterceptOnError"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_request_intercept_on_error,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},
    
    { ngx_string("SecRulePerfTime"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_rule_perf_time,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecRequestBodyInMemoryLimit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_request_body_inmemory_limit,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecRequestBodyLimit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_request_body_limit,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecRequestBodyNoFilesLimit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_request_body_no_files_limit,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecRequestEncoding"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_request_encoding,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecResponseBodyAccess"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_response_body_access,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecResponseBodyLimit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_response_body_limit,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecRequestBodyLimitAction"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_cmd_resquest_body_limit_action,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecResponseBodyMimeType"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_cmd_response_body_mime_type,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},
    
    { ngx_string("SecResponseBodyMimeTypesClear"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_conf_set_cmd_response_body_mime_types_clear,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},
    
    { ngx_string("SecRule"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_conf_set_cmd_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecRuleEngine"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_rule_engine,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecXmlExternalEntity"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_xml_external_entity,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecRuleInheritance"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_rule_inheritance,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecRuleScript"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_conf_set_cmd_rule_script,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecRuleRemoveById"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_cmd_rule_remove_by_id,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecRuleRemoveByTag"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_cmd_rule_remove_by_tag,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecRuleRemoveByMsg"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_cmd_rule_remove_by_msg,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecHashMethodPm"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_cmd_hash_method_pm,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecHashMethodRx"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_cmd_hash_method_rx,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecRuleUpdateActionById"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_cmd_rule_update_action_by_id,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecRuleUpdateTargetById"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_conf_set_cmd_rule_update_target_by_id,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecRuleUpdateTargetByTag"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_conf_set_cmd_rule_update_target_by_tag,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecRuleUpdateTargetByMsg"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_conf_set_cmd_rule_update_target_by_msg,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecTmpDir"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_tmp_dir,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecUploadDir"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_upload_dir,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecUploadFileLimit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_upload_file_limit,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecUploadFileMode"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_upload_filemode,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecUploadKeepFiles"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_upload_keep_files,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecTmpSaveUploadedFiles"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_upload_save_tmp_files,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecWebAppId"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_web_app_id,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecSensorId"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_sensor_id,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { 
        ngx_string("SecHttpBlKey"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_httpBl_key,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecHashEngine"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_hash_engine,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("SecHashKey"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_cmd_hash_key,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},


    { ngx_string("SecHashParam"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_cmd_hash_param,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    ngx_null_command
};


