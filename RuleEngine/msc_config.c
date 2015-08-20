/*
 * shajf
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


/* -- Directory context creation and initialisation -- */

/**
 * Creates a fresh directory configuration.
 */
void *create_directory_config(ngx_pool_t *mp, char *path)
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

/**
 * @brief Copies rules between one phase of two configuration contexts.
 *
 * Copies rules between one phase of two configuration contexts,
 * taking exceptions into account.
 *
 * @param mp ngx pool structure
 * @param parent_ruleset Parent's msre_ruleset
 * @param child_ruleset Child's msre_ruleset
 * @param exceptions_arr Exceptions' ngx_array_t
 * @retval 0 Everything went well.
 * @retval -1 Something went wrong.
 *
 */
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
    directory_config *merged = create_directory_config(mp, NULL);

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

/**
 *
 */
static const char *add_rule(cmd_parms *cmd, directory_config *dcfg, int type,
                            const char *p1, const char *p2, const char *p3)
{
    char *my_error_msg = NULL;
    //msre_rule *rule = NULL, *tmp_rule = NULL;
    char *rid = NULL;
    msre_rule *rule = NULL;
    extern msc_engine *modsecurity;

    /* Create a ruleset if one does not exist. */
    if ((dcfg->ruleset == NULL)||(dcfg->ruleset == NGX_CONF_UNSET_PTR)) {
        dcfg->ruleset = msre_ruleset_create(modsecurity->msre, cmd->pool);
        if (dcfg->ruleset == NULL) return FATAL_ERROR;
    }

    /* Create the rule now. */
    switch(type) {
        #if defined(WITH_LUA)
        case RULE_TYPE_LUA :
            rule = msre_rule_lua_create(dcfg->ruleset, cmd->config_file->name,
                cmd->config_file->line_number, p1, p2, &my_error_msg);
            break;
        #endif
        default :
            rule = msre_rule_create(dcfg->ruleset, type, cmd->config_file->name,
                cmd->config_file->line_number, p1, p2, p3, &my_error_msg);
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
            return ngx_pstrndup(cmd->pool, "ModSecurity: Disruptive actions can only "
                "be specified by chain starter rules.");
        }

        /* Must NOT specify a skipafter action. */
        if (rule->actionset->skip_after != NGX_CONF_UNSET_PTR) {
            return ngx_pstrndup(cmd->pool, "ModSecurity: SkipAfter actions can only "
                "be specified by chain starter rules.");
        }

        /* Must NOT specify a phase. */
        if (rule->actionset->phase != NGX_CONF_UNSET) {
            return ngx_pstrndup(cmd->pool, "ModSecurity: Execution phases can only be "
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
            return ngx_pstrndup(cmd->pool, "ModSecurity: Metadata actions (id, rev, msg, tag, severity, ver, accuracy, maturity, logdata) "
                " can only be specified by chain starter rules.");
        }

        /* Must NOT use skip. */
        if (rule->actionset->skip_count != NGX_CONF_UNSET) {
            return ngx_pstrndup(cmd->pool, "ModSecurity: The skip action can only be used "
                " by chain starter rules. ");
        }
    }

    /* Merge actions with the parent.
     *
     * ENH Probably do not want this done fully for chained rules.
     */
    rule->actionset = msre_actionset_merge(modsecurity->msre, cmd->pool, dcfg->tmp_default_actionset,
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
        return ngx_pstrndup(cmd->pool, "ModSecurity: Disruptive actions "
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
        dcfg->tmp_rule_placeholders = ngx_table_make(cmd->pool, 10);
        if (dcfg->tmp_rule_placeholders == NULL) return FATAL_ERROR;
    }

    /* Keep track of any rule IDs we need to skip after */
    if (rule->actionset->skip_after != NGX_CONF_UNSET_PTR) {
        char *tmp_id = ngx_pstrndup(cmd->pool, rule->actionset->skip_after);
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

/**
 *
 */
static const char *add_marker(cmd_parms *cmd, directory_config *dcfg,
                              const char *p1, const char *p2, const char *p3)
{
    char *my_error_msg = NULL;
    msre_rule *rule = NULL;
    extern msc_engine *modsecurity;
    int p;

    /* Create a ruleset if one does not exist. */
    if ((dcfg->ruleset == NULL)||(dcfg->ruleset == NGX_CONF_UNSET_PTR)) {
        dcfg->ruleset = msre_ruleset_create(modsecurity->msre, cmd->pool);
        if (dcfg->ruleset == NULL) return FATAL_ERROR;
    }

    /* Create the rule now. */
    rule = msre_rule_create(dcfg->ruleset, RULE_TYPE_MARKER, cmd->config_file->name, cmd->config_file->line_number, p1, p2, p3, &my_error_msg);
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

/**
 *
 */
static const char *update_rule_action(cmd_parms *cmd, directory_config *dcfg,
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
        return ngx_pstrcat(cmd->pool, "ModSecurity: Attempt to update action for rule \"",p1,"\" failed: Rule does not have an actionset.", NULL);
    }

    /* Create a new actionset */
    new_actionset = msre_actionset_create(modsecurity->msre, cmd->pool, p2, &my_error_msg);
    if (new_actionset == NULL) return FATAL_ERROR;
    if (my_error_msg != NULL) return my_error_msg;

    /* Must NOT change an id */
    if ((new_actionset->id != NGX_CONF_UNSET_PTR) && (rule->actionset->id != NULL) && (strcmp(rule->actionset->id, new_actionset->id) != 0)) {
        return ngx_pstrndup(cmd->pool, "ModSecurity: Rule IDs cannot be updated via SecRuleUpdateActionById.");
    }

    /* Must NOT alter the phase */
    if ((new_actionset->phase != NGX_CONF_UNSET) && (rule->actionset->phase != new_actionset->phase)) {
        return ngx_pstrndup(cmd->pool, "ModSecurity: Rule phases cannot be updated via SecRuleUpdateActionById.");
    }

    /* Merge new actions with the rule */
    /* ENH: Will this leak the old actionset? */
    rule->actionset = msre_actionset_merge(modsecurity->msre, cmd->pool, rule->actionset,
        new_actionset, 1);
    msre_actionset_set_defaults(rule->actionset);

    /* Update the unparsed rule */
    rule->unparsed = msre_rule_generate_unparsed(ruleset->mp, rule, NULL, NULL, NULL);

    return NULL;
}

/* -- Configuration directives -- */

static const char *cmd_action(cmd_parms *cmd, void *_dcfg, const char *p1)
{
    return add_rule(cmd, (directory_config *)_dcfg, RULE_TYPE_ACTION, SECACTION_TARGETS, SECACTION_ARGS, p1);
}

static const char *cmd_marker(cmd_parms *cmd, void *_dcfg, const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    const char *action = ngx_pstrcat(dcfg->mp, SECMARKER_BASE_ACTIONS, p1, NULL);
    return add_marker(cmd, (directory_config *)_dcfg, SECMARKER_TARGETS, SECMARKER_ARGS, action);
}

static const char *cmd_cookiev0_separator(cmd_parms *cmd, void *_dcfg,
        const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    if (strlen(p1) != 1) {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid cookie v0 separator: ", p1,NULL);
    }

    dcfg->cookiev0_separator = p1;

    return NULL;
}

static const char *cmd_argument_separator(cmd_parms *cmd, void *_dcfg,
        const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    if (strlen(p1) != 1) {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid argument separator: ", p1,NULL);
    }

    dcfg->argument_separator = p1[0];

    return NULL;
}

static const char *cmd_cookie_format(cmd_parms *cmd, void *_dcfg,
                                     const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    if (strcmp(p1, "0") == 0) dcfg->cookie_format = COOKIES_V0;
    else
    if (strcmp(p1, "1") == 0) dcfg->cookie_format = COOKIES_V1;
    else {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid cookie format: ", p1,NULL);
    }

    return NULL;
}

/**
 * Adds component signature to the list of signatures kept in configuration.
 */
static const char *cmd_component_signature(cmd_parms *cmd, void *_dcfg,
                                           const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    /* ENH Enforce "Name/VersionX.Y.Z (comment)" format. */
    *(char **)ngx_array_push(dcfg->component_signatures) = (char *)p1;

    return NULL;
}

static const char *cmd_content_injection(cmd_parms *cmd, void *_dcfg, int flag)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;
    dcfg->content_injection_enabled = flag;
    return NULL;
}

static const char *cmd_persistdb(cmd_parms *cmd, void *_dcfg, const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    char *errmsg;

    dcfg->persistdb = do_open_kvstore(cmd->pool,p1,&errmsg);
    
    if(dcfg->persistdb== NULL) return errmsg;

    return NULL;
}

static const char *cmd_debug_log(cmd_parms *cmd, void *_dcfg, const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    dcfg->debuglog_name = p1;
    
    dcfg->debuglog_fd = ngx_open_file_log(cmd->pool,dcfg->debuglog_name);

    if (dcfg->debuglog_fd == NULL) {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Failed to open debug log file: ",
            dcfg->debuglog_name,NULL);
    }

    return NULL;
}

/**
* \brief Add SecCollectionTimeout configuration option
*
* \param cmd Pointer to configuration data
* \param _dcfg Pointer to directory configuration
* \param p1 Pointer to configuration option
*
* \retval NULL On failure
* \retval ngx_psprintf On Success
*/
static const char *cmd_collection_timeout(cmd_parms *cmd, void *_dcfg,
                                       const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    dcfg->col_timeout = atoi(p1);
    /* max 30 days */
    if ((dcfg->col_timeout >= 0)&&(dcfg->col_timeout <= 2592000)) return NULL;

    return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for SecCollectionTimeout: ", p1,NULL);
}

static const char *cmd_debug_log_level(cmd_parms *cmd, void *_dcfg,
                                       const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    dcfg->debuglog_level = atoi(p1);
    if ((dcfg->debuglog_level >= 0)&&(dcfg->debuglog_level <= 9)) return NULL;

    return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for SecDebugLogLevel: ", p1,NULL);
}

static const char *cmd_default_action(cmd_parms *cmd, void *_dcfg,
                                      const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    extern msc_engine *modsecurity;
    char *my_error_msg = NULL;

    dcfg->tmp_default_actionset = msre_actionset_create(modsecurity->msre, cmd->pool, p1, &my_error_msg);
    if (dcfg->tmp_default_actionset == NULL) {
        if (my_error_msg != NULL) return my_error_msg;
        else return FATAL_ERROR;
    }

    /* Must specify a disruptive action. */
    /* ENH: Remove this requirement? */
    if (dcfg->tmp_default_actionset->intercept_action == NGX_CONF_UNSET) {
        return ngx_pstrndup(cmd->pool, "ModSecurity: SecDefaultAction must specify a disruptive action.");
    }

    /* Must specify a phase. */
    /* ENH: Remove this requirement? */
    if (dcfg->tmp_default_actionset->phase == NGX_CONF_UNSET) {
        return ngx_pstrndup(cmd->pool, "ModSecurity: SecDefaultAction must specify a phase.");
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
        return ngx_pstrndup(cmd->pool, "ModSecurity: SecDefaultAction must not "
            "contain any metadata actions (id, rev, msg, tag, severity, ver, accuracy, maturity, logdata).");
    }

    /* Must not use chain. */
    if (dcfg->tmp_default_actionset->is_chained != NGX_CONF_UNSET) {
        return ngx_pstrndup(cmd->pool, "ModSecurity: SecDefaultAction must not "
            "contain a chain action.");
    }

    /* Must not use skip. */
    if (dcfg->tmp_default_actionset->skip_count != NGX_CONF_UNSET) {
        return ngx_pstrndup(cmd->pool, "ModSecurity: SecDefaultAction must not "
            "contain a skip action.");
    }

    /* Must not use skipAfter. */
    if (dcfg->tmp_default_actionset->skip_after != NGX_CONF_UNSET_PTR) {
        return ngx_pstrndup(cmd->pool, "ModSecurity: SecDefaultAction must not "
            "contain a skipAfter action.");
    }

    return NULL;
}

static const char *cmd_disable_backend_compression(cmd_parms *cmd, void *_dcfg, int flag)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;
    dcfg->disable_backend_compression = flag;
    return NULL;
}


/**
* \brief Add SecStreamInBodyInspection configuration option
*
* \param cmd Pointer to configuration data
* \param _dcfg Pointer to directory configuration
* \param p1 Pointer to configuration option
*
* \retval NULL On failure
* \retval ngx_psprintf On Success
*/
static const char *cmd_stream_inbody_inspection(cmd_parms *cmd, void *_dcfg, int flag)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;
    dcfg->stream_inbody_inspection = flag;
    return NULL;
}


/**
* \brief Add SecStreamOutBodyInspection configuration option
*
* \param cmd Pointer to configuration data
* \param _dcfg Pointer to directory configuration
* \param p1 Pointer to configuration option
*
* \retval NULL On failure
* \retval ngx_psprintf On Success
*/
static const char *cmd_stream_outbody_inspection(cmd_parms *cmd, void *_dcfg, int flag)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;
    dcfg->stream_outbody_inspection = flag;
    return NULL;
}
/**
* \brief Add SecRulePerfTime configuration option
*
* \param cmd Pointer to configuration data
* \param _dcfg Pointer to directory configuration
* \param p1 Pointer to configuration option
*
* \retval NULL On failure
* \retval ngx_psprintf On Success
*/
static const char *cmd_rule_perf_time(cmd_parms *cmd, void *_dcfg,
        const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    long int limit;

    if (dcfg == NULL) return NULL;

    limit = strtol(p1, NULL, 10);
    if ((limit == LONG_MAX)||(limit == LONG_MIN)||(limit <= 0)) {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for SecRulePerfTime: ", p1,NULL);
    }

    dcfg->max_rule_time = limit;

    return NULL;
}

char *parser_conn_limits_operator(ngx_pool_t *mp, const char *p2,
    TreeRoot **whitelist, TreeRoot **suspicious_list, 
    const char *filename)
{
    int res = 0;
    char *config_orig_path;
    char *param = strchr(p2, ' ');
    char *file = NULL;
    char *error_msg = NULL;
    param++;

    config_orig_path = ngx_pstrmemdup(mp, filename,
        strlen(filename) - strlen(ngx_filepath_name_get(filename)));

    ngx_filepath_merge(&file, config_orig_path, param, NGX_FILEPATH_TRUENAME,
        mp);

    if ((strncasecmp(p2, "!@ipMatchFromFile", strlen("!@ipMatchFromFile")) == 0) ||
        (strncasecmp(p2, "!@ipMatchF", strlen("!@ipMatchF")) == 0)) {

        res = ip_tree_from_file(whitelist, file, mp, &error_msg);
    }
    else if (strncasecmp(p2, "!@ipMatch", strlen("!@ipMatch")) == 0) {
        res = ip_tree_from_param(mp, param, whitelist, &error_msg);
    }
    else if ((strncasecmp(p2, "@ipMatchFromFile", strlen("@ipMatchFromFile")) == 0) ||
        (strncasecmp(p2, "@ipMatchF", strlen("@ipMatchF")) == 0)) {

        res = ip_tree_from_file(suspicious_list, file, mp, &error_msg);
    }
    else if (strncasecmp(p2, "@ipMatch", strlen("@ipMatch")) == 0) {
        res = ip_tree_from_param(mp, param, suspicious_list, &error_msg);
    }
    else {
        return ngx_pstrcat(mp, "ModSecurity: Invalid operator for " \
           "SecConnReadStateLimit:,",p2," expected operators: @ipMatch, @ipMatchF " \
           "or @ipMatchFromFile with or without !", NULL);
    }

    if (res) {
        char *error;
        error = ngx_pstrcat(mp, "ModSecurity: failed to load IPs " \
            "from: ", param,NULL);

        if (*error_msg) {
            error = ngx_pstrcat(mp, error," ", error_msg,NULL);
        }

        return error;
    }

    return NULL;
}



static const char *cmd_request_body_inmemory_limit(cmd_parms *cmd, void *_dcfg,
                                                   const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    long int limit;

    if (dcfg == NULL) return NULL;

    limit = strtol(p1, NULL, 10);
    if ((limit == LONG_MAX)||(limit == LONG_MIN)||(limit <= 0)) {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for SecRequestBodyInMemoryLimit: ", p1,NULL);
    }

    dcfg->reqbody_inmemory_limit = limit;

    return NULL;
}

static const char *cmd_request_body_limit(cmd_parms *cmd, void *_dcfg,
                                          const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    long int limit;

    if (dcfg == NULL) return NULL;

    limit = strtol(p1, NULL, 10);
    if ((limit == LONG_MAX)||(limit == LONG_MIN)||(limit <= 0)) {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for SecRequestBodyLimit: ", p1,NULL);
    }

    dcfg->reqbody_limit = limit;

    return NULL;
}

static const char *cmd_request_body_no_files_limit(cmd_parms *cmd, void *_dcfg,
                                                   const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    long int limit;

    if (dcfg == NULL) return NULL;

    limit = strtol(p1, NULL, 10);
    if ((limit == LONG_MAX)||(limit == LONG_MIN)||(limit <= 0)) {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for SecRequestBodyNoFilesLimit: ", p1,NULL);
    }

    dcfg->reqbody_no_files_limit = limit;

    return NULL;
}

static const char *cmd_request_body_access(cmd_parms *cmd, void *_dcfg,
                                           const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;

    if (strcasecmp(p1, "on") == 0) dcfg->reqbody_access = 1;
    else
    if (strcasecmp(p1, "off") == 0) dcfg->reqbody_access = 0;
    else
    return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for SecRequestBodyAccess: ", p1,NULL);

    return NULL;
}

/**
* \brief Add SecInterceptOnError configuration option
*
* \param cmd Pointer to configuration data
* \param _dcfg Pointer to directory configuration
* \param p1 Pointer to configuration option
*
* \retval NULL On failure
* \retval ngx_psprintf On success
*/
static const char *cmd_request_intercept_on_error(cmd_parms *cmd, void *_dcfg,
                                           const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;

    if (strcasecmp(p1, "on") == 0) dcfg->reqintercept_oe = 1;
    else
    if (strcasecmp(p1, "off") == 0) dcfg->reqintercept_oe = 0;
    else
    return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for SecInterceptOnError: ", p1,NULL);

    return NULL;
}


static const char *cmd_request_encoding(cmd_parms *cmd, void *_dcfg,
                                        const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;

    /* ENH Validate encoding */

    dcfg->request_encoding = p1;

    return NULL;
}

static const char *cmd_response_body_access(cmd_parms *cmd, void *_dcfg,
                                            const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;

    if (strcasecmp(p1, "on") == 0) dcfg->resbody_access = 1;
    else
    if (strcasecmp(p1, "off") == 0) dcfg->resbody_access = 0;
    else
    return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for SecResponseBodyAccess: ", p1,NULL);

    return NULL;
}

static const char *cmd_response_body_limit(cmd_parms *cmd, void *_dcfg,
                                           const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    long int limit;

    limit = strtol(p1, NULL, 10);
    if ((limit == LONG_MAX)||(limit == LONG_MIN)||(limit <= 0)) {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for SecResponseBodyLimit: ", p1,NULL);
    }

    if (limit > RESPONSE_BODY_HARD_LIMIT) {
        return ngx_psprintf(cmd->pool, NGX_INT64_LEN+ngx_strlen("ModSecurity: Response size limit can not exceed the hard limit: %li")+2,
                "ModSecurity: Response size limit can not exceed the hard limit: %l", RESPONSE_BODY_HARD_LIMIT);
    }

    dcfg->of_limit = limit;

    return NULL;
}

static const char *cmd_response_body_limit_action(cmd_parms *cmd, void *_dcfg,
                                                  const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;

    if (dcfg->is_enabled == MODSEC_DETECTION_ONLY)  {
        dcfg->of_limit_action = RESPONSE_BODY_LIMIT_ACTION_PARTIAL;
        return NULL;
    }

    if (strcasecmp(p1, "ProcessPartial") == 0) dcfg->of_limit_action = RESPONSE_BODY_LIMIT_ACTION_PARTIAL;
    else
    if (strcasecmp(p1, "Reject") == 0) dcfg->of_limit_action = RESPONSE_BODY_LIMIT_ACTION_REJECT;
    else
    return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for SecResponseBodyLimitAction: ", p1,NULL);

    return NULL;
}

/**
* \brief Add SecRequestBodyLimitAction configuration option
*
* \param cmd Pointer to configuration data
* \param _dcfg Pointer to directory configuration
* \param p1 Pointer to configuration option
*
* \retval NULL On failure
* \retval ngx_psprintf On success
*/
static const char *cmd_resquest_body_limit_action(cmd_parms *cmd, void *_dcfg,
                                                  const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;

    if (dcfg->is_enabled == MODSEC_DETECTION_ONLY)  {
        dcfg->if_limit_action = REQUEST_BODY_LIMIT_ACTION_PARTIAL;
        return NULL;
    }

    if (strcasecmp(p1, "ProcessPartial") == 0) dcfg->if_limit_action = REQUEST_BODY_LIMIT_ACTION_PARTIAL;
    else
    if (strcasecmp(p1, "Reject") == 0) dcfg->if_limit_action = REQUEST_BODY_LIMIT_ACTION_REJECT;
    else
    return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for SecRequestBodyLimitAction: ", p1,NULL);

    return NULL;
}

static const char *cmd_response_body_mime_type(cmd_parms *cmd, void *_dcfg,
                                               const char *_p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    char *p1 = ngx_pstrndup(cmd->pool, _p1);

    /* TODO check whether the parameter is a valid MIME type of "???" */

    if ((dcfg->of_mime_types == NULL)||(dcfg->of_mime_types == NGX_CONF_UNSET_PTR)) {
        dcfg->of_mime_types = ngx_table_make(cmd->pool, 10);
    }

    strtolower_inplace((unsigned char *)p1);
    ngx_table_setn(dcfg->of_mime_types, p1, "1");

    return NULL;
}

static const char *cmd_response_body_mime_types_clear(cmd_parms *cmd,
                                                      void *_dcfg)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;

    dcfg->of_mime_types_cleared = 1;

    if ((dcfg->of_mime_types != NULL)&&(dcfg->of_mime_types != NGX_CONF_UNSET_PTR)) {
        ngx_table_clear(dcfg->of_mime_types);
    }

    return NULL;
}

/**
 * \brief Add SecRuleUpdateTargetById
 *
 * \param cmd Pointer to configuration data
 * \param _dcfg Pointer to directory configuration
 * \param p1 Pointer to configuration option
 * \param p2 Pointer to configuration option
 * \param p3 Pointer to configuration option
 *
 * \retval NULL On failure|Success
 */
static const char *cmd_rule_update_target_by_id(cmd_parms *cmd, void *_dcfg,
        const char *p1, const char *p2, const char *p3)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    rule_exception *re = (rule_exception*)ngx_pcalloc(cmd->pool, sizeof(rule_exception));
    if (dcfg == NULL) return NULL;

    if(p1 == NULL)  {
        return ngx_pstrndup(cmd->pool, "Updating target by ID with no ID");
    }

    re->type = RULE_EXCEPTION_REMOVE_ID;
    /* TODO: Validate the range here, while we can still tell the user if it's invalid */
    re->param = p1;

    if(dcfg->ruleset == NULL) {
        return ngx_pstrndup(cmd->pool, "Updating target by ID with no ruleset in this context");
    }

    return msre_ruleset_rule_update_target_matching_exception(NULL, dcfg->ruleset, re, p2, p3);
}

/**
 * \brief Add SecRuleUpdateTargetByTag  configuration option
 *
 * \param cmd Pointer to configuration data
 * \param _dcfg Pointer to directory configuration
 * \param p1 Pointer to configuration option RULETAG
 * \param p2 Pointer to configuration option TARGET
 * \param p3 Pointer to configuration option REPLACED_TARGET
 * \todo Finish documenting
 *
 * \retval NULL On success
 * \retval ngx_psprintf On failure
 *
 * \todo Figure out error checking
 */
static const char *cmd_rule_update_target_by_tag(cmd_parms *cmd, void *_dcfg,
        const char *p1, const char *p2, const char *p3)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    rule_exception *re = ngx_pcalloc(cmd->pool, sizeof(rule_exception));
    if (dcfg == NULL) return NULL;

    if(p1 == NULL)  {
        return ngx_pstrndup(cmd->pool, "Updating target by tag with no tag");
    }

    re->type = RULE_EXCEPTION_REMOVE_TAG;
    re->param = p1;
    re->param_data = msc_pregcomp(cmd->pool, p1, 0, NULL, NULL);
    if (re->param_data == NULL) {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid regular expression: ", p1,NULL);
    }

    return msre_ruleset_rule_update_target_matching_exception(NULL, dcfg->ruleset, re, p2, p3);
}
/**
 * \brief Add SecRuleUpdateTargetByMsg configuration option
 *
 * \param cmd Pointer to configuration data
 * \param _dcfg Pointer to directory configuration
 * \param p1 Pointer to configuration option RULEMSG
 * \param p2 Pointer to configuration option TARGET
 * \param p3 Pointer to configuration option REPLACED_TARGET
 * \todo Finish documenting
 *
 * \retval NULL On success
 * \retval ngx_psprintf On failure
 *
 * \todo Figure out error checking
 */
static const char *cmd_rule_update_target_by_msg(cmd_parms *cmd, void *_dcfg,
        const char *p1, const char *p2, const char *p3)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    rule_exception *re = (rule_exception*)ngx_pcalloc(cmd->pool, sizeof(rule_exception));
    if (dcfg == NULL) return NULL;

    if(p1 == NULL)  {
        return ngx_pstrndup(cmd->pool, "Updating target by message with no message");
    }

    re->type = RULE_EXCEPTION_REMOVE_MSG;
    re->param = p1;
    re->param_data = msc_pregcomp(cmd->pool, p1, 0, NULL, NULL);
    if (re->param_data == NULL) {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid regular expression: ", p1,NULL);
    }

    return msre_ruleset_rule_update_target_matching_exception(NULL, dcfg->ruleset, re, p2, p3);
}


static const char *cmd_rule(cmd_parms *cmd, void *_dcfg,
        const char *p1, const char *p2, const char *p3)
{
    return add_rule(cmd, (directory_config *)_dcfg, RULE_TYPE_NORMAL, p1, p2, p3);
}


static const char *cmd_rule_engine(cmd_parms *cmd, void *_dcfg, const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    if (dcfg == NULL) return NULL;

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
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for " \
                "SecRuleEngine: ", p1,NULL);
    }

    return NULL;
}



static const char *cmd_rule_inheritance(cmd_parms *cmd, void *_dcfg, int flag)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;
    dcfg->rule_inheritance = flag;
    return NULL;
}

static const char *cmd_rule_script(cmd_parms *cmd, void *_dcfg,
                                   const char *p1, const char *p2)
{
    #if defined(WITH_LUA)
    return add_rule(cmd, (directory_config *)_dcfg, RULE_TYPE_LUA,p1, p2, NULL);
    #else
    return NULL;
    #endif
}

static const char *cmd_rule_remove_by_id(cmd_parms *cmd, void *_dcfg,
                                         const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    rule_exception *re = (rule_exception*)ngx_pcalloc(cmd->pool, sizeof(rule_exception));
    if (dcfg == NULL) return NULL;

    re->type = RULE_EXCEPTION_REMOVE_ID;
    re->param = p1;
    *(rule_exception **)ngx_array_push(dcfg->rule_exceptions) = re;

    /* Remove the corresponding rules from the context straight away. */
    msre_ruleset_rule_remove_with_exception(dcfg->ruleset, re);

    return NULL;
}

/**
* \brief Add SecRuleRemoveByTag  configuration option
*
* \param cmd Pointer to configuration data
* \param _dcfg Pointer to directory configuration
* \param p1 Pointer to configuration option
*
* \retval NULL On failure
* \retval ngx_psprintf On success
*/
static const char *cmd_rule_remove_by_tag(cmd_parms *cmd, void *_dcfg,
                                          const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    rule_exception *re = (rule_exception*)ngx_pcalloc(cmd->pool, sizeof(rule_exception));
    if (dcfg == NULL) return NULL;

    re->type = RULE_EXCEPTION_REMOVE_TAG;
    re->param = p1;
    re->param_data = msc_pregcomp(cmd->pool, p1, 0, NULL, NULL);
    if (re->param_data == NULL) {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid regular expression: ", p1,NULL);
    }
    *(rule_exception **)ngx_array_push(dcfg->rule_exceptions) = re;

    /* Remove the corresponding rules from the context straight away. */
    msre_ruleset_rule_remove_with_exception(dcfg->ruleset, re);


    return NULL;
}

static const char *cmd_rule_remove_by_msg(cmd_parms *cmd, void *_dcfg,
                                          const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    rule_exception *re = (rule_exception*)ngx_pcalloc(cmd->pool, sizeof(rule_exception));
    if (dcfg == NULL) return NULL;

    re->type = RULE_EXCEPTION_REMOVE_MSG;
    re->param = p1;
    re->param_data = msc_pregcomp(cmd->pool, p1, 0, NULL, NULL);
    if (re->param_data == NULL) {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid regular expression: ", p1,NULL);
    }
    *(rule_exception **)ngx_array_push(dcfg->rule_exceptions) = re;

    /* Remove the corresponding rules from the context straight away. */
    msre_ruleset_rule_remove_with_exception(dcfg->ruleset, re);


    return NULL;
}

static const char *cmd_rule_update_action_by_id(cmd_parms *cmd, void *_dcfg,
        const char *p1, const char *p2)
{
    int offset = 0, rule_id = atoi(p1);
    char *opt = strchr(p1,':');
    char *savedptr = NULL;
    char *param = ngx_pstrndup(cmd->pool, p1);

    if (rule_id <= 0) {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for ID for update action: ", p1,NULL);
    }

    if(opt != NULL) {
        opt++;
        offset = atoi(opt);
        opt = ngx_strtok(param,":", &savedptr);
        return update_rule_action(cmd, (directory_config *)_dcfg, (const char *)opt, p2, offset);
    }

    return update_rule_action(cmd, (directory_config *)_dcfg, p1, p2, offset);
}

static const char *cmd_tmp_dir(cmd_parms *cmd, void *_dcfg, const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    if (dcfg == NULL) return NULL;

    if (strcasecmp(p1, "none") == 0) dcfg->tmp_dir = NULL;
    else dcfg->tmp_dir = p1;

    return NULL;
}

static const char *cmd_upload_dir(cmd_parms *cmd, void *_dcfg, const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    if (dcfg == NULL) return NULL;

    if (strcasecmp(p1, "none") == 0) dcfg->upload_dir = NULL;
    else dcfg->upload_dir =  p1;

    return NULL;
}

static const char *cmd_upload_file_limit(cmd_parms *cmd, void *_dcfg,
                                         const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    if (dcfg == NULL) return NULL;

    if (strcasecmp(p1, "default") == 0) {
        dcfg->upload_file_limit = NGX_CONF_UNSET;
    }
    else {
        dcfg->upload_file_limit = atoi(p1);
    }

    return NULL;
}

static const char *cmd_upload_filemode(cmd_parms *cmd, void *_dcfg,
                                       const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    if (dcfg == NULL) return NULL;

    if (strcasecmp(p1, "default") == 0) {
        dcfg->upload_filemode = NGX_CONF_UNSET;
    }
    else {
        long int mode = strtol(p1, NULL, 8); /* expects octal mode */
        if ((mode == LONG_MAX)||(mode == LONG_MIN)||(mode <= 0)||(mode > 07777)) {
            return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for SecUploadFileMode: ", p1,NULL);
        }

        dcfg->upload_filemode = (int)mode;
    }

    return NULL;
}

static const char *cmd_upload_keep_files(cmd_parms *cmd, void *_dcfg,
                                         const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    if (dcfg == NULL) return NULL;

    if (strcasecmp(p1, "on") == 0) {
        dcfg->upload_keep_files = KEEP_FILES_ON;
    } else
    if (strcasecmp(p1, "off") == 0) {
        dcfg->upload_keep_files = KEEP_FILES_OFF;
    } else
    if (strcasecmp(p1, "relevantonly") == 0) {
        dcfg->upload_keep_files = KEEP_FILES_RELEVANT_ONLY;
    } else {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid setting for SecUploadKeepFiles: ",
            p1,NULL);
    }
    return NULL;
}

static const char *cmd_upload_save_tmp_files(cmd_parms *cmd, void *_dcfg,
    const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    if (dcfg == NULL) return NULL;

    if (strcasecmp(p1, "on") == 0)
    {
        dcfg->upload_validates_files = 1;
    }
    else if (strcasecmp(p1, "off") == 0)
    {
        dcfg->upload_validates_files = 0;
    }
    else
    {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid setting for SecTmpSaveUploadedFiles: ",
            p1,NULL);
    }

    return NULL;
}

static const char *cmd_web_app_id(cmd_parms *cmd, void *_dcfg, const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    /* ENH enforce format (letters, digits, ., _, -) */
    dcfg->webappid = p1;

    return NULL;
}

static const char *cmd_sensor_id(cmd_parms *cmd, void *_dcfg, const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    /* ENH enforce format (letters, digits, ., _, -) */
    dcfg->sensor_id = p1;

    return NULL;
}

/**
* \brief Add SecXmlExternalEntity configuration option
*
* \param cmd Pointer to configuration data
* \param _dcfg Pointer to directory configuration
* \param p1 Pointer to configuration option
*
* \retval NULL On failure
* \retval ngx_psprintf On Success
*/
static const char *cmd_xml_external_entity(cmd_parms *cmd, void *_dcfg, const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;

    if (strcasecmp(p1, "on") == 0)  {
        dcfg->xml_external_entity = 1;
    }
    else if (strcasecmp(p1, "off") == 0)    {
        dcfg->xml_external_entity = 0;
    }
    else return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for SecXmlExternalEntity: ", p1,NULL);

    return NULL;
}


/**
* \brief Add SecHashEngine configuration option
*
* \param cmd Pointer to configuration data
* \param _dcfg Pointer to directory configuration
* \param p1 Pointer to configuration option
*
* \retval NULL On failure
* \retval ngx_psprintf On Success
*/
static const char *cmd_hash_engine(cmd_parms *cmd, void *_dcfg, const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;

    if (strcasecmp(p1, "on") == 0)  {
        dcfg->hash_is_enabled = HASH_ENABLED;
        dcfg->hash_enforcement = HASH_ENABLED;
    }
    else if (strcasecmp(p1, "off") == 0)    {
        dcfg->hash_is_enabled = HASH_DISABLED;
        dcfg->hash_enforcement = HASH_DISABLED;
    }
    else return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for SecHashEngine: ", p1,NULL);

    return NULL;
}

/**
* \brief Add SecHashPram configuration option
*
* \param cmd Pointer to configuration data
* \param _dcfg Pointer to directory configuration
* \param p1 Pointer to configuration option
*
* \retval NULL On success
*/
static const char *cmd_hash_param(cmd_parms *cmd, void *_dcfg, const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    if (dcfg == NULL) return NULL;

    if (p1 == NULL) return NULL;
    dcfg->crypto_param_name = p1;

    return NULL;
}

/**
* \brief Add SecHashKey configuration option
*
* \param cmd Pointer to configuration data
* \param _dcfg Pointer to directory configuration
* \param _p1 Pointer to configuration option
* \param _p2 Pointer to configuration option
*
* \retval NULL On success
*/
static const char *cmd_hash_key(cmd_parms *cmd, void *_dcfg, const char *_p1, const char *_p2)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    char *p1 = NULL;

    if (dcfg == NULL) return NULL;
    if (_p1 == NULL) return NULL;

    if (strcasecmp(_p1, "Rand") == 0)    {
        p1 = ngx_pstrndup(cmd->pool, getkey(cmd->pool));
        dcfg->crypto_key = p1;
        dcfg->crypto_key_len = strlen(dcfg->crypto_key);
    } else    {
        p1 = ngx_pstrndup(cmd->pool, _p1);
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

/**
* \brief Add SecHashMethodPm configuration option
*
* \param cmd Pointer to configuration data
* \param _dcfg Pointer to directory configuration
* \param p1 Pointer to configuration option
* \param p2 Pointer to configuration option
*
* \retval NULL On failure
* \retval ngx_psprintf On Success
*/
static const char *cmd_hash_method_pm(cmd_parms *cmd, void *_dcfg,
        const char *p1, const char *p2)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    rule_exception *re = (rule_exception*)ngx_pcalloc(cmd->pool, sizeof(hash_method));
    const char *_p2 = ngx_pstrndup(cmd->pool, p2);
    ACMP *p = NULL;
    const char *phrase = NULL;
    const char *next = NULL;

    if (dcfg == NULL) return NULL;

    p = acmp_create(0, cmd->pool);
    if (p == NULL) return NULL;

    if(phrase == NULL)
        phrase = ngx_pstrndup(cmd->pool, _p2);

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
            return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid pattern: ", p2,NULL);
        }
        dcfg->crypto_hash_href_pm = 1;
    }
    else if (strcasecmp(p1, "HashFormAction") == 0) {
        re->type = HASH_URL_FACTION_HASH_PM;
        re->param = _p2;
        re->param_data = (void *)p;
        if (re->param_data == NULL) {
            return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid pattern: ", p2,NULL);
        }
        dcfg->crypto_hash_faction_pm = 1;
    }
    else if (strcasecmp(p1, "HashLocation") == 0) {
        re->type = HASH_URL_LOCATION_HASH_PM;
        re->param = _p2;
        re->param_data = (void *)p;
        if (re->param_data == NULL) {
            return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid pattern: ", p2,NULL);
        }
        dcfg->crypto_hash_location_pm = 1;
    }
    else if (strcasecmp(p1, "HashIframeSrc") == 0) {
        re->type = HASH_URL_IFRAMESRC_HASH_PM;
        re->param = _p2;
        re->param_data = (void *)p;
        if (re->param_data == NULL) {
            return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid pattern: ", p2,NULL);
        }
        dcfg->crypto_hash_iframesrc_pm = 1;
    }
    else if (strcasecmp(p1, "HashFrameSrc") == 0) {
        re->type = HASH_URL_FRAMESRC_HASH_PM;
        re->param = _p2;
        re->param_data = (void *)p;
        if (re->param_data == NULL) {
            return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid pattern: ", p2,NULL);
        }
        dcfg->crypto_hash_framesrc_pm = 1;
    }

    *(hash_method **)ngx_array_push(dcfg->hash_method) = re;

    return NULL;
}

/**
 * \brief Add SecHashMethodRx configuration option
 *
 * \param cmd Pointer to configuration data
 * \param _dcfg Pointer to directory configuration
 * \param p1 Pointer to configuration option
 * \param p2 Pointer to configuration option
 *
 * \retval NULL On failure
 * \retval ngx_psprintf On Success
 */
static const char *cmd_hash_method_rx(cmd_parms *cmd, void *_dcfg,
        const char *p1, const char *p2)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    rule_exception *re = (rule_exception*)ngx_pcalloc(cmd->pool, sizeof(hash_method));
    const char *_p2 = ngx_pstrndup(cmd->pool, p2);
    if (dcfg == NULL) return NULL;

    if (strcasecmp(p1, "HashHref") == 0) {
        re->type = HASH_URL_HREF_HASH_RX;
        re->param = _p2;
        re->param_data = msc_pregcomp(cmd->pool, p2, 0, NULL, NULL);
        if (re->param_data == NULL) {
            return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid regular expression: ", p2,NULL);
        }
        dcfg->crypto_hash_href_rx = 1;
    }
    else if (strcasecmp(p1, "HashFormAction") == 0) {
        re->type = HASH_URL_FACTION_HASH_RX;
        re->param = _p2;
        re->param_data = msc_pregcomp(cmd->pool, p2, 0, NULL, NULL);
        if (re->param_data == NULL) {
            return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid regular expression: ", p2,NULL);
        }
        dcfg->crypto_hash_faction_rx = 1;
    }
    else if (strcasecmp(p1, "HashLocation") == 0) {
        re->type = HASH_URL_LOCATION_HASH_RX;
        re->param = _p2;
        re->param_data = msc_pregcomp(cmd->pool, p2, 0, NULL, NULL);
        if (re->param_data == NULL) {
            return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid regular expression: ", p2,NULL);
        }
        dcfg->crypto_hash_location_rx = 1;
    }
    else if (strcasecmp(p1, "HashIframeSrc") == 0) {
        re->type = HASH_URL_IFRAMESRC_HASH_RX;
        re->param = _p2;
        re->param_data = msc_pregcomp(cmd->pool, p2, 0, NULL, NULL);
        if (re->param_data == NULL) {
            return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid regular expression: ", p2,NULL);
        }
        dcfg->crypto_hash_iframesrc_rx = 1;
    }
    else if (strcasecmp(p1, "HashFrameSrc") == 0) {
        re->type = HASH_URL_FRAMESRC_HASH_RX;
        re->param = _p2;
        re->param_data = msc_pregcomp(cmd->pool, p2, 0, NULL, NULL);
        if (re->param_data == NULL) {
            return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid regular expression: ", p2,NULL);
        }
        dcfg->crypto_hash_framesrc_rx = 1;
    }

    *(hash_method **)ngx_array_push(dcfg->hash_method) = re;

    return NULL;
}

/**
* \brief Add SecHttpBlKey configuration option
*
* \param cmd Pointer to configuration data
* \param _dcfg Pointer to directory configuration
* \param p1 Pointer to configuration option
*
* \retval NULL On success
*/
static const char *cmd_httpBl_key(cmd_parms *cmd, void *_dcfg, const char *p1)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    if (dcfg == NULL) return NULL;

    if (p1 == NULL) return NULL;
    dcfg->httpBlkey = p1;

    return NULL;
}

/* PCRE Limits */

static const char *cmd_pcre_match_limit(cmd_parms *cmd,
        void *_dcfg, const char *p1)
{
    long val;

    val = atol(p1);
    if (val <= 0) {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid setting for "
                "SecPcreMatchLimit: ", p1,NULL);
    }
    msc_pcre_match_limit = (unsigned long int)val;

    return NULL;
}

static const char *cmd_pcre_match_limit_recursion(cmd_parms *cmd,
        void *_dcfg, const char *p1)
{
    long val;

    val = atol(p1);
    if (val <= 0) {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid setting for "
                "SecPcreMatchLimitRecursion: ", p1,NULL);
    }
    msc_pcre_match_limit_recursion = (unsigned long int)val;

    return NULL;
}


/* -- Geo Lookup configuration -- */

static const char *cmd_geo_lookup_db(cmd_parms *cmd, void *_dcfg,
        const char *p1)
{
    const char *filename = p1;
    char *error_msg;
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;

    if (geo_init(dcfg, filename, &error_msg) <= 0) {
        return error_msg;
    }

    return NULL;
}

/**
* \brief Add SecUnicodeCodePage configuration option
*
* Depcrecated
*
* \param cmd Pointer to configuration data
* \param _dcfg Pointer to directory configuration
* \param p1 Pointer to configuration option
*
* \retval NULL On success
*/
static const char *cmd_unicode_codepage(cmd_parms *cmd,
                                        void *_dcfg, const char *p1)
{
    long val;

    val = atol(p1);
    if (val <= 0) {
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid setting for "
                                       "SecUnicodeCodePage: ", p1,NULL);
    }

    unicode_codepage = (unsigned long int)val;

    return NULL;
}

/**
* \brief Add SecUnicodeMapFile configuration option
*
* \param cmd Pointer to configuration data
* \param _dcfg Pointer to directory configuration
* \param p1 Pointer to configuration option
*
* \retval NULL On success
*/
static const char *cmd_unicode_map(cmd_parms *cmd, void *_dcfg,
                                     const char *p1, const char *p2)
{
    const char *filename = p1;
    char *error_msg;
    long val = 0;
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;

    if(p2 != NULL)  {
        val = atol(p2);
        if (val <= 0) {
            return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid setting for "
                    "SecUnicodeMapFile: ", p2,NULL);
        }

        unicode_codepage = (unsigned long int)val;
    }

    if (unicode_map_init(dcfg, filename, &error_msg) <= 0) {
        return error_msg;
    }

    return NULL;
}

/**
* \brief Add SecGsbLookupDb configuration option
*
* \param cmd Pointer to configuration data
* \param _dcfg Pointer to directory configuration
* \param p1 Pointer to configuration option
*
* \retval NULL On success
*/
static const char *cmd_gsb_lookup_db(cmd_parms *cmd, void *_dcfg,
                                     const char *p1)
{
    const char *filename = p1;
    char *error_msg;
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;

    if (gsb_db_init(dcfg, filename, &error_msg) <= 0) {
        return error_msg;
    }

    return NULL;
}

/* -- Cache -- */

static const char *cmd_cache_transformations(cmd_parms *cmd, void *_dcfg,
                                             const char *p1, const char *p2)
{
    directory_config *dcfg = (directory_config *)_dcfg;

    if (dcfg == NULL) return NULL;

    if (strcasecmp(p1, "on") == 0)
        dcfg->cache_trans = MODSEC_CACHE_ENABLED;
    else if (strcasecmp(p1, "off") == 0)
        dcfg->cache_trans = MODSEC_CACHE_DISABLED;
    else
        return ngx_pstrcat(cmd->pool, "ModSecurity: Invalid value for SecCacheTransformations: ", p1,NULL);

    /* Process options */
    if (p2 != NULL) {
        ngx_table_t *vartable = ngx_table_make(cmd->pool, 4);
        ngx_int_t rc;
        char *error_msg = NULL;
        const char *charval = NULL;
        int64_t intval = 0;

        if (vartable == NULL) {
            return ngx_pstrndup(cmd->pool, "ModSecurity: Unable to process options for SecCacheTransformations");
        }
        rc = msre_parse_generic(cmd->pool, p2, vartable, &error_msg);
        if (rc < 0) {
            return ngx_pstrcat(cmd->pool, "ModSecurity: Unable to parse options for SecCacheTransformations: ", error_msg,NULL);
        }

        /* incremental */
        charval = ngx_table_get(vartable, "incremental");
        if (charval != NULL) {
            if (strcasecmp(charval, "on") == 0)
                dcfg->cache_trans_incremental = 1;
            else if (strcasecmp(charval, "off") == 0)
                dcfg->cache_trans_incremental = 0;
            else
                return ngx_pstrcat(cmd->pool, "ModSecurity: SecCacheTransformations invalid incremental value: ", charval,NULL);
        }

        /* minlen */
        charval = ngx_table_get(vartable, "minlen");
        if (charval != NULL) {
            intval = ngx_atoi64(charval);
            if (errno == ERANGE) {
                return ngx_pstrcat(cmd->pool, "ModSecurity: SecCacheTransformations minlen out of range: ", charval,NULL);
            }
            if (intval < 0) {
                return ngx_pstrcat(cmd->pool, "ModSecurity: SecCacheTransformations minlen must be positive: ", charval,NULL);
            }

            /* The NGX_CONF_UNSET indicator is -1, a signed long, and therfore
             * we cannot be >= the unsigned value of NGX_CONF_UNSET.
             */
            if ((unsigned long)intval >= (unsigned long)NGX_CONF_UNSET) {
                return ngx_psprintf(cmd->pool,
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
                return ngx_pstrcat(cmd->pool, "ModSecurity: SecCacheTransformations maxlen out of range: ", charval,NULL);
            }
            if (intval < 0) {
                return ngx_pstrcat(cmd->pool, "ModSecurity: SecCacheTransformations maxlen must be positive: ", charval,NULL);
            }

            /* The NGX_CONF_UNSET indicator is -1, a signed long, and therfore
             * we cannot be >= the unsigned value of NGX_CONF_UNSET.
             */
            if ((unsigned long)intval >= (unsigned long)NGX_CONF_UNSET) {
                return ngx_psprintf(cmd->pool,
                        ngx_strlen("ModSecurity: SecCacheTransformations maxlen must be less than: %ul")+NGX_INT64_LEN+2,
                        "ModSecurity: SecCacheTransformations maxlen must be less than: %ul", (unsigned long)NGX_CONF_UNSET);
            }

            if ((intval != 0) && ((size_t)intval < dcfg->cache_trans_min)) {
                return ngx_psprintf(cmd->pool,
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
                return ngx_pstrcat(cmd->pool, "ModSecurity: SecCacheTransformations maxitems out of range: ", charval,NULL);
            }
            if (intval < 0) {
                return ngx_pstrcat(cmd->pool, "ModSecurity: SecCacheTransformations maxitems must be positive: ", charval,NULL);
            }
            dcfg->cache_trans_maxitems = (size_t)intval;
        }
    }

    return NULL;
}


/* -- Configuration directives definitions -- */
const command_rec module_directives[] = {

    INIT_TAKE1 (
        "SecAction",
        cmd_action,
        NULL,
        "an action list"
    ),

    INIT_TAKE1 (
        "SecArgumentSeparator",
        cmd_argument_separator,
        NULL,
        "character that will be used as separator when parsing application/x-www-form-urlencoded content."
    ),

    INIT_TAKE1 (
        "SecCookiev0Separator",
        cmd_cookiev0_separator,
        NULL,
        "character that will be used as separator when parsing cookie v0 content."
    ),


    INIT_TAKE12 (
        "SecCacheTransformations",
        cmd_cache_transformations,
        NULL,
        "whether or not to cache transformations. Defaults to true."
    ),

    INIT_TAKE1 (
        "SecComponentSignature",
        cmd_component_signature,
        NULL,
        "component signature to add to ModSecurity signature."
    ),

    INIT_FLAG (
        "SecContentInjection",
        cmd_content_injection,
        NULL,
        "On or Off"
    ),

    INIT_FLAG (
        "SecStreamOutBodyInspection",
        cmd_stream_outbody_inspection,
        NULL,
        "On or Off"
    ),

    INIT_FLAG (
        "SecStreamInBodyInspection",
        cmd_stream_inbody_inspection,
        NULL,
        "On or Off"
    ),

    INIT_TAKE1 (
        "SecCookieFormat",
        cmd_cookie_format,
        NULL,
        "version of the Cookie specification to use for parsing. Possible values are 0 and 1."
    ),

    INIT_TAKE1 (
        "SecPersistdb",
        cmd_persistdb,
        NULL,
        "name of the persistent data storage database" // TODO
    ),

    INIT_TAKE1 (
        "SecDebugLog",
        cmd_debug_log,
        NULL,
        "path to the debug log file"
    ),

    INIT_TAKE1 (
        "SecDebugLogLevel",
        cmd_debug_log_level,
        NULL,
        "debug log level, which controls the verbosity of logging."
        " Use values from 0 (no logging) to 9 (a *lot* of logging)."
    ),

    INIT_TAKE1 (
        "SecCollectionTimeout",
        cmd_collection_timeout,
        NULL,
        "set default collections timeout. default it 3600"
    ),

    INIT_TAKE1 (
        "SecDefaultAction",
        cmd_default_action,
        NULL,
        "default action list"
    ),

    INIT_FLAG (
        "SecDisableBackendCompression",
        cmd_disable_backend_compression,
        NULL,
        "When set to On, removes the compression headers from the backend requests."
    ),

    INIT_TAKE1 (
        "SecGsbLookupDB",
        cmd_gsb_lookup_db,
        NULL,
        "database google safe browsing"
    ),

	INIT_TAKE1 (
        "SecUnicodeCodePage",
        cmd_unicode_codepage,
        NULL,
        "Unicode CodePage"
    ),

	INIT_TAKE12 (
        "SecUnicodeMapFile",
        cmd_unicode_map,
        NULL,
        "Unicode Map file"
    ),

    INIT_TAKE1 (
        "SecGeoLookupDB",
        cmd_geo_lookup_db,
        NULL,
        "database for geographical lookups module."
    ),


    INIT_TAKE1 (
        "SecMarker",
        cmd_marker,
        NULL,
        "marker for a skipAfter target"
    ),

    INIT_TAKE1 (
        "SecPcreMatchLimit",
        cmd_pcre_match_limit,
        NULL,
        "PCRE match limit"
    ),

    INIT_TAKE1 (
        "SecPcreMatchLimitRecursion",
        cmd_pcre_match_limit_recursion,
        NULL,
        "PCRE match limit recursion"
    ),

    INIT_TAKE1 (
        "SecRequestBodyAccess",
        cmd_request_body_access,
        NULL,
        "On or Off"
    ),

    INIT_TAKE1 (
        "SecInterceptOnError",
        cmd_request_intercept_on_error,
        NULL,
        "On or Off"
    ),

    INIT_TAKE1 (
        "SecRulePerfTime",
        cmd_rule_perf_time,
        NULL,
        "Threshold to log slow rules in usecs."
    ),


    INIT_TAKE1 (
        "SecRequestBodyInMemoryLimit",
        cmd_request_body_inmemory_limit,
        NULL,
        "maximum request body size that will be placed in memory (except for POST urlencoded requests)."
    ),

    INIT_TAKE1 (
        "SecRequestBodyLimit",
        cmd_request_body_limit,
        NULL,
        "maximum request body size ModSecurity will accept."
    ),

    INIT_TAKE1 (
        "SecRequestBodyNoFilesLimit",
        cmd_request_body_no_files_limit,
        NULL,
        "maximum request body size ModSecurity will accept, but excluding the size of uploaded files."
    ),

    INIT_TAKE1 (
        "SecRequestEncoding",
        cmd_request_encoding,
        NULL,
        "character encoding used in request."
    ),

    INIT_TAKE1 (
        "SecResponseBodyAccess",
        cmd_response_body_access,
        NULL,
        "On or Off"
    ),

    INIT_TAKE1 (
        "SecResponseBodyLimit",
        cmd_response_body_limit,
        NULL,
        "byte limit for response body"
    ),

    INIT_TAKE1 (
        "SecResponseBodyLimitAction",
        cmd_response_body_limit_action,
        NULL,
        "what happens when the response body limit is reached"
    ),

    INIT_TAKE1 (
        "SecRequestBodyLimitAction",
        cmd_resquest_body_limit_action,
        NULL,
        "what happens when the request body limit is reached"
    ),

    INIT_ITERATE (
        "SecResponseBodyMimeType",
        cmd_response_body_mime_type,
        NULL,
        "adds given MIME types to the list of types that will be buffered on output"
    ),

	INIT_NO_ARGS (
        "SecResponseBodyMimeTypesClear",
        cmd_response_body_mime_types_clear,
        NULL,
        "clears the list of MIME types that will be buffered on output"
    ),

    INIT_TAKE23 (
        "SecRule",
        cmd_rule,
        NULL,
        "rule target, operator and optional action list"
    ),

    INIT_TAKE1 (
        "SecRuleEngine",
        cmd_rule_engine,
        NULL,
        "On or Off"
    ),

    INIT_TAKE1 (
        "SecXmlExternalEntity",
        cmd_xml_external_entity,
        NULL,
        "On or Off"
    ),

    INIT_FLAG (
        "SecRuleInheritance",
        cmd_rule_inheritance,
        NULL,
        "On or Off"
    ),

    INIT_TAKE12 (
        "SecRuleScript",
        cmd_rule_script,
        NULL,
        "rule script and optional actionlist"
    ),

	INIT_ITERATE (
        "SecRuleRemoveById",
        cmd_rule_remove_by_id,
        NULL,
        "rule ID for removal"
    ),

    INIT_ITERATE (
        "SecRuleRemoveByTag",
        cmd_rule_remove_by_tag,
        NULL,
        "rule tag for removal"
    ),

    INIT_ITERATE (
        "SecRuleRemoveByMsg",
        cmd_rule_remove_by_msg,
        NULL,
        "rule message for removal"
    ),

	INIT_TAKE2 (
        "SecHashMethodPm",
        cmd_hash_method_pm,
        NULL,
        "Hash method and pattern"
    ),

    INIT_TAKE2 (
        "SecHashMethodRx",
        cmd_hash_method_rx,
        NULL,
        "Hash method and regex"
    ),

    INIT_TAKE2 (
        "SecRuleUpdateActionById",
        cmd_rule_update_action_by_id,
        NULL,
        "updated action list"
    ),

    INIT_TAKE23 (
        "SecRuleUpdateTargetById",
        cmd_rule_update_target_by_id,
        NULL,
        "updated target list"
    ),

    INIT_TAKE23 (
        "SecRuleUpdateTargetByTag",
        cmd_rule_update_target_by_tag,
        NULL,
        "rule tag pattern and updated target list"
    ),

    INIT_TAKE23 (
        "SecRuleUpdateTargetByMsg",
        cmd_rule_update_target_by_msg,
        NULL,
        "rule message pattern and updated target list"
    ),

    INIT_TAKE1 (
        "SecTmpDir",
        cmd_tmp_dir,
        NULL,
        "path to the temporary storage area"
    ),

    INIT_TAKE1 (
        "SecUploadDir",
        cmd_upload_dir,
        NULL,
        "path to the file upload area"
    ),

    INIT_TAKE1 (
        "SecUploadFileLimit",
        cmd_upload_file_limit,
        NULL,
        "limit the number of uploaded files processed"
    ),

    INIT_TAKE1 (
        "SecUploadFileMode",
        cmd_upload_filemode,
        NULL,
        "octal permissions mode for uploaded files"
    ),

    INIT_TAKE1 (
        "SecUploadKeepFiles",
        cmd_upload_keep_files,
        NULL,
        "On or Off"
    ),

    INIT_TAKE1 (
        "SecTmpSaveUploadedFiles",
        cmd_upload_save_tmp_files,
        NULL,
        "On or Off"
    ),

    INIT_TAKE1 (
        "SecWebAppId",
        cmd_web_app_id,
        NULL,
        "id"
    ),

    INIT_TAKE1 (
        "SecSensorId",
        cmd_sensor_id,
        NULL,
        "sensor id"
    ),

    INIT_TAKE1 (
        "SecHttpBlKey",
        cmd_httpBl_key,
        NULL,
        "httpBl access key"
    ),

    INIT_TAKE1 (
        "SecHashEngine",
        cmd_hash_engine,
        NULL,
        "On or Off"
    ),

	INIT_TAKE2 (
        "SecHashKey",
        cmd_hash_key,
        NULL,
        "Set Hash key"
    ),

    INIT_TAKE1 (
        "SecHashParam",
        cmd_hash_param,
        NULL,
        "Set Hash parameter"
    ),
	
	INIT_EMPTY()
};
