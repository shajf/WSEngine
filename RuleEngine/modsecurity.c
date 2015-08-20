
#include "modsecurity.h"
#include "msc_log.h"
#include "msc_parsers.h"

unsigned long int  unicode_codepage = 0;
int *unicode_map_table = NULL;

/**
 * Creates and initialises a ModSecurity engine instance.
 */
msc_engine *modsecurity_create(ngx_pool_t *mp, int processing_mode) {
    msc_engine *msce = NULL;

    msce = (msc_engine*)ngx_pcalloc(mp, sizeof(msc_engine));

    if (msce == NULL) return NULL;

    msce->mp = mp;
    msce->processing_mode = processing_mode;

    msce->msre = msre_engine_create(msce->mp);
    
    if (msce->msre == NULL) return NULL;
    

    msre_engine_register_default_variables(msce->msre);
    msre_engine_register_default_operators(msce->msre);
    msre_engine_register_default_tfns(msce->msre);
    msre_engine_register_default_actions(msce->msre);
    
    // TODO: msre_engine_register_default_reqbody_processors(msce->msre);

    return msce;
}

static void modsecurity_tx_cleanup(void *data){

}

ngx_int_t  modsecurity_tx_init(modsec_rec *msr){

    const char *s = NULL;
    const ngx_array_t *arr;
    char *semicolon = NULL;
    char *comma = NULL;
    ngx_table_entry_t *te;
    ngx_uint_t i;
    ngx_pool_cleanup_t *cln;

    /* Register TX cleanup */

    cln = ngx_pool_cleanup_add(msr->mp, sizeof(ngx_pool_cleanup_t));
    cln->handler = modsecurity_tx_cleanup;
    cln->data = (void*)msr;
    
    /* Initialise C-L */
    msr->request_content_length = -1;
    s = ngx_table_get(msr->request_headers, "Content-Length");
    if (s != NULL) {
        msr->request_content_length = strtol(s, NULL, 10);
    }

    /* Figure out whether this request has a body */
    msr->reqbody_chunked = 0;
    msr->reqbody_should_exist = 0;
    if (msr->request_content_length == -1) {
        /* There's no C-L, but is chunked encoding used? */
        char *transfer_encoding = (char *)ngx_table_get(msr->request_headers, "Transfer-Encoding");
        if ((transfer_encoding != NULL)&&(m_strcasestr(transfer_encoding, "chunked") != NULL)) {
            msr->reqbody_should_exist = 1;
            msr->reqbody_chunked = 1;
        }
    } else {
        /* C-L found */
        msr->reqbody_should_exist = 1;
    }

    /* Initialise C-T */
    msr->request_content_type = NULL;
    s = ngx_table_get(msr->request_headers, "Content-Type");
    if (s != NULL) msr->request_content_type = s;

    /* Decide what to do with the request body. */
    if ((msr->request_content_type != NULL)
       && (strncasecmp(msr->request_content_type, "application/x-www-form-urlencoded", 33) == 0))
    {
        /* Always place POST requests with
         * "application/x-www-form-urlencoded" payloads in memory.
         */
        msr->msc_reqbody_storage = MSC_REQBODY_MEMORY;
        msr->msc_reqbody_spilltodisk = 0;
        msr->msc_reqbody_processor = "URLENCODED";
    } else {
        /* If the C-L is known and there's more data than
         * our limit go to disk straight away.
         */
        if ((msr->request_content_length != -1)
           && (msr->request_content_length > msr->txcfg->reqbody_inmemory_limit))
        {
            msr->msc_reqbody_storage = MSC_REQBODY_DISK;
        }

        /* In all other cases, try using the memory first
         * but switch over to disk for larger bodies.
         */
        msr->msc_reqbody_storage = MSC_REQBODY_MEMORY;
        msr->msc_reqbody_spilltodisk = 1;

        if (msr->request_content_type != NULL) {
            if (strncasecmp(msr->request_content_type, "multipart/form-data", 19) == 0) {
                msr->msc_reqbody_processor = "MULTIPART";
            }
        }
    }

    /* Check if we are forcing buffering, then use memory only. */
    if (msr->txcfg->reqbody_buffering != REQUEST_BODY_FORCEBUF_OFF) {
        msr->msc_reqbody_storage = MSC_REQBODY_MEMORY;
        msr->msc_reqbody_spilltodisk = 0;
    }

    /* Initialise arguments */
    msr->arguments = ngx_table_make(msr->mp, 32);
    if (msr->arguments == NULL) return -1;
    if (msr->query_string != NULL) {
        int invalid_count = 0;

        if (parse_arguments(msr, msr->query_string, strlen(msr->query_string),
            msr->txcfg->argument_separator, "QUERY_STRING", msr->arguments,
            &invalid_count) < 0)
        {
            msr_log(msr, 1, "Initialisation: Error occurred while parsing QUERY_STRING arguments.");
            return -1;
        }

        if (invalid_count) {
            msr->urlencoded_error = 1;
        }
    }

    msr->arguments_to_sanitize = ngx_table_make(msr->mp, 16);
    if (msr->arguments_to_sanitize == NULL) return -1;
    msr->request_headers_to_sanitize = ngx_table_make(msr->mp, 16);
    if (msr->request_headers_to_sanitize == NULL) return -1;
    msr->response_headers_to_sanitize = ngx_table_make(msr->mp, 16);
    if (msr->response_headers_to_sanitize == NULL) return -1;
    msr->pattern_to_sanitize = ngx_table_make(msr->mp, 32);
    if (msr->pattern_to_sanitize == NULL) return -1;

    /* remove targets */
    msr->removed_targets = ngx_table_make(msr->mp, 16);
    if (msr->removed_targets == NULL) return -1;

    /* Initialise cookies */
    msr->request_cookies = ngx_table_make(msr->mp, 16);
    if (msr->request_cookies == NULL) return -1;

    /* Initialize matched vars */
    msr->matched_vars = ngx_table_make(msr->mp, 8);
    if (msr->matched_vars == NULL) return -1;
    ngx_table_clear(msr->matched_vars);

    msr->perf_rules = ngx_table_make(msr->mp, 8);
    if (msr->perf_rules == NULL) return -1;
    ngx_table_clear(msr->perf_rules);

    /* Locate the cookie headers and parse them */
    arr = ngx_table_elts(msr->request_headers);
    te = (ngx_table_entry_t *)arr->elts;
    for (i = 0; i < arr->nelts; i++) {
        if (strcasecmp(te[i].key, "Cookie") == 0) {
            if (msr->txcfg->cookie_format == COOKIES_V0) {
                semicolon = ngx_pstrndup(msr->mp, te[i].val);
                while((*semicolon != 0)&&(*semicolon != ';')) semicolon++;
                if(*semicolon == ';')    {
                    parse_cookies_v0(msr, te[i].val, msr->request_cookies, ";");
                } else  {
                    comma = ngx_pstrndup(msr->mp, te[i].val);
                    while((*comma != 0)&&(*comma != ',')) comma++;
                    if(*comma == ',')    {
                        comma++;
                        if(*comma == 0x20)   {// looks like comma is the separator
                            if (msr->txcfg->debuglog_level >= 5) {
                                msr_log(msr, 5, "Cookie v0 parser: Using comma as a separator. Semi-colon was not identified!");
                            }
                            parse_cookies_v0(msr, te[i].val, msr->request_cookies, ",");
                        } else {
                            parse_cookies_v0(msr, te[i].val, msr->request_cookies, ";");
                        }
                    } else  {
                        parse_cookies_v0(msr, te[i].val, msr->request_cookies, ";");
                    }
                }
            } else {
                parse_cookies_v1(msr, te[i].val, msr->request_cookies);
            }
        }
    }

    /* Collections. */
    msr->tx_vars = ngx_table_make(msr->mp, 32);
    if (msr->tx_vars == NULL) return -1;

    msr->geo_vars = ngx_table_make(msr->mp, 8);
    if (msr->geo_vars == NULL) return -1;

    msr->collections_original = ngx_table_make(msr->mp, 8);
    if (msr->collections_original == NULL) return -1;
    msr->collections = ngx_table_make(msr->mp, 8);
    if (msr->collections == NULL) return -1;
    msr->collections_dirty = ngx_table_make(msr->mp, 8);
    if (msr->collections_dirty == NULL) return -1;

    /* Other */
    msr->tcache = NULL;
    msr->tcache_items = 0;

    msr->matched_rules = ngx_array_create(msr->mp, 16, sizeof(void *));
    if (msr->matched_rules == NULL) return -1;

    msr->matched_var = (msc_string *)ngx_pcalloc(msr->mp, sizeof(msc_string));
    if (msr->matched_var == NULL) return -1;

    msr->highest_severity = 255; /* high, invalid value */

    msr->removed_rules = ngx_array_create(msr->mp, 16, sizeof(char *));
    if (msr->removed_rules == NULL) return -1;

    msr->removed_rules_tag = ngx_array_create(msr->mp, 16, sizeof(char *));
    if (msr->removed_rules_tag == NULL) return -1;

    msr->removed_rules_msg = ngx_array_create(msr->mp, 16, sizeof(char *));
    if (msr->removed_rules_msg == NULL) return -1;

    return 1;
}

/**
 * Format an alert message.
 */
const char * msc_alert_message(modsec_rec *msr, msre_actionset *actionset, const char *action_message,const char *rule_message)
{
    const char *message = NULL;

    if (rule_message == NULL) rule_message = "Unknown error.";

    if (action_message == NULL) {
        message = ngx_pstrcat(msr->mp, rule_message, msre_format_metadata(msr, actionset),NULL);
    }

    else {
        message = ngx_pstrcat(msr->mp, action_message," ",rule_message, msre_format_metadata(msr, actionset),NULL);
    }

    return message;
}

/**
 * Log an alert message to the log, adding the rule metadata at the end.
 */
void msc_alert(modsec_rec *msr, int level, msre_actionset *actionset, const char *action_message,const char *rule_message)
{
    const char *message = msc_alert_message(msr, actionset, action_message, rule_message);

    msr_log(msr, level, "%s", message);
}

/**
 *
 */
static ngx_int_t modsecurity_process_phase_request_headers(modsec_rec *msr) {
    ngx_ext_time_t time_before;
    ngx_int_t rc = 0;
    
    if (msr->txcfg->debuglog_level >= 4) {
        msr_log(msr, 4, "Starting phase REQUEST_HEADERS.");
    }
    
    time_before = ngx_ext_time_now();

    if (msr->txcfg->ruleset != NULL) {
        rc = msre_ruleset_process_phase(msr->txcfg->ruleset, msr);
    }
    
    msr->time_phase1 = ngx_ext_time_now() - time_before;

    return rc;
}

/**
 *
 */
static ngx_int_t modsecurity_process_phase_request_body(modsec_rec *msr) {
    ngx_ext_time_t time_before;
    ngx_int_t rc = 0;

    
    if ((msr->allow_scope == ACTION_ALLOW_REQUEST)||(msr->allow_scope == ACTION_ALLOW)) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Skipping phase REQUEST_BODY (allow used).");
        }
        
        return 0;
    } else {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Starting phase REQUEST_BODY.");
        }
    }
    
    time_before = ngx_ext_time_now();

    if (msr->txcfg->ruleset != NULL) {
        rc = msre_ruleset_process_phase(msr->txcfg->ruleset, msr);
    }
    
    msr->time_phase2 = ngx_ext_time_now() - time_before;

    return rc;
}

/**
 *
 */
static ngx_int_t modsecurity_process_phase_response_headers(modsec_rec *msr) {
    ngx_ext_time_t time_before;
    ngx_int_t rc = 0;
    
    if (msr->allow_scope == ACTION_ALLOW) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Skipping phase RESPONSE_HEADERS (allow used).");
        }
        
        return 0;
    } else {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Starting phase RESPONSE_HEADERS.");
        }
    }
    
    time_before = ngx_ext_time_now();

    if (msr->txcfg->ruleset != NULL) {
        rc = msre_ruleset_process_phase(msr->txcfg->ruleset, msr);
    }
    
    msr->time_phase3 = ngx_ext_time_now() - time_before;

    return rc;
}

/**
 *
 */
static ngx_int_t modsecurity_process_phase_response_body(modsec_rec *msr) {
    ngx_ext_time_t time_before;
    ngx_int_t rc = 0;
    
    if (msr->allow_scope == ACTION_ALLOW) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Skipping phase RESPONSE_BODY (allow used).");
        }
        
        return 0;
    } else {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Starting phase RESPONSE_BODY.");
        }
    }
    
    time_before = ngx_ext_time_now();

    if (msr->txcfg->ruleset != NULL) {
        rc = msre_ruleset_process_phase(msr->txcfg->ruleset, msr);
    }
    
    msr->time_phase4 = ngx_ext_time_now() - time_before;


    return rc;
}

/**
 * Processes one transaction phase. The phase number does not
 * need to be explicitly provided since it's already available
 * in the modsec_rec structure.
 */
ngx_int_t modsecurity_process_phase(modsec_rec *msr, unsigned int phase) {
    /* Check if we should run. */
    if ((msr->was_intercepted)&&(phase != PHASE_LOGGING)) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Skipping phase %d as request was already intercepted.", phase);
        }
        
        return 0;
    }

    /* Do not process the same phase twice. */
    if (msr->phase >= phase) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Skipping phase %d because it was previously run (at %d now).",
                phase, msr->phase);
        }
        
        return 0;
    }

    msr->phase = phase;

    /* Clear out the transformation cache at the start of each phase */
    if (msr->txcfg->cache_trans == MODSEC_CACHE_ENABLED) {
        if (msr->tcache) {
            ngx_hash2_index_t *hi;
            void *dummy;
            ngx_table_t *tab;
            const void *key;
            ssize_t klen;
            ngx_pool_t *mp = msr->mp;

            for (hi = ngx_hash2_first(mp, msr->tcache); hi; hi = ngx_hash2_next(hi)) {
                ngx_hash2_this(hi, &key, &klen, &dummy);
                tab = (ngx_table_t *)dummy;

                if (tab == NULL) continue;

                ngx_table_clear(tab);
                ngx_hash2_set(msr->tcache, key, klen, NULL);
            }

            if (msr->txcfg->debuglog_level >= 9) {
                msr_log(msr, 9, "Cleared transformation cache for phase %d", msr->phase);
            }
        }

        msr->tcache_items = 0;
        msr->tcache = ngx_hash2_make(msr->mp);
        if (msr->tcache == NULL) return -1;
    }

    switch(phase) {
        case 1 :
            return modsecurity_process_phase_request_headers(msr);
        case 2 :
            return modsecurity_process_phase_request_body(msr);
        case 3 :
            return modsecurity_process_phase_response_headers(msr);
        case 4 :
            return modsecurity_process_phase_response_body(msr);
        default :
            msr_log(msr, 1, "Invalid processing phase: %d", msr->phase);
            break;
    }

    return -1;
}
