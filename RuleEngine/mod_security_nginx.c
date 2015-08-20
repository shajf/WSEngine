

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_base64.h>

#include "modsecurity.h"
#include "msc_http_var.h"
#include "nginx_io.h"
#include "msc_log.h"

typedef struct {
    
    ngx_flag_t on;
    
    directory_config *config;
}modsec_loc_conf_t;

/* Defined in msc_config.c */
extern const command_rec module_directives[];

unsigned long int  msc_pcre_match_limit = 0;

unsigned long int  msc_pcre_match_limit_recursion = 0;

msc_engine  *modsecurity = NULL;

static ngx_int_t modsec_init(ngx_conf_t *cf);

static void *modsec_create_conf(ngx_conf_t *cf);
static char *modsec_merge_conf(ngx_conf_t *cf,void *parent,void *child);

static char *ngx_http_modsecurity_config(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/*security check http request */
static ngx_int_t modsec_http_in_check(ngx_http_request_t *r);

/*http request body check after readed body*/
static void modsec_request_body_check(ngx_http_request_t *r);

/*security check http response header*/
static ngx_int_t modsec_http_out_header_check(ngx_http_request_t *r);

/*security check http response body */
static ngx_int_t modsec_http_out_body_check(ngx_http_request_t *r,ngx_chain_t *in);

static ngx_http_module_t  modsec_module_ctx = {
    NULL,                                  /* preconfiguration */
    modsec_init,                           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    modsec_create_conf,                    /* create location configuration */
    modsec_merge_conf                      /* merge location configuration */
};


static ngx_command_t modsec_commands[] = {

    { ngx_string("ModSecEngine"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(modsec_loc_conf_t, on),
      NULL },

    { ngx_string("SecPolicy"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_modsecurity_config,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      
    ngx_null_command
};

ngx_module_t  ngx_http_modsec_module = {
    NGX_MODULE_V1,
    &modsec_module_ctx,                    /* module context */
    modsec_commands,
    //module_directives,                       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static void *modsec_create_conf(ngx_conf_t *cf){
    
    modsec_loc_conf_t *conf = (modsec_loc_conf_t*)ngx_pcalloc(cf->pool,sizeof(modsec_loc_conf_t));

    if(conf == NULL){
        return NULL;
    }
    
    conf->on = NGX_CONF_UNSET;
    conf->config = NGX_CONF_UNSET_PTR;

    return conf;
}

static char *modsec_merge_conf(ngx_conf_t *cf,void *parent,void *child){
    
    return NGX_CONF_OK;
}

static char *
ngx_http_modsecurity_config(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){

    modsec_loc_conf_t *mscf = conf;
    ngx_str_t       *value;
    const char      *msg;
    ngx_pool_t *ptemp;

    if (mscf->config != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    mscf->config = create_directory_config(cf->pool,NULL);

    if (mscf->config == NULL) {
        return NGX_CONF_ERROR;
    }

    /*create modsecurity rule engine*/
    modsecurity = modsecurity_create(cf->pool,MODSEC_ONLINE);
    if(modsecurity == NULL){
        return NGX_CONF_ERROR;
    }
    
    /*create a temp pool for loading rule config*/
    ptemp = ngx_create_pool(1024,cf->log);
    
    if(ptemp == NULL){
        return NGX_CONF_ERROR;
    }

    /*load modsecurity rules from config*/
    msg = read_config((void*)mscf->config,cf->pool,ptemp,(const char*)value[1].data);

    if (msg != NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ModSecurityConfig in %s:%ui: %s",
                cf->conf_file->file.name.data, cf->conf_file->line, msg);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t modsec_init(ngx_conf_t *cf){
    

    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf,ngx_http_core_module);
    
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);

    if(h == NULL){
        
        return NGX_ERROR;
    }

    *h = modsec_http_in_check;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = modsec_http_out_header_check;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = modsec_http_out_body_check;
    
    return NGX_OK;
}

const command_rec *modsec_find_command(const char *cmdname){
    
    const command_rec *cmd;
    int i=0;
    
    for(;;){

		cmd = &module_directives[i++]; 
        
		if(cmd==NULL||cmd->args_how==EMPTY){
			break;	
		}

		if(strcasecmp(cmd->name,cmdname)==0){
            return cmd;
        }
    }

    return NULL;
}

/**
 * Retrieves a previously stored transaction context by
 * looking at the main request, and the previous requests.
 */
static modsec_rec *retrieve_tx_context(ngx_http_request_t *r) {
    modsec_rec *msr = NULL;

    msr = (modsec_rec *)ngx_table_get(r->main->notes, NOTE_MSR);
    if (msr != NULL) {
        msr->r = r;
        return msr;
    }
    return NULL;
}

/**
 * Stores transaction context where it can be found in subsequent
 * phases, redirections, or subrequests.
 */
static void store_tx_context(modsec_rec *msr, ngx_http_request_t *r) {
    ngx_table_setn(r->main->notes, NOTE_MSR, (void *)msr);
}

static void context_tx_cleanup(void *data){
    
    modsec_rec *msr = (modsec_rec*)data;
    
    ngx_destroy_pool(msr->mp);
}

static modsec_rec* create_tx_context(ngx_http_request_t *r){

    char salt[TXID_SIZE];
    char *txid;
    ngx_pool_cleanup_t              *cln;
    
    modsec_rec *msr = NULL;

    modsec_loc_conf_t *mscf = ngx_http_get_module_loc_conf(r,ngx_http_modsec_module);
    
    msr = (modsec_rec *)ngx_pcalloc(r->pool, sizeof(modsec_rec));
    
    if (msr == NULL) return NULL;
    
    msr->mp = ngx_create_pool(1024,r->pool->log);
    
    if(msr->mp == NULL) return NULL;

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_t));
    cln->handler = context_tx_cleanup;
    cln->data = (void*)msr;

    msr->modsecurity = modsecurity;
    msr->r = r;
    msr->r_early = r;
    
    msr->request_time = ngx_ext_time_make(r->start_sec, r->start_msec);

    msr->txcfg = create_directory_config(msr->mp,NULL);
    
    if (msr->txcfg == NULL) {
        ngx_destroy_pool(msr->mp);
        return NULL;
    }

    msr->txcfg = merge_directory_configs(msr->mp, msr->txcfg, mscf->config);
    
    if (msr->txcfg == NULL) {
        ngx_destroy_pool(msr->mp);
        return NULL;

    }

    init_directory_config(msr->txcfg);

    generate_random_bytes(salt, TXID_SIZE);

    txid = ngx_pcalloc (msr->mp, TXID_SIZE);

    ngx_base64_encode(txid, salt, TXID_SIZE);
    
    msr->txid = txid;

    if (msr->txcfg->debuglog_level >= 4) {
        msr_log(msr, 4, "Initialising transaction (txid %s).", msr->txid);
    }

    /* Populate tx fields */
    msr->error_messages = ngx_array_create(msr->mp, 5, sizeof(error_message_t *));
    msr->alerts = ngx_array_create(msr->mp, 5, sizeof(char *));

    msr->server_software = "wsengine";
    msr->local_addr = msc_http_var_local_addr(msr);
    msr->local_port = msc_http_var_local_port(msr);

    msr->remote_addr = msc_http_var_remote_addr(msr);
    msr->remote_port = msc_http_var_remote_port(msr);

    msr->request_line = msc_http_var_request_line(msr);
    msr->request_uri = msc_http_var_request_uri(msr);
    ngx_uri_parse(msr->mp,msr->request_uri,&msr->parsed_uri);

    msr->request_method = msc_http_var_request_method(msr);
    msr->query_string = msc_http_var_query_string(msr);
    msr->request_protocol = msc_http_var_request_protocol(msr);
    msr->request_headers = msc_http_var_request_headers(msr);
    msr->hostname = msc_http_var_hostname(msr);

    msr->msc_full_request_buffer = NULL;
    msr->msc_full_request_length = 0;
    msr->msc_rule_mptmp = NULL;

    /* Invoke the engine to continue with initialisation */
    if (modsecurity_tx_init(msr) < 0) {
        msr_log(msr, 1, "Failed to initialise transaction (txid %s).", msr->txid);
        
        ngx_destroy_pool(msr->mp);
        return NULL;
    }

    store_tx_context(msr, r);
    return msr;
}

/**
 * Intercepts transaction, using the method specified
 * in the structure itself. MUST return an HTTP status code,
 * which will be used to terminate the transaction.
 */
ngx_int_t modsec_perform_interception(modsec_rec *msr) {
    msre_actionset *actionset = NULL;
    const char *message = NULL;
    const char *phase_text = "";
    int status = NGX_DECLINED;
    int log_level = 1;
    size_t phase_text_len = 0;
    /* Sanity checks first. */

    if (msr->was_intercepted == 0) {
        msr_log(msr, 1, "Internal Error: Asked to intercept request but was_intercepted is zero");
        return NGX_DECLINED;
    }

    if (msr->phase > 4) {
        msr_log(msr, 1, "Internal Error: Asked to intercept request in phase %d.", msr->phase);
        msr->was_intercepted = 0;
        return NGX_DECLINED;
    }

    /* OK, we're good to go. */

    actionset = msr->intercept_actionset;
    phase_text = ngx_psprintf(msr->mp, NGX_INT64_LEN+16," (phase %d)", msr->phase);
    phase_text_len = ngx_strlen(phase_text);

    /* By default we log at level 1 but we switch to 4
     * if a nolog action was used or this is not the initial request
     * to hide the message.
     */
    log_level = (actionset->log != 1) ? 4 : 1;

    /* Determine how to respond and prepare the log message. */
    switch(actionset->intercept_action) {
        case ACTION_DENY :
            if (actionset->intercept_status != 0) {
                status = actionset->intercept_status;
                message = ngx_psprintf(msr->mp, NGX_INT64_LEN+ngx_strlen("Access denied with code %d%s.")+phase_text_len+2,
                        "Access denied with code %d%s.",
                        status, phase_text);
            } else {
                log_level = 1;
                status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                message = ngx_psprintf(msr->mp, 
        ngx_strlen("Access denied with code 500%s (Internal Error: Invalid status code requested %d).")+NGX_INT64_LEN+phase_text_len+2,
                        "Access denied with code 500%s (Internal Error: Invalid status code requested %d).",
                        phase_text, actionset->intercept_status);
            }
            break;

        case ACTION_DROP :
            status = NGX_HTTP_FORBIDDEN;
            message = ngx_psprintf(msr->mp, ngx_strlen("Access denied with connection close%s.")+phase_text_len+2,
                    "Access denied with connection close%s.",
                phase_text);
            break;

        case ACTION_ALLOW :
            status = NGX_DECLINED;
            message = ngx_psprintf(msr->mp, ngx_strlen("Access allowed%s.")+phase_text_len+2,"Access allowed%s.", phase_text);
            msr->was_intercepted = 0;
            msr->allow_scope = ACTION_ALLOW;
            break;

        case ACTION_ALLOW_PHASE :
            status = NGX_DECLINED;
            
            message = ngx_psprintf(msr->mp, ngx_strlen("Access to phase allowed%s.")+phase_text_len+2,
                    "Access to phase allowed%s.", phase_text);

            msr->was_intercepted = 0;
            msr->allow_scope = ACTION_ALLOW_PHASE;
            break;

        case ACTION_ALLOW_REQUEST :
            status = NGX_DECLINED;
            message = ngx_psprintf(msr->mp,
                    ngx_strlen("Access to request allowed%s.")+phase_text_len+2,
                    "Access to request allowed%s.", phase_text);

            msr->was_intercepted = 0;
            msr->allow_scope = ACTION_ALLOW_REQUEST;
            break;

        default :
            log_level = 1;
            status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            message = ngx_psprintf(msr->mp,
                    ngx_strlen("Access denied with code 500%s (Internal Error: invalid interception action %d).")+phase_text_len+NGX_INT64_LEN+2,
                    "Access denied with code 500%s (Internal Error: invalid interception action %d).",
                    phase_text, actionset->intercept_action);
            break;
    }

    /* If the level is not high enough to add an alert message, but "auditlog"
     * is enabled, then still add the message. */
    if ((log_level > 3) && (actionset->auditlog != 0)) {
        *(const char **)ngx_array_push(msr->alerts) = msc_alert_message(msr, actionset, NULL, message);
    }

    /* Log the message now. */
    msc_alert(msr, log_level, actionset, message, msr->intercept_message);

    /* However, this will mark the txn relevant again if it is <= 3,
     * which will mess up noauditlog.  We need to compensate for this
     * so that we do not increment twice when auditlog is enabled and
     * prevent incrementing when auditlog is disabled.
     */
    if ((actionset->auditlog == 0) && (log_level <= 3)) {
        msr->is_relevant--;
    }

    return status;
}

/*security check http request */
static ngx_int_t modsec_http_in_check(ngx_http_request_t *r){
    
    ngx_int_t rc;
    modsec_rec *msr = NULL;

    /* This function needs to run only once per transaction
     * (i.e. subrequests and redirects are excluded).
     */
    if(r->main!=r){
        
        return NGX_DECLINED;
    }
    /*if we can't find the context then create it first*/ 
    msr = retrieve_tx_context(r);

    if(msr == NULL){
        msr = create_tx_context(r);

        if(msr== NULL){
            return NGX_DECLINED;
        }
    }

    /*Has this phase been completed already*/
    if(msr->phase_request_body_complete){ 
        msr_log(msr, 1, "Internal Error: Attempted to process the request body more than once.");
        return NGX_DECLINED;
    }
    
    msr->phase_request_body_complete = 1;

    msr->remote_user = msc_http_var_remote_user(msr);
    
    if (msr->txcfg->is_enabled == 0) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Processing disabled, skipping (http request ).");
        }
        return NGX_DECLINED;
    }
    
    /*check http request line and headers*/

    if (modsecurity_process_phase(msr, PHASE_REQUEST_HEADERS) > 0) {
        /* There was a match; see if we need to intercept. */
        rc = modsec_perform_interception(msr);
        if (rc != NGX_DECLINED) {
            /* Intercepted */
            return rc;
        }
    }

    /* The rule engine could have been disabled in phase 1. */
    if (msr->txcfg->is_enabled == MODSEC_DISABLED) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Skipping phase 2 as the rule engine was disabled by a rule in phase 1.");
        }

        return NGX_DECLINED;
    }

    /* Check that the request body is not too long, but only
     * if configuration allows for request body access.
     */
    msr->inbound_error = 0;
    if (msr->txcfg->reqbody_access == 1) {
        /* Check request body limit (non-chunked requests only). */
        if (msr->request_content_length > msr->txcfg->reqbody_limit) {

            if((msr->txcfg->is_enabled == MODSEC_ENABLED) && (msr->txcfg->if_limit_action == REQUEST_BODY_LIMIT_ACTION_REJECT)) {
                msr->inbound_error = 1;
                msr_log(msr, 1, "Request body (Content-Length) is larger than the "
                        "configured limit (%l). Deny with status (%d)", msr->txcfg->reqbody_limit, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE);
                return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
            } else if ((msr->txcfg->is_enabled == MODSEC_ENABLED) && (msr->txcfg->if_limit_action == REQUEST_BODY_LIMIT_ACTION_PARTIAL)){
                msr->inbound_error = 1;
                msr_log(msr, 1, "Request body (Content-Length) is larger than the "
                        "configured limit (%l).", msr->txcfg->reqbody_limit);
            } else if ((msr->txcfg->is_enabled == MODSEC_DETECTION_ONLY) && (msr->txcfg->if_limit_action == REQUEST_BODY_LIMIT_ACTION_PARTIAL)){
                msr_log(msr, 1, "Request body (Content-Length) is larger than the "
                        "configured limit (%l).", msr->txcfg->reqbody_limit);
                msr->inbound_error = 1;
            } else  {
                msr_log(msr, 1, "Request body (Content-Length) is larger than the "
                        "configured limit (%l).", msr->txcfg->reqbody_limit);
                msr->inbound_error = 1;
            }
        }
    }

    /* Figure out whether to extract multipart files. */
    if ((msr->txcfg->upload_keep_files != KEEP_FILES_OFF) /* user might want to keep them */
            || (msr->txcfg->upload_validates_files)) /* user might want to validate them */
    {
        msr->upload_extract_files = 1;
        msr->upload_remove_files = 1;
    }
    
    /*read http request body*/
    rc = ngx_http_read_client_request_body(r, modsec_request_body_check);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    
    } 
    
    return NGX_DONE;
}

static void modsec_request_body_check(ngx_http_request_t *r){
    
    char *error_msg;
    ngx_int_t rc;

    modsec_rec *msr = retrieve_tx_context(r);
    
    if(msr == NULL){
        ngx_http_finalize_request(r,NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    
    rc = read_http_request_body(msr,&error_msg);

    if(rc<0){
        
        switch(rc) {
            case -1 :
                if (error_msg != NULL) {
                    msr_log(msr, 1, "%s", error_msg);
                }
                
                ngx_http_finalize_request(r,NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
                break;

            case -5 : /* Request body limit reached. */
                msr->inbound_error = 1;
                if((msr->txcfg->is_enabled == MODSEC_ENABLED) && (msr->txcfg->if_limit_action== REQUEST_BODY_LIMIT_ACTION_REJECT)){
                    if (error_msg != NULL) {
                        msr_log(msr, 1, "%s. Deny with code (%d)", error_msg, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE);
                    }
                    
                    ngx_http_finalize_request(r,NGX_HTTP_REQUEST_ENTITY_TOO_LARGE);
                    return;
                } else  {
                    if (error_msg != NULL) {
                        msr_log(msr, 1, "%s", error_msg);
                    }
                }
                break;

            default :
                /* allow through */
                break;
        }

        msr->msc_reqbody_error = 1;
        msr->msc_reqbody_error_msg = error_msg;
    }

    /* Process phase REQUEST_BODY */
    rc = NGX_DECLINED;
    if (modsecurity_process_phase(msr, PHASE_REQUEST_BODY) > 0) {
        rc = modsec_perform_interception(msr);
    }

    if(msr->txcfg->stream_inbody_inspection && msr->msc_reqbody_read)    {
        const char *clen = NULL;
        clen = (const char*)ngx_psprintf(msr->mp,NGX_INT64_LEN+2,"%z",msr->stream_input_length);

        if(clen){
            add_http_request_header(msr,"Content-Length",clen,&r->headers_in.content_length);
        }
    }

    /* Remove the compression ability indications the client set,
     * but only if we need to disable backend compression.
     */
    if (msr->txcfg->disable_backend_compression) {
        
        if(r->headers_in.acc_encoding){
        
            r->headers_in.acc_encoding->hash = 0;
            r->headers_in.acc_encoding = NULL;
        }
        
        if(r->headers_in.te){
            r->headers_in.te->hash = 0;
            r->headers_in.te = NULL;
        }
    }

    ngx_http_finalize_request(r,rc);
}

static ngx_int_t init_header_filter(modsec_rec *msr){

    ngx_http_request_t *r = msr->r;

    /* Put back the Accept-Encoding and TE request headers
     * if they were removed from the request.
     */
    if (msr->txcfg->disable_backend_compression) {
        char *ae = (char *)ngx_table_get(msr->request_headers, "Accept-Encoding");
        char *te = (char *)ngx_table_get(msr->request_headers, "TE");

        if (ae != NULL) {
            add_http_request_header(msr,"Accept-Encoding",ae,&r->headers_in.acc_encoding);
        }

        if (te != NULL) {
            add_http_request_header(msr,"TE",te,&r->headers_in.te);
        }
    }
    
    /* Update our context from the request structure. */
    msr->response_status = msc_http_var_response_status(msr);
    msr->status_line = msc_http_var_status_line(msr);
    msr->response_protocol = msc_http_var_response_protocol(msr);

    if(msr->txcfg->crypto_hash_location_rx == 1 || msr->txcfg->crypto_hash_location_pm == 1)
        modify_response_header(msr);

    msr->response_headers = msc_http_var_response_headers(msr);
        
    return NGX_OK;
}
/*security check http response header*/
static ngx_int_t modsec_http_out_header_check(ngx_http_request_t *r){
   
    ngx_int_t rc;

    modsec_rec *msr = retrieve_tx_context(r);
    /*only check raw request*/
    if(msr==NULL||r!=r->main||msr->phase_response_headers_complete){
        return ngx_http_next_header_filter(r);
    }
    
    msr->phase_response_headers_complete = 1;
    
    init_header_filter(msr);

    /* Process phase RESPONSE_HEADERS */
    rc = modsecurity_process_phase(msr, PHASE_RESPONSE_HEADERS);
    if (rc < 0) { /* error */
        return ngx_http_filter_finalize_request(r,NULL,NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    if (rc > 0) { /* transaction needs to be interrupted */
        rc = modsec_perform_interception(msr);
        if (rc != NGX_DECLINED) { /* DECLINED means we allow-ed the request. */
            msr->of_status = OF_STATUS_COMPLETE;
            msr->resbody_status = RESBODY_STATUS_ERROR;
            return ngx_http_filter_finalize_request(r,NULL,rc);
        }
    }

    return ngx_http_next_header_filter(r);
}

/**
 * Examines the configuration and the response MIME type
 * in order to determine whether body buffering should
 * run or not.
 */

static int body_check_should_run(modsec_rec *msr, ngx_http_request_t *r) {
    char *content_type = NULL;

    /* Check configuration. */
    if (msr->txcfg->resbody_access != 1) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "body check: Response body buffering is not enabled.");
        }

        return 0;
    }

    /* Check MIME type. */

    if ((msr->txcfg->of_mime_types == NULL)||(msr->txcfg->of_mime_types == NGX_CONF_UNSET_PTR)) {
        msr_log(msr, 1, "body check: MIME type structures corrupted (internal error).");
        return -1;
    }
    
    content_type =  (char*)msc_http_var_content_type(msr);

    if (content_type != NULL) {
        char *p = NULL;

        /* Hide the character encoding information
         * if present. Sometimes the content type header
         * looks like this "text/html; charset=xyz" ...
         */
        p = strstr(content_type, ";");
        if (p != NULL) {
            *p = '\0';
        }

        strtolower_inplace((unsigned char *)content_type);

        if (strcmp(content_type, "text/html") == 0) {
            /* Useful information to have should we later
             * decide to do something with the HTML output.
             */
            msr->resbody_contains_html = 1;
        }
    } else {
        content_type = "null";
    }

    if (ngx_table_get(msr->txcfg->of_mime_types, content_type) != NULL) return 1;

    msr_log(msr, 4, "body filter: Not buffering response body for unconfigured MIME type \"%s\".", content_type);

    return 0;
}
/**
 * Initialises the body filter.
 */
static ngx_int_t body_check_init(modsec_rec *msr)
{
    ngx_http_request_t *r = msr->r;
    long int content_length = 0;
    ngx_int_t rc;

    msr->of_status = OF_STATUS_IN_PROGRESS;

    rc = body_check_should_run(msr, r);

    if (rc < 0) return -1; /* body_check_should_run() generates error msg */
    if (rc == 0) return 0;

    /* Do not check the output limit if we are willing to
     * process partial response bodies.
     */

    if (msr->txcfg->of_limit_action == RESPONSE_BODY_LIMIT_ACTION_PARTIAL) {
        return 1;
    }

    /* Look up the Content-Length header to see if we know
     * the amount of data coming our way. If we do and if
     * it's too much we might want to stop processing right here.
     */
    content_length = (long int)msc_http_var_content_length(msr,0);


    if ((content_length == LONG_MIN)||(content_length == LONG_MAX)||(content_length < 0)||(content_length >= 1073741824)) {
        msr_log(msr, 1, "body filter: Invalid Content-Length: %d", content_length);
        return -1; /* Invalid. */
    }

    if (content_length == 0) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "body filter: Skipping response since Content-Length is zero.");
        }

        return 0;
    }

    if (content_length > msr->txcfg->of_limit) {
        msr_log(msr, 1, "body filter: Content-Length (%d) over the limit (%d).",content_length,msr->txcfg->of_limit);
        msr->outbound_error = 1;
        return -2; /* Over the limit. */
    }

    return 1;
}


/**
 *
 */
static int flatten_response_body(modsec_rec *msr,ngx_chain_t *in) {
    
    ngx_int_t rc;

    msr->resbody_status = RESBODY_STATUS_READ_CHAIN;

    if (msr->resbody_length + 1 <= 0) {
        msr_log(msr, 1, "body filter: Invalid response length: %z" ,msr->resbody_length);
        return -1;
    }

    msr->resbody_data = ngx_palloc(msr->mp, msr->resbody_length + 1);
    if (msr->resbody_data == NULL) {
        msr_log(msr, 1, "body filter: Response body data memory allocation failed. Asked for: %z",
                msr->resbody_length + 1);
        return -1;
    }
    
    rc = ngx_chain_copy_to_buf(in,(u_char*)msr->resbody_data,msr->resbody_length);

    if (rc != NGX_OK) {
        msr_log(msr, 1, "body filter: Failed to flatten chain (%d)", rc);
        return -1;
    }

    msr->resbody_data[msr->resbody_length] = '\0';
    msr->resbody_status = RESBODY_STATUS_READ;

    if (msr->txcfg->stream_outbody_inspection && msr->txcfg->hash_is_enabled == HASH_DISABLED)  {

        msr->stream_output_length = msr->resbody_length;

        if (msr->stream_output_data == NULL) {
            msr_log(msr, 1, "body filter: Stream Response body data memory allocation failed. Asked for: %z" ,
                    msr->stream_output_length + 1);
            return -1;
        }

        memset(msr->stream_output_data, 0, msr->stream_output_length+1);
        memcpy(msr->stream_output_data, msr->resbody_data, msr->stream_output_length);
        msr->stream_output_data[msr->stream_output_length] = '\0';
    } else if (msr->txcfg->stream_outbody_inspection && msr->txcfg->hash_is_enabled == HASH_ENABLED)    {
        int retval = 0;
        ngx_ext_time_t time1 = ngx_ext_time_now();

        retval = init_response_body_html_parser(msr);

        if(retval == 1) {
            retval = hash_response_body_links(msr);
            if(retval > 0) {
                retval = inject_hashed_response_body(msr, retval);
                if (msr->txcfg->debuglog_level >= 4) {
                    msr_log(msr, 4, "Hash completed in %T usec.", (ngx_ext_time_now() - time1));
                }

            }
        }

        if(msr->of_stream_changed == 0) {
            msr->stream_output_length = msr->resbody_length;

            if (msr->stream_output_data == NULL) {
                msr_log(msr, 1, "Output filter: Stream Response body data memory allocation failed. Asked for: %z",
                        msr->stream_output_length + 1);
                return -1;
            }

            memset(msr->stream_output_data, 0, msr->stream_output_length+1);
            memcpy(msr->stream_output_data, msr->resbody_data, msr->stream_output_length);
            msr->stream_output_data[msr->stream_output_length] = '\0';
        }
    }

    return 1;
}

/*security check http response body */
static ngx_int_t modsec_http_out_body_check(ngx_http_request_t *r,ngx_chain_t *in){
    
    ngx_int_t rc;
    modsec_rec *msr = retrieve_tx_context(r);
    ngx_chain_t *cl = in;

    int start_skipping = 0;
    
    if(in==NULL||msr==NULL||r!=r->main||r->header_only||msr->phase_response_body_complete||msr->of_status == OF_STATUS_COMPLETE){
        
        return ngx_http_next_body_filter(r,in);
    }
    
    msr->phase_response_body_complete = 1;

    msr->outbound_error = 0;
    /* Decide whether to observe the response body. */
    rc = body_check_init(msr);

    switch(rc){
        
        case -2: /*response too large*/
        case -1: /*error*/
            msr->of_status = OF_STATUS_COMPLETE;
            msr->resbody_status = RESBODY_STATUS_ERROR;
            return ngx_http_filter_finalize_request(r,NULL,NGX_HTTP_INTERNAL_SERVER_ERROR);
        
        case 0 :
            /* We do not want to observe this response body
             * but we need to remain attached to observe
             * when it is completed so that we can run
             * the RESPONSE_BODY phase.
             */
            msr->of_skipping = 1;
            msr->resbody_status = RESBODY_STATUS_NOT_READ;
            break;
        default :
            /* Continue (observe the response body). */
            break;
    }

    /* Loop through the chains  in order
     * to extract the size of the data available.
     */
    msr->resbody_length = 0;
    
    for(;;){
       
        /* Look into response data if configured to do so,
         * unless we've already processed a partial response.
         */
        if ((msr->of_skipping == 0)&&(!msr->of_partial)) { /* Observe the response data. */
            /* Retrieve data from the bucket. */

            /* Check the response size. */
            if (msr->resbody_length > (size_t)msr->txcfg->of_limit) {
                /* The size of the response is larger than what we're
                 * ready to accept. We need to decide what we want to do
                 * about it.
                 */
                msr->outbound_error = 1;
                if (msr->txcfg->of_limit_action == RESPONSE_BODY_LIMIT_ACTION_REJECT) {
                    /* Reject response. */
                    msr_log(msr, 1, "body filter: Response body too large (over limit of %l, "
                            "total not specified).", msr->txcfg->of_limit);

                    msr->of_status = OF_STATUS_COMPLETE;
                    msr->resbody_status = RESBODY_STATUS_PARTIAL;
                    
                    return ngx_http_filter_finalize_request(r,NULL,NGX_HTTP_INTERNAL_SERVER_ERROR);
                } else {
                    /* Process partial response. */
                    start_skipping = 1;
                    msr->resbody_length = msr->txcfg->of_limit;

                    if (msr->txcfg->debuglog_level >= 4) {
                        msr_log(msr, 4, "Output filter: Processing partial response body (limit %l)",
                                msr->txcfg->of_limit);
                    }
                }
            } else {
                msr->resbody_length += ngx_buf_size(cl->buf);
            }
        }
        
        if(cl->next==NULL) {
            msr->of_done_reading = 1; 
            break;
        }

       cl = cl->next;
    } 

    if ((msr->of_skipping == 0)&&(msr->of_partial == 0)) {

        /* Do we need to process a partial response? */
        if (start_skipping) {

            if (msr->txcfg->stream_outbody_inspection)  {
                if(msr->stream_output_data != NULL) {
                    free(msr->stream_output_data);
                    msr->stream_output_data = NULL;
                }

                msr->stream_output_data = (char *)malloc(msr->resbody_length+1);
            }

            if (flatten_response_body(msr,in) < 0) {
                if (msr->txcfg->stream_outbody_inspection)  {
                    if(msr->stream_output_data != NULL) {
                        free(msr->stream_output_data);
                        msr->stream_output_data = NULL;
                    }
                }

                return ngx_http_filter_finalize_request(r,NULL,NGX_HTTP_INTERNAL_SERVER_ERROR);
            }

            /* Process phase RESPONSE_BODY */
            rc = modsecurity_process_phase(msr, PHASE_RESPONSE_BODY);
            if (rc < 0) {
                return ngx_http_filter_finalize_request(r,NULL,NGX_HTTP_INTERNAL_SERVER_ERROR);
            }
            if (rc > 0) {
                rc = modsec_perform_interception(msr);
                if (rc != NGX_DECLINED) { /* DECLINED means we allow-ed the request. */
                    return ngx_http_filter_finalize_request(r,NULL,NGX_HTTP_INTERNAL_SERVER_ERROR);
                }
            }

            msr->of_partial = 1;

            return ngx_http_next_body_filter(r,in);
        }

        if (msr->of_done_reading == 0) {
            /* We are done for now. We will be called again with more data. */
            return ngx_http_next_body_filter(r,in);
        }

        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Output filter: Completed receiving response body (buffered %s - %z bytes).",
                    (msr->of_partial ? "partial" : "full"), msr->resbody_length);
        }
    } else { /* Not looking at response data. */
        if (msr->of_done_reading == 0) {
            if (msr->txcfg->debuglog_level >= 9) {
                msr_log(msr, 9, "Output filter: Sending input brigade directly.");
            }

            return ngx_http_next_body_filter(r,in);
        }

        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Output filter: Completed receiving response body (non-buffering).");
        }
    }
    
    msr->of_status = OF_STATUS_COMPLETE;
    
    if (msr->txcfg->stream_outbody_inspection)  {
        if(msr->stream_output_data != NULL) {
            free(msr->stream_output_data);
            msr->stream_output_data = NULL;
        }

        msr->stream_output_data = (char *)malloc(msr->resbody_length+1);
    }

    if (flatten_response_body(msr,in) < 0) {
        if (msr->txcfg->stream_outbody_inspection)  {
            if(msr->stream_output_data != NULL) {
                free(msr->stream_output_data);
                msr->stream_output_data = NULL;
            }
        }
        
        ngx_http_finalize_request(r,NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = modsecurity_process_phase(msr, PHASE_RESPONSE_BODY);
    if (rc < 0) {
        ngx_http_finalize_request(r,rc);
        return rc;
    }

    if (rc > 0) {
        rc = modsec_perform_interception(msr);
        if (rc != NGX_DECLINED) { /* DECLINED means we allow-ed the request. */
            ngx_http_finalize_request(r,rc);
            return rc;
        }
    }

    return ngx_http_next_body_filter(r,in);
}

