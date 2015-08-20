
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <wsengine.h>

typedef struct {

    wsengine_module_t* mods[WSENGINE_MODULE_MAX];

}wsengine_t;

static wsengine_t wsengine,*wsengine_ptr = &wsengine;

static ngx_int_t wsengine_pre_init(ngx_conf_t *cf);

static ngx_int_t wsengine_init(ngx_conf_t *cf);

static void *wsengine_create_loc_conf(ngx_conf_t *cf);

static char * wsengine_merge_loc_conf(ngx_conf_t *cf,void *parent,void *child);

static ngx_int_t wsengine_header_filter(ngx_http_request_t *r);

static ngx_int_t wsengine_request_check(ngx_http_request_t *r);

static ngx_int_t wsengine_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

static ngx_command_t  wsengine_commands[] = {

    { ngx_string("wsengine"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(wsengine_loc_conf_t, on),
      NULL 
     },
    
    {   ngx_string("wsengine_context_hash_size"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        0,
        offsetof(wsengine_loc_conf_t, size),
        NULL
    },
    
    ngx_null_command
};

static ngx_http_module_t wsengine_module_ctx = {

    wsengine_pre_init,                       /* preconfiguration */
    wsengine_init,                           /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    wsengine_create_loc_conf,              /* create location configuration */
    wsengine_merge_loc_conf                /* merge location configuration */
};

ngx_module_t  wsengine_module = {
    NGX_MODULE_V1,
    &wsengine_module_ctx,                  /* module context */
    wsengine_commands,                     /* module directives */
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


static char * wsengine_merge_loc_conf(ngx_conf_t *cf,void *parent,void *child){
    
    return NGX_CONF_OK;
}

static void *wsengine_create_loc_conf(ngx_conf_t *cf){
    
    wsengine_loc_conf_t *conf;

    conf = (wsengine_loc_conf_t*)ngx_pcalloc(cf->pool,sizeof(wsengine_loc_conf_t));
    
    if(conf == NULL){
        return NULL;
    }

    return conf;
}

static ngx_int_t wsengine_pre_init(ngx_conf_t *cf){
    
    int i;

    for(i=0;i<WSENGINE_MODULE_MAX;i++){
        
        wsengine_ptr->mods[i] = NULL;
    }
    
    return NGX_OK;
}

static ngx_int_t wsengine_init(ngx_conf_t *cf){
    
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf,ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);

    if(h == NULL){
        return NGX_ERROR;
    }

    *h = wsengine_request_check;


    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = wsengine_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = wsengine_body_filter;
    
    return NGX_OK;
}


static ngx_int_t wsengine_header_filter(ngx_http_request_t *r){
    
    return NGX_DECLINED;
}

static ngx_int_t wsengine_request_check(ngx_http_request_t *r){
    
    return NGX_DECLINED;
}

static ngx_int_t wsengine_body_filter(ngx_http_request_t *r, ngx_chain_t *in){
    
    return NGX_DECLINED;
}

command_rec * wsengine_find_command(int modid,const char *cmdname){
	
	int i;
	wsengine_module_t *mod = NULL;
	
	command_rec *cmd;

	if(modid<=WSENGINE_MODULE_START||modid>=WSENGINE_MODULE_MAX) {
		
		return NULL;
	}

	for(i=0;i<WSENGINE_MODULE_MAX;i++){

		mod = wsengine_ptr->mods[i];
        
        if(mod==NULL) continue;

		if(mod->id == modid){
			break;	
		}
	}
	
	if(i>=WSENGINE_MODULE_MAX){
		return NULL;	
	}

	i = 0;
	
	while((cmd=&(mod->module_cmds[i++]))){
		
		if(strcasecmp(cmd->name,cmdname) == 0){
			
			return cmd;
		}
	}

	return NULL;
}

void wsengine_module_register(wsengine_module_t *mod) {
    
    wsengine_ptr->mods[mod->rank] = mod;
}

