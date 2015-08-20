#ifndef WSENGINE_H
#define WSENGINE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <config.h>

typedef struct wsengine_module_t wsengine_module_t;

enum wsengine_module_ids {
    
    WSENGINE_MODULE_START = 0,
    WSENGINE_RULE_ENGINE_MODULE,

    WSENGINE_MODULE_MAX
};

struct wsengine_module_t{
    ngx_uint_t  id;
    const char *name;
    ngx_uint_t  rank;
    
    command_rec *module_cmds;
    
    ngx_int_t (*wsengine_req_scheck)(void *ctx,ngx_http_request_t *r);

    ngx_int_t (*wsengine_res_header_scheck)(void *ctx,ngx_http_request_t *r);
    
    ngx_int_t (*wsengine_res_body_scheck)(void *ctx,ngx_http_request_t *r,ngx_chain_t *in);

    ngx_int_t (*wsengine_auditlog)(void *ctx,ngx_http_request_t *r);
    
    ngx_int_t (*wsengine_context_init)(void *ctx,ngx_http_request_t *r);

    void*     (*wsengine_context_create)(ngx_http_request_t *r);

};

typedef struct {
    int on;
    ngx_uint_t size;
}wsengine_loc_conf_t;

void wsengine_module_register(wsengine_module_t *mod);

command_rec * wsengine_find_command(int modid,const char *cmdname);

#endif /*WSENGINE_H*/
