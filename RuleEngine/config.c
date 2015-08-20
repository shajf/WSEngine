
#include <ngx_config.h>
#include <ngx_core.h>
#include "config.h"
#include "modsecurity.h"

#define VARBUF_MAX_LEN (16*1024*1024)
#define VARBUF_INIT_LEN 200

static cmd_parms default_parms ={NULL, NULL,NULL, NULL, NULL, NULL};


/*****************************************************************
 * Let's begin with the basics; parsing the line and
 * invoking the function...
 */

#define MAX_ARGC 64

static const char *invoke_cmd(const command_rec *cmd, cmd_parms *parms,
                              void *mconfig, const char *args)
{
    char *w, *w2, *w3;
    const char *errmsg = NULL;

    parms->info = cmd->cmd_data;
    parms->cmd = cmd;

    switch (cmd->args_how) {
    case RAW_ARGS:
        return cmd->MSCRAW_ARGS(parms, mconfig, args);

    case TAKE_ARGV:
        {
            char *argv[MAX_ARGC];
            int argc = 0;

            do {
                w = ngx_getword_conf(parms->pool, &args);
                if (*w == '\0' && *args == '\0') {
                    break;
                }
                argv[argc] = w;
                argc++;
            } while (argc < MAX_ARGC && *args != '\0');

            return cmd->MSCTAKE_ARGV(parms, mconfig, argc, argv);
        }

    case NO_ARGS:
        if (*args != 0)
            return ngx_pstrcat(parms->pool, cmd->name, " takes no arguments",
                               NULL);

        return cmd->MSCNO_ARGS(parms, mconfig);

    case TAKE1:
        w = ngx_getword_conf(parms->pool, &args);

        if (*w == '\0' || *args != 0)
            return ngx_pstrcat(parms->pool, cmd->name, " takes one argument",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        return cmd->MSCTAKE1(parms, mconfig, w);

    case TAKE2:
        w = ngx_getword_conf(parms->pool, &args);
        w2 = ngx_getword_conf(parms->pool, &args);

        if (*w == '\0' || *w2 == '\0' || *args != 0)
            return ngx_pstrcat(parms->pool, cmd->name, " takes two arguments",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        return cmd->MSCTAKE2(parms, mconfig, w, w2);

    case TAKE12:
        w = ngx_getword_conf(parms->pool, &args);
        w2 = ngx_getword_conf(parms->pool, &args);

        if (*w == '\0' || *args != 0)
            return ngx_pstrcat(parms->pool, cmd->name, " takes 1-2 arguments",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        return cmd->MSCTAKE2(parms, mconfig, w, *w2 ? w2 : NULL);

    case TAKE3:
        w = ngx_getword_conf(parms->pool, &args);
        w2 = ngx_getword_conf(parms->pool, &args);
        w3 = ngx_getword_conf(parms->pool, &args);

        if (*w == '\0' || *w2 == '\0' || *w3 == '\0' || *args != 0)
            return ngx_pstrcat(parms->pool, cmd->name, " takes three arguments",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        return cmd->MSCTAKE3(parms, mconfig, w, w2, w3);

    case TAKE23:
        w = ngx_getword_conf(parms->pool, &args);
        w2 = ngx_getword_conf(parms->pool, &args);
        w3 = *args ? ngx_getword_conf(parms->pool, &args) : NULL;

        if (*w == '\0' || *w2 == '\0' || *args != 0)
            return ngx_pstrcat(parms->pool, cmd->name,
                               " takes two or three arguments",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        return cmd->MSCTAKE3(parms, mconfig, w, w2, w3);

    case TAKE123:
        w = ngx_getword_conf(parms->pool, &args);
        w2 = *args ? ngx_getword_conf(parms->pool, &args) : NULL;
        w3 = *args ? ngx_getword_conf(parms->pool, &args) : NULL;

        if (*w == '\0' || *args != 0)
            return ngx_pstrcat(parms->pool, cmd->name,
                               " takes one, two or three arguments",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        return cmd->MSCTAKE3(parms, mconfig, w, w2, w3);

    case TAKE13:
        w = ngx_getword_conf(parms->pool, &args);
        w2 = *args ? ngx_getword_conf(parms->pool, &args) : NULL;
        w3 = *args ? ngx_getword_conf(parms->pool, &args) : NULL;

        if (*w == '\0' || (w2 && *w2 && !w3) || *args != 0)
            return ngx_pstrcat(parms->pool, cmd->name,
                               " takes one or three arguments",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        return cmd->MSCTAKE3(parms, mconfig, w, w2, w3);

    case ITERATE:
        w = ngx_getword_conf(parms->pool, &args);
        
        if (*w == '\0')
            return ngx_pstrcat(parms->pool, cmd->name,
                               " requires at least one argument",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        while (*w != '\0') {
            errmsg = cmd->MSCTAKE1(parms, mconfig, w);

            if (errmsg && strcmp(errmsg, DECLINE_CMD) != 0)
                return errmsg;

            w = ngx_getword_conf(parms->pool, &args);
        }

        return errmsg;

    case ITERATE2:
        w = ngx_getword_conf(parms->pool, &args);

        if (*w == '\0' || *args == 0)
            return ngx_pstrcat(parms->pool, cmd->name,
                      
					" requires at least two arguments",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        while (*(w2 = ngx_getword_conf(parms->pool, &args)) != '\0') {

            errmsg = cmd->MSCTAKE2(parms, mconfig, w, w2);

            if (errmsg && strcmp(errmsg, DECLINE_CMD) != 0)
                return errmsg;
        }

        return errmsg;

    case FLAG:
        w = ngx_getword_conf(parms->pool, &args);

        if (*w == '\0' || (strcasecmp(w, "on") && strcasecmp(w, "off")))
            return ngx_pstrcat(parms->pool, cmd->name, " must be On or Off",
                               NULL);

        return cmd->MSCFLAG(parms, mconfig, strcasecmp(w, "off") != 0);

    default:
        return ngx_pstrcat(parms->pool, cmd->name,
                  
				" is improperly configured internally (server bug)",
                           NULL);
    }
}
static const char* process_cmd_line(void *mconfig,ngx_pool_t *p,ngx_pool_t *temp_pool,const char *l,cmd_parms *parms){
    
    const char *args;
    char *cmd_name;
    const command_rec *cmd;

    if (*l == '#' || *l == '\0')
        return NULL;
	
	args = ngx_resolve_env(temp_pool,l);

	cmd_name = ngx_getword_conf(p,&args);
	
	if(*cmd_name == '\0'){
		
		return NULL;
	}
	
	cmd = modsec_find_command(cmd_name);

	if(cmd) {
		
		return invoke_cmd(cmd,parms,mconfig,args);
	}
	
	return (const char*)ngx_pstrcat(p,"Invalid cmd:",cmd_name,NULL);
}

static const char* process_config(void *mconfig,cmd_parms *parms,ngx_pool_t *p,ngx_pool_t *temp_pool){
    
    ngx_int_t rc;
	const char *errval;
    struct ngx_varbuf vb;
    size_t max_len = VARBUF_MAX_LEN;
    
    if(p == temp_pool) max_len = HUGE_STRING_LEN;
    
    ngx_varbuf_init(temp_pool, &vb, VARBUF_INIT_LEN);

    while ((rc = ngx_varbuf_cfg_getline(&vb, parms->config_file, max_len))
           == NGX_OK) {
        errval = process_cmd_line(mconfig,p, temp_pool, vb.buf, parms);

        if (errval!=NULL){

			if(p!=temp_pool) ngx_varbuf_free(&vb);
			
			return errval;
		}
    }

    if(p!=temp_pool) ngx_varbuf_free(&vb);

    return NULL;
}

const char* read_config(void *mconfig,ngx_pool_t *p,ngx_pool_t *ptemp,const char* filename){

    ngx_configfile_t *cfp;
    ngx_int_t rv;
    cmd_parms parms;
    
    parms = default_parms;
    parms.pool = p;
    parms.temp_pool = ptemp;
    
    rv = ngx_pcfg_openfile(&cfp, p, filename);

    if(rv!=NGX_OK){
        
        return ngx_pstrcat(p,"Could not open configuration file: %s",filename,NULL);
    }

    parms.config_file = cfp;
    
    return process_config(mconfig,&parms,p,ptemp);
}


