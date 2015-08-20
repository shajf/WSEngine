/*
 *By shajianfeng
 * */
#ifndef LINE_CONF_FILE_H
#define LINE_CONF_FILE_H

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct {
    /**< an apr_file_getc()-like function */
    ngx_int_t (*getch) (char *ch, void *param);
    /**< an apr_file_gets()-like function */
    ngx_int_t (*getstr) (void *buf, size_t bufsiz, void *param);
    /**< a close handler function */
    ngx_int_t (*close) (void *param);
    /**< the argument passed to getch/getstr/close */
    void *param;
    /**< the filename / description */
    const char *name;
    /**< current line number, starting at 1 */
    size_t line_number;
}ngx_configfile_t;


extern int ngx_cfg_closefile(ngx_configfile_t *cfp); 

/* Open a ngx_configfile_t as FILE, return open ngx_configfile_t struct pointer */
extern ngx_int_t ngx_pcfg_openfile(ngx_configfile_t **ret_cfg,ngx_pool_t *p, const char *name);

extern ngx_configfile_t * ngx_pcfg_open_custom(
            ngx_pool_t *p, const char *descr, void *param,
            ngx_int_t (*getc_func) (char *ch, void *param),
            ngx_int_t (*gets_func) (void *buf, size_t bufsize, void *param),
            ngx_int_t (*close_func) (void *param));

/* Read one character from a configfile_t */
extern ngx_int_t ngx_cfg_getc(char *ch, ngx_configfile_t *cfp);

extern ngx_int_t ngx_cfg_getline(char *buf, size_t bufsize,
                                        ngx_configfile_t *cfp);


extern ngx_int_t ngx_varbuf_cfg_getline(struct ngx_varbuf *vb,
                                          ngx_configfile_t *cfg, 
                                          size_t max_len);

extern char * ngx_getword_conf(ngx_pool_t *p, const char **line);

extern const char * ngx_resolve_env(ngx_pool_t *p, const char * word);

#endif /*LINE_CONF_FILE_H*/
