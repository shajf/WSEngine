/*
* shajf
*/

#ifndef _MSC_RE_H_
#define _MSC_RE_H_

#include <ngx_config.h>
#include <ngx_core.h>

#define ABSOLUTE_VALUE 0
#define POSITIVE_VALUE 1
#define NEGATIVE_VALUE 2

typedef struct msre_engine msre_engine;
typedef struct msre_ruleset msre_ruleset;
typedef struct msre_ruleset_internal msre_ruleset_internal;
typedef struct msre_rule msre_rule;
typedef struct msre_var_metadata msre_var_metadata;
typedef struct msre_var msre_var;
typedef struct msre_op_metadata msre_op_metadata;
typedef struct msre_tfn_metadata msre_tfn_metadata;
typedef struct msre_actionset msre_actionset;
typedef struct msre_action_metadata msre_action_metadata;
typedef struct msre_action msre_action;
typedef struct msre_reqbody_processor_metadata msre_reqbody_processor_metadata;
typedef struct msre_cache_rec msre_cache_rec;

#include "modsecurity.h"
#include "msc_pcre.h"
#include "msc_tree.h"
#include "persist_sqlite.h"

/* Actions, variables, functions and operator functions */
char  *update_rule_target_ex(modsec_rec *msr, msre_ruleset *ruleset, msre_rule *rule, const char *p2,const char *p3);

int  msre_ruleset_rule_matches_exception(msre_rule *rule, rule_exception *re);

char *msre_ruleset_rule_update_target_matching_exception(modsec_rec *msr, msre_ruleset *ruleset, rule_exception *re,const char *p2, const char *p3);

char *msre_ruleset_phase_rule_update_target_matching_exception(modsec_rec *msr, msre_ruleset *ruleset, rule_exception *re,ngx_array_t *phase_arr, const char *p2, const char *p3);

ngx_int_t  collection_original_setvar(modsec_rec *msr, const char *col_name, const msc_string *orig_var);

int  expand_macros(modsec_rec *msr, msc_string *var, msre_rule *rule, ngx_pool_t *mptmp);

msre_var_metadata  *msre_resolve_var(msre_engine *engine, const char *name);

msre_var  *msre_create_var_ex(ngx_pool_t *pool, msre_engine *engine, const char *name, const char *param,modsec_rec *msr, char **error_msg);

int  msre_parse_generic(ngx_pool_t *pool, const char *text, ngx_table_t *vartable,char **error_msg);

int  rule_id_in_range(int ruleid, const char *range);

msre_var  *generate_single_var(modsec_rec *msr, msre_var *var, ngx_array_t *tfn_arr,msre_rule *rule, ngx_pool_t *mptmp);

#if defined(WITH_LUA)
ngx_table_t  *generate_multi_var(modsec_rec *msr, msre_var *var, ngx_array_t *tfn_arr,msre_rule *rule, ngx_pool_t *mptmp);
#endif

/* Structures with the corresponding functions */

struct msre_engine {
    ngx_pool_t              *mp;
    ngx_table_t             *variables;
    ngx_table_t             *operators;
    ngx_table_t             *actions;
    ngx_table_t             *tfns;
    ngx_table_t             *reqbody_processors;
};

msre_engine  *msre_engine_create(ngx_pool_t *parent_pool);

void  msre_engine_destroy(msre_engine *engine);

msre_op_metadata  *msre_engine_op_resolve(msre_engine *engine, const char *name);

struct msre_ruleset {
    ngx_pool_t              *mp;
    msre_engine             *engine;

    ngx_array_t      *phase_request_headers;
    ngx_array_t      *phase_request_body;
    ngx_array_t      *phase_response_headers;
    ngx_array_t      *phase_response_body;
    ngx_array_t      *phase_logging;
};

ngx_int_t  msre_ruleset_process_phase(msre_ruleset *ruleset, modsec_rec *msr);

ngx_int_t  msre_ruleset_process_phase_internal(msre_ruleset *ruleset, modsec_rec *msr);

msre_ruleset  *msre_ruleset_create(msre_engine *engine, ngx_pool_t *mp);

int  msre_ruleset_rule_add(msre_ruleset *ruleset, msre_rule *rule, int phase);

msre_rule  *msre_ruleset_fetch_rule(msre_ruleset *ruleset, const char *id, int offset);

int  msre_ruleset_rule_remove_with_exception(msre_ruleset *ruleset, rule_exception *re);

/*
int  msre_ruleset_phase_rule_remove_with_exception(msre_ruleset *ruleset, rule_exception *re,
    ngx_array_t *phase_arr);
*/

#define RULE_NO_MATCH           0
#define RULE_MATCH              1

#define RULE_PH_NONE            0  /* Not a placeholder */
#define RULE_PH_SKIPAFTER       1  /* Implicit placeholder for skipAfter */
#define RULE_PH_MARKER          2  /* Explicit placeholder for SecMarker */

#define RULE_TYPE_NORMAL        0  /* SecRule */
#define RULE_TYPE_ACTION        1  /* SecAction */
#define RULE_TYPE_MARKER        2  /* SecMarker */
#if defined(WITH_LUA)
#define RULE_TYPE_LUA           3  /* SecRuleScript */
#endif

struct msre_rule {
    ngx_array_t      *targets;
    const char              *op_name;
    const char              *op_param;
    void                    *op_param_data;
    msre_op_metadata        *op_metadata;
    unsigned int             op_negated;
    msre_actionset          *actionset;
    const char              *p1;
    const char              *unparsed;
    const char              *filename;
    int                      line_num;
    int                      placeholder;
    int                      type;

    msre_ruleset            *ruleset;
    msre_rule               *chain_starter;
    #if defined(PERFORMANCE_MEASUREMENT)
    unsigned int             execution_time;
    unsigned int             trans_time;
    unsigned int             op_time;
    #endif

    #if defined(WITH_LUA)
    /* Compiled Lua script. */
    msc_script              *script;
    #endif

    ngx_pcre_t                 *sub_regex;
    char                    *sub_str;
    char                    *re_str;
    int                     re_precomp;
    int                     escape_re;

    TreeRoot                *ip_op;
};

char  *msre_rule_generate_unparsed(ngx_pool_t *pool, const msre_rule *rule, const char *targets, const char *args, const char *actions);

msre_rule  *msre_rule_create(msre_ruleset *ruleset, int type,
    const char *fn, int line, const char *targets,
    const char *args, const char *actions, char **error_msg);

#if defined(WITH_LUA)
msre_rule  *msre_rule_lua_create(msre_ruleset *ruleset,
    const char *fn, int line, const char *script_filename,
    const char *actions, char **error_msg);
#endif

#define VAR_SIMPLE              0    /* REQUEST_URI */
#define VAR_LIST                1

#define PHASE_REQUEST_HEADERS   1
#define PHASE_REQUEST_BODY      2
#define PHASE_RESPONSE_HEADERS  3
#define PHASE_RESPONSE_BODY     4
#define PHASE_LOGGING           5

typedef int (*fn_op_param_init_t)(msre_rule *rule, char **error_msg);
typedef int (*fn_op_execute_t)(modsec_rec *msr, msre_rule *rule, msre_var *var, char **error_msg);

struct msre_op_metadata {
    const char              *name;
    fn_op_param_init_t       param_init;
    fn_op_execute_t          execute;
};

typedef int (*fn_tfn_execute_t)(ngx_pool_t *pool, unsigned char *input, long int input_length, char **rval, long int *rval_length);

struct msre_tfn_metadata {
    const char              *name;

    /* Functions should populate *rval and return 1 on
     * success, or return -1 on failure (in which case *rval
     * should contain the error message. Strict functions
     * (those that validate in
     * addition to transforming) can return 0 when input
     * fails validation. Functions are free to perform
     * in-place transformation, or to allocate a new buffer
     * from the provideded temporary (per-rule) memory pool.
     *
     * NOTE Strict transformation functions not supported yet.
     */
    fn_tfn_execute_t execute;
};

void  msre_engine_tfn_register(msre_engine *engine, const char *name,fn_tfn_execute_t execute);

void  msre_engine_op_register(msre_engine *engine, const char *name,fn_op_param_init_t fn1, fn_op_execute_t fn2);

void  msre_engine_register_default_tfns(msre_engine *engine);

void  msre_engine_register_default_variables(msre_engine *engine);

void  msre_engine_register_default_operators(msre_engine *engine);

void  msre_engine_register_default_actions(msre_engine *engine);

msre_tfn_metadata  *msre_engine_tfn_resolve(msre_engine *engine, const char *name);

#define VAR_DONT_CACHE  0
#define VAR_CACHE       1

typedef char *(*fn_var_validate_t)(msre_ruleset *ruleset, msre_var *var);
typedef int (*fn_var_generate_t)(modsec_rec *msr, msre_var *var, msre_rule *rule, ngx_table_t *table, ngx_pool_t *mptmp);

struct msre_var_metadata {
    const char              *name;
    unsigned int             type;          /* VAR_TYPE_ constants */
    unsigned int             argc_min;
    unsigned int             argc_max;
    fn_var_validate_t        validate;
    fn_var_generate_t        generate;
    unsigned int             is_cacheable;  /* 0 - no, 1 - yes */
    unsigned int             availability;  /* when does this variable become available? */
};

struct msre_var {
    char                    *name;
    const char              *value;
    unsigned int             value_len;
    char                    *param;
    const void              *param_data;
    msre_var_metadata       *metadata;
    msc_regex_t             *param_regex;
    unsigned int             is_negated;
    unsigned int             is_counting;
};


struct msre_actionset {
    ngx_table_t             *actions;

    /* Metadata */
    const char              *id;
    const char              *rev;
    const char              *msg;
    const char              *logdata;
    const char              *version;
    int                      maturity;
    int                      accuracy;
    int                      severity;
    int                      phase;
    msre_rule               *rule;
    int                     arg_min;
    int                     arg_max;

    /* Flow */
    int                      is_chained;
    int                      skip_count;
    const char              *skip_after;

    /* Disruptive */
    int                      intercept_action;
    int                      intercept_status;

    /* "block" needs parent action to reset it */
    msre_action             *parent_intercept_action_rec;
    msre_action             *intercept_action_rec;
    int                      parent_intercept_action;

    /* Other */
    int                      log;
    int                      auditlog;
    int                      block;
};

void  msre_engine_variable_register(msre_engine *engine, const char *name,
    unsigned int type, unsigned int argc_min, unsigned int argc_max,
    fn_var_validate_t validate, fn_var_generate_t generate,
    unsigned int is_cacheable, unsigned int availability);

msre_actionset  *msre_actionset_create(msre_engine *engine, ngx_pool_t *mp, const char *text,char **error_msg);

msre_actionset  *msre_actionset_merge(msre_engine *engine, ngx_pool_t *mp, msre_actionset *parent,msre_actionset *child, int inherit_by_default);

msre_actionset  *msre_actionset_create_default(msre_engine *engine);

void  msre_actionset_set_defaults(msre_actionset *actionset);

void  msre_actionset_init(msre_actionset *actionset, msre_rule *rule);

typedef char *(*fn_action_validate_t)(msre_engine *engine, ngx_pool_t *mp, msre_action *action);
typedef ngx_int_t (*fn_action_init_t)(msre_engine *engine, ngx_pool_t *mp, msre_actionset *actionset, msre_action *action);
typedef ngx_int_t (*fn_action_execute_t)(modsec_rec *msr, ngx_pool_t *mptmp, msre_rule *rule, msre_action *action);

#define ACTION_DISRUPTIVE       1
#define ACTION_NON_DISRUPTIVE   2
#define ACTION_METADATA         3
#define ACTION_FLOW             4

#define NO_PLUS_MINUS           0
#define ALLOW_PLUS_MINUS        1

#define ACTION_CARDINALITY_ONE  1
#define ACTION_CARDINALITY_MANY 2

#define ACTION_CGROUP_NONE       0
#define ACTION_CGROUP_DISRUPTIVE 1
#define ACTION_CGROUP_LOG        2
#define ACTION_CGROUP_AUDITLOG   3

struct msre_action_metadata {
    const char              *name;
    unsigned int             type;
    unsigned int             argc_min;
    unsigned int             argc_max;
    unsigned int             allow_param_plusminus;
    unsigned int             cardinality;
    unsigned int             cardinality_group;
    fn_action_validate_t     validate;
    fn_action_init_t         init;
    fn_action_execute_t      execute;
};

struct msre_action {
    msre_action_metadata    *metadata;
    const char              *param;
    const void              *param_data;
    unsigned int             param_plusminus; /* ABSOLUTE_VALUE, POSITIVE_VALUE, NEGATIVE_VALUE */
};

void  msre_engine_reqbody_processor_register(msre_engine *engine,const char *name, void *fn_init, void *fn_process, void *fn_complete);

typedef int (*fn_reqbody_processor_init_t)(modsec_rec *msr, char **error_msg);
typedef int (*fn_reqbody_processor_process_t)(modsec_rec *msr, const char *buf,unsigned int size, char **error_msg);
typedef int (*fn_reqbody_processor_complete_t)(modsec_rec *msr, char **error_msg);

struct msre_reqbody_processor_metadata {
    const char                       *name;
    fn_reqbody_processor_init_t       init;
    fn_reqbody_processor_process_t    process;
    fn_reqbody_processor_complete_t   complete;
};


ngx_int_t  msre_parse_vars(msre_ruleset *ruleset, const char *text,ngx_array_t *arr, char **error_msg);

char  *msre_format_metadata(modsec_rec *msr, msre_actionset *actionset);

/* -- Data Cache -- */

struct msre_cache_rec {
    int                      hits;
    int                      changed;
    int                      num;
    const char              *path;
    const char              *val;
    size_t               val_len;
};

struct fuzzy_hash_param_data {
    const char *file;
    int threshold;
};

#endif
