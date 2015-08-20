/*
* shajf
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include "re.h"
#include "msc_log.h"

static const char *const severities[] = {
    "EMERGENCY",
    "ALERT",
    "CRITICAL",
    "ERROR",
    "WARNING",
    "NOTICE",
    "INFO",
    "DEBUG",
    NULL,
};

static int fetch_target_exception(msre_rule *rule, modsec_rec *msr, msre_var *var, const char *exceptions);

static ngx_int_t msre_parse_targets(msre_ruleset *ruleset, const char *text,ngx_array_t *arr, char **error_msg);

static char *msre_generate_target_string(ngx_pool_t *pool, msre_rule *rule);

static msre_var *msre_create_var(msre_ruleset *ruleset, const char *name, const char *param,modsec_rec *msr, char **error_msg);

static msre_action *msre_create_action(msre_engine *engine, ngx_pool_t *mp, const char *name,const char *param, char **error_msg);

static ngx_int_t msre_rule_process(msre_rule *rule, modsec_rec *msr);

/* -- Actions, variables, functions and operator functions ----------------- */

/**
 * \brief Remove rule targets to be processed
 *
 * \param rule Pointer to the rule
 * \param msr ModSecurity transaction resource
 * \param var Pointer to target structure.
 * \param targets Exception list.
 */
static int fetch_target_exception(msre_rule *rule, modsec_rec *msr, msre_var *var, const char *exceptions)   {
    const char *targets = NULL;
    char *savedptr = NULL, *target = NULL;
    char *c = NULL, *name = NULL, *value = NULL;
    char *variable = NULL, *myvar = NULL;
    char *myvalue = NULL, *myname = NULL;
    int match = 0;

    if(msr == NULL)
        return 0;

    if(var == NULL)
        return 0;

    if(rule == NULL)
        return 0;

    if(rule->actionset == NULL)
        return 0;

    if(rule->actionset->id !=NULL)    {

        myvar = ngx_pstrndup(msr->mp, var->name);

        c = ngx_strchr(myvar,':');

        if(c != NULL) {
            myname = ngx_strtok(myvar,":",&myvalue);
        } else {
            myname = myvar;
        }

        match = 0;

        targets = ngx_pstrndup(msr->mp, exceptions);

        if(targets != NULL) {
            if (msr->txcfg->debuglog_level >= 9) {
                msr_log(msr, 9, 
                    "fetch_target_exception: Found exception target list [%s] for rule id %s", targets, rule->actionset->id);
            }
            target = ngx_strtok((char *)targets, ",", &savedptr);

            while(target != NULL)   {

                variable = ngx_pstrndup(msr->mp, target);

                c = ngx_strchr(variable,':');

                if(c != NULL) {
                    name = ngx_strtok(variable,":",&value);
                } else {
                    name = variable;
                    value = NULL;
                }

                if((ngx_strlen(myname) == ngx_strlen(name)) &&
                        (strncasecmp(myname, name,ngx_strlen(myname)) == 0))   {

                    if(value != NULL && myvalue != NULL)  {
                        if((ngx_strlen(myvalue) == ngx_strlen(value)) &&
                                strncasecmp(myvalue,value,ngx_strlen(myvalue)) == 0) {
                            if (msr->txcfg->debuglog_level >= 9) {
                                msr_log(msr, 9, "fetch_target_exception: Target %s will not be processed.", target);
                            }
                            match = 1;
                        }
                    } else if (value == NULL && myvalue == NULL)    {
                        if (msr->txcfg->debuglog_level >= 9) {
                            msr_log(msr, 9, "fetch_target_exception: Target %s will not be processed.", target);
                        }
                        match = 1;
                    } else if (value == NULL && myvalue != NULL)   {
                        if (msr->txcfg->debuglog_level >= 9) {
                            msr_log(msr, 9, "fetch_target_exception: Target %s will not be processed.", target);
                        }
                        match = 1;
                    }
                }

                target = ngx_strtok(NULL, ",", &savedptr);
            }
        } else  {
            if (msr->txcfg->debuglog_level >= 9) {
                msr_log(msr, 9, "fetch_target_exception: No exception target found for rule id %s.", rule->actionset->id);

            }
        }

    }

    if(match == 1)
        return 1;

    return 0;
}

/**
 * \brief Update target for all matching rules in set, in any phase
 *
 * \param msr ModSecurity transaction resource
 * \param ruleset Pointer to set of rules to modify
 * \param re Pointer to exception object describing which rules to modify
 * \param p2 Pointer to configuration option TARGET
 * \param p3 Pointer to configuration option REPLACED_TARGET
 */
char *msre_ruleset_rule_update_target_matching_exception(modsec_rec *msr, msre_ruleset *ruleset, rule_exception *re, const char *p2, const char *p3) {
    char *err;

    if(ruleset == NULL)
        return NULL;

    if(p2 == NULL)  {
        return ngx_pstrndup(ruleset->mp, "Trying to update without a target");
    }

    if (NULL != (err = msre_ruleset_phase_rule_update_target_matching_exception(msr, ruleset, re, ruleset->phase_request_headers, p2, p3)))
        return err;
    if (NULL != (err = msre_ruleset_phase_rule_update_target_matching_exception(msr, ruleset, re, ruleset->phase_request_body, p2, p3)))
        return err;
    if (NULL != (err = msre_ruleset_phase_rule_update_target_matching_exception(msr, ruleset, re, ruleset->phase_response_headers, p2, p3)))
        return err;
    if (NULL != (err = msre_ruleset_phase_rule_update_target_matching_exception(msr, ruleset, re, ruleset->phase_response_body, p2, p3)))
        return err;
    if (NULL != (err = msre_ruleset_phase_rule_update_target_matching_exception(msr, ruleset, re, ruleset->phase_logging, p2, p3)))
        return err;

    /* Everything worked! */
    return NULL;
}


/**
 * \brief Update target for all matching rules in set for a specific phase
 *
 * \param msr ModSecurity transaction resource
 * \param ruleset Pointer to set of rules to modify
 * \param re Pointer to exception object describing which rules to modify
 * \param phase_arr Pointer to phase that should be edited
 * \param p2 Pointer to configuration option TARGET
 * \param p3 Pointer to configuration option REPLACED_TARGET
 *
 * \todo Figure out error checking
 */
char *msre_ruleset_phase_rule_update_target_matching_exception(modsec_rec *msr, msre_ruleset *ruleset, rule_exception *re,
        ngx_array_t *phase_arr, const char *p2,
        const char *p3)
{
    msre_rule **rules;
    ngx_uint_t i;
    int  mode;
    char *err;

    mode = 0;
    rules = (msre_rule **)phase_arr->elts;
    for (i = 0; i < phase_arr->nelts; i++) {
        msre_rule *rule = (msre_rule *)rules[i];

        if (mode == 0) { /* Looking for next rule. */
            if (msre_ruleset_rule_matches_exception(rule, re)) {

                err = update_rule_target_ex(NULL, ruleset, rule, p2, p3);
                if (err) return err;
                if (rule->actionset->is_chained) mode = 2; /* Match all rules in this chain. */
            } else {
                if (rule->actionset->is_chained) mode = 1; /* Skip all rules in this chain. */
            }
        } else { /* Handling rule that is part of a chain. */
            if (mode == 2) { /* We want to change the rule. */
                err = update_rule_target_ex(msr, ruleset, rule, p2, p3);
                if (err) return err;
            }

            if ((rule->actionset == NULL)||(rule->actionset->is_chained == 0)) mode = 0;
        }
    }

    return NULL;
}


char *update_rule_target_ex(modsec_rec *msr, msre_ruleset *ruleset, msre_rule *rule, const char *p2,
        const char *p3)   {

    msre_var **targets = NULL;
    const char *current_targets = NULL;
    char *my_error_msg = NULL, *target = NULL;
    char *p = NULL, *savedptr = NULL;
    unsigned int is_negated = 0, is_counting = 0;
    char *name = NULL, *value = NULL;
    char *opt = NULL, *param = NULL;
    char *target_list = NULL, *replace = NULL;
    int rc, match = 0, var_appended = 0;
    ngx_uint_t i;

    if(rule != NULL)    {

        target_list = strdup(p2);
        if(target_list == NULL)
            return ngx_pstrndup(ruleset->mp, "Error to update target - memory allocation");;

        if(p3 != NULL)  {
            replace = strdup(p3);
            if(replace == NULL) {
                free(target_list);
                target_list = NULL;
                return ngx_pstrndup(ruleset->mp, "Error to update target - memory allocation");;
            }
        }

        if(replace != NULL) {

            opt = ngx_strchr(replace,'!');

            if(opt != NULL)  {
                *opt = '\0';
                opt++;
                param = opt;
                is_negated = 1;
            } else if ((opt = ngx_strchr(replace,'&')) != NULL)  {
                *opt = '\0';
                opt++;
                param = opt;
                is_counting = 1;
            } else  {
                param = replace;
            }

            opt = ngx_strchr(param,':');

            if(opt != NULL) {
                name = ngx_strtok(param,":",&value);
            } else {
                name = param;
            }

            if(ngx_table_get(ruleset->engine->variables, name) == NULL)   {
                if(target_list != NULL)
                    free(target_list);
                if(replace != NULL)
                    free(replace);
                if(msr) {
                    msr_log(msr, 9, "Error to update target - [%s] is not valid target", name);
                }
                return ngx_psprintf(ruleset->mp, 
                    ngx_strlen("Error to update target - [] is not valid target")+ngx_strlen(name)+2,
                    "Error to update target - [%s] is not valid target", name);
            }


            if(msr) {
                msr_log(msr, 9, "Trying to replace by variable name [%s] value [%s]", name, value);
            }

            targets = (msre_var **)rule->targets->elts;
            // TODO need a good way to remove the element from array, maybe change array by tables or rings
            for (i = 0; i < rule->targets->nelts; i++) {
                if((ngx_strlen(targets[i]->name) == ngx_strlen(name)) &&
                        (strncasecmp(targets[i]->name,name,ngx_strlen(targets[i]->name)) == 0) &&
                        (targets[i]->is_negated == is_negated) &&
                        (targets[i]->is_counting == is_counting))    {

                    if(value != NULL && targets[i]->param != NULL)  {
                        if((ngx_strlen(targets[i]->param) == ngx_strlen(value)) &&
                                strncasecmp(targets[i]->param,value,ngx_strlen(targets[i]->param)) == 0) {
                            memset(targets[i]->name,0,ngx_strlen(targets[i]->name));
                            memset(targets[i]->param,0,ngx_strlen(targets[i]->param));
                            targets[i]->is_counting = 0;
                            targets[i]->is_negated = 1;
                            match = 1;
                        }
                    } else if (value == NULL && targets[i]->param == NULL){
                        memset(targets[i]->name,0,ngx_strlen(targets[i]->name));
                        targets[i]->is_counting = 0;
                        targets[i]->is_negated = 1;
                        match = 1;
                    } else
                        continue;

                }
            }
        }

        p = ngx_strtok(target_list, ",", &savedptr);

        while(p != NULL) {
            if(replace != NULL) {
                if(match == 1)  {
                    rc = msre_parse_targets(ruleset, p, rule->targets, &my_error_msg);
                    if (rc < 0) {
                        if(msr) {
                            msr_log(msr, 9, "Error parsing rule targets to replace variable");
                        }
                        goto end;
                    }
                    if(msr) {
                        msr_log(msr, 9, "Successfully replaced variable");
                    }
                var_appended = 1;

                } else  {
                    if(msr) {
                        msr_log(msr, 9, "Cannot find variable to replace");
                    }
                    goto end;
                }
            } else {

                target = strdup(p);
                if(target == NULL)
                    return NULL;

                is_negated = is_counting = 0;
                param = name = value = NULL;

                opt = ngx_strchr(target,'!');

                if(opt != NULL)  {
                    *opt = '\0';
                    opt++;
                    param = opt;
                    is_negated = 1;
                } else if ((opt = ngx_strchr(target,'&')) != NULL)  {
                    *opt = '\0';
                    opt++;
                    param = opt;
                    is_counting = 1;
                } else  {
                    param = target;
                }

                opt = ngx_strchr(param,':');

                if(opt != NULL) {
                    name = ngx_strtok(param,":",&value);
                } else {
                    name = param;
                }

                if(ngx_table_get(ruleset->engine->variables, name) == NULL)   {
                    if(target_list != NULL)
                        free(target_list);
                    if(replace != NULL)
                        free(replace);
                    if(msr) {
                        msr_log(msr, 9, "Error to update target - [%s] is not valid target", name);
                    }
                    return ngx_psprintf(ruleset->mp, 
                        ngx_strlen("Error to update target - [] is not valid target")+ngx_strlen(name)+2,
                        "Error to update target - [%s] is not valid target", name);
                }

                if(msr) {
                    msr_log(msr, 9, "Trying to append variable name [%s] value [%s]", name, value);
                }
                match = 0;

                targets = (msre_var **)rule->targets->elts;
                for (i = 0; i < rule->targets->nelts; i++) {
                    if((ngx_strlen(targets[i]->name) == ngx_strlen(name)) &&
                            (strncasecmp(targets[i]->name,name,ngx_strlen(targets[i]->name)) == 0) &&
                            (targets[i]->is_negated == is_negated) &&
                            (targets[i]->is_counting == is_counting))    {

                        if(value != NULL && targets[i]->param != NULL)  {
                            if((ngx_strlen(targets[i]->param) == ngx_strlen(value)) &&
                                    strncasecmp(targets[i]->param,value,ngx_strlen(targets[i]->param)) == 0) {
                                match = 1;
                            }
                        } else if (value == NULL && targets[i]->param == NULL){
                            match = 1;
                        } else
                            continue;

                    }
                }

                if(target != NULL)  {
                    free(target);
                    target = NULL;
                }

                if(match == 0 ) {
                    rc = msre_parse_targets(ruleset, p, rule->targets, &my_error_msg);
                    if (rc < 0) {
                        if(msr) {
                            msr_log(msr, 9, "Error parsing rule targets to append variable");
                        }
                        goto end;
                    }
                    var_appended = 1;
                } else {
                    if(msr) {
                        msr_log(msr, 9, "Skipping variable, already appended");
                    }
                }
            }

            p = ngx_strtok(NULL,",",&savedptr);
        }

        if(var_appended == 1)  {
            current_targets = msre_generate_target_string(ruleset->mp, rule);
            rule->unparsed = msre_rule_generate_unparsed(ruleset->mp, rule, current_targets, NULL, NULL);
            rule->p1 = ngx_pstrndup(ruleset->mp, current_targets);
            if(msr) {
                msr_log(msr, 9, "Successfully appended variable");
            }
        }
    }

end:
    if(target_list != NULL) {
        free(target_list);
        target_list = NULL;
    }
    if(replace != NULL) {
        free(replace);
        replace = NULL;
    }
    if(target != NULL)  {
        free(target);
        target = NULL;
    }
    return NULL;
}

int msre_ruleset_rule_matches_exception(msre_rule *rule, rule_exception *re)   {
    int match = 0;

    /* Only remove non-placeholder rules */
    if (rule->placeholder == RULE_PH_NONE) {
        switch(re->type) {
            case RULE_EXCEPTION_REMOVE_ID :
                if ((rule->actionset != NULL)&&(rule->actionset->id != NULL)) {
                    int ruleid = atoi(rule->actionset->id);

                    if (rule_id_in_range(ruleid, re->param)) {
                        match = 1;
                    }
                }

                break;
            case RULE_EXCEPTION_REMOVE_MSG :
                if ((rule->actionset != NULL)&&(rule->actionset->msg != NULL)) {
                    char *my_error_msg = NULL;

                    int rc = msc_regexec(re->param_data,
                            rule->actionset->msg, ngx_strlen(rule->actionset->msg),
                            &my_error_msg);
                    if (rc >= 0) {
                        match = 1;
                    }
                }

                break;
            case RULE_EXCEPTION_REMOVE_TAG :
                if ((rule->actionset != NULL)&&(ngx_is_empty_table(rule->actionset->actions) == 0)) {
                    char *my_error_msg = NULL;
                    const ngx_array_t *tarr = NULL;
                    const ngx_table_entry_t *telts = NULL;
                    ngx_uint_t act;

                    tarr = ngx_table_elts(rule->actionset->actions);
                    telts = (const ngx_table_entry_t*)tarr->elts;

                    for (act = 0; act < tarr->nelts; act++) {
                        msre_action *action = (msre_action *)telts[act].val;
                        if((action != NULL) && (action->metadata != NULL) && (strcmp("tag", action->metadata->name) == 0))  {

                            int rc = msc_regexec(re->param_data,
                                    action->param, ngx_strlen(action->param),
                                    &my_error_msg);
                            if (rc >= 0)    {
                                match = 1;
                            }
                        }
                    }
                }
                break;
        }
    }
    return match;
}



/**
 * Remove actions with the same cardinality group from the actionset.
 */
static void msre_actionset_cardinality_fixup(msre_actionset *actionset, msre_action *action) {
    const ngx_array_t *tarr = NULL;
    const ngx_table_entry_t *telts = NULL;
    ngx_uint_t i;

    if ((actionset == NULL) || (action == NULL)) return;

    tarr = ngx_table_elts(actionset->actions);
    telts = (const ngx_table_entry_t*)tarr->elts;

    for (i = 0; i < tarr->nelts; i++) {
        msre_action *target = (msre_action *)telts[i].val;
        if (target->metadata->cardinality_group == action->metadata->cardinality_group) {

            ngx_table_unset(actionset->actions, target->metadata->name);
        }
    }
}

static char *msre_generate_target_string(ngx_pool_t *pool, msre_rule *rule)  {

    char *target_str = NULL;
    msre_var **targets = NULL;
    ngx_uint_t i = 0;

    targets = (msre_var **)rule->targets->elts;

    for (i = 0; i < rule->targets->nelts; i++) {

        if(targets[i]->name != NULL && ngx_strlen(targets[i]->name) > 0)    {
            target_str = ngx_pstrcat(pool,
                    (target_str == NULL) ? "" : ngx_psprintf(pool, ngx_strlen(target_str)+4,"%s|", target_str),
                    (targets[i]->is_negated == 0) ? "" : "!",
                    (targets[i]->is_counting == 0) ? "" : "&",
                    (targets[i]->name == NULL) ? "" : targets[i]->name,
                    (targets[i]->param == NULL) ? "" : ngx_psprintf(pool, ngx_strlen(targets[i]->param)+4,":%s", targets[i]->param),
                    NULL);
        }

    }

    return target_str;
}

/**
 * Generate an action string from an actionset.
 */
static char *msre_actionset_generate_action_string(ngx_pool_t *pool, const msre_actionset *actionset)  {
    const ngx_array_t *tarr = NULL;
    const ngx_table_entry_t *telts = NULL;
    char *actions = NULL;
    int chain;
    ngx_uint_t i;

    if (actionset == NULL) return NULL;

    chain = ((actionset->rule != NGX_CONF_UNSET_PTR) && actionset->rule->chain_starter) ? 1 : 0;

    tarr = ngx_table_elts(actionset->actions);
    telts = (const ngx_table_entry_t*)tarr->elts;

    for (i = 0; i < tarr->nelts; i++) {
        msre_action *action = (msre_action *)telts[i].val;
        int use_quotes = 0;

        if (chain) {
            /* Skip some actions that are not used in a chain. */
            if (   (action->metadata->type == ACTION_DISRUPTIVE)
                    || (action->metadata->type == ACTION_METADATA)
                    || (ngx_strcmp("log", action->metadata->name) == 0)
                    || (ngx_strcmp("auditlog", action->metadata->name) == 0)
                    || (ngx_strcmp("nolog", action->metadata->name) == 0)
                    || (ngx_strcmp("noauditlog", action->metadata->name) == 0)
                    || (ngx_strcmp("severity", action->metadata->name) == 0)
                    || (ngx_strcmp("ver", action->metadata->name) == 0)
                    || (ngx_strcmp("maturity", action->metadata->name) == 0)
                    || (ngx_strcmp("accuracy", action->metadata->name) == 0)
                    || (ngx_strcmp("tag", action->metadata->name) == 0)
                    || (ngx_strcmp("phase", action->metadata->name) == 0)) 
            {
                continue;
            }
        }

        /* Check if we need any quotes */
        if (action->param != NULL) {
            int j;
            for(j = 0; action->param[j] != '\0'; j++) {
                if (ngx_isspace(action->param[j])) {
                    use_quotes = 1;
                    break;
                }
            }
            if (j == 0) use_quotes = 1;
        }

        actions = ngx_pstrcat(pool,
                (actions == NULL) ? "" : actions,
                (actions == NULL) ? "" : ",",
                action->metadata->name,
                (action->param == NULL) ? "" : ":",
                (use_quotes) ? "'" : "",
                (action->param == NULL) ? "" : action->param,
                (use_quotes) ? "'" : "",
                NULL);
    }

    return actions;
}

/**
 * Add an action to an actionset.
 */
static void msre_actionset_action_add(msre_actionset *actionset, msre_action *action)
{
    msre_action *add_action = action;

    if ((actionset == NULL)) return;

    /**
     * The "block" action is just a placeholder for the parent action.
     */
    if ((actionset->parent_intercept_action_rec != NULL) && (actionset->parent_intercept_action_rec != NGX_CONF_UNSET_PTR) && (ngx_strcmp("block", action->metadata->name) == 0) && (ngx_strcmp("block", action->metadata->name) == 0)) {
        /* revert back to parent */
        actionset->intercept_action = actionset->parent_intercept_action;
        add_action = actionset->parent_intercept_action_rec;
    }

    if ((add_action == NULL)) return;

    if (add_action->metadata->cardinality_group != ACTION_CGROUP_NONE) {
        msre_actionset_cardinality_fixup(actionset, add_action);
    }

    if (add_action->metadata->cardinality == ACTION_CARDINALITY_ONE) {
        /* One action per actionlist. */
        ngx_table_setn(actionset->actions, add_action->metadata->name, (void *)add_action);
    } else {
        /* Multiple actions per actionlist. */
        ngx_table_addn(actionset->actions, add_action->metadata->name, (void *)add_action);
    }
}

/**
 * Creates msre_var instances (rule variables) out of the
 * given text string and places them into the supplied table.
 */
static ngx_int_t msre_parse_targets(msre_ruleset *ruleset, const char *text,
        ngx_array_t *arr, char **error_msg)
{
    const ngx_array_t *tarr;
    const ngx_table_entry_t *telts;
    ngx_table_t *vartable;
    unsigned int count = 0;
    ngx_int_t rc;
    msre_var *var;
    ngx_uint_t i;

    if (text == NULL) return -1;

    /* Extract name & value pairs first */
    vartable = ngx_table_make(ruleset->mp, 10);
    if (vartable == NULL) return -1;
    rc = msre_parse_generic(ruleset->mp, text, vartable, error_msg);
    if (rc < 0) return rc;

    /* Loop through the table and create variables */
    tarr = ngx_table_elts(vartable);
    telts = (const ngx_table_entry_t*)tarr->elts;
    for (i = 0; i < tarr->nelts; i++) {
        var = msre_create_var(ruleset, telts[i].key, telts[i].val, NULL, error_msg);
        if (var == NULL) return -1;
        *(msre_var **)ngx_array_push(arr) = var;
        count++;
    }

    return count;
}

/**
 * Creates msre_action instances by parsing the given string, placing
 * them into the supplied array.
 */
static ngx_int_t msre_parse_actions(msre_engine *engine, ngx_pool_t *mp, msre_actionset *actionset,
        const char *text, char **error_msg)
{
    const ngx_array_t *tarr;
    const ngx_table_entry_t *telts;
    ngx_table_t *vartable;
    unsigned int count = 0;
    ngx_int_t rc;
    msre_action *action;
    ngx_uint_t i;


    if (error_msg == NULL) {
        return -1;
    }
    *error_msg = NULL;


    if (text == NULL) {
        *error_msg = ngx_pstrndup(mp, "Internal error: " \
            "msre_parse_actions, variable text is NULL");
        return -1;
    }

    /* Extract name & value pairs first */
    vartable = ngx_table_make(mp, 10);
    if (vartable == NULL) {
        *error_msg = ngx_pstrndup(mp, "Internal error: " \
            "msre_parse_actions, failed to create vartable");

        return -1;
    }
    rc = msre_parse_generic(mp, text, vartable, error_msg);
    if (rc < 0) {
        if (*error_msg == NULL)
            *error_msg = ngx_psprintf(mp, NGX_INT64_LEN+2,"Internal error: " \
                "msre_parse_actions, msre_parse_generic failed. Return " \
                "code: %d", rc);

        return rc;
    }

    /* Loop through the table and create actions */
    tarr = ngx_table_elts(vartable);
    telts = (const ngx_table_entry_t*)tarr->elts;
    for (i = 0; i < tarr->nelts; i++) {
        /* Create action. */
        action = msre_create_action(engine, mp, telts[i].key, telts[i].val, error_msg);
        if (action == NULL) {
            if (*error_msg == NULL)
                *error_msg = ngx_pstrndup(mp, "Internal error: " \
                    "msre_parse_actions, msre_create_action failed.");
            return -1;
        }

        /* Initialise action (option). */
        if (action->metadata->init != NULL) {
            action->metadata->init(engine, mp, actionset, action);
        }

        msre_actionset_action_add(actionset, action);

        count++;
    }

    return count;
}

/**
 * Locates variable metadata given the variable name.
 */
msre_var_metadata *msre_resolve_var(msre_engine *engine, const char *name)
{
    return (msre_var_metadata *)ngx_table_get(engine->variables, name);
}

/**
 * Locates action metadata given the action name.
 */
static msre_action_metadata *msre_resolve_action(msre_engine *engine, const char *name)
{
    return (msre_action_metadata *)ngx_table_get(engine->actions, name);
}

/**
 * Creates a new variable instance given the variable name
 * and an (optional) parameter.
 */
msre_var *msre_create_var_ex(ngx_pool_t *pool, msre_engine *engine, const char *name, const char *param,
        modsec_rec *msr, char **error_msg)
{
    const char *varparam = param;
    msre_var *var = ngx_pcalloc(pool, sizeof(msre_var));
    if (var == NULL) return NULL;

    if (error_msg == NULL) return NULL;
    *error_msg = NULL;

    /* Handle negation and member counting */
    if (name[0] == '!') {
        var->is_negated = 1;
        var->name = (char *)name + 1;
    }
    else
        if (name[0] == '&') {
            var->is_counting = 1;
            var->name = (char *)name + 1;
        }
        else {
            var->name = (char *)name;
        }

    /* Treat HTTP_* targets as an alias for REQUEST_HEADERS:* */
    if (   (var->name != NULL)
            && (ngx_strlen(var->name) > 5)
            && (ngx_strncmp("HTTP_", var->name, 5) == 0))
    {
        const char *oldname = var->name;
        var->name = ngx_pstrndup(pool, "REQUEST_HEADERS");
        varparam = ngx_pstrndup(pool, oldname + 5);
    }


    /* Resolve variable */
    var->metadata = msre_resolve_var(engine, var->name);
    if (var->metadata == NULL) {
        *error_msg = ngx_psprintf(pool,
            ngx_strlen("Unknown variable: ")+ngx_strlen(name)+2,
            "Unknown variable: %s", name);
        return NULL;
    }

    /* The counting operator "&" can only be used against collections. */
    if (var->is_counting) {
        if (var->metadata->type == VAR_SIMPLE) {
            *error_msg = ngx_pstrndup(pool, "The & modificator does not apply to "
                    "non-collection variables.");
            return NULL;
        }
    }

    /* Check the parameter. */
    if (varparam == NULL) {
        if (var->metadata->argc_min > 0) {
            *error_msg = ngx_psprintf(pool, 
                ngx_strlen("Missing mandatory parameter for variable .")+ngx_strlen(name)+2,
                "Missing mandatory parameter for variable %s.",
                    name);
            return NULL;
        }
    } else { /* Parameter present */

        /* Do we allow a parameter? */
        if (var->metadata->argc_max == 0) {
            *error_msg = ngx_psprintf(pool,
                ngx_strlen("Variable  does not support parameters.")+ngx_strlen(name)+2,
                "Variable %s does not support parameters.",
                    name);
            return NULL;
        }

        var->param = (char *)varparam;

    }

    return var;
}

/**
 * Create a new variable object from the provided name and value.
 *
 * NOTE: this allocates out of the global pool and should not be used
 *       per-request
 */
static msre_var *msre_create_var(msre_ruleset *ruleset, const char *name, const char *param,
        modsec_rec *msr, char **error_msg)
{
    msre_var *var = msre_create_var_ex(ruleset->mp, ruleset->engine, name, param, msr, error_msg);
    if (var == NULL) return NULL;

    /* Validate & initialise variable */
    if (var->metadata->validate != NULL) {
        *error_msg = var->metadata->validate(ruleset, var);
        if (*error_msg != NULL) {
            return NULL;
        }
    }

    return var;
}

/**
 * Creates a new action instance given its name and an (optional) parameter.
 */
msre_action *msre_create_action(msre_engine *engine, ngx_pool_t *mp, const char *name, const char *param,
        char **error_msg)
{
    msre_action *action = NULL;

    if (error_msg == NULL) {
        return NULL;
    }
    *error_msg = NULL;


    action = ngx_pcalloc(mp, sizeof(msre_action));

    if (action == NULL) {
        *error_msg = ngx_pstrndup(mp, "Internal error: " \
            "msre_create_action, not able to allocate action");

        return NULL;
    }

    /* Resolve action */
    action->metadata = msre_resolve_action(engine, name);
    if (action->metadata == NULL) {
        *error_msg = ngx_pstrcat(mp, "Unknown action: ", name,NULL);
        return NULL;
    }

    if (param == NULL) { /* Parameter not present */
        if (action->metadata->argc_min > 0) {
            *error_msg = ngx_pstrcat(mp, "Missing mandatory parameter for action ",name,NULL);
            return NULL;
        }
    } else { /* Parameter present */

        /* Should we allow the parameter? */
        if (action->metadata->argc_max == 0) {
            *error_msg = ngx_pstrcat(mp, "Extra parameter provided to action ", name,NULL);
            return NULL;
        }

        /* Handle +/- modificators */
        if ((param[0] == '+')||(param[0] == '-')) {
            if (action->metadata->allow_param_plusminus == 0) {
                *error_msg = ngx_psprintf(mp,
                        ngx_strlen("Action  does not allow +/- modificators.")+ngx_strlen(name)+2,
                        "Action %s does not allow +/- modificators.", name);
                return NULL;
            }
            else { /* Modificators allowed. */
                if (param[0] == '+') {
                    action->param = param + 1;
                    action->param_plusminus = POSITIVE_VALUE;
                } else
                    if (param[0] == '-') {
                        action->param = param + 1;
                        action->param_plusminus = NEGATIVE_VALUE;
                    }
            }
        } else {
            action->param = param;
        }

        /* Validate parameter */
        if (action->metadata->validate != NULL) {
            *error_msg = action->metadata->validate(engine, mp, action);
            if (*error_msg != NULL) return NULL;
        }
    }

    return action;
}

/**
 * Generic parser that is used as basis for target and action parsing.
 * It breaks up the input string into name-parameter pairs and places
 * them into the given table.
 */
int msre_parse_generic(ngx_pool_t *mp, const char *text, ngx_table_t *vartable,
        char **error_msg)
{
    char *p = (char *)text;
    int count = 0;

    if (error_msg == NULL) return -1;
    *error_msg = NULL;

    count = 0;
    while(*p != '\0') {
        char *name = NULL, *value = NULL;

        /* ignore whitespace */
        while(ngx_isspace(*p)) p++;
        if (*p == '\0') return count;

        /* we are at the beginning of the name */
        name = p;
        while((*p != '\0')&&(*p != '|')&&(*p != ':')&&(*p != ',')&&(!ngx_isspace(*p))) p++; /* ENH replace with isvarnamechar() */

        /* get the name */
        name = ngx_pstrmemdup(mp, name, p - name);

        if (*p != ':') { /* we don't have a parameter */
            /* add to the table with no value */
            ngx_table_addn(vartable, name, NULL);
            count++;

            /* go over any whitespace present */
            while(ngx_isspace(*p)) p++;

            /* we're done */
            if (*p == '\0') {
                return count;
            }

            /* skip over the separator character and continue */
            if ((*p == ',')||(*p == '|')) {
                p++;
                continue;
            }

            *error_msg = ngx_psprintf(mp,
                 NGX_INT64_LEN+ngx_strlen("Unexpected character at position : ")+ngx_strlen(text)+2,
                "Unexpected character at position %d: %s",
                    (int)(p - text), text);
            return -1;
        }

        /* we have a parameter */

        p++; /* move over the colon */

        /* we'll allow empty values */
        if (*p == '\0') {
            ngx_table_addn(vartable, name, NULL);
            count++;
            return count;
        }

        if ((*p == ',')||(*p == '|')) {
            ngx_table_addn(vartable, name, NULL);
            count++;
            /* move over the separator char and continue */
            p++;
            continue;
        }

        /* we really have a parameter */

        if (*p == '\'') { /* quoted value */
            char *d = NULL;

            p++; /* go over the openning quote */
            value = d = strdup(p);
            if (d == NULL) return -1;

            for(;;) {
                if (*p == '\0') {
                    *error_msg = ngx_psprintf(mp,
                        ngx_strlen("Missing closing quote at position : ")+ngx_strlen(text)+NGX_INT64_LEN+2,
                        "Missing closing quote at position %d: %s",
                            (int)(p - text), text);
                    free(value);
                    return -1;
                } else
                    if (*p == '\\') {
                        if ( (*(p + 1) == '\0') || ((*(p + 1) != '\'')&&(*(p + 1) != '\\')) ) {
                            *error_msg = ngx_psprintf(mp, 
                                ngx_strlen("Invalid quoted pair at position : ")+ngx_strlen(text)+NGX_INT64_LEN+2,
                                "Invalid quoted pair at position %d: %s",
                                    (int)(p - text), text);
                            free(value);
                            return -1;
                        }
                        p++;
                        *(d++) = *(p++);
                    } else
                        if (*p == '\'') {
                            *d = '\0';
                            p++;
                            break;
                        }
                        else {
                            *(d++) = *(p++);
                        }
            }

            d = value;
            value = ngx_pstrndup(mp, d);
            free(d);
        } else { /* non-quoted value */
            value = p;
            while((*p != '\0')&&(*p != ',')&&(*p != '|')&&(!ngx_isspace(*p))) p++;
            value = ngx_pstrmemdup(mp, value, p - value);
        }

        /* add to table */
        ngx_table_addn(vartable, name, value);
        count++;

        /* move to the first character of the next name-value pair */
        while(ngx_isspace(*p)||(*p == ',')||(*p == '|')) p++;
    }

    return count;
}


/* -- Actionset functions -------------------------------------------------- */

/**
 * Creates an actionset instance and (as an option) populates it by
 * parsing the given string which contains a list of actions.
 */
msre_actionset *msre_actionset_create(msre_engine *engine, ngx_pool_t *mp, const char *text,
        char **error_msg)
{
    msre_actionset *actionset = NULL;

    if (error_msg == NULL) {
        return NULL;
    }

    *error_msg = NULL;

    actionset = (msre_actionset *)ngx_pcalloc(mp,
            sizeof(msre_actionset));

    if (actionset == NULL) {
        *error_msg = ngx_pstrndup(mp, "Internal error: " \
                "msre_actionset_create, not able to allocate msre_actionset");
        return NULL;
    }

    actionset->actions = ngx_table_make(mp, 25);
    if (actionset->actions == NULL) {
        *error_msg = ngx_pstrndup(mp, "Internal error: " \
                "msre_actionset_create, not able to create actions table");
        return NULL;
    }

    /* Metadata */
    actionset->id = NGX_CONF_UNSET_PTR;
    actionset->rev = NGX_CONF_UNSET_PTR;
    actionset->msg = NGX_CONF_UNSET_PTR;
    actionset->version = NGX_CONF_UNSET_PTR;
    actionset->logdata = NGX_CONF_UNSET_PTR;
    actionset->phase = NGX_CONF_UNSET;
    actionset->severity = -1;
    actionset->accuracy = -1;
    actionset->maturity = -1;
    actionset->rule = NGX_CONF_UNSET_PTR;
    actionset->arg_max = -1;
    actionset->arg_min = -1;

    /* Flow */
    actionset->is_chained = NGX_CONF_UNSET;
    actionset->skip_count = NGX_CONF_UNSET;
    actionset->skip_after = NGX_CONF_UNSET_PTR;

    /* Disruptive */
    actionset->parent_intercept_action_rec = NGX_CONF_UNSET_PTR;
    actionset->intercept_action_rec = NGX_CONF_UNSET_PTR;
    actionset->parent_intercept_action = NGX_CONF_UNSET;
    actionset->intercept_action = NGX_CONF_UNSET;
    actionset->intercept_status = NGX_CONF_UNSET;

    /* Other */
    actionset->auditlog = NGX_CONF_UNSET;
    actionset->log = NGX_CONF_UNSET;

    /* Parse the list of actions, if it's present */
    if (text != NULL) {
        int ret = msre_parse_actions(engine, mp, actionset, text, error_msg);
        if (ret < 0) {
            if (*error_msg == NULL) 
                *error_msg = ngx_psprintf(mp, 
                    ngx_strlen("Internal error: msre_actionset_create, msre_parse_actions failed without further information. Return code: ")+NGX_INT64_LEN+2,
                    "Internal error: msre_actionset_create, msre_parse_actions failed without further information. Return code: %d", ret);

            return NULL;
        }
    }

    return actionset;
}

/**
 * Create a (shallow) copy of the supplied actionset.
 */
static msre_actionset *msre_actionset_copy(ngx_pool_t *mp, msre_actionset *orig) {
    msre_actionset *copy = NULL;

    if (orig == NULL) return NULL;
    copy = (msre_actionset *)ngx_pmemdup(mp, orig, sizeof(msre_actionset));
    if (copy == NULL) return NULL;
    copy->actions = ngx_table_copy(mp, orig->actions);

    return copy;
}

/**
 * Merges two actionsets into one.
 */
msre_actionset *msre_actionset_merge(msre_engine *engine, ngx_pool_t *mp, msre_actionset *parent,
        msre_actionset *child, int inherit_by_default)
{
    msre_actionset *merged = NULL;
    const ngx_array_t *tarr;
    const ngx_table_entry_t *telts;
    ngx_uint_t i;

    if (inherit_by_default == 0) {
        /* There is nothing to merge in this case. */
	    return msre_actionset_copy(mp, child);
    }

    /* Start with a copy of the parent configuration. */
    merged = msre_actionset_copy(mp, parent);
    if (merged == NULL) return NULL;

    if (child == NULL) {
        /* The child actionset does not exist, hence
         * go with the parent one.
         */
        return merged;
    }

    /* First merge the hard-coded stuff. */

    /* Metadata */
    if (child->id != NGX_CONF_UNSET_PTR) merged->id = child->id;
    if (child->rev != NGX_CONF_UNSET_PTR) merged->rev = child->rev;
    if (child->msg != NGX_CONF_UNSET_PTR) merged->msg = child->msg;
    if (child->version != NGX_CONF_UNSET_PTR) merged->version = child->version;
    if (child->logdata != NGX_CONF_UNSET_PTR) merged->logdata = child->logdata;
    if (child->severity != NGX_CONF_UNSET) merged->severity = child->severity;
    if (child->accuracy != NGX_CONF_UNSET) merged->accuracy = child->accuracy;
    if (child->maturity != NGX_CONF_UNSET) merged->maturity = child->maturity;
    if (child->phase != NGX_CONF_UNSET) merged->phase = child->phase;
    if (child->rule != NGX_CONF_UNSET_PTR) merged->rule = child->rule;
    if (child->arg_min != NGX_CONF_UNSET) merged->arg_min = child->arg_min;
    if (child->arg_max != NGX_CONF_UNSET) merged->arg_max = child->arg_max;

    /* Flow */
    merged->is_chained = child->is_chained;
    if (child->skip_count != NGX_CONF_UNSET) merged->skip_count = child->skip_count;
    if (child->skip_after != NGX_CONF_UNSET_PTR) merged->skip_after = child->skip_after;

    /* Disruptive */
    if (child->intercept_action != NGX_CONF_UNSET) {
        merged->intercept_action_rec = child->intercept_action_rec;
        merged->intercept_action = child->intercept_action;
    }

    if (child->intercept_status != NGX_CONF_UNSET) merged->intercept_status = child->intercept_status;

    /* Other */
    if (child->auditlog != NGX_CONF_UNSET) merged->auditlog = child->auditlog;
    if (child->log != NGX_CONF_UNSET) merged->log = child->log;


    /* Now merge the actions. */

    tarr = ngx_table_elts(child->actions);
    telts = (const ngx_table_entry_t*)tarr->elts;
    for (i = 0; i < tarr->nelts; i++) {
        msre_actionset_action_add(merged, (msre_action *)telts[i].val);
    }

    return merged;
}

/**
 * Creates an actionset that contains a default list of actions.
 */
msre_actionset *msre_actionset_create_default(msre_engine *engine) {
    char  *my_error_msg = NULL;
    return msre_actionset_create(engine,
            engine->mp,
            "phase:2,log,auditlog,pass",
            &my_error_msg);
}

/**
 * Sets the default values for the hard-coded actionset configuration.
 */
void msre_actionset_set_defaults(msre_actionset *actionset) {

    if (actionset == NULL) {
        return;
    }
    /* Metadata */
    if (actionset->id == NGX_CONF_UNSET_PTR) actionset->id = NULL;
    if (actionset->rev == NGX_CONF_UNSET_PTR) actionset->rev = NULL;
    if (actionset->msg == NGX_CONF_UNSET_PTR) actionset->msg = NULL;
    if (actionset->version == NGX_CONF_UNSET_PTR) actionset->version = NULL;
    if (actionset->logdata == NGX_CONF_UNSET_PTR) actionset->logdata = NULL;
    if (actionset->phase == NGX_CONF_UNSET) actionset->phase = 2;
    if (actionset->severity == -1) {} /* leave at -1 */
    if (actionset->accuracy == -1) {} /* leave at -1 */
    if (actionset->maturity == -1) {} /* leave at -1 */
    if (actionset->rule == NGX_CONF_UNSET_PTR) actionset->rule = NULL;
    if (actionset->arg_max == NGX_CONF_UNSET) actionset->arg_max = -1;
    if (actionset->arg_min == NGX_CONF_UNSET) actionset->arg_min = -1;

    /* Flow */
    if (actionset->is_chained == NGX_CONF_UNSET) actionset->is_chained = 0;
    if (actionset->skip_count == NGX_CONF_UNSET) actionset->skip_count = 0;
    if (actionset->skip_after == NGX_CONF_UNSET_PTR) actionset->skip_after = NULL;

    /* Disruptive */
    if (actionset->parent_intercept_action_rec == NGX_CONF_UNSET_PTR) actionset->parent_intercept_action_rec = NULL;
    if (actionset->intercept_action_rec == NGX_CONF_UNSET_PTR) actionset->intercept_action_rec = NULL;
    if (actionset->parent_intercept_action == NGX_CONF_UNSET) actionset->parent_intercept_action = ACTION_NONE;
    if (actionset->intercept_action == NGX_CONF_UNSET) actionset->intercept_action = ACTION_NONE;
    if (actionset->intercept_status == NGX_CONF_UNSET) actionset->intercept_status = 403;

    /* Other */
    if (actionset->auditlog == NGX_CONF_UNSET) actionset->auditlog = 1;
    if (actionset->log == NGX_CONF_UNSET) actionset->log = 1;
}

/* -- Engine functions ----------------------------------------------------- */

/**
 * Creates a new engine instance.
 */
msre_engine *msre_engine_create(ngx_pool_t *parent_pool) {
    msre_engine *engine;
    ngx_pool_t *mp;

    /* Create new memory pool */
    if ((mp=ngx_create_pool(1024*4, parent_pool->log)) == NULL) return NULL;

    /* Init fields */
    engine = (msre_engine*)ngx_pcalloc(mp, sizeof(msre_engine));

    if (engine == NULL) return NULL;
    engine->mp = mp;
    
    engine->tfns = ngx_table_make(mp, 50);
    if (engine->tfns == NULL) return NULL;
    engine->operators = ngx_table_make(mp, 25);
    if (engine->operators == NULL) return NULL;
    engine->variables = ngx_table_make(mp, 100);
    if (engine->variables == NULL) return NULL;
    engine->actions = ngx_table_make(mp, 50);
    if (engine->actions == NULL) return NULL;
    engine->reqbody_processors = ngx_table_make(mp, 10);
    if (engine->reqbody_processors == NULL) return NULL;

    return engine;
}


/* -- Recipe functions ----------------------------------------------------- */

#define NEXT_CHAIN  1
#define NEXT_RULE   2
#define SKIP_RULES  3



/**
 * Default implementation of the ruleset phase processing; it processes
 * the rules in the ruleset attached to the currently active
 * transaction phase.
 */
#if defined(PERFORMANCE_MEASUREMENT)

#define PERFORMANCE_MEASUREMENT_LOOP 5000

static ngx_int_t msre_ruleset_process_phase_(msre_ruleset *ruleset, modsec_rec *msr);

ngx_int_t msre_ruleset_process_phase(msre_ruleset *ruleset, modsec_rec *msr) {
    ngx_array_t *arr = NULL;
    msre_rule **rules = NULL;
    ngx_int_t rc;
    int i;

    switch (msr->phase) {
        case PHASE_REQUEST_HEADERS :
            arr = ruleset->phase_request_headers;
            break;
        case PHASE_REQUEST_BODY :
            arr = ruleset->phase_request_body;
            break;
        case PHASE_RESPONSE_HEADERS :
            arr = ruleset->phase_response_headers;
            break;
        case PHASE_RESPONSE_BODY :
            arr = ruleset->phase_response_body;
            break;
        case PHASE_LOGGING :
            arr = ruleset->phase_logging;
            break;
        default :
            msr_log(msr, 1, "Internal Error: Invalid phase %d", msr->phase);
            return -1;
    }

    rules = (msre_rule **)arr->elts;
    for (i = 0; i < arr->nelts; i++) {
        msre_rule *rule = rules[i];
        rule->execution_time = 0;
    }

    for (i = 0; i < PERFORMANCE_MEASUREMENT_LOOP; i++) {
        rc = msre_ruleset_process_phase_(ruleset, msr);
    }

    msr_log(msr, 1, "Phase %d", msr->phase);

    rules = (msre_rule **)arr->elts;
    for (i = 0; i < arr->nelts; i++) {
        msre_rule *rule = rules[i];

        /* Ignore markers, which are never processed. */
        if (rule->placeholder == RULE_PH_MARKER) continue;

        msr_log(msr, 1, "Rule %pp [id \"%s\"][file \"%s\"][line \"%d\"]: %u usec", rule,
                ((rule->actionset != NULL)&&(rule->actionset->id != NULL)) ? rule->actionset->id : "-",
                rule->filename != NULL ? rule->filename : "-",
                rule->line_num,
                (rule->execution_time / PERFORMANCE_MEASUREMENT_LOOP));
    }

    return rc;
}

static ngx_int_t msre_ruleset_process_phase_(msre_ruleset *ruleset, modsec_rec *msr) {
#else
    ngx_int_t msre_ruleset_process_phase(msre_ruleset *ruleset, modsec_rec *msr) {
#endif
        ngx_array_t *arr = NULL;
        msre_rule **rules;
        ngx_int_t rc;
        const char *skip_after = NULL;
        msre_rule *last_rule = NULL;
        ngx_uint_t i;
        int mode, skip, skipped, saw_starter;

        /* First determine which set of rules we need to use. */
        switch (msr->phase) {
            case PHASE_REQUEST_HEADERS :
                arr = ruleset->phase_request_headers;
                break;
            case PHASE_REQUEST_BODY :
                arr = ruleset->phase_request_body;
                break;
            case PHASE_RESPONSE_HEADERS :
                arr = ruleset->phase_response_headers;
                break;
            case PHASE_RESPONSE_BODY :
                arr = ruleset->phase_response_body;
                break;
            case PHASE_LOGGING :
                arr = ruleset->phase_logging;
                break;
            default :
                msr_log(msr, 1, "Internal Error: Invalid phase %d", msr->phase);
                return -1;
        }

        if (msr->txcfg->debuglog_level >= 9) {
            msr_log(msr, 9, "This phase consists of %d rule(s).", arr->nelts);
        }

        ngx_table_clear(msr->matched_vars);

        /* Loop through the rules in the selected set. */
        skip = 0;
        skipped = 0;
        saw_starter = 0;
        mode = NEXT_RULE;
        rules = (msre_rule **)arr->elts;
        for (i = 0; i < arr->nelts; i++) {
            msre_rule *rule = rules[i];
#if defined(PERFORMANCE_MEASUREMENT)
            ngx_ext_time_t time1 = 0;
#endif

            /* Reset the rule interception flag */
            msr->rule_was_intercepted = 0;

            /* SKIP_RULES is used to skip all rules until we hit a placeholder
             * with the specified rule ID and then resume execution after that.
             */
            if (mode == SKIP_RULES) {
                /* Go to the next rule if we have not yet hit the skip_after ID */

                if ((rule->placeholder == RULE_PH_NONE) || (rule->actionset->id == NULL) || (ngx_strcmp(skip_after, rule->actionset->id) != 0)) {

                    if(i>=1)
                        last_rule = rules[i-1];
                    else
                        last_rule = rules[0];

                    if((last_rule != NULL) && (last_rule->actionset != NULL) && last_rule->actionset->is_chained && (saw_starter == 1)) {
                        mode = NEXT_RULE;
                        skipped = 1;
                        --i;
                    } else {
                        mode = SKIP_RULES;
                        skipped = 0;
                        saw_starter = 0;

                        if (msr->txcfg->debuglog_level >= 9) {
                            msr_log(msr, 9, "Current rule is id=\"%s\" [chained %d] is trying to find the SecMarker=\"%s\" [stater %d]",rule->actionset->id,last_rule->actionset->is_chained,skip_after,saw_starter);
                        }

                    }

                    continue;
                }

                if (msr->txcfg->debuglog_level >= 9) {
                    msr_log(msr, 9, "Found rule %pp id=\"%s\".", rule, skip_after);
                }

                /* Go to the rule *after* this one to continue execution. */
                if (msr->txcfg->debuglog_level >= 4) {
                    msr_log(msr, 4, "Continuing execution after rule id=\"%s\".", skip_after);
                }

                saw_starter = 0;
                skipped = 0;
                skip_after = NULL;
                mode = NEXT_RULE;
                ngx_table_clear(msr->matched_vars);
                continue;
            }

            /* Skip any rule marked as a placeholder */
            if (rule->placeholder != RULE_PH_NONE) {
                continue;
            }

            /* NEXT_CHAIN is used when one of the rules in a chain
             * fails to match and then we need to skip the remaining
             * rules in that chain in order to get to the next
             * rule that can execute.
             */
            if (mode == NEXT_CHAIN) {
                if (rule->actionset->is_chained == 0) {
                    mode = NEXT_RULE;
                }

                /* Go to the next rule. */
                ngx_table_clear(msr->matched_vars);
                continue;
            }

            /* If we are here that means the mode is NEXT_RULE, which
             * then means we have done processing any chains. However,
             * if the "skip" parameter is set we need to skip over.
             */
            if ((mode == NEXT_RULE)&&(skip > 0)) {
                /* Decrement the skip counter by one. */
                skip--;

                /* If the current rule is part of a chain then
                 * we need to skip over the entire chain. Thus
                 * we change the mode to NEXT_CHAIN. The skip
                 * counter will not decrement as we are moving
                 * over the rules belonging to the chain.
                 */
                if (rule->actionset->is_chained) {
                    mode = NEXT_CHAIN;
                }

                /* Go to the next rule. */
                ngx_table_clear(msr->matched_vars);
                continue;
            }

            /* Check if this rule was removed at runtime */
        if (((rule->actionset->id !=NULL) && !ngx_is_empty_array(msr->removed_rules)) ||
                 (ngx_is_empty_array(msr->removed_rules_tag)==0) || (ngx_is_empty_array(msr->removed_rules_msg)==0)) {
            ngx_uint_t j, act;
            int rc;
            int do_process = 1;
            const char *range = NULL;
            rule_exception *re = NULL;
            char *my_error_msg;
            const ngx_array_t *tag_tarr = NULL;
            const ngx_table_entry_t *tag_telts = NULL;

            for(j = 0; j < msr->removed_rules_msg->nelts; j++) {
                re = ((rule_exception **)msr->removed_rules_msg->elts)[j];

                if(rule->actionset->msg !=NULL)  {

                    if (msr->txcfg->debuglog_level >= 9) {
                        msr_log(msr, 9, "Checking removal of rule msg=\"%s\" against: %s", rule->actionset->msg, re->param);
                    }

                    rc = msc_regexec(re->param_data,
                            rule->actionset->msg, ngx_strlen(rule->actionset->msg),
                            &my_error_msg);
                    if (rc >= 0)    {
                        do_process = 0;
                        break;
                    }
                }
            }

            for(j = 0; j < msr->removed_rules->nelts; j++) {
                range = ((const char**)msr->removed_rules->elts)[j];

                if(rule->actionset->id !=NULL)  {

                    if (msr->txcfg->debuglog_level >= 9) {
                        msr_log(msr, 9, "Checking removal of rule id=\"%s\" against: %s", rule->actionset->id, range);
                    }

                    if (rule_id_in_range(atoi(rule->actionset->id), range)) {
                        do_process = 0;
                        break;
                    }
                }
            }

            tag_tarr = ngx_table_elts(rule->actionset->actions);
            tag_telts = (const ngx_table_entry_t*)tag_tarr->elts;

            for (act = 0; act < tag_tarr->nelts; act++) {
                msre_action *action = (msre_action *)tag_telts[act].val;

                if((action != NULL) && (action->metadata != NULL ) && ngx_strcmp("tag", action->metadata->name) == 0)  {

                    for(j = 0; j < msr->removed_rules_tag->nelts; j++) {
                        re = ((rule_exception **)msr->removed_rules_tag->elts)[j];


                        if(action->param != NULL)   {
                            /* Expand variables in the tag argument. */
                            msc_string *var = (msc_string *)ngx_pcalloc(msr->mp, sizeof(msc_string));

                            var->value = (char *)action->param;
                            var->value_len = ngx_strlen(action->param);
                            expand_macros(msr, var, NULL, msr->mp);

                            if (msr->txcfg->debuglog_level >= 9) {
                                msr_log(msr, 9, "Checking removal of rule tag=\"%s\" against: %s", var->value, re->param);
                            }

                            rc = msc_regexec(re->param_data,
                                    var->value, ngx_strlen(var->value),
                                    &my_error_msg);
                            if (rc >= 0)    {
                                do_process = 0;
                                break;
                            }

                        }
                    }
                }
            }

            /* Go to the next rule if this one has been removed. */
            if (do_process == 0) {
                if (msr->txcfg->debuglog_level >= 5) {
                    msr_log(msr, 5, "Not processing %srule id=\"%s\": "
                            "removed by ctl action",
                            rule->actionset->is_chained ? "chained " : "",
                            rule->actionset->id);
                }

                /* Skip the whole chain, if this is a chained rule */
                if (rule->actionset->is_chained) {
                    mode = NEXT_CHAIN;
                }

                skipped = 0;
                saw_starter = 0;
                ngx_table_clear(msr->matched_vars);
                continue;
            }
        }

        if(msr->txcfg->is_enabled == MODSEC_DISABLED)   {
            saw_starter = 0;
            skipped = 0;
            skip_after = NULL;
            mode = NEXT_RULE;
            ngx_table_clear(msr->matched_vars);
            continue;
        }

        if (msr->txcfg->debuglog_level >= 4) {
            ngx_pool_t *p = msr->mp;
            const char *fn = NULL;
            const char *id = NULL;
            const char *rev = NULL;

            if (rule->filename != NULL) {
                fn = ngx_psprintf(p, 
                    ngx_strlen(" [file \"%s\"] [line \"%d\"]")+ngx_strlen(rule->filename)+NGX_INT64_LEN+2,
                    " [file \"%s\"] [line \"%d\"]", rule->filename, rule->line_num);
            }

            if (rule->actionset != NULL && rule->actionset->id != NULL) {
                id = ngx_psprintf(p,
                    ngx_strlen(" [id \"%s\"]")+ngx_strlen(rule->actionset->id)+2,
                    " [id \"%s\"]", rule->actionset->id);
            }

            if (rule->actionset != NULL && rule->actionset->rev != NULL) {
                rev = ngx_psprintf(p,
                    ngx_strlen(" [rev \"%s\"]")+ngx_strlen(rule->actionset->rev)+2,
                    " [rev \"%s\"]", rule->actionset->rev);
            }

            msr_log(msr, 4, "Recipe: Invoking rule %pp;%s%s%s.",
                    rule, (fn ? fn : ""), (id ? id : ""), (rev ? rev : ""));
            msr_log(msr, 5, "Rule %pp: %s", rule, rule->unparsed);
        }

#if defined(PERFORMANCE_MEASUREMENT)
        time1 = ngx_ext_time_now();
#endif

        rc = msre_rule_process(rule, msr);

#if defined(PERFORMANCE_MEASUREMENT)
        rule->execution_time += (ngx_ext_time_now() - time1);
#endif

        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Rule returned %d.", rc);
        }

        if (rc == RULE_NO_MATCH) {
            if (rule->actionset->is_chained) {
                /* If the current rule is part of a chain then
                 * we need to skip over all the rules in the chain.
                 */
                mode = NEXT_CHAIN;
                if (msr->txcfg->debuglog_level >= 9) {
                    msr_log(msr, 9, "No match, chained -> mode NEXT_CHAIN.");
                }
            } else {
                /* This rule is not part of a chain so we simply
                 * move to the next rule.
                 */
                mode = NEXT_RULE;
                if (msr->txcfg->debuglog_level >= 9) {
                    msr_log(msr, 9, "No match, not chained -> mode NEXT_RULE.");
                }
            }

            ngx_table_clear(msr->matched_vars);
            skipped = 0;
            saw_starter = 0;
        }
        else if (rc == RULE_MATCH) {
            if (msr->rule_was_intercepted) {
                /* If the transaction was intercepted by this rule we will
                 * go back. Do note that we are relying on the
                 * rule to know if it is a part of a chain and
                 * not intercept if it is.
                 */
                if (msr->txcfg->debuglog_level >= 9) {
                    msr_log(msr, 9, "Match, intercepted -> returning.");
                }

                if(i>=1)
                    last_rule = rules[i-1];
                else
                    last_rule = rules[0];

                ngx_table_clear(msr->matched_vars);
                return 1;
            }

            if (rule->actionset->skip_after != NULL) {
                skip_after = rule->actionset->skip_after;
                mode = SKIP_RULES;
                saw_starter = 1;

                if (msr->txcfg->debuglog_level >= 9) {
                    msr_log(msr, 9, "Skipping after rule %pp id=\"%s\" -> mode SKIP_RULES.", rule, skip_after);
                }

                continue;
            }

            if(skipped == 1)    {
                mode = SKIP_RULES;
                continue;
            }

            /* We had a match but the transaction was not
             * intercepted. In that case we proceed with the
             * next rule...
             */
            mode = NEXT_RULE;
            if (msr->txcfg->debuglog_level >= 9) {
                msr_log(msr, 9, "Match -> mode NEXT_RULE.");
            }

            /* ...unless we need to skip, in which case we
             * determine how many rules/chains we need to
             * skip and configure the counter accordingly.
             */
            if (rule->actionset->is_chained == 0) {
                ngx_table_clear(msr->matched_vars);
                if (rule->chain_starter != NULL) {
                    if (rule->chain_starter->actionset->skip_count > 0) {
                        skip = rule->chain_starter->actionset->skip_count;
                        if (msr->txcfg->debuglog_level >= 4) {
                            msr_log(msr, 4, "Skipping %d rules/chains (from a chain).", skip);
                        }
                    }
                }
                else if (rule->actionset->skip_count > 0) {
                    skip = rule->actionset->skip_count;
                    if (msr->txcfg->debuglog_level >= 4) {
                        msr_log(msr, 4, "Skipping %d rules/chains.", skip);
                    }
                }
            }
        }
        else if (rc < 0) {
            msr_log(msr, 1, "Rule processing failed.");


            if (msr->txcfg->reqintercept_oe == 1)   {
                ngx_table_clear(msr->matched_vars);
                return -1;
            } else  {
                if (rule->actionset->is_chained) {
                    /* If the current rule is part of a chain then
                     * we need to skip over all the rules in the chain.
                     */
                    mode = NEXT_CHAIN;
                    if (msr->txcfg->debuglog_level >= 9) {
                        msr_log(msr, 9, "Ruled failed, chained -> mode NEXT_CHAIN.");
                    }
                } else {
                    /* This rule is not part of a chain so we simply
                     * move to the next rule.
                     */
                    mode = NEXT_RULE;
                    if (msr->txcfg->debuglog_level >= 9) {
                        msr_log(msr, 9, "Rule failed, not chained -> mode NEXT_RULE.");
                    }
                }

                ngx_table_clear(msr->matched_vars);
                skipped = 0;
                saw_starter = 0;
            }
        }
        else {
            msr_log(msr, 1, "Rule processing failed with unknown return code: %d.", rc);
            ngx_table_clear(msr->matched_vars);
            return -1;
        }
    }

    /* ENH warn if chained rules are missing. */
    ngx_table_clear(msr->matched_vars);
    return 0;
}

/**
 * Creates a ruleset that will be handled by the default
 * implementation.
 */
msre_ruleset *msre_ruleset_create(msre_engine *engine, ngx_pool_t *mp) {
    msre_ruleset *ruleset;

    ruleset = (msre_ruleset*)ngx_pcalloc(mp, sizeof(msre_ruleset));
    if (ruleset == NULL) return NULL;
    ruleset->mp = mp;
    ruleset->engine = engine;

    ruleset->phase_request_headers = ngx_array_create(ruleset->mp, 25, sizeof(const msre_rule *));
    ruleset->phase_request_body = ngx_array_create(ruleset->mp, 25, sizeof(const msre_rule *));
    ruleset->phase_response_headers = ngx_array_create(ruleset->mp, 25, sizeof(const msre_rule *));
    ruleset->phase_response_body = ngx_array_create(ruleset->mp, 25, sizeof(const msre_rule *));
    ruleset->phase_logging = ngx_array_create(ruleset->mp, 25, sizeof(const msre_rule *));

    return ruleset;
}

/**
 * Adds one rule to the given phase of the ruleset.
 */
int msre_ruleset_rule_add(msre_ruleset *ruleset, msre_rule *rule, int phase) {
    ngx_array_t *arr = NULL;

    switch (phase) {
        case PHASE_REQUEST_HEADERS :
            arr = ruleset->phase_request_headers;
            break;
        case PHASE_REQUEST_BODY :
            arr = ruleset->phase_request_body;
            break;
        case PHASE_RESPONSE_HEADERS :
            arr = ruleset->phase_response_headers;
            break;
        case PHASE_RESPONSE_BODY :
            arr = ruleset->phase_response_body;
            break;
        case PHASE_LOGGING :
            arr = ruleset->phase_logging;
            break;
        default :
            return -1;
    }

    /* ENH verify the rule's use of targets is consistent with
     * the phase it selected to run at.
     */

    msre_actionset_set_defaults(rule->actionset);
    rule->actionset->rule = rule;

    *(const msre_rule **)ngx_array_push(arr) = rule;

    return 1;
}

static msre_rule * msre_ruleset_fetch_phase_rule(const msre_ruleset *ruleset, const char *id,
        const ngx_array_t *phase_arr, int offset)
{
    msre_rule **rules = (msre_rule **)phase_arr->elts;
    ngx_uint_t i;

    for (i = 0; i < phase_arr->nelts; i++) {
        msre_rule *rule = (msre_rule *)rules[i];

        /* Rule with an action, not a sub-rule (chain) and a matching id */
        if (  (rule->actionset != NULL)
                && (!rule->actionset->is_chained || !rule->chain_starter)
                && (rule->actionset->id != NULL)
                && (ngx_strcmp(rule->actionset->id, id) == 0))
        {
            /* Return rule that matched unless it is a placeholder */
            if(offset == 0) {
                return (rule->placeholder == RULE_PH_NONE) ? rule : NULL;
            }
            else    {
                if (i+offset < phase_arr->nelts)    {
                    msre_rule *rule_off = (msre_rule *)rules[i+offset];
                    return (rule_off->placeholder == RULE_PH_NONE) ? rule_off : NULL;
                }
            }
        }
    }

    return NULL;
}

/**
 * Fetches rule from the ruleset all rules that match the given exception.
 */
msre_rule * msre_ruleset_fetch_rule(msre_ruleset *ruleset, const char *id, int offset) {
    msre_rule *rule = NULL;

    if (ruleset == NULL) return NULL;

    rule = msre_ruleset_fetch_phase_rule(ruleset, id, ruleset->phase_request_headers, offset);
    if (rule != NULL) return rule;

    rule = msre_ruleset_fetch_phase_rule(ruleset, id, ruleset->phase_request_body, offset);
    if (rule != NULL) return rule;

    rule = msre_ruleset_fetch_phase_rule(ruleset, id, ruleset->phase_response_headers, offset);
    if (rule != NULL) return rule;

    rule = msre_ruleset_fetch_phase_rule(ruleset, id, ruleset->phase_response_body, offset);
    if (rule != NULL) return rule;

    rule = msre_ruleset_fetch_phase_rule(ruleset, id, ruleset->phase_logging, offset);

    return rule;
}

static int msre_ruleset_phase_rule_remove_with_exception(msre_ruleset *ruleset, rule_exception *re,
        ngx_array_t *phase_arr)
{
    msre_rule **rules;
    ngx_uint_t i, j;
    
    int mode, removed_count;

    j = 0;
    mode = 0;
    removed_count = 0;
    rules = (msre_rule **)phase_arr->elts;
    for (i = 0; i < phase_arr->nelts; i++) {
        msre_rule *rule = (msre_rule *)rules[i];

        if (mode == 0) { /* Looking for next rule. */
            int remove_rule = 0;

            /* Only remove non-placeholder rules */
            if (rule->placeholder == RULE_PH_NONE) {
                switch(re->type) {
                    case RULE_EXCEPTION_REMOVE_ID :
                        if ((rule->actionset != NULL)&&(rule->actionset->id != NULL)) {
                            int ruleid = atoi(rule->actionset->id);

                            if (rule_id_in_range(ruleid, re->param)) {
                                remove_rule = 1;
                            }
                        }

                        break;

                    case RULE_EXCEPTION_REMOVE_MSG :
                        if ((rule->actionset != NULL)&&(rule->actionset->msg != NULL)) {
                            char *my_error_msg = NULL;

                            int rc = msc_regexec(re->param_data,
                                    rule->actionset->msg, ngx_strlen(rule->actionset->msg),
                                    &my_error_msg);
                            if (rc >= 0) {
                                remove_rule = 1;
                            }
                        }

                        break;
                    case RULE_EXCEPTION_REMOVE_TAG :
                        if ((rule->actionset != NULL)&&(ngx_is_empty_table(rule->actionset->actions) == 0)) {
                            char *my_error_msg = NULL;
                            const ngx_array_t *tarr = NULL;
                            const ngx_table_entry_t *telts = NULL;
                            ngx_uint_t act;

                            tarr = ngx_table_elts(rule->actionset->actions);
                            telts = (const ngx_table_entry_t*)tarr->elts;

                            for (act = 0; act < tarr->nelts; act++) {
                                msre_action *action = (msre_action *)telts[act].val;
                                if((action != NULL) && (action->metadata != NULL) && (strcmp("tag", action->metadata->name) == 0))  {

                                    int rc = msc_regexec(re->param_data,
                                            action->param, ngx_strlen(action->param),
                                            &my_error_msg);
                                    if (rc >= 0)    {
                                        remove_rule = 1;
                                    }
                                }
                            }
                        }
                        break;
                }
            }

            if (remove_rule) {
                /* Do not increment j. */
                removed_count++;
                if (rule->actionset->is_chained) mode = 2; /* Remove rules in this chain. */
            } else {
                if (rule->actionset->is_chained) mode = 1; /* Keep rules in this chain. */
                rules[j++] = rules[i];
            }
        } else { /* Handling rule that is part of a chain. */
            if (mode == 2) { /* We want to remove the rule. */
                /* Do not increment j. */
                removed_count++;
            } else {
                rules[j++] = rules[i];
            }

            if ((rule->actionset == NULL)||(rule->actionset->is_chained == 0)) mode = 0;
        }
    }

    /* Update the number of rules in the array. */
    phase_arr->nelts -= removed_count;

    return 0;
}

/**
 * Removes from the ruleset all rules that match the given exception.
 */
int msre_ruleset_rule_remove_with_exception(msre_ruleset *ruleset, rule_exception *re) {
    int count = 0;

    if (ruleset == NULL) return 0;

    count += msre_ruleset_phase_rule_remove_with_exception(ruleset, re, ruleset->phase_request_headers);
    count += msre_ruleset_phase_rule_remove_with_exception(ruleset, re, ruleset->phase_request_body);
    count += msre_ruleset_phase_rule_remove_with_exception(ruleset, re, ruleset->phase_response_headers);
    count += msre_ruleset_phase_rule_remove_with_exception(ruleset, re, ruleset->phase_response_body);
    count += msre_ruleset_phase_rule_remove_with_exception(ruleset, re, ruleset->phase_logging);

    return count;
}


/* -- Rule functions ------------------------------------------------------- */

/**
 * Returns the name of the supplied severity level.
 */
static const char *msre_format_severity(int severity) {
    if ((severity >= 0)&&(severity <= 7)) {
        return severities[severity];
    }
    else {
        return "(invalid value)";
    }
}

/**
 * Creates a string containing the metadata of the supplied rule.
 */
char *msre_format_metadata(modsec_rec *msr, msre_actionset *actionset) {
    const ngx_array_t *tarr;
    const ngx_table_entry_t *telts;
    char *id = "";
    char *rev = "";
    char *msg = "";
    char *logdata = "";
    char *severity = "";
    char *accuracy = "";
    char *maturity = "";
    char *version = "";
    char *tags = "";
    char *fn = "";
    ngx_uint_t k;
    const char *nname ;
    size_t nname_size;

    if (actionset == NULL) return "";

    if ((actionset->rule != NULL) && (actionset->rule->filename != NULL)) {
        fn = ngx_psprintf(msr->mp, 
            ngx_strlen(" [file \"%s\"] [line \"%d\"]")+ngx_strlen(actionset->rule->filename)+NGX_INT64_LEN+2,
            " [file \"%s\"] [line \"%d\"]",
                actionset->rule->filename, actionset->rule->line_num);
    }
    if (actionset->id != NULL) {
        nname = log_escape(msr->mp, actionset->id);
        nname_size = ngx_strlen(nname);

        id = ngx_psprintf(msr->mp, ngx_strlen(" [id \"%s\"]")+nname_size+2,
            " [id \"%s\"]",nname);
    }
    if (actionset->rev != NULL) {
        
        nname = log_escape(msr->mp, actionset->rev);

        nname_size = ngx_strlen(nname);
        
        rev = ngx_psprintf(msr->mp,
            ngx_strlen(" [rev \"%s\"]")+nname_size+2,
            " [rev \"%s\"]",
            nname);
    }

    if (actionset->msg != NULL) {
        /* Expand variables in the message string. */
        msc_string *var = (msc_string *)ngx_pcalloc(msr->mp, sizeof(msc_string));
        var->value = (char *)actionset->msg;
        var->value_len = ngx_strlen(actionset->msg);
        expand_macros(msr, var, NULL, msr->mp);
        nname = log_escape_ex(msr->mp, var->value, var->value_len);
        nname_size = ngx_strlen(nname);

        msg = ngx_psprintf(msr->mp, 
            ngx_strlen(" [msg \"%s\"]")+nname_size+2,
            " [msg \"%s\"]",nname);
    }

    if (actionset->logdata != NULL) {
        /* Expand variables in the message string. */
        msc_string *var = (msc_string *)ngx_pcalloc(msr->mp, sizeof(msc_string));
        var->value = (char *)actionset->logdata;
        var->value_len = ngx_strlen(actionset->logdata);
        expand_macros(msr, var, NULL, msr->mp);
        
        nname = log_escape_hex(msr->mp, (unsigned char *)var->value, var->value_len);
        nname_size = ngx_strlen(nname);

        logdata = ngx_psprintf(msr->mp, 
            ngx_strlen(" [data \"%s")+nname_size+2,
            " [data \"%s",nname);
        
        logdata = ngx_pstrcat(msr->mp, logdata, "\"]", NULL);

        /* If it is > 512 bytes, then truncate at 512 with ellipsis.
         * NOTE: 512 actual data + 9 bytes of label = 521
         */
        if (ngx_strlen(logdata) > 521) {
            logdata[517] = '.';
            logdata[518] = '.';
            logdata[519] = '.';
            logdata[520] = '"';
            logdata[521] = ']';
            logdata[522] = '\0';
        }
    }
    if ((actionset->severity >= 0)&&(actionset->severity <= 7)) {
        
        nname = msre_format_severity(actionset->severity);
        nname_size = ngx_strlen(nname);

        severity = ngx_psprintf(msr->mp,
            ngx_strlen(" [severity \"%s\"]")+nname_size+2,
            " [severity \"%s\"]",
                nname);
    }

    if (actionset->version != NULL) {
        nname = log_escape(msr->mp, actionset->version);
        nname_size = ngx_strlen(nname);

        version = ngx_psprintf(msr->mp, ngx_strlen(" [ver \"%s\"]")+nname_size+2,
            " [ver \"%s\"]",
                nname);
    }
    if (actionset->maturity >= 0) {

        maturity = ngx_psprintf(msr->mp, ngx_strlen(" [maturity \"%d\"]")+NGX_INT64_LEN+2,
            " [maturity \"%d\"]",
                actionset->maturity);
    }

    if (actionset->accuracy >= 0) {
        accuracy = ngx_psprintf(msr->mp,ngx_strlen(" [accuracy \"%d\"]")+NGX_INT64_LEN+2,
            " [accuracy \"%d\"]",
                actionset->accuracy);
    }

    /* Extract rule tags from the action list. */
    tarr = ngx_table_elts(actionset->actions);
    telts = (const ngx_table_entry_t*)tarr->elts;

    for (k = 0; k < tarr->nelts; k++) {
        msre_action *action = (msre_action *)telts[k].val;
        if (ngx_strcmp(telts[k].key, "tag") == 0) {
            /* Expand variables in the tag argument. */
            msc_string *var = (msc_string *)ngx_pcalloc(msr->mp, sizeof(msc_string));

            var->value = (char *)action->param;
            var->value_len = ngx_strlen(action->param);
            expand_macros(msr, var, NULL, msr->mp);
            
            nname = log_escape(msr->mp, var->value);
            nname_size = ngx_strlen(nname);

            tags = ngx_psprintf(msr->mp, ngx_strlen("%s [tag \"%s\"]")+ngx_strlen(tags)+nname_size+2,
                "%s [tag \"%s\"]", tags,nname);
        }
    }

    return ngx_pstrcat(msr->mp, fn, id, rev, msg, logdata, severity, version, maturity, accuracy, tags, NULL);
}

char * msre_rule_generate_unparsed(ngx_pool_t *pool,  const msre_rule *rule, const char *targets,
        const char *args, const char *actions)
{
    char *unparsed = NULL;
    const char *r_targets = targets;
    const char *r_args = args;
    const char *r_actions = actions;
    char *nname1,*nname2,*nname3;

    if (r_targets == NULL) {
        r_targets = rule->p1;
    }
    if (r_args == NULL) {
        r_args = ngx_pstrcat(pool, (rule->op_negated ? "!" : ""), "@", rule->op_name, " ", rule->op_param, NULL);
    }
    if (r_actions == NULL) {
        r_actions = msre_actionset_generate_action_string(pool, rule->actionset);
    }

    switch (rule->type) {
        case RULE_TYPE_NORMAL:
            if (r_actions == NULL) {
                nname1 = log_escape(pool, r_targets);
                nname2 = log_escape(pool, r_args);

                unparsed = ngx_pstrcat(pool, "SecRule \"",nname1,"\" ","\"",nname2,"\"",NULL);
            }

            else {

                nname1 = log_escape(pool, r_targets);
                nname2 = log_escape(pool, r_args);
                nname3 = log_escape(pool, r_actions);

                unparsed = ngx_pstrcat(pool, 
                    "SecRule \"",nname1,"\" ","\"",nname2,"\" ","\"",nname3,"\"",NULL);
            }
            break;
        case RULE_TYPE_ACTION:
            unparsed = ngx_pstrcat(pool, "SecAction \"",log_escape(pool, r_actions),"\"",NULL);
            break;
        case RULE_TYPE_MARKER:
            unparsed = ngx_pstrcat(pool,"SecMarker \"",rule->actionset->id,"\"",NULL);
            break;
    }

    return unparsed;
}

/**
 * Assembles a new rule using the strings that contain a list
 * of targets (variables), arguments, and actions.
 */
msre_rule *msre_rule_create(msre_ruleset *ruleset, int type,
        const char *fn, int line, const char *targets,
        const char *args, const char *actions, char **error_msg)
{
    msre_rule *rule;
    char *my_error_msg;
    const char *argsp;
    int rc;

    if (error_msg == NULL) return NULL;
    *error_msg = NULL;

    rule = (msre_rule *)ngx_pcalloc(ruleset->mp, sizeof(msre_rule));
    if (rule == NULL) return NULL;

    rule->type = type;
    rule->ruleset = ruleset;
    rule->targets = ngx_array_create(ruleset->mp, 10, sizeof(const msre_var *));
    rule->p1 = ngx_pstrndup(ruleset->mp, targets);
    rule->filename = ngx_pstrndup(ruleset->mp, fn);
    rule->line_num = line;

    /* Parse targets */
    rc = msre_parse_targets(ruleset, targets, rule->targets, &my_error_msg);
    if (rc < 0) {
        *error_msg = ngx_pstrcat(ruleset->mp, "Error creating rule: ", my_error_msg,NULL);
        return NULL;
    }

    /* Parse args */
    argsp = args;

    /* Is negation used? */
    if (*argsp == '!') {
        rule->op_negated = 1;
        argsp++;
        while((ngx_isspace(*argsp))&&(*argsp != '\0')) argsp++;
    }

    /* Is the operator explicitly selected? */
    if (*argsp != '@') {
        /* Go with a regular expression. */
        rule->op_name = "rx";
        rule->op_param = argsp;
    } else  {
        /* Explicitly selected operator. */
        char *p = (char *)(argsp + 1);
        while((!ngx_isspace(*p))&&(*p != '\0')) p++;
        rule->op_name = ngx_pstrmemdup(ruleset->mp, argsp + 1, p - (argsp + 1));
        while(ngx_isspace(*p)) p++; /* skip over the whitespace at the end*/
        rule->op_param = p; /* IMP1 So we always have a parameter even when it's empty? */
    }

    /* Find the operator. */
    rule->op_metadata = msre_engine_op_resolve(ruleset->engine, rule->op_name);
    if (rule->op_metadata == NULL) {
        *error_msg = ngx_pstrcat(ruleset->mp,
                "Error creating rule: Failed to resolve operator: ", rule->op_name,NULL);
        return NULL;
    }

    /* Initialise & validate parameter */
    if (rule->op_metadata->param_init != NULL) {
        if (rule->op_metadata->param_init(rule, &my_error_msg) <= 0) {
            *error_msg = ngx_pstrcat(ruleset->mp, "Error creating rule: ", my_error_msg,NULL);
            return NULL;
        }
    }

    /* Parse actions */
    if (actions != NULL) {
        /* Create per-rule actionset */
        rule->actionset = msre_actionset_create(ruleset->engine, ruleset->mp, actions, &my_error_msg);
        if (rule->actionset == NULL) {
            *error_msg = ngx_pstrcat(ruleset->mp, "Error parsing actions: ", my_error_msg,NULL);
            return NULL;
        }
    }

    /* Add the unparsed rule */
    rule->unparsed = msre_rule_generate_unparsed(ruleset->mp, rule, targets, args, NULL);

    return rule;
}


/**
 * Perform non-disruptive actions associated with the provided actionset.
 */
static void msre_perform_nondisruptive_actions(modsec_rec *msr, msre_rule *rule,
        msre_actionset *actionset, ngx_pool_t *mptmp)
{
    const ngx_array_t *tarr;
    const ngx_table_entry_t *telts;
    ngx_uint_t i;

    tarr = ngx_table_elts(actionset->actions);
    telts = (const ngx_table_entry_t*)tarr->elts;
    for (i = 0; i < tarr->nelts; i++) {
        msre_action *action = (msre_action *)telts[i].val;
        if (action->metadata->type == ACTION_NON_DISRUPTIVE) {
            if (action->metadata->execute != NULL) {
                action->metadata->execute(msr, mptmp, rule, action);
            }
        }
    }
}

/**
 * Perform the disruptive actions associated with the given actionset.
 */
static void msre_perform_disruptive_actions(modsec_rec *msr, msre_rule *rule,
        msre_actionset *actionset, ngx_pool_t *mptmp, const char *message)
{
    const ngx_array_t *tarr;
    const ngx_table_entry_t *telts;
    ngx_uint_t i;

    /* Execute the disruptive actions. Do note that this does
     * not mean the request will be interrupted straight away. All
     * disruptive actions need to do here is update the information
     * that will be used to act later.
     */
    tarr = ngx_table_elts(actionset->actions);
    telts = (const ngx_table_entry_t*)tarr->elts;
    for (i = 0; i < tarr->nelts; i++) {
        msre_action *action = (msre_action *)telts[i].val;
        if (action->metadata->type == ACTION_DISRUPTIVE) {
            if (action->metadata->execute != NULL) {
                action->metadata->execute(msr, mptmp, rule, action);
            }
        }
    }

    /* If "noauditlog" was used do not mark the transaction relevant. */
    if (actionset->auditlog != 0) {
        msr->is_relevant++;
    }

    /* We only do stuff when in ONLINE mode. In all other
     * cases we only emit warnings.
     */
    if ((msr->phase == PHASE_LOGGING)
            || (msr->txcfg->is_enabled == MODSEC_DETECTION_ONLY)
            || (msr->modsecurity->processing_mode == MODSEC_OFFLINE)
            || (actionset->intercept_action == ACTION_NONE))
    {
        int log_level;

        /* If "nolog" was used log at a higher level to prevent an "alert". */
        if (actionset->log == 0) {
            log_level = 4;

            /* But, if "auditlog" is enabled, then still add the message. */
            if (actionset->auditlog != 0) {
                *(const char **)ngx_array_push(msr->alerts) = msc_alert_message(msr, actionset, NULL, message);
            }

        }
        else {
            log_level = 2;
        }

        msc_alert(msr, log_level, actionset, "Warning.", message);

        /* However, this will mark the txn relevant again if it is <= 3,
         * which will mess up noauditlog.  We need to compensate for this
         * so that we do not increment twice when auditlog is enabled and
         * prevent incrementing when auditlog is disabled.
         */
        if (log_level <= 3) {
            msr->is_relevant--;
        }

        return;
    }

    /* Signal to the engine we need to intercept this
     * transaction, and rememer the rule that caused it.
     */
    msr->was_intercepted = 1;
    msr->rule_was_intercepted = 1;
    msr->intercept_phase = msr->phase;
    msr->intercept_actionset = actionset;
    msr->intercept_message = message;
}

/**
 * Invokes the rule operator against the given value.
 */
static int execute_operator(msre_var *var, msre_rule *rule, modsec_rec *msr,
    msre_actionset *acting_actionset, ngx_pool_t *mptmp)
{
    ngx_ext_time_t time_before_op = 0;
    char *my_error_msg = NULL;
    const char *full_varname = NULL;
    const ngx_array_t *tarr = NULL;
    const ngx_table_entry_t *telts = NULL;
    rule_exception *re = NULL;
    char *exceptions = NULL;
    int rc;
    ngx_uint_t i;

    /* determine the full var name if not already resolved
     *
     * NOTE: this can happen if the var does not match but it is
     * being tested for non-existance as in:
     *   @REQUEST_HEADERS:Foo "@eq 0"
     *   @REQUEST_HEADERS:Foo "!@eq 1"
     */
    if ((var->param != NULL) && (var->name != NULL) && (ngx_strchr(var->name,':') == NULL)) {
        full_varname = ngx_psprintf(mptmp, ngx_strlen("%s%s:%s")+ngx_strlen(var->name)+ngx_strlen(var->param)+4,
                                    "%s%s:%s",
                                    (var->is_counting ? "&" : ""),
                                    var->name, var->param);
    }
    else if ((var->name != NULL) && var->is_counting && (*var->name != '&')) {
        full_varname = ngx_pstrcat(mptmp, "&", var->name, NULL);
    }
    else {
        full_varname = var->name;
    }

    tarr = ngx_table_elts(msr->removed_targets);
    telts = (const ngx_table_entry_t*)tarr->elts;

    for (i = 0; i < tarr->nelts; i++) {
        exceptions = (char *)telts[i].key;
        re = (rule_exception *)telts[i].val;

        rc = msre_ruleset_rule_matches_exception(rule, re);

        if (rc > 0) {
            rc = fetch_target_exception(rule, msr, var, exceptions);

            if(rc > 0)  {

                if (msr->txcfg->debuglog_level >= 4) {
                    msr_log(msr, 4, "Executing operator \"%s%s\" with param \"%s\" against %s skipped.",
                            (rule->op_negated ? "!" : ""), rule->op_name,
                            log_escape(msr->mp, rule->op_param), full_varname);
                }

                return RULE_NO_MATCH;

            }
        }

    }

    if (msr->txcfg->debuglog_level >= 4) {
        msr_log(msr, 4, "Executing operator \"%s%s\" with param \"%s\" against %s.",
                (rule->op_negated ? "!" : ""), rule->op_name,
                log_escape(msr->mp, rule->op_param), full_varname);
    }

    if (msr->txcfg->debuglog_level >= 9) {
        msr_log(msr, 9, "Target value: \"%s\"", log_escape_nq_ex(msr->mp, var->value,
                    var->value_len));
    }

#if defined(PERFORMANCE_MEASUREMENT)
    time_before_op = ngx_ext_time_now();
#else
    if (msr->txcfg->debuglog_level >= 4 || msr->txcfg->max_rule_time > 0) {
        time_before_op = ngx_ext_time_now();
    }
#endif

    rc = rule->op_metadata->execute(msr, rule, var, &my_error_msg);

#if defined(PERFORMANCE_MEASUREMENT)
    {
        /* Record performance but do not log anything. */
        ngx_ext_time_t t1 = ngx_ext_time_now();
        rule->op_time += (t1 - time_before_op);
    }
    #else
    if (msr->txcfg->debuglog_level >= 4) {
        ngx_ext_time_t t1 = ngx_ext_time_now();
        msr_log(msr, 4, "Operator completed in %T usec.", (t1 - time_before_op));
    }

    if(msr->txcfg->max_rule_time > 0)  {
        ngx_ext_time_t t1 = ngx_ext_time_now();
        ngx_ext_time_t rule_time = 0;
        const char *rt_time = NULL;

        if(rule->actionset->id != NULL) {
            rt_time = ngx_table_get(msr->perf_rules, rule->actionset->id);
            if(rt_time == NULL) {
                rt_time = ngx_psprintf(msr->mp, NGX_INT64_LEN+2,"%T", (t1 - time_before_op));
                rule_time = (ngx_ext_time_t)atoi(rt_time);
                if(rule_time >= msr->txcfg->max_rule_time)
                    ngx_table_setn(msr->perf_rules, rule->actionset->id, rt_time);
            } else  {
                rule_time = (ngx_ext_time_t)atoi(rt_time);
                rule_time += (t1 - time_before_op);
                if(rule_time >= msr->txcfg->max_rule_time)  {
                    rt_time = ngx_psprintf(msr->mp, NGX_INT64_LEN+2,"%T", rule_time);
                    ngx_table_setn(msr->perf_rules, rule->actionset->id, rt_time);
                }
            }
        }
    }
#endif

    if (rc < 0) {
        msr_log(msr, 4, "Operator error: %s", my_error_msg);
        return -1;
    }

    if (((rc == 0)&&(rule->op_negated == 0))||((rc == 1)&&(rule->op_negated == 1))) {
        /* No match, do nothing. */
        return RULE_NO_MATCH;
    }
    else {
        /* Match. */
        if (rc == 0) {
            char *op_param = log_escape(msr->mp, rule->op_param);

            /* Truncate op parameter. */
            if (ngx_strlen(op_param) > 252) {
                op_param = ngx_psprintf(msr->mp, 252+10,"%*s ...",252,op_param);
            }
            
            char *nname1 = log_escape(msr->mp, rule->op_name);
            char *nname2 = log_escape(msr->mp, full_varname);

            /* Operator did not match so we need to provide a message. */
            my_error_msg = ngx_psprintf(msr->mp, 
                ngx_strlen("Match of \"%s %s\" against \"%s\" required.")+ngx_strlen(nname1)+ngx_strlen(op_param)+ngx_strlen(nname2)+2,
                "Match of \"%s %s\" against \"%s\" required.",nname1,op_param,nname2);
        }

        /* Save the rules that match */
        *(const msre_rule **)ngx_array_push(msr->matched_rules) = rule;

        /* Save the last matched var data */
        if(var != NULL && msr != NULL)   {
            msc_string *mvar = NULL;

            msr->matched_var->name = ngx_pstrndup(msr->mp, var->name);
            msr->matched_var->name_len = ngx_strlen(msr->matched_var->name);
            msr->matched_var->value = ngx_pmemdup(msr->mp, var->value, var->value_len);
            msr->matched_var->value_len = var->value_len;

            mvar = ngx_palloc(msr->mp, sizeof(msc_string));
            mvar->name = ngx_pstrndup(msr->mp, var->name);
            mvar->name_len = ngx_strlen(mvar->name);
            mvar->value = ngx_pmemdup(msr->mp, var->value, var->value_len);
            mvar->value_len = var->value_len;

            ngx_table_addn(msr->matched_vars, mvar->name, (void *)mvar);

        }

        /* Keep track of the highest severity matched so far */
        if ((acting_actionset->severity > 0) && (acting_actionset->severity < msr->highest_severity)
            && !rule->actionset->is_chained)   {
            msr->highest_severity = acting_actionset->severity;
        }


        /* Perform non-disruptive actions. */
        msre_perform_nondisruptive_actions(msr, rule, rule->actionset, mptmp);

        /* Perform disruptive actions, but only if
         * this rule is not part of a chain.
         */
        if (rule->actionset->is_chained == 0) {
            msre_perform_disruptive_actions(msr, rule, acting_actionset, mptmp, my_error_msg);
        }

        return RULE_MATCH;
    }
}

/**
 * Executes rule against the given transaction.
 */
static ngx_int_t msre_rule_process_normal(msre_rule *rule, modsec_rec *msr) {
    const ngx_array_t *arr = NULL;
    const ngx_table_entry_t *te = NULL;
    msre_actionset *acting_actionset = NULL;
    msre_var **targets = NULL;
    ngx_pool_t *mptmp = msr->msc_rule_mptmp;
    ngx_table_t *tartab = NULL;
    ngx_table_t *vartab = NULL;
    ngx_uint_t i; 
    int rc = 0, match_count = 0;
    int invocations = 0;
    int multi_match = 0;

    /* Choose the correct metadata/disruptive action actionset. */
    acting_actionset = rule->actionset;
    if (rule->chain_starter != NULL) {
        acting_actionset = rule->chain_starter->actionset;
    }

    /* Configure recursive matching. */
    if (ngx_table_get(rule->actionset->actions, "multiMatch") != NULL) {
        multi_match = 1;
    }

    /* ENH: What is a good initial size? */
    tartab = ngx_table_make(mptmp, 24);
    if (tartab == NULL) return -1;
    vartab = ngx_table_make(mptmp, 24);
    if (vartab == NULL) return -1;

    /* Expand variables to create a list of targets. */

    targets = (msre_var **)rule->targets->elts;
    for (i = 0; i < rule->targets->nelts; i++) {
        ngx_uint_t j;
        int list_count;

        ngx_table_clear(vartab);

        /* ENH Introduce a new variable hook that would allow the code
         *     behind the variable to return the size of the collection
         *     without having to generate the variables.
         */

        /* Expand individual variables first. */
        list_count = targets[i]->metadata->generate(msr, targets[i], rule, vartab, mptmp);

        if (targets[i]->is_counting) {
            /* Count how many there are and just add the score to the target list. */
            msre_var *newvar = (msre_var *)ngx_pmemdup(mptmp, targets[i], sizeof(msre_var));
            newvar->value = ngx_psprintf(mptmp, NGX_INT64_LEN+2,"%d", list_count);
            newvar->value_len = ngx_strlen(newvar->value);
            ngx_table_addn(tartab, newvar->name, (void *)newvar);
        } else {
            /* And either add them or remove from the final target list. */
            arr = ngx_table_elts(vartab);
            te = (ngx_table_entry_t *)arr->elts;
            for(j = 0; j < arr->nelts; j++) {
                if (targets[i]->is_negated == 0) {
                    ngx_table_addn(tartab, te[j].key, te[j].val);
                } else {
                    ngx_table_unset(tartab, te[j].key);
                }
            }
        }
    }

    /* Log the target variable expansion */
    if (msr->txcfg->debuglog_level >= 4) {
        const char *expnames = NULL;

        arr = ngx_table_elts(tartab);
        if (arr->nelts > 1) {
            te = (ngx_table_entry_t *)arr->elts;
            expnames = ngx_pstrndup(mptmp, ((msre_var *)te[0].val)->name);
            for(i = 1; i < arr->nelts; i++) {
                expnames = ngx_psprintf(mptmp, 
                    ngx_strlen("%s|%s")+ngx_strlen(expnames)+ngx_strlen(((msre_var *)te[i].val)->name)+2,
                    "%s|%s", expnames, ((msre_var *)te[i].val)->name);
            }

            if (ngx_strcmp(rule->p1, expnames) != 0) {
                msr_log(msr, 4, "Expanded \"%s\" to \"%s\".", rule->p1, expnames);
            }
        }
    }

    /* Loop through targets on the final target list,
     * perform transformations as necessary, and invoke
     * the operator.
     */

    arr = ngx_table_elts(tartab);
    te = (ngx_table_entry_t *)arr->elts;
    for (i = 0; i < arr->nelts; i++) {
        int changed;
        int usecache = 0;
        ngx_table_t *cachetab = NULL;
        ngx_ext_time_t time_before_trans = 0;
        msre_var *var;

        /* Take one target. */
        var = (msre_var *)te[i].val;

        /* Is this var cacheable? */
        if (msr->txcfg->cache_trans != MODSEC_CACHE_DISABLED) {
            usecache = 1;

            /* Counting vars are not cacheable due to them being created
             * in a local per-rule pool.
             */
            if (var->is_counting) {
                if (msr->txcfg->debuglog_level >= 9) {
                    msr_log(msr, 9, "CACHE: Disabled - &%s is dynamic", var->name);
                }

                usecache = 0;
            }
            /* Only cache if if the variable is available in this phase */
            else if (msr->phase < var->metadata->availability) {
                if (msr->txcfg->debuglog_level >= 9) {
                    msr_log(msr, 9, "CACHE: Disabled - %s is not yet available in phase %d (requires phase %d or later)", var->name, msr->phase, var->metadata->availability);
                }

                usecache = 0;
            }
            /* check the cache options */
            else if (var->value_len < msr->txcfg->cache_trans_min) {
                if (msr->txcfg->debuglog_level >= 9) {
                    msr_log(msr, 9, "CACHE: Disabled - %s value length=%u, smaller than minlen=%z", var->name, var->value_len, msr->txcfg->cache_trans_min);
                }

                usecache = 0;
            }
            else if ((msr->txcfg->cache_trans_max != 0) && (var->value_len > msr->txcfg->cache_trans_max)) {
                if (msr->txcfg->debuglog_level >= 9) {
                    msr_log(msr, 9, "CACHE: Disabled - %s value length=%u, larger than maxlen=%z", var->name, var->value_len, msr->txcfg->cache_trans_max);
                }

                usecache = 0;
            }

            /* if cache is still enabled, check the VAR for cacheablity */
            if (usecache) {
                if (var->metadata->is_cacheable == VAR_CACHE) {
                    if (msr->txcfg->debuglog_level >= 9) {
                        msr_log(msr, 9, "CACHE: Enabled");
                    }

                    #ifdef CACHE_DEBUG
                    msr_log(msr, 9, "CACHE: Fetching cache entry from hash=%pp: %pp=%s", msr->tcache, var, var->name);
                    #endif

                    /* Fetch cache table for this target */
                    cachetab = (ngx_table_t *)ngx_hash2_get(msr->tcache, var->value, sizeof(var->value));

                    /* Create an empty cache table if this is the first time */
                    #ifdef CACHE_DEBUG
                    if (cachetab) {
                        msr_log(msr, 9, "CACHE: Using cache table %pp", cachetab);
                    }
                    else
                    #else
                    if (cachetab == NULL)
                    #endif
                    {
                        /* NOTE: We use the pointer to the var value as a hash
                         *       key as it is unique. This pointer *must*
                         *       remain valid through the entire phase. If
                         *       it does not, then we will not receive a cache
                         *       hit and just wasted RAM. So, it is important
                         *       that any such vars be marked as VAR_DONT_CACHE.
                         *
                         * ENH: Only use pointer for non-scalar vars
                         */
                        cachetab = ngx_table_make(msr->mp, 3);
                        ngx_hash2_set(msr->tcache, var->value, sizeof(var->value), cachetab);

                        #ifdef CACHE_DEBUG
                        msr_log(msr, 9, "CACHE: Created a new cache table %pp for %pp", cachetab, var->value);
                        #endif
                    }

                }
                else {
                    usecache = 0;

                    if (msr->txcfg->debuglog_level >= 9) {
                        msr_log(msr, 9, "CACHE: %s transformations are not cacheable", var->name);
                    }
                }
            }
        }

        #if defined(PERFORMANCE_MEASUREMENT)
        time_before_trans = ngx_ext_time_now();
        #else
        if (msr->txcfg->debuglog_level >= 4) {
            time_before_trans = ngx_ext_time_now();
        }
        #endif

        /* Transform target. */
        {
            const ngx_array_t *tarr;
            const ngx_table_entry_t *telts;
            const char *tfnspath = NULL;
            char *tfnskey = NULL;
            int tfnscount = 0;
            int last_cached_tfn = 0;
            msre_cache_rec *crec = NULL;
            msre_cache_rec *last_crec = NULL;
            ngx_uint_t k;
            msre_action *action;
            msre_tfn_metadata *metadata;
            ngx_table_t *normtab;
            const char *lastvarval = NULL;
            size_t lastvarlen = 0;
            int tfnchanged = 0;

            changed = 0;
            normtab = ngx_table_make(mptmp, 10);
            if (normtab == NULL) return -1;
            tarr = ngx_table_elts(rule->actionset->actions);
            telts = (const ngx_table_entry_t*)tarr->elts;

            /* Build the final list of transformation functions. */
            for (k = 0; k < tarr->nelts; k++) {
                action = (msre_action *)telts[k].val;

                if (ngx_strcmp(telts[k].key, "t") == 0) {
                    if (ngx_strcmp(action->param, "none") == 0) {
                        ngx_table_clear(normtab);
                        tfnspath = NULL;
                        tfnskey = NULL;
                        tfnscount = 0;
                        last_crec = NULL;
                        last_cached_tfn = 0;
                        continue;
                    }

                    if (action->param_plusminus == NEGATIVE_VALUE) {
                        ngx_table_unset(normtab, action->param);
                    }
                    else {
                        tfnscount++;

                        ngx_table_addn(normtab, action->param, (void *)action);

                        /* Check the cache, saving the 'most complete' as a
                         * starting point
                         */
                        if (usecache) {
                            tfnspath = ngx_pstrcat(mptmp,(tfnspath?tfnspath:""), (tfnspath?",":""), action->param,NULL);
                            tfnskey = ngx_psprintf(mptmp,NGX_INT64_LEN+ngx_strlen(tfnspath)+10, "%xd;%s", tfnscount, tfnspath);
                            crec = (msre_cache_rec *)ngx_table_get(cachetab, tfnskey);

                            #ifdef CACHE_DEBUG
                            msr_log(msr, 9, "CACHE: %s %s cached=%d", var->name, tfnskey, (crec ? 1 : 0));
                            #endif

                            if (crec != NULL) {
                                last_crec = crec;
                                last_cached_tfn = tfnscount;
                            }
                        }
                    }
                }
            }

            /* If the last cached tfn is the last in the list
             * then we can stop here and just execute the action immediatly
             */
            if (usecache && !multi_match &&
                (crec != NULL) && (crec == last_crec))
            {
                crec->hits++;

                if (crec->changed) {
                    var->value = ngx_pmemdup(mptmp, crec->val, crec->val_len);
                    var->value_len = crec->val_len;
                }

                if (msr->txcfg->debuglog_level >= 9) {
                    msr_log(msr, 9, "T (%d) %s: \"%s\" [fully cached hits=%d]", crec->changed, crec->path,
                        log_escape_nq_ex(mptmp, var->value, var->value_len), crec->hits);
                }

                #if defined(PERFORMANCE_MEASUREMENT) 
                {
                    ngx_ext_time_t t1 = ngx_ext_time_now();
                    rule->trans_time += (t1 - time_before_trans);
                }
                #else
                if (msr->txcfg->debuglog_level >= 4) {
                    ngx_ext_time_t t1 = ngx_ext_time_now();

                    msr_log(msr, 4, "Transformation completed in %T usec.",
                        (t1 - time_before_trans));
                }
                #endif

                rc = execute_operator(var, rule, msr, acting_actionset, mptmp);

                if (rc < 0) {
                    return -1;
                }

                if (rc == RULE_MATCH) {
                    match_count++;

                    /* Return straight away if the transaction
                     * was intercepted - no need to process the remaining
                     * targets.
                     */
                    if (msr->rule_was_intercepted) {
                        return RULE_MATCH;
                    }
                }

                continue; /* next target */
            }


            /* Perform transformations. */

            tarr = ngx_table_elts(normtab);

            /* Execute transformations in a loop. */

            /* Start after the last known cached transformation if we can */
            if (!multi_match && (last_crec != NULL)) {
                k = last_cached_tfn;
                tfnspath = last_crec->path;
                last_crec->hits++;

                if ((changed = last_crec->changed) > 0) {
                    var->value = last_crec->val;
                    var->value_len = last_crec->val_len;
                }

                if (msr->txcfg->debuglog_level >= 9) {
                    msr_log(msr, 9, "T (%d) %s: \"%s\" [partially cached hits=%d]", last_crec->changed,
                        tfnspath, log_escape_nq_ex(mptmp, var->value, var->value_len), last_crec->hits);
                }
            }
            else {
                tfnspath = NULL;
                k = 0;
            }

            /* Make a copy of the value so that we can change it in-place. */
            if (tarr->nelts) {
                var->value = ngx_pstrmemdup(mptmp, var->value, var->value_len);
                /* var->value_len remains the same */
            }

            telts = (const ngx_table_entry_t*)tarr->elts;
            for (; k < tarr->nelts; k++) {
                char *rval = NULL;
                long int rval_length = -1;

                /* In multi-match mode we execute the operator
                 * once at the beginning and then once every
                 * time the variable is changed by the transformation
                 * function.
                 */
                if (multi_match && (k == 0 || tfnchanged)) {
                    invocations++;

                    #if defined(PERFORMANCE_MEASUREMENT)
                    {
                        ngx_ext_time_t t1 = ngx_ext_time_now();
                        rule->trans_time += (t1 - time_before_trans);
                    }
                    #else
                    if (msr->txcfg->debuglog_level >= 4) {
                        ngx_ext_time_t t1 = ngx_ext_time_now();

                        msr_log(msr, 4, "Transformation completed in %T usec.",
                            (t1 - time_before_trans));
                    }
                    #endif

                    rc = execute_operator(var, rule, msr, acting_actionset, mptmp);

                    if (rc < 0) {
                        return -1;
                    }

                    if (rc == RULE_MATCH) {
                        match_count++;

                        /* Return straight away if the transaction
                        * was intercepted - no need to process the remaining
                        * targets.
                        */
                        if (msr->rule_was_intercepted) {
                            return RULE_MATCH;
                        }
                    }
                }

                /* Perform one transformation. */
                action = (msre_action *)telts[k].val;
                metadata = (msre_tfn_metadata *)action->param_data;
                tfnchanged = metadata->execute(mptmp,
                    (unsigned char *)var->value, var->value_len,
                    &rval, &rval_length);

                if (tfnchanged < 0) {
                    return -1;
                }

                if (tfnchanged) {
                    changed++;
                }

                /* Use the new values */
                var->value = rval;
                var->value_len = rval_length;

                /* Cache the transformation */
                if (usecache) {
                    ngx_uint_t tfnsnum = k + 1;

                    /* Generate the cache key */
                    tfnspath = ngx_pstrcat(msr->mp,(tfnspath ? tfnspath : ""),
                        (tfnspath ? "," : ""), action->param,NULL);

                    tfnskey = ngx_psprintf(msr->mp, NGX_INT64_LEN+ngx_strlen(tfnspath)+10,"%xd;%s", tfnsnum, tfnspath);

                    if ((msr->txcfg->cache_trans_maxitems != 0) &&
                        (msr->tcache_items >= msr->txcfg->cache_trans_maxitems))
                    {
                        /* Warn only once if we attempt to go over the cache limit. */
                        if (msr->tcache_items == msr->txcfg->cache_trans_maxitems) {
                            msr->tcache_items++;
                            msr_log(msr, 4, "CACHE: Disabled - phase=%d"
                                            " maxitems=%z"
                                            " limit reached.",
                                            msr->phase,
                                            msr->txcfg->cache_trans_maxitems);
                        }
                    }
                    else if (msr->txcfg->cache_trans_incremental ||
                        (tfnsnum == tarr->nelts))
                    {
                        /* ENH1: Add flag to vars to tell which ones can change across phases store the rest in a global cache */
                        crec = (msre_cache_rec *)ngx_pcalloc(msr->mp, sizeof(msre_cache_rec));
                        if (crec == NULL) return -1;

                        crec->hits = 0;
                        crec->changed = changed;
                        crec->num = k + 1;
                        crec->path = tfnspath;

                        /* We want to cache a copy if it changed otherwise
                         * we just want to use a pointer to the last changed value.
                         */
                        crec->val = (!lastvarval || tfnchanged) ? ngx_pmemdup(msr->mp, var->value, var->value_len) : lastvarval;
                        crec->val_len = changed ? ((!lastvarval || tfnchanged) ? var->value_len : lastvarlen) : 0;

                        /* Keep track of the last changed var value */
                        if (tfnchanged) {
                            lastvarval = crec->val;
                            lastvarlen = crec->val_len;
                        }

                        #ifdef CACHE_DEBUG
                        if (changed) {
                            msr_log(msr, 9, "CACHE: Caching %s=\"%s\" (%pp)",
                                            tfnskey,
                                            log_escape_nq_ex(mptmp,
                                                             crec->val,
                                                             crec->val_len),
                                            var);
                        }
                        else {
                            msr_log(msr, 9, "CACHE: Caching %s=<no change> (%pp)",
                                            tfnskey,
                                            var);
                        }
                        #endif

                        msr->tcache_items++;

                        ngx_table_setn(cachetab, tfnskey, (void *)crec);
                    }
                }

                if (msr->txcfg->debuglog_level >= 9) {
                    msr_log(msr, 9, "T (%d) %s: \"%s\"", rc, metadata->name,
                        log_escape_nq_ex(mptmp, var->value, var->value_len));
                }
            }
        }

        /* Execute operator if multi-matching is not enabled,
         * or if it is and we need to process the result of the
         * last transformation.
         */
        if (!multi_match || changed) {
            invocations++;

            #if defined(PERFORMANCE_MEASUREMENT)
            {
                ngx_ext_time_t t1 = ngx_ext_time_now();
                rule->trans_time += (t1 - time_before_trans);
            }
            #else
            if (msr->txcfg->debuglog_level >= 4) {
                ngx_ext_time_t t1 = ngx_ext_time_now();

                msr_log(msr, 4, "Transformation completed in %T usec.",
                    (t1 - time_before_trans));
            }
            #endif

            rc = execute_operator(var, rule, msr, acting_actionset, mptmp);

            if (rc < 0) {
                return -1;
            }

            if (rc == RULE_MATCH) {
                match_count++;

                /* Return straight away if the transaction
                 * was intercepted - no need to process the remaining
                 * targets.
                 */
                if (msr->rule_was_intercepted) {
                    return RULE_MATCH;
                }
            }
        }
    }


    return (match_count ? RULE_MATCH : RULE_NO_MATCH);
}


/**
 *
 */
static ngx_int_t msre_rule_process(msre_rule *rule, modsec_rec *msr) {
    /* Use a fresh memory sub-pool for processing each rule */
    if (msr->msc_rule_mptmp == NULL) {
		msr->msc_rule_mptmp = ngx_create_pool(4096,msr->mp->log);

        if (msr->msc_rule_mptmp == NULL) {
            return -1;
        }
    } else {
		ngx_reset_pool(msr->msc_rule_mptmp);
    }


    return msre_rule_process_normal(rule, msr);
}

/**
 * Checks whether the given rule ID is in the given range.
 */
int rule_id_in_range(int ruleid, const char *range) {
    char *p = NULL, *saveptr = NULL;
    char *data = NULL;

    if (range == NULL) return 0;
    data = strdup(range);
    if (data == NULL) return 0;

    p = ngx_strtok(data, ",", &saveptr);
    while(p != NULL) {
        char *s = strstr(p, "-");
        if (s == NULL) {
            if (ruleid == atoi(p)) {
                free(data);
                return 1;
            }
        } else {
            int start = atoi(p);
            int end = atoi(s + 1);
            if ((ruleid >= start)&&(ruleid <= end)) {
                free(data);
                return 1;
            }
        }
        p = ngx_strtok(NULL, ",", &saveptr);
    }

    free(data);

    return 0;
}
