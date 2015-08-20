/*
 * =====================================================================================
 *       Copyright (C) 2014 jianfeng sha
 *
 *       Filename:  msc_log.c
 *
 *       Description:  
 *
 *       Created:  11/08/14 07:40:15
 *
 *       Author:  jianfeng sha , csp001314@163.com
 *
 * =====================================================================================
 */

#include "msc_log.h"


/**
 * Extended internal log helper function. Use msr_log instead. If fixup is
 * true, the message will be stripped of any trailing newline and any
 * required bytes will be escaped.
 */
static void internal_log_ex(ngx_http_request_t *r, directory_config *dcfg, modsec_rec *msr,
    int level, int fixup, const char *text, va_list ap)
{
    size_t nbytes;
    ngx_file_t *debuglog_file = NULL;
    int filter_debug_level = 0;
    char str1[1024] = "";
    char str2[1256] = "";

    /* Find the logging FD and determine the logging level from configuration. */
    if (dcfg != NULL) {
        if ((dcfg->debuglog_fd != NULL)&&(dcfg->debuglog_fd != NGX_CONF_UNSET_PTR)) {
            debuglog_file = dcfg->debuglog_fd;
        }

        if (dcfg->debuglog_level != NGX_CONF_UNSET) {
            filter_debug_level = dcfg->debuglog_level;
        }
    }

    /* Return immediately if we don't have where to write
     * or if the log level of the message is higher than
     * wanted in the log.
     */
    if (( (debuglog_file == NULL) || (level > filter_debug_level) )) return;

    /* Construct the message. */
    ngx_vsnprintf((u_char*)str1, sizeof(str1), text, ap);
    if (fixup) {
        int len = ngx_strlen(str1);

        /* Strip line ending. */
        if (len && str1[len - 1] == '\n') {
            str1[len - 1] = '\0';
        }
        if (len > 1 && str1[len - 2] == '\r') {
            str1[len - 2] = '\0';
        }
    }

    /* Construct the log entry. */
    ngx_snprintf((u_char*)str2, sizeof(str2), 
        "[%s][rid#%pp][%V][%d] %s\n",
        current_logtime(msr->mp),
		r,
		&r->uri,
		level, 
		(fixup ? log_escape_nq(msr->mp, str1) : str1));

    /* Write to the debug log. */
    if ((debuglog_file != NULL)&&(level <= filter_debug_level)) {
        nbytes = ngx_strlen(str2);
        ngx_write_file(debuglog_file,(u_char*)str2,nbytes,0);
    }


    return;
}


/**
 * Logs one message at the given level to the debug log (and to the
 * ngx error log if the message is important enough.
 */
void  msr_log(modsec_rec *msr, int level, const char *text, ...){
	
    va_list ap;

    va_start(ap, text);
    internal_log_ex(msr->r, msr->txcfg, msr, level, 0, text, ap);
    va_end(ap);
}

/**
 * Logs one message at level 3 to the debug log.
 */
void  msr_log_error(modsec_rec *msr, const char *text, ...){
	
    va_list ap;

    va_start(ap, text);
    internal_log_ex(msr->r, msr->txcfg, msr, 3, 1, text, ap);
    va_end(ap);
}

/**
 * Logs one message at level 4 to the debug log
 * The 'text' will first be escaped.
 */
void  msr_log_warn(modsec_rec *msr, const char *text, ...){

    va_list ap;

    va_start(ap, text);
    internal_log_ex(msr->r, msr->txcfg, msr, 4, 1, text, ap);
    va_end(ap);
}

/**
 * Converts an nginx error log message into one line of text.
 */
char  *format_error_log_message(ngx_pool_t *mp, error_message_t *em){
	
    char *s_file = "", *s_line = "", *s_level = "";
    char *s_status = "", *s_message = "";
    char *msg = NULL;

    if (em == NULL) return NULL;

    if (em->file != NULL) {
		s_file = log_escape(mp, (char*)em->file);

        s_file = ngx_psprintf(mp, strlen("[file \"\"] ")+ngx_strlen(s_file)+10,
			"[file \"%s\"] ", s_file);

        if (s_file == NULL) return NULL;
    }

    if (em->line > 0) {
        s_line = ngx_psprintf(mp, NGX_INT64_LEN+strlen("[line ] ")+4,
		"[line %d] ", em->line);

        if (s_line == NULL) return NULL;
    }

    s_level = ngx_psprintf(mp, NGX_INT64_LEN+strlen("[level ] ")+4,
		"[level %d] ", em->level);

    if (s_level == NULL) return NULL;

    if (em->status != 0) {
        
		s_status = ngx_psprintf(mp, strlen("[status ] ")+NGX_INT64_LEN+4,
			"[status %d] ", em->status);

        if (s_status == NULL) return NULL;
    }

    if (em->message != NULL) {
        s_message = log_escape_nq(mp, em->message);
        if (s_message == NULL) return NULL;
    }

    msg = ngx_pstrcat(mp,s_file, s_line, s_level, s_status, s_message,NULL);

    if (msg == NULL) return NULL;

    return msg;
}


