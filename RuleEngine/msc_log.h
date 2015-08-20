/*
 * =====================================================================================
 *
 *       Copyright (C) 2014 jianfeng sha
 *
 *       Filename:  msc_log.h
 *
 *       Description:  
 *
 *       Created:  11/08/14 07:33:46
 *
 *       Author:  jianfeng sha , csp001314@163.com
 *
 * =====================================================================================
 */
#ifndef __MSC_LOG_H__
#define __MSC_LOG_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include "modsecurity.h"

void  msr_log(modsec_rec *msr, int level, const char *text, ...);

void  msr_log_error(modsec_rec *msr, const char *text, ...);

void  msr_log_warn(modsec_rec *msr, const char *text, ...);

char  *format_error_log_message(ngx_pool_t *mp, error_message_t *em);

#endif /* __MSC_LOG_H__ */

