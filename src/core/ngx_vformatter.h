/*
 * =====================================================================================
 *      Copyright (C) 2014 jianfeng sha
 *
 *      Filename:  ngx_vformatter.h
 *
 *      Description:  
 *
 *      Created:  11/06/14 17:07:50
 *
 *      Author:  jianfeng sha , csp001314@163.com
 * =====================================================================================
 */
#ifndef _NGX_VFORMATTER_H_INCLUDED_
#define _NGX_VFORMATTER_H_INCLUDED_

#define NGX_SSIZE_T_FMT "ld"

/*  And NGX_SIZE_T_FMT */
#define NGX_SIZE_T_FMT "lu"

/*  And NGX_OFF_T_FMT */
#define NGX_OFF_T_FMT "ld"

/*  And NGX_PID_T_FMT */
#define NGX_PID_T_FMT "d"

/*  And NGX_INT64_T_FMT */
#define NGX_INT64_T_FMT "ld"

/*  And NGX_UINT64_T_FMT */
#define NGX_UINT64_T_FMT "lu"

/*  And NGX_UINT64_T_HEX_FMT */
#define NGX_UINT64_T_HEX_FMT "lx"

typedef struct {
    /* * The current position */
    char *curpos;
    /* * The end position of the format string */
    char *endpos;
}ngx_vformatter_buff_t;

int ngx_vformatter(int (*flush_func)(ngx_vformatter_buff_t *),ngx_vformatter_buff_t *vbuff, const char *fmt, va_list ap);

#endif /*_NGX_VFORMATTER_H_INCLUDED_*/
