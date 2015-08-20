/*
 * =====================================================================================
 *      Copyright (C) 2014 jianfeng sha
 *
 *      Filename:  vbuf.h
 *
 *      Description:  
 *
 *      Created:  11/13/14 18:07:05
 *
 *      Author:  jianfeng sha , csp001314@163.com
 * =====================================================================================
 */
#ifndef VBUF_H
#define VBUF_H

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct ele_rwable_t ele_rwable_t;

typedef struct {
    char *start;
    char *pos;
    char *end;
}vbuf_t;

struct ele_rwable_t{
    ngx_int_t (*write)(vbuf_t *vbuf,ele_rwable_t *elem);
    ngx_int_t (*read)(vbuf_t *vbuf,ele_rwable_t *elem);
};

#define VBUF_SIZE(vbuf)             ((size_t)((vbuf)->end-(vbuf)->start))
#define VBUF_CONTENT_SIZE(vbuf)     ((size_t)((vbuf)->pos-(vbuf)->start))
#define VBUF_UPDATE(vbuf,size)      ((vbuf)->pos+=(size))
#define VBUF_FULL(vbuf,size)        ((vbuf)->pos+(size)>(vbuf)->end)
#define VBUF_EMPTY(vbuf)            ((vbuf)->pos == (vbuf)->start)
#define VBUF_RESET(vbuf)            ((vbuf)->pos = (vbuf)->start)
#define VBUF_EMPTY_SIZE(vbuf)       ((size_t)((vbuf)->end-(vbuf)->pos))

vbuf_t *create_vbuf(size_t size);
void destroy_vbuf(vbuf_t *vbuf);

/*vbuf write functions*/
ngx_int_t vbuf_write_bytes(vbuf_t *vbuf,void *data,size_t data_size);
ngx_int_t vbuf_write_str(vbuf_t *vbuf,const char *value);
ngx_int_t vbuf_write_nstr(vbuf_t *vbuf,char *value,size_t len);
ngx_int_t vbuf_write_boolean(vbuf_t *vbuf,int v);
ngx_int_t vbuf_write_short(vbuf_t *vbuf,short v);
ngx_int_t vbuf_write_int(vbuf_t *vbuf,int v);
ngx_int_t vbuf_write_long(vbuf_t *vbuf,long v);
ngx_int_t vbuf_write_ushort(vbuf_t *vbuf,unsigned short v);
ngx_int_t vbuf_write_uint(vbuf_t *vbuf,unsigned int v);
ngx_int_t vbuf_write_ulong(vbuf_t *vbuf,unsigned long v);
ngx_int_t vbuf_write_float(vbuf_t *vbuf,float v);
ngx_int_t vbuf_write_double(vbuf_t *vbuf,double v);
ngx_int_t vbuf_write_int8(vbuf_t *vbuf,int8_t v);
ngx_int_t vbuf_write_int16(vbuf_t *vbuf,int16_t v);
ngx_int_t vbuf_write_int32(vbuf_t *vbuf,int32_t v);
ngx_int_t vbuf_write_int64(vbuf_t *vbuf,int64_t v);
ngx_int_t vbuf_write_uint8(vbuf_t *vbuf,uint8_t v);
ngx_int_t vbuf_write_uint16(vbuf_t *vbuf,uint16_t v);
ngx_int_t vbuf_write_uint32(vbuf_t *vbuf,uint32_t v);
ngx_int_t vbuf_write_uint64(vbuf_t *vbuf,uint64_t v);
ngx_int_t vbuf_write_size(vbuf_t *vbuf,size_t v);
ngx_int_t vbuf_write_ssize(vbuf_t *vbuf,ssize_t v);
ngx_int_t vbuf_write_off(vbuf_t *vbuf,off_t v);

ngx_int_t vbuf_write_rwable(vbuf_t *vbuf,ele_rwable_t *elem);

/*vbuf read functions*/
void vbuf_read_skip_bytes(vbuf_t *vbuf,size_t len);
void vbuf_read_bytes(vbuf_t *vbuf,void **data,size_t *data_len);
void vbuf_read_str(vbuf_t *vbuf,char **data,size_t *data_len);
int  vbuf_read_boolean(vbuf_t *vbuf);
short vbuf_read_short(vbuf_t *vbuf);
int vbuf_read_int(vbuf_t *vbuf);
long vbuf_read_long(vbuf_t *vbuf);
unsigned short vbuf_read_ushort(vbuf_t *vbuf);
unsigned int vbuf_read_uint(vbuf_t *vbuf);
unsigned long  vbuf_read_ulong(vbuf_t *vbuf);
float  vbuf_read_float(vbuf_t *vbuf);
double  vbuf_read_double(vbuf_t *vbuf);
int8_t vbuf_read_int8(vbuf_t *vbuf);
int16_t  vbuf_read_int16(vbuf_t *vbuf);
int32_t  vbuf_read_int32(vbuf_t *vbuf);
int64_t  vbuf_read_int64(vbuf_t *vbuf);
uint8_t  vbuf_read_uint8(vbuf_t *vbuf);
uint16_t  vbuf_read_uint16(vbuf_t *vbuf);
uint32_t  vbuf_read_uint32(vbuf_t *vbuf);
uint64_t  vbuf_read_uint64(vbuf_t *vbuf);
size_t vbuf_read_size(vbuf_t *vbuf);
ssize_t vbuf_read_ssize(vbuf_t *vbuf);
off_t  vbuf_read_off(vbuf_t *vbuf);
ngx_int_t vbuf_read_rwable(vbuf_t *vbuf,ele_rwable_t *elem);
#endif /*VBUF_H*/

