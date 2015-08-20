/*
 * =====================================================================================
 *      Copyright (C) 2014 jianfeng sha
 *
 *      Filename:  vbuf.c
 *
 *      Description:  
 *
 *      Created:  11/13/14 18:39:25
 *
 *      Author:  jianfeng sha , csp001314@163.com
 *
 * =====================================================================================
 */

#include "vbuf.h"

static vbuf_t * expand_vbuf(vbuf_t *vbuf){
    
    vbuf_t *new_vbuf = NULL;
    size_t new_size,old_size;

    if(vbuf == NULL) return NULL;

    old_size = VBUF_SIZE(vbuf);

    old_size = old_size == 0?1:old_size;

    new_size = old_size*2+sizeof(*vbuf);

    new_vbuf = (vbuf_t *)malloc(new_size);

    if(!new_vbuf) return NULL;

    new_vbuf->start = (char*)(new_vbuf+1);
    new_vbuf->pos = new_vbuf->start;
    new_vbuf->end = ((char*)new_vbuf)+new_size;

    /*copy old data to new vbuf*/

    memcpy(new_vbuf->start,vbuf->start,VBUF_SIZE(vbuf));

    VBUF_UPDATE(new_vbuf,VBUF_SIZE(vbuf));

    /*free old vbuf*/

    free(vbuf);

    return new_vbuf;
}

vbuf_t *create_vbuf(size_t size){
    size_t m_size;
    vbuf_t *vbuf;
    m_size = size<=sizeof(vbuf_t)?sizeof(vbuf_t)*2:size+sizeof(vbuf_t);
    
    vbuf = (vbuf_t*)malloc(m_size);

    if(vbuf == NULL) return NULL;

    vbuf->start = (char*)(vbuf+1);
    vbuf->pos = vbuf->start;
    vbuf->end = ((char*)vbuf)+m_size;

    return vbuf;
}

void destroy_vbuf(vbuf_t *vbuf){
    
    if(vbuf==NULL) return;

    free(vbuf);
}

#define  VALUE_WRITE(buf, value, byte_num)				\
	do {								                \
		size_t bytes=(byte_num)*8;				        \
		size_t i = 1;						            \
		for(i=1;i<=(byte_num);i++)				        \
		{							                    \
			buf[i-1]=(value)>>(bytes-i*8)&0xff;	        \
		}							                    \
	} while(0)

ngx_int_t 
write_bytes2_buf(vbuf_t *vbuf,unsigned char *bytes,size_t len)
{
    vbuf_t *rvbuf ;

    rvbuf = VBUF_FULL(vbuf,len)?expand_vbuf(vbuf):vbuf;
    
    if(rvbuf==NULL) return NGX_ERROR;
    
    memcpy(rvbuf->pos,bytes,len);

    VBUF_UPDATE(rvbuf,len);
    
    return NGX_OK;
}

/*vbuf write functions*/
ngx_int_t vbuf_write_bytes(vbuf_t *vbuf,void *data,size_t data_size)
{
    ngx_int_t rc = vbuf_write_size(vbuf,data_size);
    if(rc!=NGX_OK) return rc;

    return write_bytes2_buf(vbuf,(unsigned char*)data,data_size);
}

ngx_int_t vbuf_write_str(vbuf_t *vbuf,const char *value)
{
    size_t len = strlen(value);
    ngx_int_t rc = vbuf_write_size(vbuf,len);
    if(rc!=NGX_OK) return rc;
    return write_bytes2_buf(vbuf,(unsigned char*)value,len);
}

ngx_int_t vbuf_write_nstr(vbuf_t *vbuf,char *value,size_t len){
    
    ngx_int_t rc = vbuf_write_size(vbuf,len);
    if(rc!=NGX_OK) return rc;
    return write_bytes2_buf(vbuf,(unsigned char*)value,len);
}

ngx_int_t vbuf_write_boolean(vbuf_t *vbuf,int v){
    
    unsigned char b_arr[1]={0};
    VALUE_WRITE(b_arr,v?1:0,1);

    return write_bytes2_buf(vbuf,b_arr,1);
}

ngx_int_t vbuf_write_short(vbuf_t *vbuf,short v){

       unsigned char b_arr[2]={0};
       VALUE_WRITE(b_arr,v,2);
       return write_bytes2_buf(vbuf,b_arr,2);
}

ngx_int_t vbuf_write_int(vbuf_t *vbuf,int v){

       unsigned char b_arr[4]={0};
       VALUE_WRITE(b_arr,v,4);
       return write_bytes2_buf(vbuf,b_arr,4);
}

ngx_int_t vbuf_write_long(vbuf_t *vbuf,long v){

	unsigned char b_arr[8]={0};
	VALUE_WRITE(b_arr,v,8);
	return write_bytes2_buf(vbuf,b_arr,8);
}

ngx_int_t vbuf_write_ushort(vbuf_t *vbuf,unsigned short v){

       unsigned char b_arr[2]={0};
       VALUE_WRITE(b_arr,v,2);
       return write_bytes2_buf(vbuf,b_arr,2);
}
    
ngx_int_t vbuf_write_uint(vbuf_t *vbuf,unsigned int v){
       unsigned char b_arr[4]={0};
       VALUE_WRITE(b_arr,v,4);
       return write_bytes2_buf(vbuf,b_arr,4);
}

ngx_int_t vbuf_write_ulong(vbuf_t *vbuf,unsigned long v)
{
	unsigned char b_arr[8]={0};
	VALUE_WRITE(b_arr,v,8);
	return write_bytes2_buf(vbuf,b_arr,8);
}

#define F_EXP_BIT_MASK	2139095040
#define F_SIGNIF_BIT_MASK  8388607
static inline int 
float2_raw_int_bits(float v)
{
	union{float f;int i;}u;
	u.f=v;
	int result=u.i;

	if (((result &F_EXP_BIT_MASK) ==F_EXP_BIT_MASK)\
	&&(result & F_SIGNIF_BIT_MASK) != 0)
	     	result = 0x7fc00000;

	return result;

}

#define D_EXP_BIT_MASK	9218868437227405312LL
#define D_SIGNIF_BIT_MASK  4503599627370495LL

static inline int64_t 
double2_raw_int_bits(double v)
{
	union{double d;int64_t i;}u;
	u.d=v;
	int64_t result=u.i;

	if (((result &D_EXP_BIT_MASK) ==D_EXP_BIT_MASK)\
	&&(result & D_SIGNIF_BIT_MASK) != 0LL)
	     	result = 0x7ff8000000000000LL;

	return result;
}

ngx_int_t vbuf_write_float(vbuf_t *vbuf,float v){

	return vbuf_write_int(vbuf,float2_raw_int_bits(v));
}

ngx_int_t vbuf_write_double(vbuf_t *vbuf,double v){

	return vbuf_write_int64(vbuf,double2_raw_int_bits(v));
}

ngx_int_t vbuf_write_int8(vbuf_t *vbuf,int8_t v){
    
       unsigned char b_arr[1]={0};
       VALUE_WRITE(b_arr,v,1);
       return write_bytes2_buf(vbuf,b_arr,1);
}

ngx_int_t vbuf_write_int16(vbuf_t *vbuf,int16_t v){

       unsigned char b_arr[2]={0};
       VALUE_WRITE(b_arr,v,2);
       return write_bytes2_buf(vbuf,b_arr,2);
}

ngx_int_t vbuf_write_int32(vbuf_t *vbuf,int32_t v){

       unsigned char b_arr[4]={0};
       VALUE_WRITE(b_arr,v,4);
       return write_bytes2_buf(vbuf,b_arr,4);
}

ngx_int_t vbuf_write_int64(vbuf_t *vbuf,int64_t v){

       unsigned char b_arr[8]={0};
       VALUE_WRITE(b_arr,v,8);
       return write_bytes2_buf(vbuf,b_arr,8);
}

ngx_int_t vbuf_write_uint8(vbuf_t *vbuf,uint8_t v){

       unsigned char b_arr[1]={0};
       VALUE_WRITE(b_arr,v,1);
       return write_bytes2_buf(vbuf,b_arr,1);
}

ngx_int_t vbuf_write_uint16(vbuf_t *vbuf,uint16_t v){

       unsigned char  b_arr[2]={0};
       VALUE_WRITE(b_arr,v,2);
       return write_bytes2_buf(vbuf,b_arr,2);
}

ngx_int_t vbuf_write_uint32(vbuf_t *vbuf,uint32_t v)
{

       unsigned char b_arr[4]={0};
       VALUE_WRITE(b_arr,v,4);
       return write_bytes2_buf(vbuf,b_arr,4);
}

ngx_int_t vbuf_write_uint64(vbuf_t *vbuf,uint64_t v)
{

       unsigned char b_arr[8]={0};
       VALUE_WRITE(b_arr,v,8);
       return write_bytes2_buf(vbuf,b_arr,8);
}

ngx_int_t vbuf_write_size(vbuf_t *vbuf,size_t v){

	size_t b_num=sizeof(size_t);
	unsigned char b_arr[sizeof(size_t)]={0};
	VALUE_WRITE(b_arr,v,b_num);
	return write_bytes2_buf(vbuf,b_arr,b_num);
}

ngx_int_t vbuf_write_ssize(vbuf_t *vbuf,ssize_t v)
{

	size_t b_num=sizeof(ssize_t);
	unsigned char b_arr[sizeof(ssize_t)]={0};
	VALUE_WRITE(b_arr,v,b_num);
	return write_bytes2_buf(vbuf,b_arr,b_num);
}

ngx_int_t vbuf_write_off(vbuf_t *vbuf,off_t v){

	size_t b_num=sizeof(off_t);
	unsigned char b_arr[sizeof(off_t)]={0};
	VALUE_WRITE(b_arr,v,b_num);
	return write_bytes2_buf(vbuf,b_arr,b_num);
}

ngx_int_t vbuf_write_rwable(vbuf_t *vbuf,ele_rwable_t *elem)
{
    if(!vbuf||!elem||!elem->write) return NGX_ERROR;

    return elem->write(vbuf,elem);
}

/*vbuf read functions*/
#define VALUE_READ(buf, value, byte_num)		 \
do{	     						                 \
	size_t i=1;					                 \
	size_t bytes=(byte_num)*8;			         \
	unsigned char b;					         \
	char *p = buf;                               \
    for (i=1; i<=byte_num; i++)			         \
	{						                     \
		b=*((unsigned char*)p); 			     \
		p+=1;					                 \
		(value) += (b<<((bytes-i*8) &0xFF));	 \
	}						                     \
} while(0)


void vbuf_read_skip_bytes(vbuf_t *vbuf,size_t len)
{
	size_t r_size=len;
	if(VBUF_FULL(vbuf,len))
	{
		r_size = VBUF_EMPTY_SIZE(vbuf);	
	}

    VBUF_UPDATE(vbuf,r_size);
}

void vbuf_read_bytes(vbuf_t *vbuf,void **data,size_t *data_len)
{

    *data_len = vbuf_read_size(vbuf);
    *data = (void*)vbuf->pos;
    vbuf_read_skip_bytes(vbuf,*data_len);
}

void vbuf_read_str(vbuf_t *vbuf,char **data,size_t *data_len)
{
    *data_len = vbuf_read_size(vbuf);
    *data = vbuf->pos;
    vbuf_read_skip_bytes(vbuf,*data_len);
}

int  vbuf_read_boolean(vbuf_t *vbuf)
{
    int v = 0;
    VALUE_READ(vbuf->pos,v,1);
    vbuf_read_skip_bytes(vbuf,1);
    return v;
}

short vbuf_read_short(vbuf_t *vbuf)
{
    
    short v = 0;
    VALUE_READ(vbuf->pos,v,2);
    vbuf_read_skip_bytes(vbuf,2);
    return v;
}

int vbuf_read_int(vbuf_t *vbuf)
{
    int v = 0;
    VALUE_READ(vbuf->pos,v,4);
    vbuf_read_skip_bytes(vbuf,4);
    return v;
}

long vbuf_read_long(vbuf_t *vbuf)
{

    long v = 0;
    VALUE_READ(vbuf->pos,v,8);
    vbuf_read_skip_bytes(vbuf,8);
    return v;
}   

unsigned short vbuf_read_ushort(vbuf_t *vbuf)
{

    unsigned short v = 0;
    VALUE_READ(vbuf->pos,v,2);
    vbuf_read_skip_bytes(vbuf,2);
    return v;
}

unsigned int vbuf_read_uint(vbuf_t *vbuf){

    unsigned int v = 0;
    VALUE_READ(vbuf->pos,v,4);
    vbuf_read_skip_bytes(vbuf,4);
    return v;
}

unsigned long  vbuf_read_ulong(vbuf_t *vbuf)
{

    unsigned long v = 0;
    VALUE_READ(vbuf->pos,v,8);
    vbuf_read_skip_bytes(vbuf,8);
    return v;
}

float  vbuf_read_float(vbuf_t *vbuf)
{

	union{float f;int i;}u;
    
    u.i = vbuf_read_int(vbuf); 
    
    return u.f;
}  

double  vbuf_read_double(vbuf_t *vbuf){

	union{double d;int64_t i;}u;
    
    u.i = vbuf_read_int64(vbuf);

    return u.d;
}

int8_t vbuf_read_int8(vbuf_t *vbuf){
    
    int8_t v = 0;
    VALUE_READ(vbuf->pos,v,1);
    vbuf_read_skip_bytes(vbuf,1);
    return v;
}

int16_t  vbuf_read_int16(vbuf_t *vbuf)
{ 
    int16_t v = 0;
    VALUE_READ(vbuf->pos,v,2);
    vbuf_read_skip_bytes(vbuf,2);
    return v;
}

int32_t  vbuf_read_int32(vbuf_t *vbuf)
{
    
    int32_t v = 0;
    VALUE_READ(vbuf->pos,v,4);
    vbuf_read_skip_bytes(vbuf,4);
    return v;
}

int64_t  vbuf_read_int64(vbuf_t *vbuf){


    int64_t v = 0;
    VALUE_READ(vbuf->pos,v,8);
    vbuf_read_skip_bytes(vbuf,8);
    return v;
}

uint8_t  vbuf_read_uint8(vbuf_t *vbuf)
{

    uint8_t v = 0;
    VALUE_READ(vbuf->pos,v,1);
    vbuf_read_skip_bytes(vbuf,1);
    return v;
}

uint16_t  vbuf_read_uint16(vbuf_t *vbuf)
{

    uint16_t v = 0;
    VALUE_READ(vbuf->pos,v,2);
    vbuf_read_skip_bytes(vbuf,2);
    return v;
}

uint32_t  vbuf_read_uint32(vbuf_t *vbuf)
{

    uint32_t v = 0;
    VALUE_READ(vbuf->pos,v,4);
    vbuf_read_skip_bytes(vbuf,4);
    return v;
}

uint64_t  vbuf_read_uint64(vbuf_t *vbuf)
{

    uint64_t v = 0;
    VALUE_READ(vbuf->pos,v,8);
    vbuf_read_skip_bytes(vbuf,8);
    return v;
}

size_t vbuf_read_size(vbuf_t *vbuf)
{
    
    size_t v = 0;
    VALUE_READ(vbuf->pos,v,sizeof(size_t));
    vbuf_read_skip_bytes(vbuf,sizeof(size_t));
    return v;
}

ssize_t vbuf_read_ssize(vbuf_t *vbuf)
{
    
    ssize_t v = 0;
    VALUE_READ(vbuf->pos,v,sizeof(ssize_t));
    vbuf_read_skip_bytes(vbuf,sizeof(ssize_t));
    return v;
}

off_t  vbuf_read_off(vbuf_t *vbuf)
{
    
    off_t v = 0;
    VALUE_READ(vbuf->pos,v,sizeof(off_t));
    vbuf_read_skip_bytes(vbuf,sizeof(off_t));
    return v;
}

ngx_int_t vbuf_read_rwable(vbuf_t *vbuf,ele_rwable_t *elem)
{

    if(!vbuf||!elem||!elem->read) return NGX_ERROR;

    return elem->read(vbuf,elem);
}

