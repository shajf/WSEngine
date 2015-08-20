/*
 * =====================================================================================
 *      Copyright (C) 2014 jianfeng sha
 *
 *      Filename:  sqlite_test.c
 *
 *      Description:  
 *
 *      Created:  11/13/14 18:01:18
 *
 *      Author:  jianfeng sha , csp001314@163.com
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include "vbuf.h"

typedef struct {
    
    ele_rwable_t elem;
    char *name;
    char *val;
    int bool_v;
    int iv;
    unsigned int uiv;
    long lv;
    unsigned long ulv;
    float fv;
    double dv;
    int64_t i64v;
    uint64_t ui64v;
}per_data_t;

static ngx_int_t data_write(vbuf_t *vbuf,ele_rwable_t *elem){
    
    per_data_t *data = (per_data_t*)elem;

    vbuf_write_str(vbuf,data->name);

    vbuf_write_str(vbuf,data->val);

    vbuf_write_boolean(vbuf,data->bool_v);

    vbuf_write_int(vbuf,data->iv);

    vbuf_write_uint(vbuf,data->uiv);

    vbuf_write_long(vbuf,data->lv);

    vbuf_write_ulong(vbuf,data->ulv);

    vbuf_write_float(vbuf,data->fv);

    vbuf_write_double(vbuf,data->dv);

    vbuf_write_int64(vbuf,data->i64v);
    
    vbuf_write_uint64(vbuf,data->ui64v);

    return 0;
}

static ngx_int_t data_read(vbuf_t *vbuf,ele_rwable_t *elem)
{
    size_t len;
    per_data_t *data = (per_data_t*)elem;
    
    vbuf_read_str(vbuf,&data->name,&len);

    vbuf_read_str(vbuf,&data->val,&len);

    data->bool_v = vbuf_read_boolean(vbuf);

    data->iv= vbuf_read_int(vbuf);

    data->uiv = vbuf_read_uint(vbuf);

    data->lv = vbuf_read_long(vbuf);

    data->ulv = vbuf_read_ulong(vbuf);

    data->fv = vbuf_read_float(vbuf);

    data->dv = vbuf_read_double(vbuf);

    data->i64v = vbuf_read_int64(vbuf);
    
    data->ui64v = vbuf_read_uint64(vbuf);
    
    return 0;
}

vbuf_t* test_vbuf(){
    
    per_data_t data,*data_ptr = &data;
    
    data_ptr->elem.write = data_write;
    data_ptr->elem.read = data_read;

    
    data_ptr->name = "__table_name";
    data_ptr->val = "__table_value";
    data_ptr->bool_v =1; 
    data_ptr->iv = -123456;
    data_ptr->uiv = 123456;
    data_ptr->lv = -88888;
    data_ptr->ulv = 88888;
    
    data_ptr->fv = -3.1415926;
    data_ptr->dv = 3.14;
    data_ptr->i64v = 4614253070214989087;
    data_ptr->ui64v = 12345666;

    vbuf_t *vbuf = create_vbuf(1024);
    
    vbuf_write_rwable(vbuf,data_ptr);
    
    //VBUF_RESET(vbuf);

   // vbuf_read_rwable(vbuf,rdata_ptr);
   
   return vbuf;

}

static void test_sqlite_query()
{
	
    per_data_t rdata,*rdata_ptr = &rdata;
	sqlite3 *pdb;
	sqlite3_stmt *stmt;
	char *errmsg;
	const char *query_sql = "select * from __tables";
	const void *data;
	size_t data_len;

	rdata_ptr->elem.write = data_write;
    rdata_ptr->elem.read = data_read;
	

    vbuf_t vbuf;
	
	sqlite3_open("sqlite3.db",&pdb);

	sqlite3_prepare(pdb,query_sql,strlen(query_sql),&stmt,&errmsg);

	sqlite3_step(stmt);
	
	data = sqlite3_column_blob(stmt,1);
	data_len = sqlite3_column_bytes(stmt,1);

	vbuf.start = (char*)data;
	vbuf.pos = vbuf.start;
	vbuf.end = vbuf.start+data_len;

	vbuf_read_rwable(&vbuf,rdata_ptr);

	sqlite3_finalize(stmt);
	sqlite3_close(pdb);

}

static void test_sqlite_insert(){
	
	const char *create_sql = "create table __tables (key varchars(10),value BLOB)";
	const char *insert_sql = "insert into __tables  values('value1',:qqq)";
	char *errmsg;
	int index;
	sqlite3 *pdb;
	sqlite3_stmt *stmt;
	
	vbuf_t *vbuf = test_vbuf();

	sqlite3_open("sqlite3.db",&pdb);

	sqlite3_exec(pdb,create_sql,NULL,NULL,&errmsg);
	
	sqlite3_prepare(pdb,insert_sql,strlen(insert_sql),&stmt,&errmsg);
	
	index = sqlite3_bind_parameter_index(stmt,":qqq");

	sqlite3_bind_blob(stmt,index,(const void*)vbuf->start,VBUF_CONTENT_SIZE(vbuf),SQLITE_STATIC);
	
	sqlite3_step(stmt);
	
	sqlite3_close(pdb);
	destroy_vbuf(vbuf);
}

int main(int argc,char **argv)
{
    test_sqlite_insert();
	test_sqlite_query();
}
