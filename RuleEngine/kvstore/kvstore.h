/*
 * =====================================================================================
 *      Copyright (C) 2014 jianfeng sha
 *
 *      Filename:  kvstore.h
 *
 *      Description:  
 *
 *      Created:  11/17/14 10:23:03
 *
 *      Author:  jianfeng sha , csp001314@163.com
 * =====================================================================================
 */
#ifndef __KVSTORE_H__
#define __KVSTORE_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <sqlite3.h>
#include "kvstore/list.h"
#include "kvstore/vbuf.h"
#define MAX_HASH_SIZE          64
#define KVTABLE_ROW_FLAG       (int8_t)0xfe

#define KVTABLE_COLUMN_DEFAULT      "__kvtable_column_null"
#define KVTABLE_KEY_SCHEMA          "__kvtable_key_entry" 
#define KVTABLE_KV_SCHEMA           "__kvtable_kv_entry"
#define KVTABLE_KV_METADATA_SCHEMA  "__kvtable_kv_metadata"

typedef struct kvstore_t kvstore_t;
typedef struct kvtable_t kvtable_t;
typedef struct kvtable_column_t kvtable_column_t;
typedef struct kvtable_kv_entry_t kvtable_kv_entry_t;

struct kvstore_t {
    ngx_pool_t *pool;
    ngx_str_t  dbname;
    sqlite3 *sqlitdb;
    struct hlist_head tables[MAX_HASH_SIZE];
    kvtable_t *cur_table;
    size_t table_n;
};

struct kvtable_t {
    struct hlist_node tabnode;
    ngx_pool_t *pool;
    kvstore_t *kvstore;
    ngx_str_t tabname;
    struct hlist_head columns[MAX_HASH_SIZE];
    kvtable_column_t *cur_column;
    size_t column_n;
};

struct kvtable_column_t {
    struct hlist_node colnode; 
    ngx_pool_t *pool;
    kvtable_t *kvtab;
    ngx_str_t column_name;
    vbuf_t *vbuf;
};

struct kvtable_kv_entry_t {
    void *key_data;
    void *val_data;
    void *data;
    vbuf_t *vbuf;
    ngx_int_t (*write_key)(kvtable_column_t *column,void *data,vbuf_t *vbuf,void *key_data);
    
    ngx_int_t (*write_val)(kvtable_column_t *column,void *data,vbuf_t *vbuf,void *val_data);
    
    ngx_int_t (*read_key)(kvtable_column_t *column,void *data,vbuf_t *vbuf,void *key_data,size_t k_size);

    ngx_int_t (*read_val)(kvtable_column_t *column,void *data,vbuf_t *vbuf,void *val_data,size_t v_size);
    
    ngx_int_t (*scan)(kvtable_column_t *column,void*data,void *key,void *val);
};



kvstore_t * do_open_kvstore(ngx_pool_t *p,const char *dbname,char ** errmsg);
void close_kvstore(kvstore_t *kvstore);

ngx_int_t do_create_kvtable(kvstore_t *kvstore,const char *tabname,const char **columns,char **errmsg);

void do_drop_kvtable(kvstore_t *kvstore,const char *tabname);

void do_drop_kvtable_column(kvstore_t *kvstore,const char *tabname,const char *column_name);


ngx_int_t do_kvtable_insert(kvstore_t *kvstore,const char *tabname,const char *column_name,kvtable_kv_entry_t *kv_entry,char **errmsg);

ngx_int_t  do_kvtable_del(kvstore_t *kvstore,const char *tabname,const char *column_name,kvtable_kv_entry_t *kv_entry,char **errmsg);

ngx_int_t  do_kvtable_scan(kvstore_t *kvstore,const char *tabname,const char *column_name,kvtable_kv_entry_t *kv_entry,char **errmsg);

void *do_kvtable_find(kvstore_t *kvstore,const char *tabname,const char *column_name,kvtable_kv_entry_t *kv_entry,char **errmsg);

#endif /*__KVSTORE_H__ */
