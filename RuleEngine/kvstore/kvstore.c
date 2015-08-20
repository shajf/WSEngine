/*
 * =====================================================================================
 *      Copyright (C) 2014 jianfeng sha
 *
 *      Filename:  kvstore.c
 *
 *      Description:  
 *
 *      Created:  11/17/14 10:23:15
 *
 *      Author:  jianfeng sha , csp001314@163.com
 *
 * =====================================================================================
 */
#include <ngx_md5.h>
#include "kvstore.h"

#define KVSTORE_SQLITE_METADATA_TABLE   "__kvstore_metadata_table"
#define KVSTORE_SQLITE_METADATA_SCHEMA  "create table if not exists __kvstore_metadata_table (dbname text,tabname text,colname text,primary key(dbname,tabname,colname))"

static size_t str_hash(const char *str)
{
    size_t hash = 0; 
    size_t  x = 0;
    
    while (*str)
    {
        hash = (hash << 4) + (*str++);  
        if ((x = hash & 0xF0000000L) != 0)
        {
            hash ^= (x >> 24);
            hash &= ~x;
        }
    }
    return (hash & 0x7FFFFFFF)%MAX_HASH_SIZE;
}

static ngx_int_t insert_to_metadata_table(kvtable_column_t *column){
    
    char *errmsg;

    kvstore_t *kvstore = column->kvtab->kvstore;
    kvtable_t *kvtab = column->kvtab;

    ngx_pool_t *p = kvstore->pool;
    sqlite3 *pdb =  kvstore->sqlitdb;

    const char *sql = ngx_psprintf(p,
            ngx_strlen("insert into %s values (%s,%s,%s)")+ngx_strlen(KVSTORE_SQLITE_METADATA_TABLE)+kvstore->dbname.len+kvtab->tabname.len+column->column_name.len+10,
            "insert into %s values (%s,%s,%s)",
            KVSTORE_SQLITE_METADATA_TABLE,
            kvstore->dbname.data,
            kvtab->tabname.data,
            column->column_name.data);

    int rc = sqlite3_exec(pdb,sql,NULL,NULL,&errmsg);

    if(rc!=SQLITE_OK){
        if(errmsg){
            sqlite3_free(errmsg);
        }
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t del_metadata_table(kvtable_column_t *column){

    char *errmsg;

    kvstore_t *kvstore = column->kvtab->kvstore;
    kvtable_t *kvtab = column->kvtab;

    ngx_pool_t *p = kvstore->pool;
    sqlite3 *pdb =  kvstore->sqlitdb;
    
    size_t tt_size=10;
    tt_size+=ngx_strlen("delete from %s where dbname=%s and tabname=%s and colname=%s");
    tt_size+=ngx_strlen(KVSTORE_SQLITE_METADATA_TABLE);
    tt_size+=kvstore->dbname.len;
    tt_size+=kvtab->tabname.len;
    tt_size+=column->column_name.len;

    const char *sql = ngx_psprintf(p,tt_size,
            "delete from %s where dbname=%s and tabname=%s and colname=%s",
            KVSTORE_SQLITE_METADATA_TABLE,
            kvstore->dbname.data,
            kvtab->tabname.data,
            column->column_name.data);

    int rc = sqlite3_exec(pdb,sql,NULL,NULL,&errmsg);

    if(rc!=SQLITE_OK){
        if(errmsg){
            sqlite3_free(errmsg);
        }
        return NGX_ERROR;
    }
    return NGX_OK;
}

static kvtable_t *get_table(kvstore_t *kvstore,const char *name){
    
    kvtable_t *kvtab = kvstore->cur_table;
    size_t hash,len;
    struct hlist_node *p;
    len = ngx_strlen(name);
	
    if(kvtab&&len==kvtab->tabname.len&&ngx_strncmp(name,kvtab->tabname.data,kvtab->tabname.len)==0)
    {
        return kvtab;
    }
    
    hash = str_hash(name);
    
    hlist_for_each_entry(kvtab,p,&kvstore->tables[hash],tabnode){
       
	if(len!=kvtab->tabname.len) continue;
	
	if(ngx_strncmp(name,kvtab->tabname.data,kvtab->tabname.len)==0) return kvtab;	
    }
    
    return NULL;
} 

static void add_column_to_table(kvtable_t *kvtab,kvtable_column_t *column,const char *name){

    size_t hash = str_hash(name);
    hlist_add_head(&column->colnode,&kvtab->columns[hash]); 
    kvtab->column_n+=1;
}

static void add_kvtab_to_kvstore(kvstore_t *kvstore,kvtable_t *kvtab,const char *name){

    size_t hash = str_hash(name);
    hlist_add_head(&kvtab->tabnode,&kvstore->tables[hash]); 
    kvstore->table_n +=1;
}

static kvtable_column_t *get_column(kvtable_t *kvtab,const char *name){
    kvtable_column_t *column = kvtab->cur_column;
    size_t hash,len;
    struct hlist_node *p;
    len = ngx_strlen(name);
	
    if(column&&len==column->column_name.len&&ngx_strncmp(name,column->column_name.data,column->column_name.len)==0)
    {
        return column;
    }
    
    hash = str_hash(name);
    
    hlist_for_each_entry(column,p,&kvtab->columns[hash],colnode){
       
	if(len!=column->column_name.len) continue;
	
	if(ngx_strncmp(name,column->column_name.data,column->column_name.len)==0) return column;	
    }
    
    return NULL;
}

static kvtable_column_t *create_column(kvtable_t *kvtab,const char *name){
     int rc; 
     char *errmsg=NULL;

     kvtable_column_t *column = (kvtable_column_t*)ngx_palloc(kvtab->pool,sizeof(kvtable_column_t));
     if(!column) return NULL;
     
     const char *sql = ngx_psprintf(kvtab->pool,
              ngx_strlen("create table if not exists ( text primary key, BLOB)")+ngx_strlen(name)+ngx_strlen(KVTABLE_KEY_SCHEMA)+ngx_strlen(KVTABLE_KV_SCHEMA)+10,
             "create table if not exists %s (%s text primary key,%s BLOB)",name,KVTABLE_KEY_SCHEMA,KVTABLE_KV_SCHEMA);
     
     rc = sqlite3_exec(kvtab->kvstore->sqlitdb,sql,NULL,NULL,&errmsg);
     if(rc!=SQLITE_OK){
        if(errmsg){
            sqlite3_free(errmsg);
        }
        return NULL;
     }

     column->vbuf = create_vbuf(512);

     if(!column->vbuf){
        return NULL;
     }

     column->pool = kvtab->pool;
     column->kvtab = kvtab;
     column->column_name.data = (u_char*)ngx_pstrndup(column->pool,name);
     column->column_name.len = ngx_strlen(column->column_name.data);
     add_column_to_table(kvtab,column,name);
     
     return column;
}

static kvtable_t *create_kvtable(kvstore_t *kvstore,const char *name){
     
     int i;
     kvtable_t *kvtab = (kvtable_t *)ngx_palloc(kvstore->pool,sizeof(kvtable_t));
     
     if(!kvtab) return NULL;
     kvtab->pool = kvstore->pool;
     kvtab->kvstore = kvstore;
     kvtab->tabname.data = (u_char*)ngx_pstrndup(kvtab->pool,name);
     kvtab->tabname.len = ngx_strlen(kvtab->tabname.data);
     kvtab->cur_column = NULL;
     kvtab->column_n = 0;
     for(i=0;i<MAX_HASH_SIZE;i++){
        INIT_HLIST_HEAD(&kvtab->columns[i]);	
     }
     add_kvtab_to_kvstore(kvstore,kvtab,name);
     return kvtab;
}

static int kvstore_metadata_callback(void *data,int argc,char **argv,char **col){
    
    char *dbname,*tabname,*colname;

    kvstore_t *kvstore = (kvstore_t *)data;
    kvtable_t *kvtab;
    kvtable_column_t *column;
	
    if(argc!=3) return -1;

    dbname = argv[0];
    tabname = argv[1];
    colname = argv[2];
    if(ngx_strncmp(dbname,kvstore->dbname.data,kvstore->dbname.len)!=0) return -1;
    
    kvtab = get_table(kvstore,tabname);
    
    if(kvtab == NULL){
	kvtab = create_kvtable(kvstore,tabname);
	if(!kvtab) return -1;
	column = create_column(kvtab,colname);
	if(!column) return -1;
    }

    else{ //table has existed
   	 column = get_column(kvtab,colname);
         if(!column){
		column = create_column(kvtab,colname);
		if(!column) return -1;
	}
   }
   return 0;
}

static int load_all_tables(kvstore_t *kvstore,const char *dbname){
    int rc;
    const char *sql = "select * from __kvstore_metadata_table";
    char *errmsg = NULL;

    rc = sqlite3_exec(kvstore->sqlitdb,sql,kvstore_metadata_callback,(void*)kvstore,&errmsg);  
    if(rc!=SQLITE_OK){
	if(errmsg){
	    sqlite3_free(errmsg);
	}
	return -1;
    }

    return 0;
}

kvstore_t * do_open_kvstore(ngx_pool_t *p,const char *dbname,char ** errmsg){
    
    kvstore_t *kvstore;
    int rc;
    int i;

    kvstore = (kvstore_t*)ngx_palloc(p,sizeof(kvstore_t));

    if(!kvstore){
        *errmsg = ngx_pstrcat(p,"no memory to open kvstore:",dbname,NULL);
        return NULL;
    }
    
    for(i=0;i<MAX_HASH_SIZE;i++){
        
        INIT_HLIST_HEAD(&kvstore->tables[i]);
    }

    rc = sqlite3_open(dbname,&kvstore->sqlitdb);

    if(rc!=SQLITE_OK||kvstore->sqlitdb == NULL){
        *errmsg = ngx_pstrcat(p,"cannot open kvstore db:",dbname,NULL);
        sqlite3_close(kvstore->sqlitdb);
        return NULL;
    }

    rc = load_all_tables(kvstore,dbname);

    if(rc!=0){
        *errmsg = ngx_pstrndup(p,"load kvstore's tables failed!");
        sqlite3_close(kvstore->sqlitdb);
        return NULL;
    }

    kvstore->pool = p;
    kvstore->dbname.data = (u_char*)ngx_pstrndup(p,dbname);
    kvstore->dbname.len = ngx_strlen(kvstore->dbname.data);
    kvstore->cur_table = NULL;

    return kvstore;
}

ngx_int_t do_create_kvtable(kvstore_t *kvstore,const char *tabname,const char **columns,char **errmsg){
    kvtable_t *kvtab;
    int i=0;
    const char *colname;
    kvtable_column_t *column;
    
    kvtab = get_table(kvstore,tabname);
    if(!kvtab){
        kvtab = create_kvtable(kvstore,tabname);
        if(!kvtab){
            *errmsg = ngx_pstrndup(kvstore->pool,"do_create_kvtable::create kvtable failed!");
             return NGX_ERROR;
        }
    }
    if(columns==NULL||columns[0]==NULL){
        column = get_column(kvtab,KVTABLE_COLUMN_DEFAULT);
        if(!column){
            column = create_column(kvtab,KVTABLE_COLUMN_DEFAULT);
            if(!column){
                *errmsg = ngx_pstrcat(kvstore->pool,"do_create_kvtable::create column:",KVTABLE_COLUMN_DEFAULT,NULL);
                return NGX_ERROR;
            }
            
            if(insert_to_metadata_table(column)!=NGX_OK){
                *errmsg = ngx_pstrndup(kvstore->pool,"do_create_kvtable::insert into metatable error!");
                return NGX_ERROR;
            }
        }
        return NGX_OK;
    }

    while(columns[i]){
        colname = columns[i++];
        column = get_column(kvtab,colname);
        if(!column){
             column = create_column(kvtab,colname);
             if(!column){
             *errmsg = ngx_pstrcat(kvstore->pool,"do_create_kvtable::create column:",colname,NULL);
              return NGX_ERROR;
             }

            if(insert_to_metadata_table(column)!=NGX_OK){
                *errmsg = ngx_pstrndup(kvstore->pool,"do_create_kvtable::insert into metatable error!");
                return NGX_ERROR;
            }
        }
    }
    return NGX_OK;	
}

static void del_a_column(kvtable_t *kvtab,kvtable_column_t *column){
    const char *sql;
    char *errmsg;

    hlist_del(&column->colnode);
    kvtab->column_n -=1;
    sql = (const char*)ngx_psprintf(kvtab->pool,column->column_name.len+11+2,"drop table %s",column->column_name.data);

    sqlite3_exec(kvtab->kvstore->sqlitdb,sql,NULL,NULL,&errmsg);
    
    del_metadata_table(column);

    destroy_vbuf(column->vbuf);
}

void do_drop_kvtable(kvstore_t *kvstore,const char *tabname){
    kvtable_column_t *column;
    struct hlist_node *p;
    int i;

    kvtable_t *kvtab = get_table(kvstore,tabname);
    if(!kvtab) return;
    
    for(i=0;i<MAX_HASH_SIZE;i++){

        hlist_for_each_entry(column,p,&kvtab->columns[i],colnode){

            del_a_column(kvtab,column);
        }
    }

    hlist_del(&kvtab->tabnode);
    kvstore->table_n -=1;
}

void do_drop_kvtable_column(kvstore_t *kvstore,const char *tabname,const char *column_name){
    
    kvtable_t *kvtab;
    kvtable_column_t *column;

    kvtab = get_table(kvstore,tabname);

    if(!kvtab) return;
    
    column = get_column(kvtab,column_name);

    if(!column) return;

    del_a_column(kvtab,column);
}

static void get_key_id(char *result,const void *data,size_t size){
    ngx_md5_t ctx,*ctx_ptr = &ctx;
    
    ngx_md5_init(ctx_ptr);

    ngx_md5_update(ctx_ptr,data,size);

    ngx_md5_final((unsigned char*)result,ctx_ptr);
}

static ngx_int_t do_insert_sqlite(kvtable_column_t *column,char *key,const void *kv_entry,size_t kv_entry_size,char **errmsg){
    ngx_pool_t * p = column->pool;
    sqlite3 *pdb = column->kvtab->kvstore->sqlitdb;
    sqlite3_stmt *stmt;
    int index;
    int rc;
    const char *ptail;

    const char *sql = (const char*)ngx_psprintf(p,
            ngx_strlen("insert into  values (,:kvdata)")+ngx_strlen(key)+column->column_name.len+10,
            "insert into %s values (%s,:kvdata)",column->column_name.data,key);

    rc = sqlite3_prepare_v2(pdb,sql,ngx_strlen(sql),&stmt,&ptail);

    if(rc!=SQLITE_OK){
        const char *emsg = sqlite3_errmsg(pdb);
        *errmsg = ngx_psprintf(p,
                ngx_strlen("compile sql statement error,")+ngx_strlen(emsg)+2,"compile sql statement error,%s",emsg); 
        return NGX_ERROR;
    }
    
    index = sqlite3_bind_parameter_index(stmt,":kvdata");

    if(index == 0){
        *errmsg = ngx_pstrndup(p,"bind parameter index error"); 
        return NGX_ERROR;
    }

    rc = sqlite3_bind_blob(stmt,index,kv_entry,kv_entry_size,SQLITE_STATIC);

    if(rc!=SQLITE_OK){
        const char *emsg = sqlite3_errmsg(pdb);
        *errmsg = ngx_psprintf(p,
                ngx_strlen("bind sql statement error,")+ngx_strlen(emsg)+2,"bind sql statement error,%s",emsg); 
        return NGX_ERROR;
    }

    rc = sqlite3_step(stmt);

    if(rc!=SQLITE_DONE){
        
        *errmsg = ngx_pstrndup(p,"insert kv entry error");
        return NGX_ERROR;
    }
    
    sqlite3_finalize(stmt);

    return NGX_OK;
}

static ngx_int_t get_table_column(kvstore_t *kvstore,const char *tabname,const char *column_name,kvtable_t **kvtab,kvtable_column_t **column,char **errmsg){

    if(column_name == NULL){
        column_name = KVTABLE_COLUMN_DEFAULT; 
    }

    *kvtab = get_table(kvstore,tabname);
    if(!(*kvtab)){
        *errmsg = ngx_psprintf(kvstore->pool,
                ngx_strlen("table  not existed.")+ngx_strlen(tabname)+2,
                "table %s not existed.",tabname);
        return NGX_ERROR;
    }
    *column = get_column(*kvtab,column_name);

    if(!(*column)){
    
        *errmsg = ngx_psprintf(kvstore->pool,
                ngx_strlen("column  not existed.")+ngx_strlen(column_name)+2,
                "column %s not existed.",column_name);
        return NGX_ERROR;
    }
    
    return NGX_OK;
}

ngx_int_t do_kvtable_insert(kvstore_t *kvstore,const char *tabname,const char *column_name,kvtable_kv_entry_t *kv_entry,char **errmsg){
    
    kvtable_t *kvtab;
    kvtable_column_t *column;
    char result[16] = {0};
    size_t k_size = 0,kv_size=0,header_size=0;
    ngx_int_t status;
    vbuf_t *vbuf;

    status = get_table_column(kvstore,tabname,column_name,&kvtab,&column,errmsg);
    
    if(status!=NGX_OK) return NGX_ERROR;

    if(!kv_entry||!kv_entry->key_data||!kv_entry->write_key){
        *errmsg = ngx_pstrndup(kvstore->pool,"invalid kv entry!");
        return NGX_ERROR;
    }
    
    vbuf = column->vbuf;
    VBUF_RESET(vbuf);

    header_size = 1+sizeof(size_t)*2;

    vbuf_read_skip_bytes(vbuf,header_size);
    
    status = kv_entry->write_key(column,kv_entry->data,vbuf,kv_entry->key_data);

    if(status!=NGX_OK){
        *errmsg = ngx_pstrndup(kvstore->pool,"write key entry failed!");
        return NGX_ERROR;
    }
    
    k_size = VBUF_CONTENT_SIZE(vbuf)-header_size;
    
    get_key_id(result,(const void *)(vbuf->start+header_size),k_size);
    
    if(kv_entry->val_data&&kv_entry->write_val){
       
        status = kv_entry->write_val(column,kv_entry->data,vbuf,kv_entry->val_data);

        if(status!=NGX_OK){
            
            *errmsg = ngx_pstrndup(kvstore->pool,"write value entry failed!");
            return NGX_ERROR;
        }
    }
    
    kv_size = VBUF_CONTENT_SIZE(vbuf)-header_size;
    
    /*write header flag,kv_size,k_size*/
    VBUF_RESET(vbuf);
    vbuf_write_int8(vbuf,KVTABLE_ROW_FLAG);
    vbuf_write_size(vbuf,kv_size);
    vbuf_write_size(vbuf,k_size);
    
    return do_insert_sqlite(column,result,(const void*)vbuf->start,VBUF_CONTENT_SIZE(vbuf),errmsg);
}

ngx_int_t  do_kvtable_del(kvstore_t *kvstore,const char *tabname,const char *column_name,kvtable_kv_entry_t *kv_entry,char **errmsg)
{
    
    ngx_int_t status;
    kvtable_t *kvtab;
    kvtable_column_t *column;
    size_t k_size;
    char result[16]={0};
    int rc;
    vbuf_t *vbuf;
    char *sqlerrmsg;

    status = get_table_column(kvstore,tabname,column_name,&kvtab,&column,errmsg);
    
    if(status!=NGX_OK) return NGX_ERROR;

    if(!kv_entry||!kv_entry->key_data||!kv_entry->write_key){
        *errmsg = ngx_pstrndup(kvstore->pool,"invalid kv entry!");
        return NGX_ERROR;
    }
    
    vbuf = column->vbuf;
    VBUF_RESET(vbuf);
    
    status = kv_entry->write_key(column,kv_entry->data,vbuf,kv_entry->key_data);

    if(status!=NGX_OK){
        *errmsg = ngx_pstrndup(kvstore->pool,"write key entry failed!");
        return NGX_ERROR;
    }
    
    k_size = VBUF_CONTENT_SIZE(vbuf);
    
    get_key_id(result,(const void *)(vbuf->start),k_size);

    const char *sql = ngx_psprintf(column->pool,
            ngx_strlen("delete from  where =")+ngx_strlen(KVTABLE_KEY_SCHEMA)+column->column_name.len+16+10,
            "delete from %s where %s=%s",column->column_name.data,KVTABLE_KEY_SCHEMA,result);

    
    rc = sqlite3_exec(kvstore->sqlitdb,sql,NULL,NULL,&sqlerrmsg);
    
    if(rc!=SQLITE_OK){
        
        *errmsg = ngx_pstrcat(column->pool,"delete failed:",sqlerrmsg,NULL);

        if(sqlerrmsg){
            sqlite3_free(sqlerrmsg);
        }
        return NGX_ERROR;
    }
    
    return NGX_OK;
}

static ngx_int_t read_a_val(kvtable_column_t *column,sqlite3_stmt *stmt,kvtable_kv_entry_t *kv_entry,char **errmsg){
    ngx_pool_t *pool = column->pool;
    vbuf_t vbuf;
    int8_t flag;
    size_t size,kv_size,k_size;
    ngx_int_t status;
    size_t header_size = 1+sizeof(size_t)*2;
    
    vbuf.start = (char*)sqlite3_column_blob(stmt,1);
    size = sqlite3_column_bytes(stmt,1);
    vbuf.pos = vbuf.start;
    vbuf.end = vbuf.start+size;

    flag = vbuf_read_int8(&vbuf);
    if(flag!=KVTABLE_ROW_FLAG){
        *errmsg = ngx_pstrndup(pool,"Invalid a row ,check header flag failed!");
        return NGX_ERROR;
    }
    
    kv_size = vbuf_read_size(&vbuf);
    k_size = vbuf_read_size(&vbuf);

    if(size!=kv_size+header_size){
        *errmsg = ngx_pstrndup(pool,"Invalid kvsize!");
        return NGX_ERROR;
    }
    
    vbuf_read_skip_bytes(&vbuf,k_size);

    status = kv_entry->read_val(column,kv_entry->data,&vbuf,kv_entry->val_data,kv_size-k_size);
    
    if(status!=NGX_ERROR){
        *errmsg = ngx_pstrndup(pool,"read value failed!");
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t read_a_row(kvtable_column_t *column,sqlite3_stmt *stmt,kvtable_kv_entry_t *kv_entry,char **errmsg){
    ngx_pool_t *pool = column->pool;
    vbuf_t vbuf;
    int8_t flag;
    size_t size,kv_size,k_size;
    ngx_int_t status;
    size_t header_size = 1+sizeof(size_t)*2;

    vbuf.start = (char*)sqlite3_column_blob(stmt,1);
    size = sqlite3_column_bytes(stmt,1);
    vbuf.pos = vbuf.start;
    vbuf.end = vbuf.start+size;

    flag = vbuf_read_int8(&vbuf);
    if(flag!=KVTABLE_ROW_FLAG){
        *errmsg = ngx_pstrndup(pool,"Invalid a row ,check header flag failed!");
        return NGX_ERROR;
    }
    
    kv_size = vbuf_read_size(&vbuf);
    k_size = vbuf_read_size(&vbuf);

    if(size!=kv_size+header_size){
        *errmsg = ngx_pstrndup(pool,"Invalid kvsize!");
        return NGX_ERROR;
    }
    
    status = kv_entry->read_key(column,kv_entry->data,&vbuf,kv_entry->key_data,k_size);
    
    if(status!=NGX_ERROR){
        *errmsg = ngx_pstrndup(pool,"read key failed!");
        return NGX_ERROR;
    }
    
    size = VBUF_CONTENT_SIZE(&vbuf);
    if(size!=k_size+header_size){
        vbuf.pos = vbuf.start+k_size+header_size;
    }

    status = kv_entry->read_val(column,kv_entry->data,&vbuf,kv_entry->val_data,kv_size-k_size);
    
    if(status!=NGX_ERROR){
        *errmsg = ngx_pstrndup(pool,"read value failed!");
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t do_kvtable_scan(kvstore_t *kvstore,const char *tabname,const char *column_name,kvtable_kv_entry_t *kv_entry,char **errmsg)
{
    ngx_int_t status;
    kvtable_t *kvtab;
    kvtable_column_t *column;
    int rc;
    sqlite3_stmt *stmt;
    const char *ptail;
    
    if(!kv_entry||!kv_entry->read_key||!kv_entry->read_val||!kv_entry->scan||!kv_entry->key_data||!kv_entry->val_data){
        *errmsg = "Invalid kv entry!";
        return NGX_ERROR;
    }

    status = get_table_column(kvstore,tabname,column_name,&kvtab,&column,errmsg);
    
    if(status!=NGX_OK) return NGX_ERROR;

    const char *sql = ngx_pstrcat(column->pool,"select * from ",column->column_name.data,NULL);
    
    rc = sqlite3_prepare_v2(kvstore->sqlitdb,sql,ngx_strlen(sql),&stmt,&ptail);

    if(rc!=SQLITE_OK){
        const char *emsg = sqlite3_errmsg(kvstore->sqlitdb);
        *errmsg = ngx_psprintf(kvstore->pool,
                ngx_strlen("compile sql statement error,")+ngx_strlen(emsg)+2,"compile sql statement error,%s",emsg); 
        return NGX_ERROR;
    }
    
    while(1){
       
        rc = sqlite3_step(stmt);
        if(rc!=SQLITE_ROW) break;
        
        status = read_a_row(column,stmt,kv_entry,errmsg);

        if(status!=NGX_OK){
            sqlite3_finalize(stmt);
            return NGX_ERROR;
        }

        status = kv_entry->scan(column,kv_entry->data,kv_entry->key_data,kv_entry->val_data);
        
        if(status!=NGX_OK) break;
    }
    sqlite3_finalize(stmt);

    return NGX_OK;
}

void * do_kvtable_find(kvstore_t *kvstore,const char *tabname,const char *column_name,kvtable_kv_entry_t *kv_entry,char **errmsg){

    ngx_int_t status;
    kvtable_t *kvtab;
    kvtable_column_t *column;
    int rc;
    sqlite3_stmt *stmt;
    const char *ptail;
    vbuf_t *vbuf;
    size_t k_size;
    char result[16]={0};

    if(!kv_entry||!kv_entry->write_key||!kv_entry->read_val||!kv_entry->key_data||!kv_entry->val_data){
        *errmsg = "Invalid kv entry!";
        return NULL;
    }

    status = get_table_column(kvstore,tabname,column_name,&kvtab,&column,errmsg);
    
    if(status!=NGX_OK) return NULL;

    vbuf = column->vbuf;
    VBUF_RESET(vbuf);
    
    status = kv_entry->write_key(column,kv_entry->data,vbuf,kv_entry->key_data);

    if(status!=NGX_OK){
        *errmsg = ngx_pstrndup(column->pool,"write key entry failed!");
        return NULL;
    }
    
    k_size = VBUF_CONTENT_SIZE(vbuf);
    
    get_key_id(result,(const void *)(vbuf->start),k_size);

    const char *sql = ngx_psprintf(column->pool,
            ngx_strlen("select * from  where =")+ngx_strlen(KVTABLE_KEY_SCHEMA)+column->column_name.len+16+10,
            "select * from %s where %s=%s",column->column_name.data,KVTABLE_KEY_SCHEMA,result);

    rc = sqlite3_prepare_v2(kvstore->sqlitdb,sql,ngx_strlen(sql),&stmt,&ptail);

    if(rc!=SQLITE_OK){
        const char *emsg = sqlite3_errmsg(kvstore->sqlitdb);
        *errmsg = ngx_psprintf(column->pool,
                ngx_strlen("compile sql statement error,")+ngx_strlen(emsg)+2,"compile sql statement error,%s",emsg); 
        return NULL;
    }
     
    status = read_a_val(column,stmt,kv_entry,errmsg);
    
    if(status!=NGX_OK){
        sqlite3_finalize(stmt);
        return NULL;
    }

    sqlite3_finalize(stmt);
    
    return kv_entry->val_data;
}
