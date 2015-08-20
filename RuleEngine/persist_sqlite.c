/*
 * =====================================================================================
 *      Copyright (C) 2014 jianfeng sha
 *
 *      Filename:  persist_sqlite.c
 *
 *      Description: 
 *
 *      Created:  11/13/14 16:12:10
 *
 *      Author:  jianfeng sha , csp001314@163.com
 *
 * =====================================================================================
 */
#include "persist_sqlite.h"
#include "msc_log.h"

static ngx_int_t write_key_fun(kvtable_column_t *column,void *data,vbuf_t *vbuf,void *key_data)
{
    msc_string* key = (msc_string*)key_data;

    return vbuf_write_nstr(vbuf,key->value,key->value_len);

}

static ngx_int_t write_val_fun(kvtable_column_t *column,void *data,vbuf_t *vbuf,void *val_data){
    
    ngx_uint_t i;

    const ngx_table_t *col = (const ngx_table_t*)val_data;
    const ngx_array_t *arr;
    ngx_table_entry_t *te;

    arr = ngx_table_elts(col);
    te = (ngx_table_entry_t *)arr->elts;
    
    for (i = 0; i < arr->nelts; i++){
       msc_string *var = (msc_string *)te[i].val;
       vbuf_write_nstr(vbuf,var->name,var->name_len);
       vbuf_write_nstr(vbuf,var->value,var->value_len);
    }
    return NGX_OK;
}

static ngx_int_t read_key_fun(kvtable_column_t *column,void *data,vbuf_t *vbuf,void *key_data,size_t k_size){
    
    modsec_rec *msr = (modsec_rec*)data;
    msc_string *key = (msc_string*)key_data;
    char *k_val;
    size_t k_val_size;

    vbuf_read_str(vbuf,&k_val,&k_val_size);
    
    key->value = ngx_pstrmemdup(msr->mp,k_val,k_val_size);
    
    key->value_len = k_val_size;

    return NGX_OK;
}

static ngx_int_t read_val_fun(kvtable_column_t *column,void *data,vbuf_t *vbuf,void *val_data,size_t v_size){
    
    modsec_rec *msr = (modsec_rec*)data;
    ngx_table_t *col = (ngx_table_t *)val_data;
    char *name,*value;
    size_t name_size,value_size;
    char *r_start = vbuf->pos;

    while(((size_t)(vbuf->pos-r_start)<v_size)){
        msc_string *var = ngx_pcalloc(msr->mp,sizeof(msc_string));
        vbuf_read_str(vbuf,&name,&name_size);
        vbuf_read_str(vbuf,&value,&value_size);
        
        var->name = ngx_pstrmemdup(msr->mp,name,name_size);
        var->name_len = name_size;

        var->value = ngx_pstrmemdup(msr->mp,value,value_size);
        var->value_len = value_size;
        
        ngx_table_addn(col, var->name, (void *)var);
    }
    return NGX_OK;
}

static ngx_int_t scan_fun(kvtable_column_t *column,void *data,void *key,void *val){
    ngx_int_t rc; 
    modsec_rec *msr = (modsec_rec*)data;
    kvtable_kv_entry_t kv_entry;

    msc_string *t_key = (msc_string*)key;
    ngx_table_t *col = (ngx_table_t *)val;
    msc_string *var;
    var = (msc_string *)ngx_table_get(col, "__expire_KEY");
    
    ngx_ext_time_t now = ngx_ext_time_sec(msr->request_time);

    kv_entry.key_data = key;
    kv_entry.val_data = val;
    kv_entry.data = data;
    kv_entry.write_key = write_key_fun;
    kv_entry.write_val = write_val_fun;
    kv_entry.read_key = NULL;
    kv_entry.read_val = NULL;
    kv_entry.scan = NULL;

    char *errmsg = NULL;
    
    if (var == NULL) {
        msr_log(msr, 1, "collections_remove_stale: Collection cleanup discovered entry with no "
            "__expire_KEY (key \"%s\").",t_key->value);

    } else {
        unsigned int expiry_time = atoi(var->value);

        if (msr->txcfg->debuglog_level >= 9) {
            msr_log(msr, 9, "collections_remove_stale: Record (key \"%s\") set to expire in %T seconds.",
                t_key->value,expiry_time - now);
        }

        if (expiry_time <= now) {
            
            rc = do_kvtable_del(msr->txcfg->persistdb,TBNAME,(const char*)column->column_name.data,&kv_entry,&errmsg);
            
            if (rc != NGX_OK) {
                msr_log(msr, 1, "collections_remove_stale: Failed deleting collection (name \"%s\", "
                    "key \"%s\"): %s",column->column_name.data,t_key->value,errmsg?"":errmsg);
                
                msr->msc_sqlite_delete_error = 1;
                
                return NGX_ERROR;
            }

            if (msr->txcfg->debuglog_level >= 4) {
                msr_log(msr, 4, "collections_remove_stale: Removed stale collection (name \"%s\", "
                    "key \"%s\").",column->column_name.data,t_key->value);
            }
        }
    }
    ngx_table_clear(col); 
    return NGX_OK;
} 

static ngx_table_t *collection_retrieve_ex(modsec_rec *msr, const char *tbname, const char *colname,
        const char *col_key, size_t col_key_len){

    ngx_int_t rc;
    ngx_table_t *col = NULL;
    const ngx_array_t *arr;
    ngx_table_entry_t *te;
    int expired = 0;
    ngx_uint_t i;
    kvtable_kv_entry_t kv_entry;

    msc_string key;

    char *errmsg;

    if (msr->txcfg->persistdb == NULL) {
        
        msr_log(msr, 1, "collection_retrieve_ex: Unable to retrieve collection (name \"%s\", key \"%s\"). Use "
            "SecPersistDB to define persistdb first.", colname,col_key);
        goto cleanup;
    }
    
    key.value = (char*)col_key;
    key.value_len = col_key_len;

    kv_entry.key_data = (void*)(&key);

    kv_entry.val_data = (void*)ngx_table_make(msr->mp,12);

    if(kv_entry.val_data == NULL) {
       
        msr_log(msr,1,"collection_retrieve_ex:ngx_table_make failed!");
        goto cleanup;
    }

    kv_entry.data = (void*)msr;
    kv_entry.write_key = write_key_fun;
    kv_entry.write_val = NULL;
    kv_entry.read_key = read_key_fun;
    kv_entry.read_val = read_val_fun;
    kv_entry.scan = NULL;

    /* ENH Need expiration (and perhaps other metadata) accessible in blob
     * form to determine if converting to a table is needed.  This will
     * save some cycles.
     */

    /* Transform raw data into a table. */
    col = (ngx_table_t*)do_kvtable_find(msr->txcfg->persistdb,tbname,colname,&kv_entry,&errmsg); 
    
    if (col == NULL) {
        msr_log(msr,1,"collection_retrieve_ex:do_kvtable_find failed:%s!",errmsg?"":errmsg);
        goto cleanup;
    }

    /* Remove expired variables. */
    do {
        arr = ngx_table_elts(col);
        te = (ngx_table_entry_t *)arr->elts;
        for (i = 0; i < arr->nelts; i++) {
            if (ngx_strncmp(te[i].key, "__expire_", 9) == 0) {
                msc_string *var = (msc_string *)te[i].val;
                int expiry_time = atoi(var->value);

                if (expiry_time <= ngx_ext_time_sec(msr->request_time)) {
                    char *key_to_expire = te[i].key;

                    /* Done early if the col expired */
                    if (ngx_strcmp(key_to_expire, "__expire_KEY") == 0) {
                        expired = 1;
                    }
                    
                    if (msr->txcfg->debuglog_level >= 9) {
                        msr_log(msr, 9, "collection_retrieve_ex: Removing key \"%s\" from collection.", key_to_expire + 9);
                        msr_log(msr, 9, "collection_retrieve_ex: Removing key \"%s\" from collection.", key_to_expire);
                    }
                    
                    ngx_table_unset(col, key_to_expire + 9);
                    ngx_table_unset(col, key_to_expire);
                    
                    if (msr->txcfg->debuglog_level >= 4) {
                        msr_log(msr, 4, "collection_retrieve_ex: Removed expired variable \"%s\".", key_to_expire + 9);
                    }
                    
                    break;
                }
            }
        }
    } while(!expired && (i != arr->nelts));

    /* Delete the collection if the variable "KEY" does not exist.
     *
     * ENH It would probably be more efficient to hold the DBM
     * open until determined if it needs deleted than to open a second
     * time.
     */
    if (ngx_table_get(col, "KEY") == NULL) {
        
        rc = do_kvtable_del(msr->txcfg->persistdb,tbname,colname,&kv_entry,&errmsg);
        
        if (rc != NGX_OK) {
            msr_log(msr, 1, "collection_retrieve_ex: Failed deleting collection (name \"%s\", "
                "key \"%s\"): %s", colname,col_key,errmsg?"":errmsg);
            
            msr->msc_sqlite_delete_error = 1;

            goto cleanup;
        }

        if (expired && (msr->txcfg->debuglog_level >= 9)) {
            msr_log(msr, 9, "collection_retrieve_ex: Collection expired (name \"%s\", key \"%s\").", colname,col_key);
        }

        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "collection_retrieve_ex: Deleted collection (name \"%s\", key \"%s\").",
                 colname,col_key);
        }
        goto cleanup;
    }

    /* Update UPDATE_RATE */
    {
        msc_string *var;
        int create_time, counter;

        var = (msc_string *)ngx_table_get(col, "CREATE_TIME");
        if (var == NULL) {
            /* Error. */
        } else {
            create_time = atoi(var->value);
            var = (msc_string *)ngx_table_get(col, "UPDATE_COUNTER");
            if (var == NULL) {
                /* Error. */
            } else {
                
		ngx_ext_time_t td;

                counter = atoi(var->value);

                /* UPDATE_RATE is removed on store, so add it back here */
                var = (msc_string *)ngx_pcalloc(msr->mp, sizeof(msc_string));
                var->name = "UPDATE_RATE";
                var->name_len = ngx_strlen(var->name);
                ngx_table_setn(col, var->name, (void *)var);
                /* NOTE: No rate if there has been no time elapsed */
                td = (ngx_ext_time_sec(ngx_ext_time_now()) - create_time);
                if (td == 0) {
                    var->value = ngx_psprintf(msr->mp, 2,"%d", 0);
                }
                else {
                    var->value = ngx_psprintf(msr->mp, NGX_INT64_LEN+2,"%T",
                        (ngx_ext_time_t)((60 * counter)/td));
                }
                var->value_len = ngx_strlen(var->value);
            }
        }
    }

    if (msr->txcfg->debuglog_level >= 4) {
        msr_log(msr, 4, "collection_retrieve_ex: Retrieved collection (name \"%s\", key \"%s\").",
            colname,col_key);
    }

    return col;

cleanup:
    return NULL;
}

/**
 *
 */
ngx_table_t *collection_retrieve(modsec_rec *msr, const char *col_name,
    const char *col_key, int col_key_len)
{

    ngx_ext_time_t  time_before = ngx_ext_time_now();
    ngx_table_t *rtable = NULL;
    

    rtable = collection_retrieve_ex(msr, TBNAME,col_name, col_key, col_key_len);
    
    msr->time_storage_read += (ngx_ext_time_now() - time_before);
    
    return rtable;
}

int collection_store(modsec_rec *msr, ngx_table_t *col) {
    char *errmsg = NULL; 
    char *tabname = NULL;
    char *colname = NULL;

    msc_string *var_name = NULL, *var_key = NULL;
    const ngx_array_t *arr;
    ngx_table_entry_t *te;
    ngx_uint_t i;
    const ngx_table_t *stored_col = NULL;
    const ngx_table_t *orig_col = NULL;
    ngx_int_t status;

    kvtable_kv_entry_t kv_entry;

    var_name = (msc_string *)ngx_table_get(col, "__name");
    if (var_name == NULL) {
        goto error;
    }

    var_key = (msc_string *)ngx_table_get(col, "__key");
    if (var_key == NULL) {
        goto error;
    }

    if (msr->txcfg->persistdb == NULL) {
        msr_log(msr, 1, "collection_store: Unable to store collection (name \"%s\", key \"%s\"). Use "
            "SecPersistDB to define persist first.", log_escape_ex(msr->mp, var_name->value, var_name->value_len),
            log_escape_ex(msr->mp, var_key->value, var_key->value_len));
        goto error;
    }

    tabname = TBNAME;
    
    colname = var_name->value;

    /* Delete IS_NEW on store. */
    ngx_table_unset(col, "IS_NEW");

    /* Delete UPDATE_RATE on store to save space as it is calculated */
    ngx_table_unset(col, "UPDATE_RATE");

    /* Update the timeout value. */
    {
        msc_string *var = (msc_string *)ngx_table_get(col, "TIMEOUT");
        if (var != NULL) {
            int timeout = atoi(var->value);
            var = (msc_string *)ngx_table_get(col, "__expire_KEY");
            if (var != NULL) {
                var->value = ngx_psprintf(msr->mp, NGX_INT64_LEN+2,
                        "%T", (ngx_ext_time_t)(ngx_ext_time_sec(ngx_ext_time_now()) + timeout));

                var->value_len = ngx_strlen(var->value);
            }
        }
    }

    /* LAST_UPDATE_TIME */
    {
        msc_string *var = (msc_string *)ngx_table_get(col, "LAST_UPDATE_TIME");
        if (var == NULL) {
            var = (msc_string *)ngx_pcalloc(msr->mp, sizeof(msc_string));
            var->name = "LAST_UPDATE_TIME";
            var->name_len = ngx_strlen(var->name);
            ngx_table_setn(col, var->name, (void *)var);
        }
        
	var->value = ngx_psprintf(msr->mp, NGX_INT64_LEN+2,"%T", (ngx_ext_time_t)(ngx_ext_time_sec(ngx_ext_time_now())));
        var->value_len = ngx_strlen(var->value);
    }

    /* UPDATE_COUNTER */
    {
        msc_string *var = (msc_string *)ngx_table_get(col, "UPDATE_COUNTER");
        int counter = 0;
        if (var == NULL) {
            var = (msc_string *)ngx_pcalloc(msr->mp, sizeof(msc_string));
            var->name = "UPDATE_COUNTER";
            var->name_len = ngx_strlen(var->name);
            ngx_table_setn(col, var->name, (void *)var);
        } else {
            counter = atoi(var->value);
        }
        var->value = ngx_psprintf(msr->mp, NGX_INT64_LEN+2,"%d", counter + 1);
        var->value_len = ngx_strlen(var->value);
    }

    /* If there is an original value, then create a delta and
     * apply the delta to the current value */
    orig_col = (const ngx_table_t *)ngx_table_get(msr->collections_original, var_name->value);

    if (orig_col != NULL) {

        stored_col = (const ngx_table_t *)collection_retrieve_ex(msr,tabname,colname,var_key->value, var_key->value_len);
    }

    arr = ngx_table_elts(col);
    te = (ngx_table_entry_t *)arr->elts;
    for (i = 0; i < arr->nelts; i++) {
        msc_string *var = (msc_string *)te[i].val;

        /* If there is an original value, then apply the delta
         * to the latest stored value */
        if (stored_col != NULL) {
            const msc_string *orig_var = (const msc_string *)ngx_table_get(orig_col, var->name);
            if (orig_var != NULL) {
                const msc_string *stored_var = (const msc_string *)ngx_table_get(stored_col, var->name);
                if (stored_var != NULL) {
                    int origval = atoi(orig_var->value);
                    int ourval = atoi(var->value);
                    int storedval = atoi(stored_var->value);
                    int delta = ourval - origval;
                    int newval = storedval + delta;

                    if (newval < 0) newval = 0; /* Counters never go below zero. */

                    var->value = ngx_psprintf(msr->mp, NGX_INT64_LEN+2,"%d", newval);
                    var->value_len = strlen(var->value);

                }
            }
        }

    }

    kv_entry.key_data = (void*)var_key;
    kv_entry.val_data = (void*)col;
    kv_entry.data = (void*)msr;
    kv_entry.write_key = write_key_fun;
    kv_entry.write_val = write_val_fun;
    kv_entry.read_key = NULL;
    kv_entry.read_val = NULL;
    kv_entry.scan = NULL;
    
    status = do_kvtable_insert(msr->txcfg->persistdb,tabname,colname,&kv_entry,&errmsg);
    
    if(status!=NGX_OK){
        
        msr_log(msr, 1, "collection_store failed. %s", errmsg?"":errmsg);
        
        goto error;
    }

    return 0;

    error:
        return -1;

}

int collections_remove_stale(modsec_rec *msr, const char *col_name) {
        
    ngx_int_t rc;
    const char *colname;
    const char *tabname = TBNAME;
    kvtable_kv_entry_t kv_entry;
    char *errmsg = NULL;
    if (msr->txcfg->persistdb == NULL) {
        /* The user has been warned about this problem enough times already by now.
         * msr_log(msr, 1, "Unable to access collection file (name \"%s\"). Use SecDataDir to "
         *     "define data directory first.", log_escape(msr->mp, col_name));
         */
        goto error;
    }

    if(strstr(col_name,"USER") || strstr(col_name,"SESSION") || strstr(col_name, "RESOURCE"))
        colname = ngx_pstrcat(msr->mp,msr->txcfg->webappid, "_", col_name, NULL);
    else
        colname = col_name;

    if (msr->txcfg->debuglog_level >= 9) {
        msr_log(msr, 9, "collections_remove_stale: Retrieving collection (name \"%s\", colname \"%s\")",col_name,colname);
    }
    
    kv_entry.key_data = ngx_pcalloc(msr->mp,sizeof(msc_string));
    kv_entry.val_data = (void*)ngx_table_make(msr->mp,12);
    kv_entry.data = (void*)msr;
    kv_entry.write_key = write_key_fun;
    kv_entry.write_val = write_val_fun;
    kv_entry.read_key = read_key_fun;
    kv_entry.read_val = read_val_fun;
    kv_entry.scan = scan_fun;

    rc = do_kvtable_scan(msr->txcfg->persistdb,tabname,colname,&kv_entry,&errmsg);

    if(rc!=NGX_OK) return -1;

    return 1;

error:

    return -1;
}
