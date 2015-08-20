/*
 * =====================================================================================
 *      Copyright (C) 2014 jianfeng sha
 *
 *      Filename:  persist_sqlite.h
 *
 *      Description:  
 *
 *      Created:  11/13/14 16:12:06
 *
 *      Author:  jianfeng sha , csp001314@163.com
 * =====================================================================================
 */

#ifndef _PERSIST_SQLITE_H_
#define _PERSIST_SQLITE_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "modsecurity.h"
#define DBNAME "colstore.db"
#define TBNAME "colstore_tb"

ngx_table_t  *collection_retrieve(modsec_rec *msr, const char *col_name,
    const char *col_value, int col_value_length);

int  collection_store(modsec_rec *msr, ngx_table_t *collection);

int  collections_remove_stale(modsec_rec *msr, const char *col_name);

#endif

