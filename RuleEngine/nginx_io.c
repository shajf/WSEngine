
/*shajf*/
#include "nginx_io.h"
#include "msc_log.h"

ngx_int_t read_http_request_body(modsec_rec *msr,char **error_msg){
    
    ngx_http_request_t *r = msr->r;
    ngx_chain_t *chain;
    ngx_buf_t *b;
    char *buf,*alloc_buf=NULL;
    size_t buf_len = 0;
    ssize_t size;

    if (error_msg == NULL) return -1;
    
    *error_msg = NULL;

    if (msr->reqbody_should_exist != 1||r->request_body==NULL||r->request_body->bufs==NULL) {
        
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "This request does not have a body.");
        }

        return 0;
    }

    if (msr->txcfg->reqbody_access != 1) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Request body access not enabled.");
        }

        return 0;
    }

    if (msr->txcfg->debuglog_level >= 4) {
        msr_log(msr, 4, "Reading request body.");
    }

    if (modsecurity_request_body_start(msr, error_msg) < 0) {
        return -1;
    }
    
    chain = r->request_body->bufs;

    while(chain){
        b = chain->buf;
        buf_len = ngx_buf_size(b);
        
        /* Check request body limit (should only trigger on chunked requests). */
        if (msr->reqbody_length + buf_len > (size_t)msr->txcfg->reqbody_limit) {

            *error_msg = ngx_psprintf(msr->mp,
                        ngx_strlen("Request body is larger than the configured limit (%l).")+NGX_INT64_LEN+2,
                        "Request body is larger than the configured limit (%l).", msr->txcfg->reqbody_limit);
            
            if((msr->txcfg->is_enabled == MODSEC_ENABLED) && (msr->txcfg->if_limit_action == REQUEST_BODY_LIMIT_ACTION_REJECT)) {
                return -5;
            } 
            
            else if((msr->txcfg->is_enabled == MODSEC_ENABLED) && (msr->txcfg->if_limit_action == REQUEST_BODY_LIMIT_ACTION_PARTIAL)) {

            }
            
            else if ((msr->txcfg->is_enabled == MODSEC_DETECTION_ONLY) && (msr->txcfg->if_limit_action == REQUEST_BODY_LIMIT_ACTION_PARTIAL)){

            } 
            else if ((msr->txcfg->is_enabled == MODSEC_DETECTION_ONLY) && (msr->txcfg->if_limit_action == REQUEST_BODY_LIMIT_ACTION_REJECT)){

            } else  {

                return -5;
            }
        }

        buf = (char*)b->pos;
        
        if(!ngx_buf_in_memory(b)&&buf_len>0){
           alloc_buf = (char*)malloc(buf_len);

           if(!alloc_buf){

                *error_msg = ngx_pstrndup(msr->mp,"No memory to read http request body!");
                return -1;
           }

           size = ngx_read_file(b->file, (u_char*)alloc_buf,buf_len, b->file_pos);

           if(size!=(ssize_t)buf_len){
                *error_msg = ngx_psprintf(msr->mp,
                        ngx_strlen("shoud read size %z bytes,but real read size %z!")+NGX_INT64_LEN*2+2,
                        "shoud read size %z bytes,but real read size %z!",buf_len,size);
                free(alloc_buf); 
                return -1;
           }
           buf = alloc_buf;
        }

        if (msr->txcfg->stream_inbody_inspection == 1)   {
            msr->stream_input_length+=buf_len;
            modsecurity_request_body_to_stream(msr, buf, buf_len, error_msg);
        }
        
        msr->reqbody_length += buf_len;
        
        if (buf_len != 0) {
            int rcbs = modsecurity_request_body_store(msr, buf, buf_len, error_msg);
            
            if (rcbs < 0) {
                if (rcbs == -5) {
                    
                    *error_msg = ngx_psprintf(msr->mp, 
                            ngx_strlen("Request body no files data length is larger than the configured limit (%l).")+NGX_INT64_LEN+2,
                            "Request body no files data length is larger than the configured limit (%l).", 
                            msr->txcfg->reqbody_no_files_limit);
                    
                    if((msr->txcfg->is_enabled == MODSEC_ENABLED) && (msr->txcfg->if_limit_action == REQUEST_BODY_LIMIT_ACTION_REJECT)) {
                        
                        if(buf!=NULL&&buf==alloc_buf){
                            free(alloc_buf);
                            alloc_buf = NULL;
                        }                    
                        return -5;
                    } 
                    
                    else if ((msr->txcfg->is_enabled == MODSEC_ENABLED) && (msr->txcfg->if_limit_action == REQUEST_BODY_LIMIT_ACTION_PARTIAL)) {
                    } 
                    
                    else if ((msr->txcfg->is_enabled == MODSEC_DETECTION_ONLY) && (msr->txcfg->if_limit_action == REQUEST_BODY_LIMIT_ACTION_PARTIAL)) {
                    } 
                    
                    else {
                        if(buf!=NULL&&buf==alloc_buf){
                            free(alloc_buf);
                            alloc_buf = NULL;
                        }                    
                        return -5;
                    }
                }

                if((msr->txcfg->is_enabled == MODSEC_ENABLED) && (msr->txcfg->if_limit_action == REQUEST_BODY_LIMIT_ACTION_REJECT)){
                    
                    if(buf!=NULL&&buf==alloc_buf){
                        free(alloc_buf);
                        alloc_buf = NULL;
                    }                    
                    return -1;
                
                }
            }

        }

        if(buf!=NULL&&buf==alloc_buf){
            free(alloc_buf);
            alloc_buf = NULL;
        }                    
        chain = chain->next;

    }
 
    // TODO: Why ignore the return code here?
    modsecurity_request_body_end(msr, error_msg);

    if (msr->txcfg->debuglog_level >= 4) {
        msr_log(msr, 4, "Completed receiving request body length %z .",
                msr->reqbody_length);
    }

    msr->if_status = IF_STATUS_WANTS_TO_RUN;

    return 1;
}


static ngx_table_elt_t* add_http_header(modsec_rec *msr,const char *key,const char *val,int req){
   
    ngx_http_request_t *r = msr->r;
 
    ngx_table_elt_t  *h;
    
    h = req==1?ngx_list_push(&r->headers_in.headers):ngx_list_push(&r->headers_out.headers); 
    
    if (h == NULL) {
        return NULL;
    }

    h->hash = 1;
    h->key.len = ngx_strlen(key);
    h->key.data = (u_char*)ngx_pstrndup(r->pool,key);
    
    h->value.len = ngx_strlen(val);
    h->value.data = (u_char*)ngx_pstrndup(r->pool,val);

    return NULL;
}

ngx_int_t add_http_request_header(modsec_rec *msr,const char *key,const char *val,ngx_table_elt_t **elt_hash){
    
    ngx_table_elt_t *h;

    h = add_http_header(msr,key,val,1);

    if(elt_hash){
        *elt_hash = h;
    }
    return h==NULL?NGX_ERROR:NGX_OK;
}

ngx_int_t add_http_response_header(modsec_rec *msr,const char *key,const char *val,ngx_table_elt_t **elt_hash){

    ngx_table_elt_t *h;

    h = add_http_header(msr,key,val,0);

    if(elt_hash){
        *elt_hash = h;
    }
    return h==NULL?NGX_ERROR:NGX_OK;
}



