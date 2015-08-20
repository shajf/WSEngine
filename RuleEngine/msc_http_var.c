
#include "msc_http_var.h"

ngx_uint_t msc_http_var_remote_port(modsec_rec *msr){
    
    ngx_http_request_t *r = msr->r;
    ngx_http_variable_value_t vv;
    ngx_str_t var = ngx_string("remote_port");
    ngx_http_get_variable_v1(r,&var,&vv);

    if(vv.not_found) return 0;

    return (ngx_uint_t)ngx_atoi(vv.data,(size_t)vv.len);
}

ngx_uint_t msc_http_var_local_port(modsec_rec *msr){
    
    ngx_http_request_t *r = msr->r;

    ngx_http_variable_value_t vv;
    ngx_str_t var = ngx_string("server_port");
    ngx_http_get_variable_v1(r,&var,&vv);

    if(vv.not_found) return 0;
    return (ngx_uint_t)ngx_atoi(vv.data,(size_t)vv.len);
}

const char *msc_http_var_remote_addr(modsec_rec *msr){
    
    ngx_http_request_t *r = msr->r;

    ngx_http_variable_value_t vv;
    ngx_str_t var = ngx_string("remote_addr");
    ngx_http_get_variable_v1(r,&var,&vv);

    if(vv.not_found) return (const char*)ngx_pstrndup(msr->mp,"0.0.0.0");

    return (const char*)ngx_http_pvdup(msr->mp,&vv);
}

const char *msc_http_var_local_addr(modsec_rec *msr){
    
    ngx_http_request_t *r = msr->r;

    ngx_http_variable_value_t vv;
    ngx_str_t var = ngx_string("server_addr");
    ngx_http_get_variable_v1(r,&var,&vv);

    if(vv.not_found) return (const char*)ngx_pstrndup(msr->mp,"0.0.0.0");

    return (const char*)ngx_http_pvdup(msr->mp,&vv);
}

const char *msc_http_var_request_line(modsec_rec *msr){
    
    ngx_http_request_t *r = msr->r;

    return (const char*)ngx_pstrdup(msr->mp,&r->request_line);
}

const char *msc_http_var_request_uri(modsec_rec *msr){

    ngx_http_request_t *r = msr->r;

    return (const char*)ngx_pstrdup(msr->mp,&r->uri);
}


const char *msc_http_var_request_method(modsec_rec *msr){
    
    ngx_http_request_t *r = msr->r;

    return (const char*)ngx_pstrdup(msr->mp,&r->method_name);
}

const char *msc_http_var_query_string(modsec_rec *msr){
    
    ngx_http_request_t *r = msr->r;
    ngx_str_t s;
    s.data = r->args_start;
    s.len = (size_t)(r->uri_end-r->args_start);

    return (const char*)ngx_pstrdup(msr->mp,&s);
}

const char *msc_http_var_request_protocol(modsec_rec *msr){

    ngx_http_request_t *r = msr->r;

    return (const char*)ngx_pstrdup(msr->mp,&r->http_protocol);
}

const char *msc_http_var_hostname(modsec_rec *msr){

    return (const char*)ngx_pstrdup(msr->mp,(ngx_str_t*)&ngx_cycle->hostname);
}

static void load_http_headers(modsec_rec *msr,ngx_table_t *table,int req){

    ngx_list_part_t             *part;
    ngx_table_elt_t             *h;
    ngx_uint_t                   i;

    ngx_http_request_t *r = msr->r;

    part = req == 1?&r->headers_in.headers.part:&r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL)
                break;

            part = part->next;
            h = part->elts;
            i = 0;
        }
        
        if(h[i].hash == 0){
            continue;
        }

        ngx_table_setn(table, (char *)h[i].key.data, (char *)h[i].value.data);

    }
    
}

ngx_table_t *msc_http_var_request_headers(modsec_rec *msr){

    ngx_table_t *table = ngx_table_make(msr->mp,16);

    load_http_headers(msr,table,1);

    return table;
}


ngx_uint_t msc_http_var_response_status(modsec_rec *msr){

    ngx_http_request_t *r = msr->r;
    ngx_http_variable_value_t vv;
    ngx_str_t var = ngx_string("status");
    ngx_http_get_variable_v1(r,&var,&vv);

    if(vv.not_found) return 0;

    return (ngx_uint_t)ngx_atoi(vv.data,(size_t)vv.len);
}

const char *msc_http_var_status_line(modsec_rec *msr){
    return (const char*)ngx_http_get_status_line(msr->r,msr->mp);
}

const char *msc_http_var_response_protocol(modsec_rec *msr){
    return (const char*)ngx_pstrndup(msr->mp,"HTTP/1.1");
}

ngx_table_t *msc_http_var_response_headers(modsec_rec *msr){

    ngx_table_t *table = ngx_table_make(msr->mp,16);

    load_http_headers(msr,table,0);

    return table;
}

const char *msc_http_var_content_type(modsec_rec *msr){
    
    ngx_http_request_t *r = msr->r;
    
    if(r->headers_out.content_type.len){
        return (const char*)ngx_pstrdup(msr->mp,&r->headers_out.content_type);
    }

    return NULL;
}

ngx_uint_t msc_http_var_content_length(modsec_rec *msr,int req){
    
    ngx_http_request_t *r = msr->r;
    
    if(req){
        
        if(r->headers_in.content_length){
            return (ngx_uint_t)ngx_atoi(r->headers_in.content_length->value.data,r->headers_in.content_length->value.len);
        }

        if(r->headers_in.content_length_n >= 0){
            return r->headers_in.content_length_n;
        }

        return 0;
    }

    if(r->headers_out.content_length){
        return (ngx_uint_t)ngx_atoi(r->headers_out.content_length->value.data,r->headers_out.content_length->value.len);
    }

    if(r->headers_out.content_length_n >= 0){
        return r->headers_out.content_length_n;
    }
    return 0;
}

const char *msc_http_var_remote_user(modsec_rec *msr){

    ngx_http_request_t *r = msr->r;

    ngx_http_variable_value_t vv;
    ngx_str_t var = ngx_string("remote_user");
    ngx_http_get_variable_v1(r,&var,&vv);

    if(vv.not_found) return "";

    return (const char*)ngx_http_pvdup(msr->mp,&vv);
}
