

#ifndef WSENGINE_CONTEXT_H_INCLUDE_
#define WSENGINE_CONTEXT_H_INCLUDE_

void* wsengine_retrieve_ctx(ngx_pool_t * pool, int modid);

ngx_int_t wsengine_set_ctx(ngx_pool_t * pool, int modid,void * data);

ngx_int_t wsengine_init_ctx(ngx_pool_t *pool,ngx_uint_t hash_size);

#endif /* WSENGINE_CONTEXT_H_INCLUDE_ */
