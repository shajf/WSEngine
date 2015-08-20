

#include <ngx_core.h>

#define WSENGINE_CTX_SIZE  1024

typedef struct wsengine_context_node_s wsengine_context_node_t;
struct wsengine_context_node_s
{
    wsengine_context_node_t   *next;
    wsengine_context_node_t  **prev;
    ngx_pool_t                *pool;
    ngx_uint_t                 index;
    void                      *data;
};

static void
wsengine_context_cleanup(void *data);

#define wsengine_context_hash_key(r, ctx_index) ((ngx_uint_t) r + ctx_index)

#define wsengine_context_unlink(node) \
                                                                              \
    *(node->prev) = node->next;                                               \
                                                                              \
    if (node->next) {                                                         \
        node->next->prev = node->prev;                                        \
    }                                                                         \
                                                                              \
    node->prev = NULL;                                                        \
 

#define wsengine_context_link(queue, node)                                \
                                                                          \
    if (node->prev != NULL) {                                             \
        wsengine_context_unlink(node);                                    \
    }                                                                     \
    node->next = (wsengine_context_node_t *) *queue;                      \
    node->prev = (wsengine_context_node_t **) queue;                      \
    *queue = node;                                                        \
                                                                          \
    if (node->next) {                                                     \
        node->next->prev = &node->next;                                   \
    }


static wsengine_context_node_t **wsengine_context_hash;
static ngx_uint_t            wsengine_context_hash_size;

/* Nginx has removed multi-thread support, so we do not need mutex */

void *
wsengine_retrieve_ctx(ngx_pool_t *pool, ngx_uint_t index)
{
    ngx_uint_t               hash;
    uint32_t                 key;
    wsengine_context_node_t *node;

    hash = (ngx_uint_t) pool + index;
    key = ngx_murmur_hash2((u_char *)&hash, sizeof(hash)) % wsengine_context_hash_size;

    node = wsengine_context_hash[key];

    while (node) {

        if (node->pool == pool && node->index == index) {

            return node->data;
        }
        node = node->next;
    }

    return NULL;

}


ngx_int_t
wsengine_set_ctx(ngx_pool_t *pool, ngx_uint_t index, void *data)
{
    ngx_uint_t              hash;
    uint32_t                key;
    wsengine_context_node_t *node;
    ngx_pool_cleanup_t     *cln;
    
    hash = (ngx_uint_t) pool + index;
    key = ngx_murmur_hash2((u_char *)&hash, sizeof(hash)) % wsengine_context_hash_size;

    node = wsengine_context_hash[key];

    while (node) {

        if (node->pool == pool
                && node->index == index) {


            node->data = data;
            return NGX_OK;
        }
        node = node->next;
    }

    cln = ngx_pool_cleanup_add(pool, sizeof(wsengine_context_node_t));

    if (cln == NULL) {

        return NGX_ERROR;
    }

    cln->handler = wsengine_context_cleanup;
    node = cln->data;

    node->prev = NULL;
    node->next = NULL;
    node->pool = pool;
    node->index = index;
    node->data = data;

    wsengine_context_link(&wsengine_context_hash[key], node);

    return NGX_OK;
}


static void
wsengine_context_cleanup(void *data)
{
    wsengine_context_node_t *node = data;

    wsengine_context_unlink(node);

}


ngx_int_t wsengine_init_ctx(ngx_pool_t *pool,ngx_uint_t hash_size){
    
    wsengine_context_hash_size = hash_size;

    wsengine_context_hash = ngx_pcalloc(pool, sizeof(wsengine_context_node_t *) * wsengine_context_hash_size);

    if (wsengine_context_hash == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


