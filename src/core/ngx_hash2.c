/*shajf*/

#include "ngx_hash2.h"

/*
 * The internal form of a hash table.
 *
 * The table is an array indexed by the hash of the key; collisions
 * are resolved by hanging a linked list of hash entries off each
 * element of the array. Although this is a really simple design it
 * isn't too bad given that pools have a low allocation overhead.
 */

typedef struct ngx_hash2_entry_t ngx_hash2_entry_t;

struct ngx_hash2_entry_t {
    ngx_hash2_entry_t *next;
    unsigned int      hash;
    const void       *key;
    ssize_t       klen;
    const void       *val;
};

/*
 * Data structure for iterating through a hash table.
 *
 * We keep a pointer to the next hash entry here to allow the current
 * hash entry to be freed or otherwise mangled between calls to
 * ngx_hash_next().
 */
struct ngx_hash2_index_t {
    ngx_hash2_t         *ht;
    ngx_hash2_entry_t   *this, *next;
    unsigned int        index;
};

/*
 * The size of the array is always a power of two. We use the maximum
 * index rather than the size so that we can use bitwise-AND for
 * modular arithmetic.
 * The count of hash entries may be greater depending on the chosen
 * collision rate.
 */
struct ngx_hash2_t {
    ngx_pool_t          *pool;
    ngx_hash2_entry_t   **array;
    ngx_hash2_index_t     iterator;  /* For ngx_hash_first(NULL, ...) */
    unsigned int         count, max;
    ngx_hashfunc_t       hash_func;
    ngx_hash2_entry_t    *free;  /* List of recycled entries */
};

#define INITIAL_MAX 15 /* tunable == 2^n - 1 */


/*
 * Hash creation functions.
 */

static ngx_hash2_entry_t **alloc_array(ngx_hash2_t *ht, unsigned int max)
{
   return (ngx_hash2_entry_t**)ngx_pcalloc(ht->pool, sizeof(*ht->array) * (max + 1));
}

ngx_hash2_t * ngx_hash2_make(ngx_pool_t *pool)
{
    ngx_hash2_t *ht;
    ht = (ngx_hash2_t*)ngx_palloc(pool, sizeof(ngx_hash2_t));
    ht->pool = pool;
    ht->free = NULL;
    ht->count = 0;
    ht->max = INITIAL_MAX;
    ht->array = alloc_array(ht, ht->max);
    ht->hash_func = ngx_hashfunc_default;
    return ht;
}

ngx_hash2_t * ngx_hash2_make_custom(ngx_pool_t *pool,
                                               ngx_hashfunc_t hash_func)
{
    ngx_hash2_t *ht = ngx_hash2_make(pool);
    ht->hash_func = hash_func;
    return ht;
}


/*
 * Hash iteration functions.
 */

ngx_hash2_index_t * ngx_hash2_next(ngx_hash2_index_t *hi)
{
    hi->this = hi->next;
    while (!hi->this) {
        if (hi->index > hi->ht->max)
            return NULL;

        hi->this = hi->ht->array[hi->index++];
    }
    hi->next = hi->this->next;
    return hi;
}

ngx_hash2_index_t * ngx_hash2_first(ngx_pool_t *p, ngx_hash2_t *ht)
{
    ngx_hash2_index_t *hi;
    if (p)
        hi = (ngx_hash2_index_t*)ngx_palloc(p, sizeof(*hi));
    else
        hi = &ht->iterator;

    hi->ht = ht;
    hi->index = 0;
    hi->this = NULL;
    hi->next = NULL;
    return ngx_hash2_next(hi);
}

void ngx_hash2_this(ngx_hash2_index_t *hi,
                                const void **key,
                                ssize_t *klen,
                                void **val)
{
    if (key)  *key  = hi->this->key;
    if (klen) *klen = hi->this->klen;
    if (val)  *val  = (void *)hi->this->val;
}


/*
 * Expanding a hash table
 */

static void expand_array(ngx_hash2_t *ht)
{
    ngx_hash2_index_t *hi;
    ngx_hash2_entry_t **new_array;
    unsigned int new_max;

    new_max = ht->max * 2 + 1;
    new_array = alloc_array(ht, new_max);
    for (hi = ngx_hash2_first(NULL, ht); hi; hi = ngx_hash2_next(hi)) {
        unsigned int i = hi->this->hash & new_max;
        hi->this->next = new_array[i];
        new_array[i] = hi->this;
    }
    ht->array = new_array;
    ht->max = new_max;
}

unsigned int ngx_hashfunc_default(const u_char *char_key,
                                                      ssize_t *klen)
{
    unsigned int hash = 0;
    const u_char *key = char_key;
    const u_char *p;
    ssize_t i;
    
    /*
     * This is the popular `times 33' hash algorithm which is used by
     * perl and also appears in Berkeley DB. This is one of the best
     * known hash functions for strings because it is both computed
     * very fast and distributes very well.
     *
     * The originator may be Dan Bernstein but the code in Berkeley DB
     * cites Chris Torek as the source. The best citation I have found
     * is "Chris Torek, Hash function for text in C, Usenet message
     * <27038@mimsy.umd.edu> in comp.lang.c , October, 1990." in Rich
     * Salz's USENIX 1992 paper about INN which can be found at
     * <http://citeseer.nj.nec.com/salz92internetnews.html>.
     *
     * The magic of number 33, i.e. why it works better than many other
     * constants, prime or not, has never been adequately explained by
     * anyone. So I try an explanation: if one experimentally tests all
     * multipliers between 1 and 256 (as I did while writing a low-level
     * data structure library some time ago) one detects that even
     * numbers are not useable at all. The remaining 128 odd numbers
     * (except for the number 1) work more or less all equally well.
     * They all distribute in an acceptable way and this way fill a hash
     * table with an average percent of approx. 86%.
     *
     * If one compares the chi^2 values of the variants (see
     * Bob Jenkins ``Hashing Frequently Asked Questions'' at
     * http://burtleburtle.net/bob/hash/hashfaq.html for a description
     * of chi^2), the number 33 not even has the best value. But the
     * number 33 and a few other equally good numbers like 17, 31, 63,
     * 127 and 129 have nevertheless a great advantage to the remaining
     * numbers in the large set of possible multipliers: their multiply
     * operation can be replaced by a faster operation based on just one
     * shift plus either a single addition or subtraction operation. And
     * because a hash function has to both distribute good _and_ has to
     * be very fast to compute, those few numbers should be preferred.
     *
     *                  -- Ralf S. Engelschall <rse@engelschall.com>
     */
     
    if (*klen == NGX_HASH_KEY_STRING) {
        for (p = key; *p; p++) {
            hash = hash * 33 + *p;
        }
        *klen = p - key;
    }
    else {
        for (p = key, i = *klen; i; i--, p++) {
            hash = hash * 33 + *p;
        }
    }

    return hash;
}


/*
 * This is where we keep the details of the hash function and control
 * the maximum collision rate.
 *
 * If val is non-NULL it creates and initializes a new hash entry if
 * there isn't already one there; it returns an updatable pointer so
 * that hash entries can be removed.
 */

static ngx_hash2_entry_t **find_entry(ngx_hash2_t *ht,
                                     const void *key,
                                     ssize_t klen,
                                     const void *val)
{
    ngx_hash2_entry_t **hep, *he;
    unsigned int hash;

    hash = ht->hash_func(key, &klen);

    /* scan linked list */
    for (hep = &ht->array[hash & ht->max], he = *hep;
         he; hep = &he->next, he = *hep) {
        if (he->hash == hash
            && he->klen == klen
            && memcmp(he->key, key, klen) == 0)
            break;
    }
    if (he || !val)
        return hep;

    /* add a new entry for non-NULL values */
    if ((he = ht->free) != NULL)
        ht->free = he->next;
    else
        he = (ngx_hash2_entry_t*)ngx_palloc(ht->pool, sizeof(*he));
    he->next = NULL;
    he->hash = hash;
    he->key  = key;
    he->klen = klen;
    he->val  = val;
    *hep = he;
    ht->count++;
    return hep;
}

ngx_hash2_t * ngx_hash2_copy(ngx_pool_t *pool,
                                        const ngx_hash2_t *orig)
{
    ngx_hash2_t *ht;
    ngx_hash2_entry_t *new_vals;
    unsigned int i, j;

    ht = (ngx_hash2_t*)ngx_palloc(pool, sizeof(ngx_hash2_t) +
                    sizeof(*ht->array) * (orig->max + 1) +
                    sizeof(ngx_hash2_entry_t) * orig->count);
    ht->pool = pool;
    ht->free = NULL;
    ht->count = orig->count;
    ht->max = orig->max;
    ht->hash_func = orig->hash_func;
    ht->array = (ngx_hash2_entry_t **)((char *)ht + sizeof(ngx_hash2_t));

    new_vals = (ngx_hash2_entry_t *)((char *)(ht) + sizeof(ngx_hash2_t) +
                                    sizeof(*ht->array) * (orig->max + 1));
    j = 0;
    for (i = 0; i <= ht->max; i++) {
        ngx_hash2_entry_t **new_entry = &(ht->array[i]);
        ngx_hash2_entry_t *orig_entry = orig->array[i];
        while (orig_entry) {
            *new_entry = &new_vals[j++];
            (*new_entry)->hash = orig_entry->hash;
            (*new_entry)->key = orig_entry->key;
            (*new_entry)->klen = orig_entry->klen;
            (*new_entry)->val = orig_entry->val;
            new_entry = &((*new_entry)->next);
            orig_entry = orig_entry->next;
        }
        *new_entry = NULL;
    }
    return ht;
}

void * ngx_hash2_get(ngx_hash2_t *ht,
                                 const void *key,
                                 ssize_t klen)
{
    ngx_hash2_entry_t *he;
    he = *find_entry(ht, key, klen, NULL);
    if (he)
        return (void *)he->val;
    else
        return NULL;
}

void ngx_hash2_set(ngx_hash2_t *ht,
                               const void *key,
                               ssize_t klen,
                               const void *val)
{
    ngx_hash2_entry_t **hep;
    hep = find_entry(ht, key, klen, val);
    if (*hep) {
        if (!val) {
            /* delete entry */
            ngx_hash2_entry_t *old = *hep;
            *hep = (*hep)->next;
            old->next = ht->free;
            ht->free = old;
            --ht->count;
        }
        else {
            /* replace entry */
            (*hep)->val = val;
            /* check that the collision rate isn't too high */
            if (ht->count > ht->max) {
                expand_array(ht);
            }
        }
    }
    /* else key not present and val==NULL */
}

unsigned int ngx_hash2_count(ngx_hash2_t *ht)
{
    return ht->count;
}

void ngx_hash2_clear(ngx_hash2_t *ht)
{
    ngx_hash2_index_t *hi;
    for (hi = ngx_hash2_first(NULL, ht); hi; hi = ngx_hash2_next(hi))
        ngx_hash2_set(ht, hi->this->key, hi->this->klen, NULL);
}

ngx_hash2_t* ngx_hash2_overlay(ngx_pool_t *p,
                                          const ngx_hash2_t *overlay,
                                          const ngx_hash2_t *base)
{
    return ngx_hash2_merge(p, overlay, base, NULL, NULL);
}

ngx_hash2_t * ngx_hash2_merge(ngx_pool_t *p,
                                         const ngx_hash2_t *overlay,
                                         const ngx_hash2_t *base,
                                         void * (*merger)(ngx_pool_t *p,
                                                     const void *key,
                                                     ssize_t klen,
                                                     const void *h1_val,
                                                     const void *h2_val,
                                                     const void *data),
                                         const void *data)
{
    ngx_hash2_t *res;
    ngx_hash2_entry_t *new_vals = NULL;
    ngx_hash2_entry_t *iter;
    ngx_hash2_entry_t *ent;
    unsigned int i,j,k;


    res = (ngx_hash2_t*)ngx_palloc(p, sizeof(ngx_hash2_t));
    res->pool = p;
    res->free = NULL;
    res->hash_func = base->hash_func;
    res->count = base->count;
    res->max = (overlay->max > base->max) ? overlay->max : base->max;
    if (base->count + overlay->count > res->max) {
        res->max = res->max * 2 + 1;
    }
    res->array = alloc_array(res, res->max);
    if (base->count + overlay->count) {
        new_vals = (ngx_hash2_entry_t*)ngx_palloc(p, sizeof(ngx_hash2_entry_t) *
                              (base->count + overlay->count));
    }
    j = 0;
    for (k = 0; k <= base->max; k++) {
        for (iter = base->array[k]; iter; iter = iter->next) {
            i = iter->hash & res->max;
            new_vals[j].klen = iter->klen;
            new_vals[j].key = iter->key;
            new_vals[j].val = iter->val;
            new_vals[j].hash = iter->hash;
            new_vals[j].next = res->array[i];
            res->array[i] = &new_vals[j];
            j++;
        }
    }

    for (k = 0; k <= overlay->max; k++) {
        for (iter = overlay->array[k]; iter; iter = iter->next) {
            i = iter->hash & res->max;
            for (ent = res->array[i]; ent; ent = ent->next) {
                if ((ent->klen == iter->klen) &&
                    (memcmp(ent->key, iter->key, iter->klen) == 0)) {
                    if (merger) {
                        ent->val = (*merger)(p, iter->key, iter->klen,
                                             iter->val, ent->val, data);
                    }
                    else {
                        ent->val = iter->val;
                    }
                    break;
                }
            }
            if (!ent) {
                new_vals[j].klen = iter->klen;
                new_vals[j].key = iter->key;
                new_vals[j].val = iter->val;
                new_vals[j].hash = iter->hash;
                new_vals[j].next = res->array[i];
                res->array[i] = &new_vals[j];
                res->count++;
                j++;
            }
        }
    }
    return res;
}

/* This is basically the following...
 * for every element in hash table {
 *    comp elemeny.key, element.value
 * }
 *
 * Like with ngx_table_do, the comp callback is called for each and every
 * element of the hash table.
 */
int ngx_hash_do(ngx_hash_do_callback_fn_t *comp,
                             void *rec, const ngx_hash2_t *ht)
{
    ngx_hash2_index_t  hix;
    ngx_hash2_index_t *hi;
    int rv, dorv  = 1;

    hix.ht    = (ngx_hash2_t *)ht;
    hix.index = 0;
    hix.this  = NULL;
    hix.next  = NULL;

    if ((hi = ngx_hash2_next(&hix))) {
        /* Scan the entire table */
        do {
            rv = (*comp)(rec, hi->this->key, hi->this->klen, hi->this->val);
        } while (rv && (hi = ngx_hash2_next(hi)));

        if (rv == 0) {
            dorv = 0;
        }
    }
    return dorv;
}

