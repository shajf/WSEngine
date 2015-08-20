
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


void make_array_core(ngx_array_t  *res, ngx_pool_t *p,ngx_uint_t nelts, size_t elt_size, int clear)
{
    /*
     * Assure sanity if someone asks for
     * array of zero elts.
     */
    if (nelts < 1) {
        nelts = 1;
    }

    if (clear) {
        res->elts = ngx_pcalloc(p, nelts * elt_size);
    }
    else {
        res->elts = ngx_palloc(p, nelts * elt_size);
    }

    res->pool = p;
    res->size = elt_size;
    res->nelts = 0;		/* No active elements yet... */
    res->nalloc = nelts;	/* ...but this many allocated */
}

ngx_array_t *
ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_array_t *a;

    a = ngx_palloc(p, sizeof(ngx_array_t));
    if (a == NULL) {
        return NULL;
    }

    if (ngx_array_init(a, p, n, size) != NGX_OK) {
        return NULL;
    }

    return a;
}


void
ngx_array_destroy(ngx_array_t *a)
{
    ngx_pool_t  *p;

    p = a->pool;

    if ((u_char *) a->elts + a->size * a->nalloc == p->d.last) {
        p->d.last -= a->size * a->nalloc;
    }

    if ((u_char *) a + sizeof(ngx_array_t) == p->d.last) {
        p->d.last = (u_char *) a;
    }
}


void *
ngx_array_push(ngx_array_t *a)
{
    void        *elt, *new;
    size_t       size;
    ngx_pool_t  *p;

    if (a->nelts == a->nalloc) {

        /* the array is full */

        size = a->size * a->nalloc;

        p = a->pool;

        if ((u_char *) a->elts + size == p->d.last
            && p->d.last + a->size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += a->size;
            a->nalloc++;

        } else {
            /* allocate a new array */

            new = ngx_palloc(p, 2 * size);
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, size);
            a->elts = new;
            a->nalloc *= 2;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts++;

    return elt;
}


void *
ngx_array_push_n(ngx_array_t *a, ngx_uint_t n)
{
    void        *elt, *new;
    size_t       size;
    ngx_uint_t   nalloc;
    ngx_pool_t  *p;

    size = n * a->size;

    if (a->nelts + n > a->nalloc) {

        /* the array is full */

        p = a->pool;

        if ((u_char *) a->elts + a->size * a->nalloc == p->d.last
            && p->d.last + size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += size;
            a->nalloc += n;

        } else {
            /* allocate a new array */

            nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);

            new = ngx_palloc(p, nalloc * a->size);
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, a->nelts * a->size);
            a->elts = new;
            a->nalloc = nalloc;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts += n;

    return elt;
}
/**
 * Determine if the array is empty (either NULL or having no elements).
 * @param a The array to check
 * @return True if empty, False otherwise
 */
int ngx_is_empty_array(const ngx_array_t *a)
{
    return ((a == NULL) || (a->nelts == 0));
}

/**
 * Remove an element from an array (as a first-in, last-out stack).
 * @param arr The array to remove an element from.
 * @return Location of the element in the array.
 * @remark If there are no elements in the array, NULL is returned.
 */
void * ngx_array_pop(ngx_array_t *arr){

    if (ngx_is_empty_array(arr)) {
        return NULL;
    }
   
    return arr->elts + (arr->size * (--arr->nelts));
}


/**
 * Remove all elements from an array.
 * @param arr The array to remove all elements from.
 * @remark As the underlying storage is allocated from a pool, no
 * memory is freed by this operation, but is available for reuse.
 */
void ngx_array_clear(ngx_array_t *arr){
    arr->nelts = 0;
}

/**
 * Concatenate two arrays together.
 * @param dst The destination array, and the one to go first in the combined 
 *            array
 * @param src The source array to add to the destination array
 */
void ngx_array_cat(ngx_array_t *dst,
			        const ngx_array_t *src)
{

    size_t  elt_size = dst->size;

    if (dst->nelts + src->nelts > dst->nalloc) {
        size_t new_size = (dst->nalloc == 0) ? 1 : dst->nalloc * 2;
        void *new_data;

        while (dst->nelts + src->nelts > new_size) {
            new_size *= 2;
        }

        new_data = ngx_pcalloc(dst->pool, elt_size * new_size);
        memcpy(new_data, dst->elts, dst->nalloc * elt_size);

        dst->elts = new_data;
        dst->nalloc = new_size;
    }

    memcpy(dst->elts + dst->nelts * elt_size, src->elts,elt_size * src->nelts);
    dst->nelts += src->nelts;
}

/**
 * Copy the entire array.
 * @param p The pool to allocate the copy of the array out of
 * @param arr The array to copy
 * @return An exact copy of the array passed in
 * @remark The alternate ngx_array_copy_hdr copies only the header, and arranges 
 *         for the elements to be copied if (and only if) the code subsequently
 *         does a push or arraycat.
 */
ngx_array_t * ngx_array_copy(ngx_pool_t *p,const ngx_array_t *arr)
{

    ngx_array_t *res =(ngx_array_t *) ngx_palloc(p, sizeof(ngx_array_t));

    make_array_core(res, p, arr->nalloc, arr->size, 0);

    memcpy(res->elts, arr->elts, arr->size * arr->nelts);
    res->nelts = arr->nelts;
    memset(res->elts + res->size * res->nelts, 0, res->size * (res->nalloc - res->nelts));
    return res;
}

/**
 * Copy the headers of the array, and arrange for the elements to be copied if
 * and only if the code subsequently does a push or arraycat.
 * @param p The pool to allocate the copy of the array out of
 * @param arr The array to copy
 * @return An exact copy of the array passed in
 * @remark The alternate ngx_array_copy copies the *entire* array.
 */
ngx_array_t * ngx_array_copy_hdr(ngx_pool_t *p,
                                      const ngx_array_t *arr)
{
    ngx_array_t *res;

    res = (ngx_array_t*)ngx_palloc(p, sizeof(ngx_array_t));
    res->pool = p;
    copy_array_hdr_core(res, arr);
    return res;
}

/**
 * Append one array to the end of another, creating a new array in the process.
 * @param p The pool to allocate the new array out of
 * @param first The array to put first in the new array.
 * @param second The array to put second in the new array.
 * @return A new array containing the data from the two arrays passed in.
*/
ngx_array_t * ngx_array_append(ngx_pool_t *p,
                                      const ngx_array_t *first,
                                      const ngx_array_t *second)
{

    ngx_array_t *res = ngx_array_copy_hdr(p, first);

    ngx_array_cat(res, second);
    return res;
}

/**
 * Generate a new string from the ngx_pool_t containing the concatenated 
 * sequence of substrings referenced as elements within the array.  The string 
 * will be empty if all substrings are empty or null, or if there are no 
 * elements in the array.  If sep is non-NUL, it will be inserted between 
 * elements as a separator.
 * @param p The pool to allocate the string out of
 * @param arr The array to generate the string from
 * @param sep The separator to use
 * @return A string containing all of the data in the array.
 */
char * ngx_array_pstrcat(ngx_pool_t *p,
				      const ngx_array_t *arr,
				      const char sep)
{

    char *cp, *res, **strpp;
    size_t len;
    ngx_uint_t i;

    if (arr->nelts <= 0 || arr->elts == NULL) {    /* Empty table? */
        return (char *) ngx_pcalloc(p, 1);
    }

    /* Pass one --- find length of required string */

    len = 0;
    for (i = 0, strpp = (char **) arr->elts; ; ++strpp) {
        if (strpp && *strpp != NULL) {
            len += strlen(*strpp);
        }
        if (++i >= arr->nelts) {
            break;
        }
        
        if (sep) {
            ++len;
        }
    }

    /* Allocate the required string */

    res = (char *) ngx_palloc(p, len + 1);
    cp = res;

    /* Pass two --- copy the argument strings into the result space */

    for (i = 0, strpp = (char **) arr->elts; ; ++strpp) {
        if (strpp && *strpp != NULL) {
            len = strlen(*strpp);
            memcpy(cp, *strpp, len);
            cp += len;
        }
        if (++i >= arr->nelts) {
            break;
        }
        if (sep) {
            *cp++ = sep;
        }
    }

    *cp = '\0';

    /* Return the result string */

    return res;
}

void *ngx_array_push_noclear(ngx_array_t *arr){

    if (arr->nelts == arr->nalloc) {
        int new_size = (arr->nalloc == 0) ? 1 : arr->nalloc * 2;
        char *new_data;

        new_data = ngx_palloc(arr->pool, arr->size * new_size);

        memcpy(new_data, arr->elts, arr->nalloc * arr->size);
        arr->elts = new_data;
        arr->nalloc = new_size;
    }

    ++arr->nelts;
    return arr->elts + (arr->size * (arr->nelts - 1));
}
