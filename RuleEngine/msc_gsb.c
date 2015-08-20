/*
* shajf
*/

#include "msc_gsb.h"

/** \brief Load GSB database
 *
 * \param dcfg Pointer to directory configuration
 * \param error_msg Error message
 *
 * \retval 1 On Success
 * \retval 0 On Fail
 */
static int gsb_db_create(directory_config *dcfg, char **error_msg)
{
    ngx_pool_t *mp = dcfg->mp;
    gsb_db *gsb = dcfg->gsb;
    char *buf = NULL, *p = NULL, *savedptr = NULL;
    char *op = NULL;
    ssize_t n;
    
    gsb->db = ngx_open_file_read(mp,gsb->dbfn);

    if (gsb->db == NULL) {
        *error_msg = ngx_psprintf(mp, ngx_strlen("Could not open gsb database \"\"")+ngx_strlen(gsb->dbfn)+2,
                "Could not open gsb database \"%s\"", gsb->dbfn);
        return 0;
    }

    buf = (char *)malloc(ngx_file_size(&gsb->db->info)+1);

    if (buf == NULL)   {
        *error_msg = ngx_pstrndup(mp, "Could not alloc memory for gsb data");
        ngx_close_file(gsb->db->fd);
        return 0;
    }
    
    n = ngx_read_file(gsb->db,(u_char*)buf,ngx_file_size(&gsb->db->info),0);

    if(n==NGX_ERROR){
        *error_msg = ngx_psprintf(mp,strlen("Could not read gsb db file:")+ngx_strlen(gsb->dbfn)+2,
                "Could not read gsb db file:%s",gsb->dbfn);

        free(buf);
        buf = NULL;
        ngx_close_file(gsb->db->fd); 
        return 0;
    }

    gsb->gsb_table = ngx_hash2_make(dcfg->mp);

    if (gsb->gsb_table == NULL)   {
        *error_msg = ngx_pstrndup(mp, "Could not alloc memory for gsb table");
        free(buf);
        buf = NULL;
        ngx_close_file(gsb->db->fd); 
        return 0;
    }

    p = ngx_strtok(buf,"\t",&savedptr);

    while (p != NULL)   {

        op = ngx_strchr(p,'+');

        if(op != NULL)   {
            char *hash = ++op;
            if(ngx_strlen(hash) == 32)
            ngx_hash2_set(gsb->gsb_table, hash, NGX_HASH_KEY_STRING, "malware");
        }

        op = ngx_strchr(p,'-');

        if(op != NULL)   {
            char *hash = ++op;
            if(ngx_strlen(hash) == 32)
            ngx_hash2_set(gsb->gsb_table, hash, NGX_HASH_KEY_STRING, NULL);
        }

        p = ngx_strtok(NULL,"\t",&savedptr);
    }


    ngx_close_file(gsb->db->fd); 
    free(buf);
    buf = NULL;

    return 1;
}


/** \brief Init GSB database
 *
 * \param dcfg Pointer to directory configuration
 * \param dbfn Database filename
 * \param error_msg Error message
 *
 * \retval gsb_db_create On Success
 * \retval -1 On Fail
 */
int gsb_db_init(directory_config *dcfg, const char *dbfn, char **error_msg)
{

    *error_msg = NULL;

    if ((dcfg->gsb == NULL) || (dcfg->gsb == NGX_CONF_UNSET_PTR)) {
        dcfg->gsb = (gsb_db*)ngx_pcalloc(dcfg->mp, sizeof(gsb_db));
        if (dcfg->gsb == NULL)  {
            return -1;
        }
    }

    dcfg->gsb->dbfn = ngx_pstrndup(dcfg->mp, dbfn);

    return gsb_db_create(dcfg, error_msg);
}

