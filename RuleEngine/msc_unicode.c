/*
* shajf
*/

#include "msc_unicode.h"

#define CODEPAGE_SEPARATORS  " \t\n\r"

/** \brief Load Unicode file
 *
 * \param dcfg Pointer to directory configuration
 * \param error_msg Error message
 *
 * \retval 1 On Success
 * \retval 0 On Fail
 */
static int unicode_map_create(directory_config *dcfg, char **error_msg)
{
    ngx_pool_t *mp = dcfg->mp;
    unicode_map *u_map = dcfg->u_map;
    ssize_t n;
    unsigned int codepage = 0;
    char *buf = NULL, *p = NULL, *savedptr = NULL;
    char *ucode = NULL, *hmap = NULL;
    int found = 0, processing = 0;
    int Code = 0, Map = 0;

    if(unicode_map_table != NULL)   {
        free(unicode_map_table);
        unicode_map_table = NULL;
    }
    
    u_map->map = ngx_open_file_read(mp,u_map->mapfn);

    if (u_map->map == NULL)
    {
        *error_msg = ngx_psprintf(mp, strlen("Could not open unicode map file: ")+ngx_strlen(u_map->mapfn)+10,
                "Could not open unicode map file: %s", u_map->mapfn);

        return 0;
    }

    buf = (char *)malloc(ngx_file_size(&u_map->map->info)+1);

    if (buf == NULL)   {
        *error_msg = ngx_psprintf(mp, strlen("Could not alloc memory for unicode map")+1,
                "Could not alloc memory for unicode map");

        ngx_close_file(u_map->map->fd);
        return 0;
    }

    n =  ngx_read_file(u_map->map,(u_char*)buf,ngx_file_size(&u_map->map->info),0);
    
    if(n==NGX_ERROR){
        *error_msg = ngx_psprintf(mp,strlen("Could not read unicode map file:")+ngx_strlen(u_map->mapfn)+10,
                "Could not read unicode map file:%s",u_map->mapfn);

        free(buf);
        buf = NULL;
        ngx_close_file(u_map->map->fd); 
        return 0;
    }

    if (unicode_map_table != NULL)  {
        memset(unicode_map_table, -1, (sizeof(int)*65536));
    } else {
        unicode_map_table = (int *)malloc(sizeof(int) * 65536);

        if(unicode_map_table == NULL) {
            *error_msg = ngx_psprintf(mp, strlen("Could not alloc memory for unicode map")+1,
                    "Could not alloc memory for unicode map");

            free(buf);
            buf = NULL;
            ngx_close_file(u_map->map->fd);
            return 0;
        }

        memset(unicode_map_table, -1, (sizeof(int)*65536));
    }

    /* Setting some unicode values - http://tools.ietf.org/html/rfc3490#section-3.1 */

    /* Set 0x3002 -> 0x2e */
    unicode_map_table[0x3002] = 0x2e;
    /* Set 0xFF61 -> 0x2e */
    unicode_map_table[0xff61] = 0x2e;
    /* Set 0xFF0E -> 0x2e */
    unicode_map_table[0xff0e] = 0x2e;
    /* Set 0x002E -> 0x2e */
    unicode_map_table[0x002e] = 0x2e;

    p = ngx_strtok(buf,CODEPAGE_SEPARATORS,&savedptr);

    while (p != NULL)   {

        codepage = atol(p);

        if (codepage == unicode_codepage)   {
            found = 1;
        }

        if (found == 1 && (strchr(p,':') != NULL))   {
            char *mapping = (char*)strdup(p);
            processing = 1;

            if(mapping != NULL) {
                ucode = ngx_strtok(mapping,":", &hmap);
                sscanf(ucode,"%x",&Code);
                sscanf(hmap,"%x",&Map);
                if(Code >= 0 && Code <= 65535)    {
                    unicode_map_table[Code] = Map;
                }

                free(mapping);
                mapping = NULL;
            }
        }

        if (processing == 1 && (strchr(p,':') == NULL)) {
            free(buf);
            buf = NULL;
            break;
        }

        p = ngx_strtok(NULL,CODEPAGE_SEPARATORS,&savedptr);
    }

    ngx_close_file(u_map->map->fd);

    if(buf) {
        free(buf);
        buf = NULL;
    }

    return 1;
}


/** \brief Init unicode map
 *
 * \param dcfg Pointer to directory configuration
 * \param mapfn Unicode map filename
 * \param error_msg Error message
 *
 * \retval unicode_map_create On Success
 * \retval -1 On Fail
 */
int unicode_map_init(directory_config *dcfg, const char *mapfn, char **error_msg)
{

    *error_msg = NULL;

    if ((dcfg->u_map == NULL) || (dcfg->u_map == NGX_CONF_UNSET_PTR)) {
        dcfg->u_map = (unicode_map*)ngx_pcalloc(dcfg->mp, sizeof(unicode_map));
        if (dcfg->u_map == NULL)  {
            return -1;
        }
    }

    dcfg->u_map->map = NULL;
    dcfg->u_map->mapfn = ngx_pstrndup(dcfg->mp, mapfn);

    return unicode_map_create(dcfg, error_msg);
}

