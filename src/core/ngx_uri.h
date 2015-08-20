
/*
 * ngx_uri.h: External Interface of ngx_uri.c
 */

/**
 * @file ngx_uri.h
 * @brief NGX-UTIL URI Routines
 */

#ifndef NGX_URI_H
#define NGX_URI_H

#include <ngx_config.h>
#include <ngx_core.h>

/**
 * @defgroup NGX_Util_URI URI
 * @ingroup NGX_Util
 * @{
 */

#define NGX_URI_FTP_DEFAULT_PORT         21 /**< default FTP port */
#define NGX_URI_SSH_DEFAULT_PORT         22 /**< default SSH port */
#define NGX_URI_TELNET_DEFAULT_PORT      23 /**< default telnet port */
#define NGX_URI_GOPHER_DEFAULT_PORT      70 /**< default Gopher port */
#define NGX_URI_HTTP_DEFAULT_PORT        80 /**< default HTTP port */
#define NGX_URI_POP_DEFAULT_PORT        110 /**< default POP port */
#define NGX_URI_NNTP_DEFAULT_PORT       119 /**< default NNTP port */
#define NGX_URI_IMAP_DEFAULT_PORT       143 /**< default IMAP port */
#define NGX_URI_PROSPERO_DEFAULT_PORT   191 /**< default Prospero port */
#define NGX_URI_WAIS_DEFAULT_PORT       210 /**< default WAIS port */
#define NGX_URI_LDAP_DEFAULT_PORT       389 /**< default LDAP port */
#define NGX_URI_HTTPS_DEFAULT_PORT      443 /**< default HTTPS port */
#define NGX_URI_RTSP_DEFAULT_PORT       554 /**< default RTSP port */
#define NGX_URI_SNEWS_DEFAULT_PORT      563 /**< default SNEWS port */
#define NGX_URI_ACAP_DEFAULT_PORT       674 /**< default ACAP port */
#define NGX_URI_NFS_DEFAULT_PORT       2049 /**< default NFS port */
#define NGX_URI_TIP_DEFAULT_PORT       3372 /**< default TIP port */
#define NGX_URI_SIP_DEFAULT_PORT       5060 /**< default SIP port */

/** Flags passed to unparse_uri_components(): */
/** suppress "scheme://user\@site:port" */
#define NGX_URI_UNP_OMITSITEPART    (1U<<0)
/** Just omit user */
#define NGX_URI_UNP_OMITUSER        (1U<<1)
/** Just omit password */
#define NGX_URI_UNP_OMITPASSWORD    (1U<<2)
/** omit "user:password\@" part */
#define NGX_URI_UNP_OMITUSERINFO    (NGX_URI_UNP_OMITUSER | \
                                     NGX_URI_UNP_OMITPASSWORD)
/** Show plain text password (default: show XXXXXXXX) */
#define NGX_URI_UNP_REVEALPASSWORD  (1U<<3)
/** Show "scheme://user\@site:port" only */
#define NGX_URI_UNP_OMITPATHINFO    (1U<<4)
/** Omit the "?queryarg" from the path */
#define NGX_URI_UNP_OMITQUERY       (1U<<5)

/** @see ngx_uri_t */
typedef struct ngx_uri_t ngx_uri_t;

/**
 * A structure to encompass all of the fields in a uri
 */
struct ngx_uri_t {
    /** scheme ("http"/"ftp"/...) */
    char *scheme;
    /** combined [user[:password]\@]host[:port] */
    char *hostinfo;
    /** user name, as in http://user:passwd\@host:port/ */
    char *user;
    /** password, as in http://user:passwd\@host:port/ */
    char *password;
    /** hostname from URI (or from Host: header) */
    char *hostname;
    /** port string (integer representation is in "port") */
    char *port_str;
    /** the request path (or NULL if only scheme://host was given) */
    char *path;
    /** Everything after a '?' in the path, if present */
    char *query;
    /** Trailing "#fragment" string, if present */
    char *fragment;

    /** structure returned from gethostbyname() */
    struct hostent *hostent;

    /** The port number, numeric, valid only if port_str != NULL */
    uint16_t port;
    
    /** has the structure been initialized */
    unsigned is_initialized:1;

    /** has the DNS been looked up yet */
    unsigned dns_looked_up:1;
    /** has the dns been resolved yet */
    unsigned dns_resolved:1;
};

/* ngx_uri.c */
/**
 * Return the default port for a given scheme.  The schemes recognized are
 * http, ftp, https, gopher, wais, nntp, snews, and prospero
 * @param scheme_str The string that contains the current scheme
 * @return The default port for this scheme
 */ 
uint16_t ngx_uri_port_of_scheme(const char *scheme_str);

/**
 * Unparse a ngx_uri_t structure to an URI string.  Optionally 
 * suppress the password for security reasons.
 * @param p The pool to allocate out of
 * @param uptr All of the parts of the uri
 * @param flags How to unparse the uri.  One of:
 * <PRE>
 *    NGX_URI_UNP_OMITSITEPART        Suppress "scheme://user\@site:port" 
 *    NGX_URI_UNP_OMITUSER            Just omit user 
 *    NGX_URI_UNP_OMITPASSWORD        Just omit password 
 *    NGX_URI_UNP_OMITUSERINFO        Omit "user:password\@" part
 *    NGX_URI_UNP_REVEALPASSWORD      Show plain text password (default: show XXXXXXXX)
 *    NGX_URI_UNP_OMITPATHINFO        Show "scheme://user\@site:port" only 
 *    NGX_URI_UNP_OMITQUERY           Omit "?queryarg" or "#fragment" 
 * </PRE>
 * @return The uri as a string
 */
char * ngx_uri_unparse(ngx_pool_t *p, 
                                    const ngx_uri_t *uptr,
                                    unsigned flags);

/**
 * Parse a given URI, fill in all supplied fields of a ngx_uri_t
 * structure. This eliminates the necessity of extracting host, port,
 * path, query info repeatedly in the modules.
 * @param p The pool to allocate out of
 * @param uri The uri to parse
 * @param uptr The ngx_uri_t to fill out
 * @return NGX_SUCCESS for success or error code
 */
ngx_int_t ngx_uri_parse(ngx_pool_t *p, const char *uri, 
                                        ngx_uri_t *uptr);

/**
 * Special case for CONNECT parsing: it comes with the hostinfo part only
 * @param p The pool to allocate out of
 * @param hostinfo The hostinfo string to parse
 * @param uptr The ngx_uri_t to fill out
 * @return NGX_SUCCESS for success or error code
 */
ngx_int_t ngx_uri_parse_hostinfo(ngx_pool_t *p, 
                                                 const char *hostinfo, 
                                                 ngx_uri_t *uptr);


#endif /* NGX_URI_H */
