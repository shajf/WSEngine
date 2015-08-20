
/*
* shajf 
*/

#ifndef _MODSECURITY_H_
#define _MODSECURITY_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hash2.h>
#include <ngx_md5.h>
#include <ngx_http.h>

#include <libxml/tree.h>
#include <libxml/HTMLparser.h>


typedef struct rule_exception rule_exception;
typedef struct rule_exception hash_method;
typedef struct modsec_rec modsec_rec;
typedef struct error_message_t error_message_t;
typedef struct msc_engine msc_engine;
typedef struct msc_data_chunk msc_data_chunk;
typedef struct msc_arg msc_arg;
typedef struct msc_string msc_string;
typedef struct msc_parm msc_parm;

#include "msc_multipart.h"
#include "msc_pcre.h"
#include "msc_util.h"
#include "msc_json.h"
#include "msc_xml.h"
#include "msc_tree.h"
#include "msc_geo.h"
#include "msc_gsb.h"
#include "msc_unicode.h"
#include "re.h"
#include "msc_crypt.h"
#include "msc_config.h"
#include "config.h"

extern  const command_rec module_directives[];
extern  unsigned long int msc_pcre_match_limit;
extern  unsigned long int msc_pcre_match_limit_recursion;
extern  unsigned long int unicode_codepage;
extern  int *unicode_map_table;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define PHASE_REQUEST_HEADERS       1
#define PHASE_REQUEST_BODY          2
#define PHASE_RESPONSE_HEADERS      3
#define PHASE_RESPONSE_BODY         4
#define PHASE_LOGGING               5
#define PHASE_FIRST                 PHASE_REQUEST_HEADERS
#define PHASE_LAST                  PHASE_LOGGING

#define CREATEMODE_UNISTD ( S_IRUSR | S_IWUSR | S_IRGRP )

#define MODSEC_OFFLINE                  0
#define MODSEC_ONLINE                   1

#define TXID_SIZE 25


#define COOKIES_V0                      0
#define COOKIES_V1                      1

#define ACTION_NONE                     0
#define ACTION_DENY                     1
#define ACTION_DROP                     2
#define ACTION_ALLOW                    3
#define ACTION_ALLOW_REQUEST            4
#define ACTION_ALLOW_PHASE              5

#define MODSEC_DISABLED                 0
#define MODSEC_DETECTION_ONLY           1
#define MODSEC_ENABLED                  2

#define MSC_REQBODY_MEMORY              1
#define MSC_REQBODY_DISK                2

#define REQUEST_BODY_FORCEBUF_OFF               0
#define REQUEST_BODY_FORCEBUF_ON                1

#define REQUEST_BODY_LIMIT_ACTION_REJECT       0
#define REQUEST_BODY_LIMIT_ACTION_PARTIAL      1

#define IF_STATUS_NONE                  0
#define IF_STATUS_WANTS_TO_RUN          1
#define IF_STATUS_COMPLETE              2

#define KEEP_FILES_OFF                  0
#define KEEP_FILES_ON                   1
#define KEEP_FILES_RELEVANT_ONLY        2

#define RESBODY_STATUS_NOT_READ         0   /* we were not configured to read the body */
#define RESBODY_STATUS_ERROR            1   /* error occured while we were reading the body */
#define RESBODY_STATUS_PARTIAL          2   /* partial body content available in the brigade */
#define RESBODY_STATUS_READ_CHAIN     3   /* body was read but not flattened */
#define RESBODY_STATUS_READ             4   /* body was read and flattened */

#define REQUEST_BODY_HARD_LIMIT                 1073741824L
#define REQUEST_BODY_DEFAULT_INMEMORY_LIMIT     131072
#define REQUEST_BODY_DEFAULT_LIMIT              134217728
#define REQUEST_BODY_NO_FILES_DEFAULT_LIMIT     1048576
#define RESPONSE_BODY_DEFAULT_LIMIT             524288
#define RESPONSE_BODY_HARD_LIMIT                1073741824L

#define RESPONSE_BODY_LIMIT_ACTION_REJECT       0
#define RESPONSE_BODY_LIMIT_ACTION_PARTIAL      1

#define OF_STATUS_NOT_STARTED           0
#define OF_STATUS_IN_PROGRESS           1
#define OF_STATUS_COMPLETE              2

#define HASH_DISABLED             0
#define HASH_ENABLED              1

#define HASH_URL_HREF_HASH_RX     0
#define HASH_URL_HREF_HASH_PM     1
#define HASH_URL_FACTION_HASH_RX  2
#define HASH_URL_FACTION_HASH_PM  3
#define HASH_URL_LOCATION_HASH_RX 4
#define HASH_URL_LOCATION_HASH_PM 5
#define HASH_URL_IFRAMESRC_HASH_RX 6
#define HASH_URL_IFRAMESRC_HASH_PM 7
#define HASH_URL_FRAMESRC_HASH_RX 8
#define HASH_URL_FRAMESRC_HASH_PM 9

#define HASH_KEYONLY              0
#define HASH_SESSIONID            1
#define HASH_REMOTEIP             2

#define MODSEC_CACHE_DISABLED           0
#define MODSEC_CACHE_ENABLED            1

#define RULE_EXCEPTION_IMPORT_ID        1
#define RULE_EXCEPTION_IMPORT_MSG       2
#define RULE_EXCEPTION_REMOVE_ID        3
#define RULE_EXCEPTION_REMOVE_MSG       4
#define RULE_EXCEPTION_REMOVE_TAG       5

#define NOTE_MSR "modsecurity-tx-context"
#define FATAL_ERROR "ModSecurity: Fatal error (memory allocation or unexpected internal error)!"

#define SECACTION_TARGETS                       "REMOTE_ADDR"
#define SECACTION_ARGS                          "@unconditionalMatch"

#define SECMARKER_TARGETS                       "REMOTE_ADDR"
#define SECMARKER_ARGS                          "@noMatch"
#define SECMARKER_BASE_ACTIONS                  "t:none,pass,marker:"

#define NBSP                            160

struct rule_exception {
    int                  type;
    const char          *param;
    void                *param_data;
};

struct msc_engine {
    ngx_pool_t              *mp;
    msre_engine             *msre;
    ngx_uint_t             processing_mode;
};


struct modsec_rec {
    ngx_pool_t          *mp;
    msc_engine          *modsecurity;

    ngx_http_request_t         *r_early;
    ngx_http_request_t         *r;
    ngx_uri_t                  parsed_uri; 
    directory_config           *txcfg;

    ngx_uint_t         reqbody_should_exist;
    ngx_uint_t         reqbody_chunked;

    ngx_uint_t         phase;
    ngx_uint_t         phase_request_body_complete;
    ngx_uint_t         phase_response_headers_complete;
    ngx_uint_t         phase_response_body_complete;
    
    ngx_uint_t         if_status;
    ngx_uint_t         if_started_forwarding;

    size_t               reqbody_length;
    
    ngx_chain_t         *of_in;
    ngx_chain_t         *of_busy;
    ngx_chain_t         *of_free;
    ngx_chain_t         *of_out;
    ngx_chain_t         *of_err_out;
    ngx_chain_t         **of_last_out;

    ngx_uint_t         of_status;
    ngx_uint_t         of_done_reading;
    ngx_uint_t         of_skipping;
    ngx_uint_t         of_partial;
    ngx_uint_t         of_is_error;

    ngx_uint_t         resbody_status;
    size_t               resbody_length;
    char                *resbody_data;
    ngx_uint_t         resbody_contains_html;

    size_t              stream_input_length;
    char                *stream_input_data;
    size_t              stream_output_length;
    char                *stream_output_data;
    ngx_uint_t        of_stream_changed;
    ngx_uint_t        if_stream_changed;

    ngx_array_t         *error_messages;
    ngx_array_t         *alerts;

    const char          *txid;
    const char          *sessionid;
    const char          *userid;

    const char          *server_software;
    const char          *local_addr;
    ngx_uint_t           local_port;
    const char          *local_user;

    /* client */

    const char          *remote_addr;
    ngx_uint_t          remote_port;
    const char          *remote_user;
	const char			*remote_host;

    /* request */

    const char          *request_line;
    const char          *request_method;
    const char          *request_uri;
    const char          *query_string;
    const char          *request_protocol;

    const char          *hostname;

    ngx_table_t         *request_headers;

    off_t               request_content_length;
    const char          *request_content_type;

    ngx_table_t         *arguments;
    ngx_table_t         *arguments_to_sanitize;
    ngx_table_t         *request_headers_to_sanitize;
    ngx_table_t         *response_headers_to_sanitize;
    ngx_table_t         *request_cookies;
    ngx_table_t         *pattern_to_sanitize;

    ngx_uint_t        urlencoded_error;
    ngx_uint_t        inbound_error;
    ngx_uint_t        outbound_error;

    ngx_uint_t         is_relevant;

    ngx_table_t         *tx_vars;

    /* ENH: refactor to allow arbitrary var tables */
    ngx_table_t         *geo_vars;

    /* response */
    ngx_uint_t         response_status;
    const char          *status_line;
    const char          *response_protocol;
    ngx_table_t         *response_headers;
    ngx_uint_t        response_headers_sent;
    off_t               bytes_sent;

    /* modsecurity request body processing stuff */

    ngx_uint_t         msc_reqbody_storage;       /* on disk or in memory */
    ngx_uint_t         msc_reqbody_spilltodisk;
    ngx_uint_t         msc_reqbody_read;

    ngx_pool_t          *msc_reqbody_mp;             /* this is where chunks are allocated from  */
    ngx_array_t         *msc_reqbody_chunks;         /* data chunks when stored in memory        */
    ngx_uint_t         msc_reqbody_length;         /* the amount of data received              */
    ngx_uint_t         msc_reqbody_chunk_position; /* used when retrieving the body            */
    ngx_uint_t         msc_reqbody_chunk_offset;   /* offset of the chunk currently in use     */
    msc_data_chunk      *msc_reqbody_chunk_current;  /* current chunk                            */
    char                *msc_reqbody_buffer;

    const char          *msc_reqbody_filename;       /* when stored on disk */
    int                  msc_reqbody_fd;
    msc_data_chunk      *msc_reqbody_disk_chunk;

    const char          *msc_reqbody_processor;
    int                  msc_reqbody_error;
    const char          *msc_reqbody_error_msg;

    size_t              msc_reqbody_no_files_length;

    char		        *msc_full_request_buffer;
    int			        msc_full_request_length;

    char                *multipart_filename;
    char                *multipart_name;
    multipart_data      *mpd;                        /* MULTIPART processor data structure */

    xml_data            *xml;                        /* XML processor data structure       */
    json_data           *json;                       /* JSON processor data structure      */

    /* audit logging */
    char                *new_auditlog_boundary;
    char                *new_auditlog_filename;
    ngx_file_t          *new_auditlog_fd;
    ngx_uint_t        new_auditlog_size;
    ngx_md5_t           new_auditlog_md5ctx;

    ngx_uint_t         was_intercepted;
    ngx_uint_t         rule_was_intercepted;
    ngx_uint_t         intercept_phase;
    msre_actionset      *intercept_actionset;
    const char          *intercept_message;

    /* performance measurement */
    ngx_ext_time_t   request_time;
    ngx_ext_time_t	 time_phase1;
    ngx_ext_time_t	 time_phase2;
    ngx_ext_time_t	 time_phase3;
    ngx_ext_time_t	 time_phase4;
    ngx_ext_time_t	 time_phase5;
    ngx_ext_time_t	 time_storage_read;
    ngx_ext_time_t	 time_storage_write;
    ngx_ext_time_t	 time_logging;
    ngx_ext_time_t	 time_gc;
    
    ngx_table_t  *perf_rules;

    ngx_array_t         *matched_rules;
    msc_string          *matched_var;
    int                  highest_severity;

    /* upload */
    int                  upload_extract_files;
    int                  upload_remove_files;
    int                  upload_files_count;

    /* other */
    ngx_table_t         *collections_original;
    ngx_table_t         *collections;
    ngx_table_t         *collections_dirty;

    /* rule processing temp pool */
    ngx_pool_t          *msc_rule_mptmp;

    /* content injection */
    const char          *content_prepend;
    off_t               content_prepend_len;
    const char          *content_append;
    off_t               content_append_len;

    /* data cache */
    ngx_hash2_t          *tcache;
    size_t           tcache_items;

    /* removed rules */
    ngx_array_t  *removed_rules;
    ngx_array_t  *removed_rules_tag;
    ngx_array_t  *removed_rules_msg;

    /* removed targets */
    ngx_table_t         *removed_targets;

    /* When "allow" is executed the variable below is
     * updated to contain the scope of the allow action. Set
     * at 0 by default, it will have ACTION_ALLOW if we are
     * to allow phases 1-4 and ACTION_ALLOW_REQUEST if we
     * are to allow phases 1-2 only.
     */
    ngx_uint_t         allow_scope;

    /* matched vars */
    ngx_table_t         *matched_vars;

    /* Generic request body processor context to be used by custom parsers. */
    void                *reqbody_processor_ctx;

    htmlDocPtr          crypto_html_tree;

    int                 msc_sqlite_delete_error;
};

struct error_message_t {
    const char          *file;
    int                  line;
    int                  level;
    ngx_int_t         status;
    const char          *message;
};

struct msc_arg {
    const char              *name;
    ngx_uint_t             name_len;
    ngx_uint_t             name_origin_offset;
    ngx_uint_t             name_origin_len;
    const char              *value;
    ngx_uint_t             value_len;
    ngx_uint_t             value_origin_offset;
    ngx_uint_t             value_origin_len;
    const char              *origin;
};

struct msc_string {
    char                    *name;
    ngx_uint_t             name_len;
    char                    *value;
    ngx_uint_t             value_len;
};

struct msc_parm {
    char                    *value;
    int                     pad_1;
    int                     pad_2;
};

struct msc_data_chunk {
    char                 *data;
    size_t               length;
    ngx_uint_t           is_permanent;
};

msc_engine  *modsecurity_create(ngx_pool_t *mp, int processing_mode);

ngx_int_t  modsecurity_tx_init(modsec_rec *msr);

const char * msc_alert_message(modsec_rec *msr, msre_actionset *actionset, const char *action_message,const char *rule_message);

void msc_alert(modsec_rec *msr, int level, msre_actionset *actionset, const char *action_message,const char *rule_message);

ngx_int_t modsecurity_request_body_start(modsec_rec *msr, char **error_msg);

ngx_int_t  modsecurity_request_body_store(modsec_rec *msr,const char *data, size_t length, char **error_msg);

ngx_int_t  modsecurity_request_body_to_stream(modsec_rec *msr, const char *buffer, int buflen, char **error_msg);

ngx_int_t  modsecurity_request_body_end(modsec_rec *msr, char **error_msg);

ngx_int_t  modsecurity_request_body_retrieve_start(modsec_rec *msr, char **error_msg);

ngx_int_t  modsecurity_request_body_retrieve_end(modsec_rec *msr);

/* Retrieves up to nbytes bytes of the request body. Returns 1 on
 * success, 0 when there is no more data, or -1 on error. On return
 * nbytes will contain the number of bytes stored in the buffer.
 */
ngx_int_t  modsecurity_request_body_retrieve(modsec_rec *msr, msc_data_chunk **chunk,long int nbytes, char **error_msg);

ngx_int_t  modsecurity_request_body_clear(modsec_rec *msr, char **error_msg);

ngx_int_t  modsecurity_process_phase(modsec_rec *msr, unsigned int phase);

ngx_int_t modsec_perform_interception(modsec_rec *msr);

const command_rec *modsec_find_command(const char *cmdname);
#endif /*_MODSECURITY_H_*/
