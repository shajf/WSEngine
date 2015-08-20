/*shajf*/
#ifndef CONFIG_H
#define CONFIG_H

#include <ngx_config.h>
#include <ngx_core.h>

#define DECLINE_CMD "\a\b"

typedef struct cmd_parms_struct cmd_parms;
typedef struct command_struct command_rec;

/**
 * How the directives arguments should be parsed.
 * @remark Note that for all of these except RAW_ARGS, the config routine is
 *      passed a freshly allocated string which can be modified or stored
 *      or whatever...
 */
enum cmd_how {
	RAW_ARGS,           /**< cmd_func parses command line itself */
	TAKE1,              /**< one argument only */
	TAKE2,              /**< two arguments only */
	ITERATE,            /**< one argument, occuring multiple times
			 * (e.g., IndexIgnore)
			 */
	ITERATE2,           /**< two arguments, 2nd occurs multiple times
			 * (e.g., AddIcon)
			 */
	FLAG,               /**< One of 'On' or 'Off' */
	NO_ARGS,            /**< No args at all, e.g. &lt;/Directory&gt; */
	TAKE12,             /**< one or two arguments */
	TAKE3,              /**< three arguments only */
	TAKE23,             /**< two or three arguments */
	TAKE123,            /**< one, two or three arguments */
	TAKE13,             /**< one or three arguments */
	TAKE_ARGV           /**< an argc and argv are passed */
};


/**
 * This structure is passed to a command which is being invoked,
 * to carry a large variety of miscellaneous data which is all of
 * use to *somebody*...
 */
struct cmd_parms_struct {
	/** Argument to command from cmd_table */
	void *info;

	/** Config file structure. */
	ngx_configfile_t *config_file;

	/** Pool to allocate new storage in */
	ngx_pool_t *pool;
	/** Pool for scratch memory; persists during configuration, but
	*  wiped before the first request is served...  */
	ngx_pool_t *temp_pool;
	/** If configuring for a directory, pathname of that directory.
	*  NOPE!  That's what it meant previous to the existence of &lt;Files&gt;,
	* &lt;Location&gt; and regex matching.  Now the only usefulness that can be
	* derived from this field is whether a command is being called in a
	* server context (path == NULL) or being called in a dir context
	* (path != NULL).  */
	char *path;
	/** configuration command */
	const command_rec *cmd;
};

/**
 * All the types of functions that can be used in directives
 * @internal
 */
typedef union {
    /** function to call for a no-args */
    const char *(*no_args) (cmd_parms *parms, void *mconfig);
    /** function to call for a raw-args */
    const char *(*raw_args) (cmd_parms *parms, void *mconfig,
                             const char *args);
    /** function to call for a argv/argc */
    const char *(*take_argv) (cmd_parms *parms, void *mconfig,
                             int argc, char *const argv[]);
    /** function to call for a take1 */
    const char *(*take1) (cmd_parms *parms, void *mconfig, const char *w);
    /** function to call for a take2 */
    const char *(*take2) (cmd_parms *parms, void *mconfig, const char *w,
                          const char *w2);
    /** function to call for a take3 */
    const char *(*take3) (cmd_parms *parms, void *mconfig, const char *w,
                          const char *w2, const char *w3);
    /** function to call for a flag */
    const char *(*flag) (cmd_parms *parms, void *mconfig, int on);
} cmd_func;

/** This configuration directive does not take any arguments */
# define MSCNO_ARGS     func.no_args
/** This configuration directive will handle its own parsing of arguments*/
# define MSCRAW_ARGS    func.raw_args
/** This configuration directive will handle its own parsing of arguments*/
# define MSCTAKE_ARGV   func.take_argv
/** This configuration directive takes 1 argument*/
# define MSCTAKE1       func.take1
/** This configuration directive takes 2 arguments */
# define MSCTAKE2       func.take2
/** This configuration directive takes 3 arguments */
# define MSCTAKE3       func.take3
/** This configuration directive takes a flag (on/off) as a argument*/
# define MSCFLAG        func.flag

/** mechanism for declaring a directive with no arguments */
# define INIT_NO_ARGS(directive, func, mconfig,  help) \
    { directive, { .no_args=func }, mconfig,  RAW_ARGS, help }
/** mechanism for declaring a directive with raw argument parsing */
# define INIT_RAW_ARGS(directive, func, mconfig,  help) \
    { directive, { .raw_args=func }, mconfig,  RAW_ARGS, help }
/** mechanism for declaring a directive with raw argument parsing */
# define INIT_TAKE_ARGV(directive, func, mconfig,  help) \
    { directive, { .take_argv=func }, mconfig,  TAKE_ARGV, help }
/** mechanism for declaring a directive which takes 1 argument */
# define INIT_TAKE1(directive, func, mconfig,  help) \
    { directive, { .take1=func }, mconfig,  TAKE1, help }
/** mechanism for declaring a directive which takes multiple arguments */
# define INIT_ITERATE(directive, func, mconfig,  help) \
    { directive, { .take1=func }, mconfig,  ITERATE, help }
/** mechanism for declaring a directive which takes 2 arguments */
# define INIT_TAKE2(directive, func, mconfig,  help) \
    { directive, { .take2=func }, mconfig,  TAKE2, help }
/** mechanism for declaring a directive which takes 1 or 2 arguments */
# define INIT_TAKE12(directive, func, mconfig,  help) \
    { directive, { .take2=func }, mconfig,  TAKE12, help }
/** mechanism for declaring a directive which takes multiple 2 arguments */
# define INIT_ITERATE2(directive, func, mconfig,  help) \
    { directive, { .take2=func }, mconfig,  ITERATE2, help }
/** mechanism for declaring a directive which takes 1 or 3 arguments */
# define INIT_TAKE13(directive, func, mconfig,  help) \
    { directive, { .take3=func }, mconfig,  TAKE13, help }
/** mechanism for declaring a directive which takes 2 or 3 arguments */
# define INIT_TAKE23(directive, func, mconfig,  help) \
    { directive, { .take3=func }, mconfig,  TAKE23, help }
/** mechanism for declaring a directive which takes 1 to 3 arguments */
# define INIT_TAKE123(directive, func, mconfig,  help) \
    { directive, { .take3=func }, mconfig,  TAKE123, help }
/** mechanism for declaring a directive which takes 3 arguments */
# define INIT_TAKE3(directive, func, mconfig,  help) \
    { directive, { .take3=func }, mconfig,  TAKE3, help }
/** mechanism for declaring a directive which takes a flag (on/off) argument */
# define INIT_FLAG(directive, func, mconfig,  help) \
    { directive, { .flag=func }, mconfig,  FLAG, help }

struct command_struct{
	/* name of this command */
	const char *name;
	/*The function te be called when this directive is parsed*/
	cmd_func func;
	/*Extra data,for functions which implemente multiple commands */
	void *cmd_data;
	/* What the command expects as arguments */
	enum cmd_how args_how;
	/* * 'usage' message, in case of syntax errors*/
	const char *errmsg;
};

const char* read_config(int modid,void *mconfig,ngx_pool_t *p,ngx_pool_t *ptemp,const char* filename);

#endif /*CONFIG_H*/
