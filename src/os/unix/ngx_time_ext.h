#ifndef NGX_TIME_EXT_H
#define NGX_TIME_EXT_H

#include <ngx_config.h>
#include <ngx_core.h>

/**
 * @defgroup ngx_ext_time Time Routines
 * @ingroup NGX 
 * @{
 */

/** month names */
extern const char ngx_ext_month_snames[12][4];
/** day names */
extern const char ngx_ext_day_snames[7][4];


/** number of microseconds since 00:00:00 january 1, 1970 UTC */
typedef int64_t ngx_ext_time_t;


/** mechanism to properly type ngx_ext_time_t literals */
#define NGX_TIME_C(val) (val ## L)

/** mechanism to properly print ngx_ext_time_t values */
#define NGX_TIME_T_FMT "T"

/** intervals for I/O timeouts, in microseconds */
typedef int64_t ngx_ext_interval_time_t;
/** short interval for I/O timeouts, in microseconds */
typedef int32_t ngx_ext_short_interval_time_t;

/** number of microseconds per second */
#define NGX_USEC_PER_SEC NGX_TIME_C(1000000)

/** @return ngx_ext_time_t as a second */
#define ngx_ext_time_sec(time) ((time) / NGX_USEC_PER_SEC)

/** @return ngx_ext_time_t as a usec */
#define ngx_ext_time_usec(time) ((time) % NGX_USEC_PER_SEC)

/** @return ngx_ext_time_t as a msec */
#define ngx_ext_time_msec(time) (((time) / 1000) % 1000)

/** @return ngx_ext_time_t as a msec */
#define ngx_ext_time_as_msec(time) ((time) / 1000)

/** @return milliseconds as an ngx_ext_time_t */
#define ngx_ext_time_from_msec(msec) ((ngx_ext_time_t)(msec) * 1000)

/** @return seconds as an ngx_ext_time_t */
#define ngx_ext_time_from_sec(sec) ((ngx_ext_time_t)(sec) * NGX_USEC_PER_SEC)

/** @return a second and usec combination as an ngx_ext_time_t */
#define ngx_ext_time_make(sec, usec) ((ngx_ext_time_t)(sec) * NGX_USEC_PER_SEC \
                                + (ngx_ext_time_t)(usec))

/**
 * @return the current time
 */
ngx_ext_time_t ngx_ext_time_now(void);

/** @see ngx_ext_time_exp_t */
typedef struct ngx_ext_time_exp_t ngx_ext_time_exp_t;

/**
 * a structure similar to ANSI struct tm with the following differences:
 *  - tm_usec isn't an ANSI field
 *  - tm_gmtoff isn't an ANSI field (it's a bsdism)
 */
struct ngx_ext_time_exp_t {
    /** microseconds past tm_sec */
    int32_t tm_usec;
    /** (0-61) seconds past tm_min */
    int32_t tm_sec;
    /** (0-59) minutes past tm_hour */
    int32_t tm_min;
    /** (0-23) hours past midnight */
    int32_t tm_hour;
    /** (1-31) day of the month */
    int32_t tm_mday;
    /** (0-11) month of the year */
    int32_t tm_mon;
    /** year since 1900 */
    int32_t tm_year;
    /** (0-6) days since sunday */
    int32_t tm_wday;
    /** (0-365) days since jan 1 */
    int32_t tm_yday;
    /** daylight saving time */
    int32_t tm_isdst;
    /** seconds east of UTC */
    int32_t tm_gmtoff;
};

/**
 * convert an ansi time_t to an ngx_ext_time_t
 * @param result the resulting ngx_ext_time_t
 * @param input the time_t to convert
 */
ngx_int_t ngx_ext_time_ansi_put(ngx_ext_time_t *result, 
                                                    time_t input);

/**
 * convert a time to its human readable components using an offset
 * from GMT
 * @param result the exploded time
 * @param input the time to explode
 * @param offs the number of seconds offset to apply
 */
ngx_int_t ngx_ext_time_exp_tz(ngx_ext_time_exp_t *result,
                                          ngx_ext_time_t input,
                                          int32_t offs);

/**
 * convert a time to its human readable components in GMT timezone
 * @param result the exploded time
 * @param input the time to explode
 */
ngx_int_t ngx_ext_time_exp_gmt(ngx_ext_time_exp_t *result, 
                                           ngx_ext_time_t input);

/**
 * convert a time to its human readable components in local timezone
 * @param result the exploded time
 * @param input the time to explode
 */
ngx_int_t ngx_ext_time_exp_lt(ngx_ext_time_exp_t *result, 
                                          ngx_ext_time_t input);

/**
 * Convert time value from human readable format to a numeric ngx_ext_time_t 
 * e.g. elapsed usec since epoch
 * @param result the resulting imploded time
 * @param input the input exploded time
 */
ngx_int_t ngx_ext_time_exp_get(ngx_ext_time_t *result, 
                                           ngx_ext_time_exp_t *input);

/**
 * Convert time value from human readable format to a numeric ngx_ext_time_t that
 * always represents GMT
 * @param result the resulting imploded time
 * @param input the input exploded time
 */
ngx_int_t ngx_ext_time_exp_gmt_get(ngx_ext_time_t *result, 
                                               ngx_ext_time_exp_t *input);

/**
 * Sleep for the specified number of micro-seconds.
 * @param t desired amount of time to sleep.
 * @warning May sleep for longer than the specified time. 
 */
void ngx_ext_sleep(ngx_ext_interval_time_t t);

/** length of a RFC822 Date */
#define NGX_RFC822_DATE_LEN (30)
/**
 * ngx_ext_rfc822_date formats dates in the RFC822
 * format in an efficient manner.  It is a fixed length
 * format which requires the indicated amount of storage,
 * including the trailing NUL terminator.
 * @param date_str String to write to.
 * @param t the time to convert 
 */
ngx_int_t ngx_ext_rfc822_date(char *date_str, ngx_ext_time_t t);

/** length of a CTIME date */
#define NGX_CTIME_LEN (25)
/**
 * ngx_ext_ctime formats dates in the ctime() format
 * in an efficient manner.  it is a fixed length format
 * and requires the indicated amount of storage including
 * the trailing NUL terminator.
 * Unlike ANSI/ISO C ctime(), ngx_ext_ctime() does not include
 * a \n at the end of the string.
 * @param date_str String to write to.
 * @param t the time to convert 
 */
ngx_int_t ngx_ext_ctime(char *date_str, ngx_ext_time_t t);

/**
 * formats the exploded time according to the format specified
 * @param s string to write to
 * @param retsize The length of the returned string
 * @param max The maximum length of the string
 * @param format The format for the time string
 * @param tm The time to convert
 */
ngx_int_t ngx_ext_strftime(char *s, size_t *retsize, 
                                       size_t max, const char *format, 
                                       ngx_ext_time_exp_t *tm);

/**
 * Improve the clock resolution for the lifetime of the given pool.
 * Generally this is only desireable on benchmarking and other very
 * time-sensitive applications, and has no impact on most platforms.
 * @param p The pool to associate the finer clock resolution 
 */
void ngx_ext_time_clock_hires(ngx_pool_t *p);

#endif  /* ! NGX_TIME_EXT_H */
