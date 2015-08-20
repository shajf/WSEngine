#include <ngx_config.h>
#include <ngx_core.h>

static int32_t get_offset(struct tm *tm)
{
    return tm->tm_gmtoff;
}

ngx_int_t ngx_ext_time_ansi_put(ngx_ext_time_t *result,
                                            time_t input)
{
    *result = (ngx_ext_time_t)input * NGX_USEC_PER_SEC;
    return NGX_OK;
}

/* NB NB NB NB This returns GMT!!!!!!!!!! */
ngx_ext_time_t ngx_ext_time_now(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * NGX_USEC_PER_SEC + tv.tv_usec;
}

static void explode_time(ngx_ext_time_exp_t *xt, ngx_ext_time_t t,
                         int32_t offset, int use_localtime)
{
    struct tm tm;
    time_t tt = (t / NGX_USEC_PER_SEC) + offset;
    xt->tm_usec = t % NGX_USEC_PER_SEC;

#if NGX_HAS_THREADS && defined (_POSIX_THREAD_SAFE_FUNCTIONS)
    if (use_localtime)
        localtime_r(&tt, &tm);
    else
        gmtime_r(&tt, &tm);
#else
    if (use_localtime)
        tm = *localtime(&tt);
    else
        tm = *gmtime(&tt);
#endif

    xt->tm_sec  = tm.tm_sec;
    xt->tm_min  = tm.tm_min;
    xt->tm_hour = tm.tm_hour;
    xt->tm_mday = tm.tm_mday;
    xt->tm_mon  = tm.tm_mon;
    xt->tm_year = tm.tm_year;
    xt->tm_wday = tm.tm_wday;
    xt->tm_yday = tm.tm_yday;
    xt->tm_isdst = tm.tm_isdst;
    xt->tm_gmtoff = get_offset(&tm);
}

ngx_int_t ngx_ext_time_exp_tz(ngx_ext_time_exp_t *result,
                                          ngx_ext_time_t input, int32_t offs)
{
    explode_time(result, input, offs, 0);
    result->tm_gmtoff = offs;
    return NGX_OK;
}

ngx_int_t ngx_ext_time_exp_gmt(ngx_ext_time_exp_t *result,
                                           ngx_ext_time_t input)
{
    return ngx_ext_time_exp_tz(result, input, 0);
}

ngx_int_t ngx_ext_time_exp_lt(ngx_ext_time_exp_t *result,
                                                ngx_ext_time_t input)
{
#if defined(__EMX__)
    /* EMX gcc (OS/2) has a timezone global we can use */
    return ngx_ext_time_exp_tz(result, input, -timezone);
#else
    explode_time(result, input, 0, 1);
    return NGX_OK;
#endif /* __EMX__ */
}

ngx_int_t ngx_ext_time_exp_get(ngx_ext_time_t *t, ngx_ext_time_exp_t *xt)
{
    ngx_ext_time_t year = xt->tm_year;
    ngx_ext_time_t days;
    static const int dayoffset[12] =
    {306, 337, 0, 31, 61, 92, 122, 153, 184, 214, 245, 275};

    /* shift new year to 1st March in order to make leap year calc easy */

    if (xt->tm_mon < 2)
        year--;

    /* Find number of days since 1st March 1900 (in the Gregorian calendar). */

    days = year * 365 + year / 4 - year / 100 + (year / 100 + 3) / 4;
    days += dayoffset[xt->tm_mon] + xt->tm_mday - 1;
    days -= 25508;              /* 1 jan 1970 is 25508 days since 1 mar 1900 */
    days = ((days * 24 + xt->tm_hour) * 60 + xt->tm_min) * 60 + xt->tm_sec;

    if (days < 0) {
        return NGX_ERROR;
    }
    *t = days * NGX_USEC_PER_SEC + xt->tm_usec;
    return NGX_OK;
}

ngx_int_t ngx_ext_time_exp_gmt_get(ngx_ext_time_t *t, 
                                               ngx_ext_time_exp_t *xt)
{
    ngx_int_t status = ngx_ext_time_exp_get(t, xt);
    if (status == NGX_OK)
        *t -= (ngx_ext_time_t) xt->tm_gmtoff * NGX_USEC_PER_SEC;
    return status;
}
#if 0
ngx_int_t ngx_ext_os_imp_time_get(ngx_ext_os_imp_time_t **ostime,
                                              ngx_ext_time_t *ngx_exttime)
{
    (*ostime)->tv_usec = *ngx_exttime % NGX_USEC_PER_SEC;
    (*ostime)->tv_sec = *ngx_exttime / NGX_USEC_PER_SEC;
    return NGX_OK;
}

ngx_int_t ngx_ext_os_exp_time_get(ngx_ext_os_exp_time_t **ostime,
                                              ngx_ext_time_exp_t *ngx_exttime)
{
    (*ostime)->tm_sec  = ngx_exttime->tm_sec;
    (*ostime)->tm_min  = ngx_exttime->tm_min;
    (*ostime)->tm_hour = ngx_exttime->tm_hour;
    (*ostime)->tm_mday = ngx_exttime->tm_mday;
    (*ostime)->tm_mon  = ngx_exttime->tm_mon;
    (*ostime)->tm_year = ngx_exttime->tm_year;
    (*ostime)->tm_wday = ngx_exttime->tm_wday;
    (*ostime)->tm_yday = ngx_exttime->tm_yday;
    (*ostime)->tm_isdst = ngx_exttime->tm_isdst;

    (*ostime)->tm_gmtoff = ngx_exttime->tm_gmtoff;

    return NGX_OK;
}

ngx_int_t ngx_ext_os_imp_time_put(ngx_ext_time_t *ngx_exttime,
                                              ngx_ext_os_imp_time_t **ostime,
                                              ngx_pool_t *cont)
{
    *ngx_exttime = (*ostime)->tv_sec * NGX_USEC_PER_SEC + (*ostime)->tv_usec;
    return NGX_OK;
}

ngx_int_t ngx_ext_os_exp_time_put(ngx_ext_time_exp_t *ngx_exttime,
                                              ngx_ext_os_exp_time_t **ostime,
                                              ngx_pool_t *cont)
{
    ngx_exttime->tm_sec = (*ostime)->tm_sec;
    ngx_exttime->tm_min = (*ostime)->tm_min;
    ngx_exttime->tm_hour = (*ostime)->tm_hour;
    ngx_exttime->tm_mday = (*ostime)->tm_mday;
    ngx_exttime->tm_mon = (*ostime)->tm_mon;
    ngx_exttime->tm_year = (*ostime)->tm_year;
    ngx_exttime->tm_wday = (*ostime)->tm_wday;
    ngx_exttime->tm_yday = (*ostime)->tm_yday;
    ngx_exttime->tm_isdst = (*ostime)->tm_isdst;

    ngx_exttime->tm_gmtoff = (*ostime)->tm_gmtoff;

    return NGX_OK;
}
#endif
void ngx_ext_sleep(ngx_ext_interval_time_t t)
{
    struct timeval tv;
    tv.tv_usec = t % NGX_USEC_PER_SEC;
    tv.tv_sec = t / NGX_USEC_PER_SEC;
    select(0, NULL, NULL, NULL, &tv);
}

void ngx_ext_unix_setup_time(void)
{
}

/* A noop on all known Unix implementations */
void ngx_ext_time_clock_hires(ngx_pool_t *p)
{
    return;
}


const char ngx_ext_month_snames[12][4] =
{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

const char ngx_ext_day_snames[7][4] =
{
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

ngx_int_t ngx_ext_rfc822_date(char *date_str, ngx_ext_time_t t)
{
    ngx_ext_time_exp_t xt;
    const char *s;
    int real_year;

    ngx_ext_time_exp_gmt(&xt, t);

    /* example: "Sat, 08 Jan 2000 18:31:41 GMT" */
    /*           12345678901234567890123456789  */

    s = &ngx_ext_day_snames[xt.tm_wday][0];
    *date_str++ = *s++;
    *date_str++ = *s++;
    *date_str++ = *s++;
    *date_str++ = ',';
    *date_str++ = ' ';
    *date_str++ = xt.tm_mday / 10 + '0';
    *date_str++ = xt.tm_mday % 10 + '0';
    *date_str++ = ' ';
    s = &ngx_ext_month_snames[xt.tm_mon][0];
    *date_str++ = *s++;
    *date_str++ = *s++;
    *date_str++ = *s++;
    *date_str++ = ' ';
    real_year = 1900 + xt.tm_year;
    /* This routine isn't y10k ready. */
    *date_str++ = real_year / 1000 + '0';
    *date_str++ = real_year % 1000 / 100 + '0';
    *date_str++ = real_year % 100 / 10 + '0';
    *date_str++ = real_year % 10 + '0';
    *date_str++ = ' ';
    *date_str++ = xt.tm_hour / 10 + '0';
    *date_str++ = xt.tm_hour % 10 + '0';
    *date_str++ = ':';
    *date_str++ = xt.tm_min / 10 + '0';
    *date_str++ = xt.tm_min % 10 + '0';
    *date_str++ = ':';
    *date_str++ = xt.tm_sec / 10 + '0';
    *date_str++ = xt.tm_sec % 10 + '0';
    *date_str++ = ' ';
    *date_str++ = 'G';
    *date_str++ = 'M';
    *date_str++ = 'T';
    *date_str++ = 0;
    return NGX_OK;
}

ngx_int_t ngx_ext_ctime(char *date_str, ngx_ext_time_t t)
{
    ngx_ext_time_exp_t xt;
    const char *s;
    int real_year;

    /* example: "Wed Jun 30 21:49:08 1993" */
    /*           123456789012345678901234  */

    ngx_ext_time_exp_lt(&xt, t);
    s = &ngx_ext_day_snames[xt.tm_wday][0];
    *date_str++ = *s++;
    *date_str++ = *s++;
    *date_str++ = *s++;
    *date_str++ = ' ';
    s = &ngx_ext_month_snames[xt.tm_mon][0];
    *date_str++ = *s++;
    *date_str++ = *s++;
    *date_str++ = *s++;
    *date_str++ = ' ';
    *date_str++ = xt.tm_mday / 10 + '0';
    *date_str++ = xt.tm_mday % 10 + '0';
    *date_str++ = ' ';
    *date_str++ = xt.tm_hour / 10 + '0';
    *date_str++ = xt.tm_hour % 10 + '0';
    *date_str++ = ':';
    *date_str++ = xt.tm_min / 10 + '0';
    *date_str++ = xt.tm_min % 10 + '0';
    *date_str++ = ':';
    *date_str++ = xt.tm_sec / 10 + '0';
    *date_str++ = xt.tm_sec % 10 + '0';
    *date_str++ = ' ';
    real_year = 1900 + xt.tm_year;
    *date_str++ = real_year / 1000 + '0';
    *date_str++ = real_year % 1000 / 100 + '0';
    *date_str++ = real_year % 100 / 10 + '0';
    *date_str++ = real_year % 10 + '0';
    *date_str++ = 0;

    return NGX_OK;
}

ngx_int_t ngx_ext_strftime(char *s, size_t *retsize, size_t max, 
                        const char *format, ngx_ext_time_exp_t *xt)
{
    struct tm tm;
    memset(&tm, 0, sizeof tm);
    tm.tm_sec  = xt->tm_sec;
    tm.tm_min  = xt->tm_min;
    tm.tm_hour = xt->tm_hour;
    tm.tm_mday = xt->tm_mday;
    tm.tm_mon  = xt->tm_mon;
    tm.tm_year = xt->tm_year;
    tm.tm_wday = xt->tm_wday;
    tm.tm_yday = xt->tm_yday;
    tm.tm_isdst = xt->tm_isdst;
    tm.tm_gmtoff = xt->tm_gmtoff;
    (*retsize) = strftime(s, max, format, &tm);
    return NGX_OK;
}
