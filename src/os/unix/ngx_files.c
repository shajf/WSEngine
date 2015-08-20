
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_HAVE_FILE_AIO)

ngx_uint_t  ngx_file_aio = 1;

#endif


ssize_t
ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{
    ssize_t  n;
    
    if(file->log){
        ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                       "read: %d, %p, %uz, %O", file->fd, buf, size, offset);
    }

#if (NGX_HAVE_PREAD)

    n = pread(file->fd, buf, size, offset);

    if (n == -1) {
        if(file->log){
            ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                      "pread() \"%s\" failed", file->name.data);
        }
        return NGX_ERROR;
    }

#else

    if (file->sys_offset != offset) {
        if (lseek(file->fd, offset, SEEK_SET) == -1) {
            if(file->log){
                ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                          "lseek() \"%s\" failed", file->name.data);
            }
            return NGX_ERROR;
        }

        file->sys_offset = offset;
    }

    n = read(file->fd, buf, size);

    if (n == -1) {
        if(file->log){
            ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                      "read() \"%s\" failed", file->name.data);
        }
        return NGX_ERROR;
    }

    file->sys_offset += n;

#endif

    file->offset += n;

    return n;
}


ssize_t
ngx_write_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{
    ssize_t  n, written;

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "write: %d, %p, %uz, %O", file->fd, buf, size, offset);

    written = 0;

#if (NGX_HAVE_PWRITE)

    for ( ;; ) {
        n = pwrite(file->fd, buf + written, size, offset);

        if (n == -1) {
            ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                          "pwrite() \"%s\" failed", file->name.data);
            return NGX_ERROR;
        }

        file->offset += n;
        written += n;

        if ((size_t) n == size) {
            return written;
        }

        offset += n;
        size -= n;
    }

#else

    if (file->sys_offset != offset) {
        if (lseek(file->fd, offset, SEEK_SET) == -1) {
            ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                          "lseek() \"%s\" failed", file->name.data);
            return NGX_ERROR;
        }

        file->sys_offset = offset;
    }

    for ( ;; ) {
        n = write(file->fd, buf + written, size);

        if (n == -1) {
            ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                          "write() \"%s\" failed", file->name.data);
            return NGX_ERROR;
        }

        file->offset += n;
        written += n;

        if ((size_t) n == size) {
            return written;
        }

        size -= n;
    }
#endif
}


ngx_fd_t
ngx_open_tempfile(u_char *name, ngx_uint_t persistent, ngx_uint_t access)
{
    ngx_fd_t  fd;

    fd = open((const char *) name, O_CREAT|O_EXCL|O_RDWR,
              access ? access : 0600);

    if (fd != -1 && !persistent) {
        (void) unlink((const char *) name);
    }

    return fd;
}


#define NGX_IOVS  8

ssize_t
ngx_write_chain_to_file(ngx_file_t *file, ngx_chain_t *cl, off_t offset,
    ngx_pool_t *pool)
{
    u_char        *prev;
    size_t         size;
    ssize_t        total, n;
    ngx_array_t    vec;
    struct iovec  *iov, iovs[NGX_IOVS];

    /* use pwrite() if there is the only buf in a chain */

    if (cl->next == NULL) {
        return ngx_write_file(file, cl->buf->pos,
                              (size_t) (cl->buf->last - cl->buf->pos),
                              offset);
    }

    total = 0;

    vec.elts = iovs;
    vec.size = sizeof(struct iovec);
    vec.nalloc = NGX_IOVS;
    vec.pool = pool;

    do {
        prev = NULL;
        iov = NULL;
        size = 0;

        vec.nelts = 0;

        /* create the iovec and coalesce the neighbouring bufs */

        while (cl && vec.nelts < IOV_MAX) {
            if (prev == cl->buf->pos) {
                iov->iov_len += cl->buf->last - cl->buf->pos;

            } else {
                iov = ngx_array_push(&vec);
                if (iov == NULL) {
                    return NGX_ERROR;
                }

                iov->iov_base = (void *) cl->buf->pos;
                iov->iov_len = cl->buf->last - cl->buf->pos;
            }

            size += cl->buf->last - cl->buf->pos;
            prev = cl->buf->last;
            cl = cl->next;
        }

        /* use pwrite() if there is the only iovec buffer */

        if (vec.nelts == 1) {
            iov = vec.elts;

            n = ngx_write_file(file, (u_char *) iov[0].iov_base,
                               iov[0].iov_len, offset);

            if (n == NGX_ERROR) {
                return n;
            }

            return total + n;
        }

        if (file->sys_offset != offset) {
            if (lseek(file->fd, offset, SEEK_SET) == -1) {
                ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                              "lseek() \"%s\" failed", file->name.data);
                return NGX_ERROR;
            }

            file->sys_offset = offset;
        }

        n = writev(file->fd, vec.elts, vec.nelts);

        if (n == -1) {
            ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                          "writev() \"%s\" failed", file->name.data);
            return NGX_ERROR;
        }

        if ((size_t) n != size) {
            ngx_log_error(NGX_LOG_CRIT, file->log, 0,
                          "writev() \"%s\" has written only %z of %uz",
                          file->name.data, n, size);
            return NGX_ERROR;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, file->log, 0,
                       "writev: %d, %z", file->fd, n);

        file->sys_offset += n;
        file->offset += n;
        offset += n;
        total += n;

    } while (cl);

    return total;
}


ngx_int_t
ngx_set_file_time(u_char *name, ngx_fd_t fd, time_t s)
{
    struct timeval  tv[2];

    tv[0].tv_sec = ngx_time();
    tv[0].tv_usec = 0;
    tv[1].tv_sec = s;
    tv[1].tv_usec = 0;

    if (utimes((char *) name, tv) != -1) {
        return NGX_OK;
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_create_file_mapping(ngx_file_mapping_t *fm)
{
    fm->fd = ngx_open_file(fm->name, NGX_FILE_RDWR, NGX_FILE_TRUNCATE,
                           NGX_FILE_DEFAULT_ACCESS);
    if (fm->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", fm->name);
        return NGX_ERROR;
    }

    if (ftruncate(fm->fd, fm->size) == -1) {
        ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
                      "ftruncate() \"%s\" failed", fm->name);
        goto failed;
    }

    fm->addr = mmap(NULL, fm->size, PROT_READ|PROT_WRITE, MAP_SHARED,
                    fm->fd, 0);
    if (fm->addr != MAP_FAILED) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
                  "mmap(%uz) \"%s\" failed", fm->size, fm->name);

failed:

    if (ngx_close_file(fm->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, fm->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", fm->name);
    }

    return NGX_ERROR;
}


void
ngx_close_file_mapping(ngx_file_mapping_t *fm)
{
    if (munmap(fm->addr, fm->size) == -1) {
        ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
                      "munmap(%uz) \"%s\" failed", fm->size, fm->name);
    }

    if (ngx_close_file(fm->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, fm->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", fm->name);
    }
}


ngx_int_t
ngx_open_dir(ngx_str_t *name, ngx_dir_t *dir)
{
    dir->dir = opendir((const char *) name->data);

    if (dir->dir == NULL) {
        return NGX_ERROR;
    }

    dir->valid_info = 0;

    return NGX_OK;
}


ngx_int_t
ngx_read_dir(ngx_dir_t *dir)
{
    dir->de = readdir(dir->dir);

    if (dir->de) {
#if (NGX_HAVE_D_TYPE)
        dir->type = dir->de->d_type;
#else
        dir->type = 0;
#endif
        return NGX_OK;
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_open_glob(ngx_glob_t *gl)
{
    int  n;

    n = glob((char *) gl->pattern, 0, NULL, &gl->pglob);

    if (n == 0) {
        return NGX_OK;
    }

#ifdef GLOB_NOMATCH

    if (n == GLOB_NOMATCH && gl->test) {
        return NGX_OK;
    }

#endif

    return NGX_ERROR;
}


ngx_int_t
ngx_read_glob(ngx_glob_t *gl, ngx_str_t *name)
{
    size_t  count;

#ifdef GLOB_NOMATCH
    count = (size_t) gl->pglob.gl_pathc;
#else
    count = (size_t) gl->pglob.gl_matchc;
#endif

    if (gl->n < count) {

        name->len = (size_t) ngx_strlen(gl->pglob.gl_pathv[gl->n]);
        name->data = (u_char *) gl->pglob.gl_pathv[gl->n];
        gl->n++;

        return NGX_OK;
    }

    return NGX_DONE;
}


void
ngx_close_glob(ngx_glob_t *gl)
{
    globfree(&gl->pglob);
}


ngx_err_t
ngx_trylock_fd(ngx_fd_t fd)
{
    struct flock  fl;

    ngx_memzero(&fl, sizeof(struct flock));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        return ngx_errno;
    }

    return 0;
}


ngx_err_t
ngx_lock_fd(ngx_fd_t fd)
{
    struct flock  fl;

    ngx_memzero(&fl, sizeof(struct flock));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLKW, &fl) == -1) {
        return ngx_errno;
    }

    return 0;
}


ngx_err_t
ngx_unlock_fd(ngx_fd_t fd)
{
    struct flock  fl;

    ngx_memzero(&fl, sizeof(struct flock));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        return  ngx_errno;
    }

    return 0;
}


#if (NGX_HAVE_POSIX_FADVISE) && !(NGX_HAVE_F_READAHEAD)

ngx_int_t
ngx_read_ahead(ngx_fd_t fd, size_t n)
{
    int  err;

    err = posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);

    if (err == 0) {
        return 0;
    }

    ngx_set_errno(err);
    return NGX_FILE_ERROR;
}

#endif


#if (NGX_HAVE_O_DIRECT)

ngx_int_t
ngx_directio_on(ngx_fd_t fd)
{
    int  flags;

    flags = fcntl(fd, F_GETFL);

    if (flags == -1) {
        return NGX_FILE_ERROR;
    }

    return fcntl(fd, F_SETFL, flags | O_DIRECT);
}


ngx_int_t
ngx_directio_off(ngx_fd_t fd)
{
    int  flags;

    flags = fcntl(fd, F_GETFL);

    if (flags == -1) {
        return NGX_FILE_ERROR;
    }

    return fcntl(fd, F_SETFL, flags & ~O_DIRECT);
}

#endif


#if (NGX_HAVE_STATFS)

size_t
ngx_fs_bsize(u_char *name)
{
    struct statfs  fs;

    if (statfs((char *) name, &fs) == -1) {
        return 512;
    }

    if ((fs.f_bsize % 512) != 0) {
        return 512;
    }

    return (size_t) fs.f_bsize;
}

#elif (NGX_HAVE_STATVFS)

size_t
ngx_fs_bsize(u_char *name)
{
    struct statvfs  fs;

    if (statvfs((char *) name, &fs) == -1) {
        return 512;
    }

    if ((fs.f_frsize % 512) != 0) {
        return 512;
    }

    return (size_t) fs.f_frsize;
}

#else

size_t
ngx_fs_bsize(u_char *name)
{
    return 512;
}

#endif


/* Any OS that requires/refuses trailing slashes should be dealt with here.
 */
ngx_int_t ngx_filepath_get(char **defpath, int32_t flags,
                                           ngx_pool_t *p)
{
    char path[NGX_PATH_MAX];

    if (!getcwd(path, sizeof(path))) {
            return NGX_ERROR;
    }
    *defpath = ngx_pstrndup(p, path);

    return NGX_OK;
}


/* Filepath_name_get returns the final element of the pathname.
 * Using the current platform's filename syntax.
 *   "/foo/bar/gum" -> "gum"
 *   "/foo/bar/gum/" -> ""
 *   "gum" -> "gum"
 *   "wi\\n32\\stuff" -> "stuff
 *
 * Corrected Win32 to accept "a/b\\stuff", "a:stuff"
 */

const char*  ngx_filepath_name_get(const char *pathname)
{
    const char path_separator = '/';
    const char *s = strrchr(pathname, path_separator);

    return s ? ++s : pathname;
}


ngx_int_t  ngx_filepath_root(const char **rootpath,
                                            const char **inpath,
                                            int32_t flags,
                                            ngx_pool_t *p)
{
    if (**inpath == '/') {
        *rootpath = ngx_pstrndup(p, "/");
        do {
            ++(*inpath);
        } while (**inpath == '/');

        return NGX_OK;
    }

    return NGX_ERROR;
}

ngx_int_t ngx_filepath_merge(char **newpath,
                                             const char *rootpath,
                                             const char *addpath,
                                             int32_t flags,
                                             ngx_pool_t *p)
{
    char *path;
    size_t rootlen; /* is the length of the src rootpath */
    size_t maxlen;  /* maximum total path length */
    size_t keptlen; /* is the length of the retained rootpath */
    size_t pathlen; /* is the length of the result path */
    size_t seglen;  /* is the end of the current segment */
    ngx_int_t rv;

    /* Treat null as an empty path.
     */
    if (!addpath)
        addpath = "";

    if (addpath[0] == '/') {
        /* If addpath is rooted, then rootpath is unused.
         * Ths violates any NGX_FILEPATH_SECUREROOTTEST and
         * NGX_FILEPATH_NOTABSOLUTE flags specified.
         */
        if (flags & NGX_FILEPATH_SECUREROOTTEST)
            return NGX_ERROR;

        if (flags & NGX_FILEPATH_NOTABSOLUTE)
            return NGX_ERROR;

        /* If NGX_FILEPATH_NOTABOVEROOT wasn't specified,
         * we won't test the root again, it's ignored.
         * Waste no CPU retrieving the working path.
         */
        if (!rootpath && !(flags & NGX_FILEPATH_NOTABOVEROOT))
            rootpath = "";
    }
    else {
        /* If NGX_FILEPATH_NOTABSOLUTE is specified, the caller
         * requires a relative result.  If the rootpath is
         * ommitted, we do not retrieve the working path,
         * if rootpath was supplied as absolute then fail.
         */
        if (flags & NGX_FILEPATH_NOTABSOLUTE) {
            if (!rootpath)
                rootpath = "";
            else if (rootpath[0] == '/')
                return NGX_ERROR;
        }
    }

    if (!rootpath) {
        /* Start with the current working path.  This is bass akwards,
         * but required since the compiler (at least vc) doesn't like
         * passing the address of a char const* for a char** arg.
         */
        char *getpath;
        rv = ngx_filepath_get(&getpath, flags, p);
        rootpath = getpath;
        if (rv != NGX_OK)
            return NGX_ERROR;

        /* XXX: Any kernel subject to goofy, uncanonical results
         * must run the rootpath against the user's given flags.
         * Simplest would be a recursive call to ngx_filepath_merge
         * with an empty (not null) rootpath and addpath of the cwd.
         */
    }

    rootlen = ngx_strlen(rootpath);
    maxlen = rootlen + ngx_strlen(addpath) + 4; /* 4 for slashes at start, after
                                             * root, and at end, plus trailing
                                             * null */
    if (maxlen > NGX_PATH_MAX) {
        return NGX_ERROR;
    }
    path = (char *)ngx_palloc(p, maxlen);

    if (addpath[0] == '/') {
        /* Ignore the given root path, strip off leading
         * '/'s to a single leading '/' from the addpath,
         * and leave addpath at the first non-'/' character.
         */
        keptlen = 0;
        while (addpath[0] == '/')
            ++addpath;
        path[0] = '/';
        pathlen = 1;
    }
    else {
        /* If both paths are relative, fail early
         */
        if (rootpath[0] != '/' && (flags & NGX_FILEPATH_NOTRELATIVE))
            return NGX_ERROR;

        /* Base the result path on the rootpath
         */
        keptlen = rootlen;
        memcpy(path, rootpath, rootlen);

        /* Always '/' terminate the given root path
         */
        if (keptlen && path[keptlen - 1] != '/') {
            path[keptlen++] = '/';
        }
        pathlen = keptlen;
    }

    while (*addpath) {
        /* Parse each segment, find the closing '/'
         */
        const char *next = addpath;
        while (*next && (*next != '/')) {
            ++next;
        }
        seglen = next - addpath;

        if (seglen == 0 || (seglen == 1 && addpath[0] == '.')) {
            /* noop segment (/ or ./) so skip it
             */
        }
        else if (seglen == 2 && addpath[0] == '.' && addpath[1] == '.') {
            /* backpath (../) */
            if (pathlen == 1 && path[0] == '/') {
                /* Attempt to move above root.  Always die if the
                 * NGX_FILEPATH_SECUREROOTTEST flag is specified.
                 */
                if (flags & NGX_FILEPATH_SECUREROOTTEST) {
                    return NGX_ERROR;
                }

                /* Otherwise this is simply a noop, above root is root.
                 * Flag that rootpath was entirely replaced.
                 */
                keptlen = 0;
            }
            else if (pathlen == 0
                     || (pathlen == 3
                         && !memcmp(path + pathlen - 3, "../", 3))
                     || (pathlen  > 3
                         && !memcmp(path + pathlen - 4, "/../", 4))) {
                /* Path is already backpathed or empty, if the
                 * NGX_FILEPATH_SECUREROOTTEST.was given die now.
                 */
                if (flags & NGX_FILEPATH_SECUREROOTTEST) {
                    return NGX_ERROR;
                }

                /* Otherwise append another backpath, including
                 * trailing slash if present.
                 */
                memcpy(path + pathlen, "../", *next ? 3 : 2);
                pathlen += *next ? 3 : 2;
            }
            else {
                /* otherwise crop the prior segment
                 */
                do {
                    --pathlen;
                } while (pathlen && path[pathlen - 1] != '/');
            }

            /* Now test if we are above where we started and back up
             * the keptlen offset to reflect the added/altered path.
             */
            if (pathlen < keptlen) {
                if (flags & NGX_FILEPATH_SECUREROOTTEST) {
                    return NGX_ERROR;
                }
                keptlen = pathlen;
            }
        }
        else {
            /* An actual segment, append it to the destination path
             */
            if (*next) {
                seglen++;
            }
            memcpy(path + pathlen, addpath, seglen);
            pathlen += seglen;
        }

        /* Skip over trailing slash to the next segment
         */
        if (*next) {
            ++next;
        }

        addpath = next;
    }
    path[pathlen] = '\0';

    /* keptlen will be the rootlen unless the addpath contained
     * backpath elements.  If so, and NGX_FILEPATH_NOTABOVEROOT
     * is specified (NGX_FILEPATH_SECUREROOTTEST was caught above),
     * compare the original root to assure the result path is
     * still within given root path.
     */
    if ((flags & NGX_FILEPATH_NOTABOVEROOT) && keptlen < rootlen) {
        if (strncmp(rootpath, path, rootlen)) {
            return NGX_ERROR;
        }
        if (rootpath[rootlen - 1] != '/'
            && path[rootlen] && path[rootlen] != '/') {
            return NGX_ERROR;
        }
    }

    *newpath = path;
    return NGX_OK;
}


ngx_int_t ngx_file_lock(ngx_file_t *thefile, int type)
{
    int rc;

    struct flock l;
    int fc;

    l.l_whence = SEEK_SET;  /* lock from current point */
    l.l_start = 0;          /* begin lock at this offset */
    l.l_len = 0;            /* lock to end of file */
    if ((type & NGX_FLOCK_TYPEMASK) == NGX_FLOCK_SHARED)
        l.l_type = F_RDLCK;
    else
        l.l_type = F_WRLCK;

    fc = (type & NGX_FLOCK_NONBLOCK) ? F_SETLK : F_SETLKW;

    /* keep trying if fcntl() gets interrupted (by a signal) */
    while ((rc = fcntl(thefile->fd, fc, &l)) < 0 && errno == EINTR)
        continue;

    if (rc == -1) {
        /* on some Unix boxes (e.g., Tru64), we get EACCES instead
         * of EAGAIN; we don't want NGX_STATUS_IS_EAGAIN() matching EACCES
         * since that breaks other things, so fix up the retcode here
         */
        if (errno == EACCES) {
            return EAGAIN;
        }
        return errno;
    }

    return NGX_OK;
}

ngx_int_t ngx_file_unlock(ngx_file_t *thefile)
{
    int rc;

    struct flock l;

    l.l_whence = SEEK_SET;  /* lock from current point */
    l.l_start = 0;          /* begin lock at this offset */
    l.l_len = 0;            /* lock to end of file */
    l.l_type = F_UNLCK;

    /* keep trying if fcntl() gets interrupted (by a signal) */
    while ((rc = fcntl(thefile->fd, F_SETLKW, &l)) < 0
           && errno == EINTR)
        continue;

    if (rc == -1)
        return errno;

    return NGX_OK;
}
