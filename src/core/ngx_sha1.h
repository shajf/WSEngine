
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHA1_H_INCLUDED_
#define _NGX_SHA1_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_SHA1_DIGESTSIZE 20

#if (NGX_HAVE_OPENSSL_SHA1_H)
#include <openssl/sha.h>
#else
#include <sha.h>
#endif


typedef SHA_CTX  ngx_sha1_t;


#define ngx_sha1_init    SHA1_Init
#define ngx_sha1_update  SHA1_Update
#define ngx_sha1_final   SHA1_Final


#endif /* _NGX_SHA1_H_INCLUDED_ */
