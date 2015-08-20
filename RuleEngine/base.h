/*
 * =====================================================================================
 *      Copyright (C) 2014 jianfeng sha
 *
 *      Filename:  base.h
 *
 *      Description:  
 *
 *      Created:  11/06/14 14:48:47
 *
 *      Author:  jianfeng sha , csp001314@163.com
 * =====================================================================================
 */

#ifndef _BASE_H_INCLUDED_
#define _BASE_H_INCLUDED_

typedef int32_t         ngx_fileperms_t;
/** 
 * @defgroup apr_file_permissions File Permissions flags  
 * @{ 
 */ 
 
#define NGX_FPROT_USETID      0x8000 /**< Set user id */ 
#define NGX_FPROT_UREAD       0x0400 /**< Read by user */ 
#define NGX_FPROT_UWRITE      0x0200 /**< Write by user */ 
#define NGX_FPROT_UEXECUTE    0x0100 /**< Execute by user */ 
 
#define NGX_FPROT_GSETID      0x4000 /**< Set group id */ 
#define NGX_FPROT_GREAD       0x0040 /**< Read by group */ 
#define NGX_FPROT_GWRITE      0x0020 /**< Write by group */ 
#define NGX_FPROT_GEXECUTE    0x0010 /**< Execute by group */ 
 
#define NGX_FPROT_WSTICKY     0x2000 /**< Sticky bit */ 
#define NGX_FPROT_WREAD       0x0004 /**< Read by others */ 
#define NGX_FPROT_WWRITE      0x0002 /**< Write by others */ 
#define NGX_FPROT_WEXECUTE    0x0001 /**< Execute by others */ 
 
#define NGX_FPROT_OS_DEFAULT  0x0FFF /**< use OS's default permissions */ 
 
/* additional permission flags for apr_file_copy  and apr_file_append */ 
#define NGX_FPROT_FILE_SOURCE_PERMS 0x1000 /**< Copy source file's permissions */ 
     
/* backcompat */ 
#define NGX_USETID     NGX_FPROT_USETID     /**< @deprecated @see NGX_FPROT_USETID     */ 
#define NGX_UREAD      NGX_FPROT_UREAD      /**< @deprecated @see NGX_FPROT_UREAD      */ 
#define NGX_UWRITE     NGX_FPROT_UWRITE     /**< @deprecated @see NGX_FPROT_UWRITE     */ 
#define NGX_UEXECUTE   NGX_FPROT_UEXECUTE   /**< @deprecated @see NGX_FPROT_UEXECUTE   */ 
#define NGX_GSETID     NGX_FPROT_GSETID     /**< @deprecated @see NGX_FPROT_GSETID     */ 
#define NGX_GREAD      NGX_FPROT_GREAD      /**< @deprecated @see NGX_FPROT_GREAD      */ 
#define NGX_GWRITE     NGX_FPROT_GWRITE     /**< @deprecated @see NGX_FPROT_GWRITE     */ 
#define NGX_GEXECUTE   NGX_FPROT_GEXECUTE   /**< @deprecated @see NGX_FPROT_GEXECUTE   */ 
#define NGX_WSTICKY    NGX_FPROT_WSTICKY    /**< @deprecated @see NGX_FPROT_WSTICKY    */ 
#define NGX_WREAD      NGX_FPROT_WREAD      /**< @deprecated @see NGX_FPROT_WREAD      */ 
#define NGX_WWRITE     NGX_FPROT_WWRITE     /**< @deprecated @see NGX_FPROT_WWRITE     */ 
#define NGX_WEXECUTE   NGX_FPROT_WEXECUTE   /**< @deprecated @see NGX_FPROT_WEXECUTE   */ 
#define NGX_OS_DEFAULT NGX_FPROT_OS_DEFAULT /**< @deprecated @see NGX_FPROT_OS_DEFAULT */ 
#define NGX_FILE_SOURCE_PERMS NGX_FPROT_FILE_SOURCE_PERMS /**< @deprecated @see NGX_FPROT_FILE_SOURCE_PERMS */ 
     
/** @} */ 

#endif /*_BASE_H_INCLUDED_*/
