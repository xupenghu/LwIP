/*
 * Copyright (c) 2001, Swedish Institute of Computer Science.
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 * $Id: cc.h,v 1.1.1.1 2003/05/17 05:06:56 chenyu Exp $
 */


#ifndef __CC_H__
#define __CC_H__

#include "stdio.h"

typedef unsigned char      u8_t;
typedef signed char      s8_t;
typedef unsigned short    u16_t;
typedef signed   short    s16_t;

typedef unsigned int    u32_t;
typedef signed   int    s32_t;
typedef unsigned int sys_prot_t;
typedef unsigned int mem_ptr_t;

#define PACK_STRUCT_FIELD(x) x
#define PACK_STRUCT_STRUCT 
#define PACK_STRUCT_BEGIN  __packed
#define PACK_STRUCT_END

#define LWIP_DEBUG
#define LWIP_PLATFORM_DIAG(x) {printf x;}
#define LWIP_PLATFORM_ASSERT(x) {printf(x);while(1);}

#define LWIP_ERROR(message, expression, handler)  \
	do { if (!(expression)) { \
  			printf(message); handler;}} while(0)

//#define LWIP_NOASSERT
//#define LWIP_ASSERT(x,y)

#define U16_F "u"
#define S16_F "d"
#define X16_F "x"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"

//#define SZT_F 8f

#define	LWIP_PROVIDE_ERRNO

#define BYTE_ORDER LITTLE_ENDIAN

extern unsigned int sys_now(void);

//* 临界代码保护宏
//#define	SYS_ARCH_DECL_PROTECT(x)	    //u32_t cpu_sr
//#define	SYS_ARCH_PROTECT(x)			    //cpu_sr = DisableInt()//OS_ENTER_CRITICAL()
//#define	SYS_ARCH_UNPROTECT(x)		    //EnableInt(cpu_sr)     //OS_EXIT_CRITICAL()

#endif /* __CC_H__ */

