/**
 * @file
 * Network buffer management
 *
 */
 
/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "lwip/opt.h"

#if LWIP_NETCONN /* don't build if not configured for use in lwipopts.h */

#include "lwip/netbuf.h"
#include "lwip/memp.h"

#include <string.h>

/**
 * Create (allocate) and initialize a new netbuf.
 * The netbuf doesn't yet contain a packet buffer!
 * 申请一个新的net_buffer空间，注意 这里不会分配任何数据空间（不指向任何pbuf）
 * 真正的数据存储区需要通过调用函数netbuf_alloc来分配
 * @return a pointer to a new netbuf
 *         NULL on lack of memory
 */
struct
netbuf *netbuf_new(void)
{
  struct netbuf *buf = NULL;

  buf = (struct netbuf *)memp_malloc(MEMP_NETBUF);	//申请netbuf空间
  if (buf != NULL) {	//如果申请成功
    buf->p = NULL;	//初始化
    buf->ptr = NULL;
    ip_addr_set_any(&buf->addr);
    buf->port = 0;
#if LWIP_NETBUF_RECVINFO || LWIP_CHECKSUM_ON_COPY
#if LWIP_CHECKSUM_ON_COPY
    buf->flags = 0;
#endif /* LWIP_CHECKSUM_ON_COPY */
    buf->toport_chksum = 0;
#if LWIP_NETBUF_RECVINFO
    ip_addr_set_any(&buf->toaddr);
#endif /* LWIP_NETBUF_RECVINFO */
#endif /* LWIP_NETBUF_RECVINFO || LWIP_CHECKSUM_ON_COPY */
    return buf;
  } else { //申请失败返回空
    return NULL;
  }
}

/**
 * Deallocate a netbuf allocated by netbuf_new().
 * 释放一个空间 如果函数调用时pbuf上还有数据 则连同pbuf一同释放
 * @param buf pointer to a netbuf allocated by netbuf_new()
 */
void
netbuf_delete(struct netbuf *buf)
{
  if (buf != NULL) {
    if (buf->p != NULL) {
      pbuf_free(buf->p);	//释放pbuf
      buf->p = buf->ptr = NULL;	//指针一定要赋值为空
    }
    memp_free(MEMP_NETBUF, buf);	//释放netbuf
  }
}

/**
 * Allocate memory for a packet buffer for a given netbuf.
 * 为netbuf结构分配size大小的空间
 * @param buf the netbuf for which to allocate a packet buffer
 * @param size the size of the packet buffer to allocate
 * @return pointer to the allocated memory
 *         NULL if no memory could be allocated
 */
void *
netbuf_alloc(struct netbuf *buf, u16_t size)
{
  LWIP_ERROR("netbuf_alloc: invalid buf", (buf != NULL), return NULL;);

  /* Deallocate any previously allocated memory. */
  if (buf->p != NULL) {	//如果函数掉用时 netbuf已经分配的空间
    pbuf_free(buf->p);	//则相应的空间会被释放掉
  }
  buf->p = pbuf_alloc(PBUF_TRANSPORT, size, PBUF_RAM);	//注意：该函数在传输层被调用 所以默认的各个协议的首部长度也会被附加到pbuf中
  if (buf->p == NULL) {	//如果分配失败返回空
     return NULL;
  }
  LWIP_ASSERT("check that first pbuf can hold size",
             (buf->p->len >= size));
  buf->ptr = buf->p;	//初始都指向第一个pbuf
  return buf->p->payload;	//返回数据区的起始位置
}

/**
 * Free the packet buffer included in a netbuf
 * 释放netbuf指向的数据区pbuf
 * @param buf pointer to the netbuf which contains the packet buffer to free
 */
void
netbuf_free(struct netbuf *buf)
{
  LWIP_ERROR("netbuf_free: invalid buf", (buf != NULL), return;);
  if (buf->p != NULL) {	//如果pbuf不为空
    pbuf_free(buf->p);	//直接释放
  }
  buf->p = buf->ptr = NULL; //如果为空 则再次强调赋值指针为空
}

/**
 * Let a netbuf reference existing (non-volatile) data.
 * 该函数功能与netbuf_alloc的功能类似 区别在于它不会非陪具体的数据区域 
 * 只是分配一个pbuf首部结构（包含各个协议的首部空间），并将pbuf的payload指针指向
 * 数据区dataptr 这种描述数据包的方式在静态数据发送时经常用到
 * @param buf netbuf which should reference the data
 * @param dataptr pointer to the data to reference
 * @param size size of the data
 * @return ERR_OK if data is referenced
 *         ERR_MEM if data couldn't be referenced due to lack of memory
 */
err_t
netbuf_ref(struct netbuf *buf, const void *dataptr, u16_t size)
{
  LWIP_ERROR("netbuf_ref: invalid buf", (buf != NULL), return ERR_ARG;);
  if (buf->p != NULL) {	//如果netbuf结构之前有数据
    pbuf_free(buf->p);	//直接释放掉
  }
  buf->p = pbuf_alloc(PBUF_TRANSPORT, 0, PBUF_REF);	//申请pbuf结构 数据区为0
  if (buf->p == NULL) {	//如果申请失败
    buf->ptr = NULL;	
    return ERR_MEM;	//返回内存错误
  }
  buf->p->payload = (void*)dataptr;	//数据区的首地址赋值为传进来要发送的数据的首地址
  buf->p->len = buf->p->tot_len = size;	//数据长度等于传进来要发送的数据长度
  buf->ptr = buf->p;
  return ERR_OK;
}

/**
 * Chain one netbuf to another (@see pbuf_chain)
 * 数据链接函数 将tail中的pbuf链接到head的pbuf之后 同时释放tail
 * @param head the first netbuf
 * @param tail netbuf to chain after head, freed by this function, may not be reference after returning
 */
void
netbuf_chain(struct netbuf *head, struct netbuf *tail)
{
  LWIP_ERROR("netbuf_ref: invalid head", (head != NULL), return;);
  LWIP_ERROR("netbuf_chain: invalid tail", (tail != NULL), return;);
  pbuf_cat(head->p, tail->p);	//将tail的pbuf链接到head的pbuf之后
  head->ptr = head->p;
  memp_free(MEMP_NETBUF, tail);	//释放tail
}

/**
 * Get the data pointer and length of the data inside a netbuf.
 * 将netbuf结构中ptr指向的pbuf数据其实地址填入dataptr中
 * 同时将该pbuf中的数据长度填入len中 netbuf记录的数据可能包含在多个pbuf中
 * 但是该函数只能返回ptr指针指向的pbuf数据信息 如果要对链表中的其他pbuf进行操作
 * 用户可以调用函数netbuf_next和netbuf_first来操作
 * @param buf netbuf to get the data from
 * @param dataptr pointer to a void pointer where to store the data pointer
 * @param len pointer to an u16_t where the length of the data is stored
 * @return ERR_OK if the information was retreived,
 *         ERR_BUF on error.
 */
err_t
netbuf_data(struct netbuf *buf, void **dataptr, u16_t *len)
{
  LWIP_ERROR("netbuf_data: invalid buf", (buf != NULL), return ERR_ARG;);
  LWIP_ERROR("netbuf_data: invalid dataptr", (dataptr != NULL), return ERR_ARG;);
  LWIP_ERROR("netbuf_data: invalid len", (len != NULL), return ERR_ARG;);

  if (buf->ptr == NULL) {	//如果为空 
    return ERR_BUF;	//返回错误
  }
  *dataptr = buf->ptr->payload;	//取数据区的首地址
  *len = buf->ptr->len;	//取数据长度
  return ERR_OK;
}

/**
 * Move the current data pointer of a packet buffer contained in a netbuf
 * to the next part.
 * The packet buffer itself is not modified.
 * 将ptr指向pbuf的下一个
 * @param buf the netbuf to modify
 * @return -1 if there is no next part
 *         1  if moved to the next part but now there is no next part
 *         0  if moved to the next part and there are still more parts
 */
s8_t
netbuf_next(struct netbuf *buf)
{
  LWIP_ERROR("netbuf_free: invalid buf", (buf != NULL), return -1;);
  if (buf->ptr->next == NULL) {	//如果next为空 返回-1
    return -1;
  }
  buf->ptr = buf->ptr->next;	//指向下一个
  if (buf->ptr->next == NULL) {	//已经是最后一个了
    return 1;	//返回1
  }
  return 0; //不是最后一个且已经指向了下一个 返回0
}

/**
 * Move the current data pointer of a packet buffer contained in a netbuf
 * to the beginning of the packet.
 * The packet buffer itself is not modified.
 * 将netbuf中的ptr指向pbuf中的第一个pbuf结构
 * @param buf the netbuf to modify
 */
void
netbuf_first(struct netbuf *buf)
{
  LWIP_ERROR("netbuf_free: invalid buf", (buf != NULL), return;);
  buf->ptr = buf->p;
}

#endif /* LWIP_NETCONN */
