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
#ifndef __LWIP_API_H__
#define __LWIP_API_H__

#include "lwip/opt.h"

#if LWIP_NETCONN /* don't build if not configured for use in lwipopts.h */

#include <stddef.h> /* for size_t */

#include "lwip/netbuf.h"
#include "lwip/sys.h"
#include "lwip/ip_addr.h"
#include "lwip/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Throughout this file, IP addresses and port numbers are expected to be in
 * the same byte order as in the corresponding pcb.
 */

/* Flags for netconn_write (u8_t) */
#define NETCONN_NOFLAG    0x00
#define NETCONN_NOCOPY    0x00 /* Only for source code compatibility */
#define NETCONN_COPY      0x01
#define NETCONN_MORE      0x02
#define NETCONN_DONTBLOCK 0x04

/* Flags for struct netconn.flags (u8_t) */
/** TCP: when data passed to netconn_write doesn't fit into the send buffer,
    this temporarily stores whether to wake up the original application task
    if data couldn't be sent in the first try. */
#define NETCONN_FLAG_WRITE_DELAYED            0x01
/** Should this netconn avoid blocking? */
#define NETCONN_FLAG_NON_BLOCKING             0x02
/** Was the last connect action a non-blocking one? */
#define NETCONN_FLAG_IN_NONBLOCKING_CONNECT   0x04
/** If this is set, a TCP netconn must call netconn_recved() to update
    the TCP receive window (done automatically if not set). */
#define NETCONN_FLAG_NO_AUTO_RECVED           0x08
/** If a nonblocking write has been rejected before, poll_tcp needs to
    check if the netconn is writable again */
#define NETCONN_FLAG_CHECK_WRITESPACE         0x10


/* Helpers to process several netconn_types by the same code */
#define NETCONNTYPE_GROUP(t)    (t&0xF0)
#define NETCONNTYPE_DATAGRAM(t) (t&0xE0)

/** Protocol family and type of the netconn */
/* 描述链接类型 */
enum netconn_type {
  NETCONN_INVALID    = 0,	//无效类型
  /* NETCONN_TCP Group */
  NETCONN_TCP        = 0x10,	//TCP
  /* NETCONN_UDP Group */
  NETCONN_UDP        = 0x20,	//UDP
  NETCONN_UDPLITE    = 0x21,	//UDP_Lite
  NETCONN_UDPNOCHKSUM= 0x22,	//无校验的udp
  /* NETCONN_RAW Group */
  NETCONN_RAW        = 0x40		//原始链接
};

/** Current state of the netconn. Non-TCP netconns are always
 * in state NETCONN_NONE! */
 /* 用于描述链接状态 主要在TCP链接中使用 */
enum netconn_state {
  NETCONN_NONE,		//不处于任何状态
  NETCONN_WRITE,	//正在发送数据
  NETCONN_LISTEN,	//侦听状态
  NETCONN_CONNECT,	//链接状态
  NETCONN_CLOSE		//关闭状态
};

/** Use to inform the callback function about changes */
enum netconn_evt {
  NETCONN_EVT_RCVPLUS,
  NETCONN_EVT_RCVMINUS,
  NETCONN_EVT_SENDPLUS,
  NETCONN_EVT_SENDMINUS,
  NETCONN_EVT_ERROR
};

#if LWIP_IGMP
/** Used for netconn_join_leave_group() */
enum netconn_igmp {
  NETCONN_JOIN,
  NETCONN_LEAVE
};
#endif /* LWIP_IGMP */

/* forward-declare some structs to avoid to include their headers */
struct ip_pcb;
struct tcp_pcb;
struct udp_pcb;
struct raw_pcb;
struct netconn;
struct api_msg_msg;

/** A callback prototype to inform about events for a netconn */
/* 定义函数指针类型的回调函数 */
typedef void (* netconn_callback)(struct netconn *, enum netconn_evt, u16_t len);

/** A netconn descriptor */
/* 链接结构netconn */
struct netconn {
  /** type of the netconn (TCP, UDP or RAW) */
  enum netconn_type type;	//连接类型
  /** current state of the netconn */
  enum netconn_state state;	//连接状态
  /** the lwIP internal protocol control block */
  union {	//内核与连接相关的控制块指针
    struct ip_pcb  *ip;		//IP控制块
    struct tcp_pcb *tcp;	//tcp控制块
    struct udp_pcb *udp;	//udp控制块
    struct raw_pcb *raw;	//原始控制块
  } pcb;
  /** the last error this netconn had */
  err_t last_err;	//该连接上函数调用时设置的错误标志
  /** sem that is used to synchroneously execute functions in the core context */
  sys_sem_t op_completed;	//信号量 用于两部分API同步
  /** mbox where received packets are stored until they are fetched
      by the netconn application thread (can grow quite big) */
  sys_mbox_t recvmbox;	//接收数据的邮箱 也可以看作是数据缓冲队列
#if LWIP_TCP
  /** mbox where new connections are stored until processed
      by the application thread */
  sys_mbox_t acceptmbox;	//用户tcp服务端 连接请求的缓冲队列
#endif /* LWIP_TCP */
  /** only used for socket layer */
#if LWIP_SOCKET
  int socket;	//socket描述符
#endif /* LWIP_SOCKET */
#if LWIP_SO_SNDTIMEO
  /** timeout to wait for sending data (which means enqueueing data for sending
      in internal buffers) */
  s32_t send_timeout;	//
#endif /* LWIP_SO_RCVTIMEO */
#if LWIP_SO_RCVTIMEO
  /** timeout to wait for new data to be received
      (or connections to arrive for listening netconns) */
  int recv_timeout;
#endif /* LWIP_SO_RCVTIMEO */
#if LWIP_SO_RCVBUF
  /** maximum amount of bytes queued in recvmbox
      not used for TCP: adjust TCP_WND instead! */
  int recv_bufsize;	//数据邮箱recvbox上可缓冲的最大数据长度
  /** number of bytes currently in recvmbox to be received,
      tested against recv_bufsize to limit bytes on recvmbox
      for UDP and RAW, used for FIONREAD */
  s16_t recv_avail;		//数据邮箱recvmbox中已经缓冲的数据长度
#endif /* LWIP_SO_RCVBUF */
  /** flags holding more netconn-internal state, see NETCONN_FLAG_* defines */
/* netconn的更多状态标志 比如在发送缓冲不足 发送是否阻塞；是否自动更新内核接收窗口等 */
  u8_t flags;		//
#if LWIP_TCP
  /** TCP: when data passed to netconn_write doesn't fit into the send buffer,
      this temporarily stores how much is already sent. */
  size_t write_offset;	//记录下一次发送索引
  /** TCP: when data passed to netconn_write doesn't fit into the send buffer,
      this temporarily stores the message.
      Also used during connect and close. */
/* 当调用netconn_write发送数据但是缓冲不足时，比如在发送缓冲不足时，数据会被暂时封装在write_msg中 等待下一次发送，*/
  struct api_msg_msg *current_msg;	
#endif /* LWIP_TCP */
  /** A callback function that is informed about events for this netconn */
  netconn_callback callback;	//连接相关的回调函数 实现socket api时使用到
};

/** Register an Network connection event */
#define API_EVENT(c,e,l) if (c->callback) {         \
                           (*c->callback)(c, e, l); \
                         }

/** Set conn->last_err to err but don't overwrite fatal errors */
#define NETCONN_SET_SAFE_ERR(conn, err) do { \
  SYS_ARCH_DECL_PROTECT(lev); \
  SYS_ARCH_PROTECT(lev); \
  if (!ERR_IS_FATAL((conn)->last_err)) { \
    (conn)->last_err = err; \
  } \
  SYS_ARCH_UNPROTECT(lev); \
} while(0);

/* Network connection functions: */
#define netconn_new(t)                  netconn_new_with_proto_and_callback(t, 0, NULL)
#define netconn_new_with_callback(t, c) netconn_new_with_proto_and_callback(t, 0, c)
struct
netconn *netconn_new_with_proto_and_callback(enum netconn_type t, u8_t proto,
                                             netconn_callback callback);
err_t   netconn_delete(struct netconn *conn);
/** Get the type of a netconn (as enum netconn_type). */
#define netconn_type(conn) (conn->type)

err_t   netconn_getaddr(struct netconn *conn, ip_addr_t *addr,
                        u16_t *port, u8_t local);
#define netconn_peer(c,i,p) netconn_getaddr(c,i,p,0)
#define netconn_addr(c,i,p) netconn_getaddr(c,i,p,1)

err_t   netconn_bind(struct netconn *conn, ip_addr_t *addr, u16_t port);
err_t   netconn_connect(struct netconn *conn, ip_addr_t *addr, u16_t port);
err_t   netconn_disconnect (struct netconn *conn);
err_t   netconn_listen_with_backlog(struct netconn *conn, u8_t backlog);
#define netconn_listen(conn) netconn_listen_with_backlog(conn, TCP_DEFAULT_LISTEN_BACKLOG)
err_t   netconn_accept(struct netconn *conn, struct netconn **new_conn);
err_t   netconn_recv(struct netconn *conn, struct netbuf **new_buf);
err_t   netconn_recv_tcp_pbuf(struct netconn *conn, struct pbuf **new_buf);
void    netconn_recved(struct netconn *conn, u32_t length);
err_t   netconn_sendto(struct netconn *conn, struct netbuf *buf,
                       ip_addr_t *addr, u16_t port);
err_t   netconn_send(struct netconn *conn, struct netbuf *buf);
err_t   netconn_write_partly(struct netconn *conn, const void *dataptr, size_t size,
                             u8_t apiflags, size_t *bytes_written);
#define netconn_write(conn, dataptr, size, apiflags) \
          netconn_write_partly(conn, dataptr, size, apiflags, NULL)
err_t   netconn_close(struct netconn *conn);
err_t   netconn_shutdown(struct netconn *conn, u8_t shut_rx, u8_t shut_tx);

#if LWIP_IGMP
err_t   netconn_join_leave_group(struct netconn *conn, ip_addr_t *multiaddr,
                                 ip_addr_t *netif_addr, enum netconn_igmp join_or_leave);
#endif /* LWIP_IGMP */
#if LWIP_DNS
err_t   netconn_gethostbyname(const char *name, ip_addr_t *addr);
#endif /* LWIP_DNS */

#define netconn_err(conn)               ((conn)->last_err)
#define netconn_recv_bufsize(conn)      ((conn)->recv_bufsize)

/** Set the blocking status of netconn calls (@todo: write/send is missing) */
#define netconn_set_nonblocking(conn, val)  do { if(val) { \
  (conn)->flags |= NETCONN_FLAG_NON_BLOCKING; \
} else { \
  (conn)->flags &= ~ NETCONN_FLAG_NON_BLOCKING; }} while(0)
/** Get the blocking status of netconn calls (@todo: write/send is missing) */
#define netconn_is_nonblocking(conn)        (((conn)->flags & NETCONN_FLAG_NON_BLOCKING) != 0)

/** TCP: Set the no-auto-recved status of netconn calls (see NETCONN_FLAG_NO_AUTO_RECVED) */
#define netconn_set_noautorecved(conn, val)  do { if(val) { \
  (conn)->flags |= NETCONN_FLAG_NO_AUTO_RECVED; \
} else { \
  (conn)->flags &= ~ NETCONN_FLAG_NO_AUTO_RECVED; }} while(0)
/** TCP: Get the no-auto-recved status of netconn calls (see NETCONN_FLAG_NO_AUTO_RECVED) */
#define netconn_get_noautorecved(conn)        (((conn)->flags & NETCONN_FLAG_NO_AUTO_RECVED) != 0)

#if LWIP_SO_SNDTIMEO
/** Set the send timeout in milliseconds */
#define netconn_set_sendtimeout(conn, timeout)      ((conn)->send_timeout = (timeout))
/** Get the send timeout in milliseconds */
#define netconn_get_sendtimeout(conn)               ((conn)->send_timeout)
#endif /* LWIP_SO_SNDTIMEO */
#if LWIP_SO_RCVTIMEO
/** Set the receive timeout in milliseconds */
#define netconn_set_recvtimeout(conn, timeout)      ((conn)->recv_timeout = (timeout))
/** Get the receive timeout in milliseconds */
#define netconn_get_recvtimeout(conn)               ((conn)->recv_timeout)
#endif /* LWIP_SO_RCVTIMEO */
#if LWIP_SO_RCVBUF
/** Set the receive buffer in bytes */
#define netconn_set_recvbufsize(conn, recvbufsize)  ((conn)->recv_bufsize = (recvbufsize))
/** Get the receive buffer in bytes */
#define netconn_get_recvbufsize(conn)               ((conn)->recv_bufsize)
#endif /* LWIP_SO_RCVBUF*/

#ifdef __cplusplus
}
#endif

#endif /* LWIP_NETCONN */

#endif /* __LWIP_API_H__ */
