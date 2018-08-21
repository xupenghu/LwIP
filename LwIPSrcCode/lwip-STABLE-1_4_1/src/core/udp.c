/**
 * @file
 * User Datagram Protocol module
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


/* udp.c
 *
 * The code for the User Datagram Protocol UDP & UDPLite (RFC 3828).
 *
 */

/* @todo Check the use of '(struct udp_pcb).chksum_len_rx'!
 */

#include "lwip/opt.h"

#if LWIP_UDP /* don't build if not configured for use in lwipopts.h */

#include "lwip/udp.h"
#include "lwip/def.h"
#include "lwip/memp.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/icmp.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "arch/perf.h"
#include "lwip/dhcp.h"

#include <string.h>

#ifndef UDP_LOCAL_PORT_RANGE_START
/* From http://www.iana.org/assignments/port-numbers:
   "The Dynamic and/or Private Ports are those from 49152 through 65535" */
#define UDP_LOCAL_PORT_RANGE_START  0xc000
#define UDP_LOCAL_PORT_RANGE_END    0xffff
#define UDP_ENSURE_LOCAL_PORT_RANGE(port) (((port) & ~UDP_LOCAL_PORT_RANGE_START) + UDP_LOCAL_PORT_RANGE_START)
#endif

/* last local UDP port */
static u16_t udp_port = UDP_LOCAL_PORT_RANGE_START;

/* The list of UDP PCBs */
/* exported in udp.h (was static) */
struct udp_pcb *udp_pcbs;

/**
 * Initialize this module.
 */
void
udp_init(void)
{
#if LWIP_RANDOMIZE_INITIAL_LOCAL_PORTS && defined(LWIP_RAND)
  udp_port = UDP_ENSURE_LOCAL_PORT_RANGE(LWIP_RAND());
#endif /* LWIP_RANDOMIZE_INITIAL_LOCAL_PORTS && defined(LWIP_RAND) */
}

/**
 * Allocate a new local UDP port.
 *
 * @return a new (free) local UDP port number
 */
static u16_t
udp_new_port(void)
{
  u16_t n = 0;
  struct udp_pcb *pcb;
  
again:
  if (udp_port++ == UDP_LOCAL_PORT_RANGE_END) {
    udp_port = UDP_LOCAL_PORT_RANGE_START;
  }
  /* Check all PCBs. */
  for(pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
    if (pcb->local_port == udp_port) {
      if (++n > (UDP_LOCAL_PORT_RANGE_END - UDP_LOCAL_PORT_RANGE_START)) {
        return 0;
      }
      goto again;
    }
  }
  return udp_port;
#if 0
  struct udp_pcb *ipcb = udp_pcbs;
  while ((ipcb != NULL) && (udp_port != UDP_LOCAL_PORT_RANGE_END)) {
    if (ipcb->local_port == udp_port) {
      /* port is already used by another udp_pcb */
      udp_port++;
      /* restart scanning all udp pcbs */
      ipcb = udp_pcbs;
    } else {
      /* go on with next udp pcb */
      ipcb = ipcb->next;
    }
  }
  if (ipcb != NULL) {
    return 0;
  }
  return udp_port;
#endif
}

/**
 * Process an incoming UDP datagram.
 * UDP报文处理函数
 * Given an incoming UDP datagram (as a chain of pbufs) this function
 * finds a corresponding UDP PCB and hands over the pbuf to the pcbs
 * recv function. If no pcb is found or the datagram is incorrect, the
 * pbuf is freed.
 *  IP层收到的包含UDP报文的数据报pbuf payload指向IP首部
 * @param p pbuf to be demultiplexed to a UDP PCB.
 * @param inp network interface on which the datagram was received. 接收到数据包的网络接口结构
 *
 */
void
udp_input(struct pbuf *p, struct netif *inp)
{
  struct udp_hdr *udphdr;  //udp头部指针
  struct udp_pcb *pcb, *prev;   //udp控制块指针 用于遍历udp链表
  struct udp_pcb *uncon_pcb;    //指向第一个匹配的处于非链接状态的的控制块
  struct ip_hdr *iphdr;     //IP数据报首部结构
  u16_t src, dest;  //保存报文中源端口号和目的端口号
  u8_t local_match; //标志控制块是否已经被匹配
  u8_t broadcast;       //记录该IP数据报是否为广播数据报

  PERF_START;

  UDP_STATS_INC(udp.recv);

  iphdr = (struct ip_hdr *)p->payload;  //指向IP数据报的首部

  /* Check minimum length (IP header + UDP header)
   * and move payload pointer to UDP header */
    /*  进行长度校验 如果整改数据报的长度不小于IP首部+UDP首部的大小  移动payload指针 指向udp首部*/
  if (p->tot_len < (IPH_HL(iphdr) * 4 + UDP_HLEN) || pbuf_header(p, -(s16_t)(IPH_HL(iphdr) * 4))) {
    /* drop short packets */
    LWIP_DEBUGF(UDP_DEBUG,
                ("udp_input: short UDP datagram (%"U16_F" bytes) discarded\n", p->tot_len));
    UDP_STATS_INC(udp.lenerr);
    UDP_STATS_INC(udp.drop);
    snmp_inc_udpinerrors();
    pbuf_free(p);   //如果失败 则释放pbuf 并跳转到end处 执行返回操作
    goto end;
  }

  udphdr = (struct udp_hdr *)p->payload; //指向udp报文首部

  /* is broadcast packet ? */
  broadcast = ip_addr_isbroadcast(&current_iphdr_dest, inp);    //判断IP数据报是否为广播

  LWIP_DEBUGF(UDP_DEBUG, ("udp_input: received datagram of length %"U16_F"\n", p->tot_len));

  /* convert src and dest ports to host byte order */
  src = ntohs(udphdr->src); //获取udp数据报的源端口号
  dest = ntohs(udphdr->dest);   //获取目的端口号

  udp_debug_print(udphdr);

  /* print the UDP source and destination */
  LWIP_DEBUGF(UDP_DEBUG,
              ("udp (%"U16_F".%"U16_F".%"U16_F".%"U16_F", %"U16_F") <-- "
               "(%"U16_F".%"U16_F".%"U16_F".%"U16_F", %"U16_F")\n",
               ip4_addr1_16(&iphdr->dest), ip4_addr2_16(&iphdr->dest),
               ip4_addr3_16(&iphdr->dest), ip4_addr4_16(&iphdr->dest), ntohs(udphdr->dest),
               ip4_addr1_16(&iphdr->src), ip4_addr2_16(&iphdr->src),
               ip4_addr3_16(&iphdr->src), ip4_addr4_16(&iphdr->src), ntohs(udphdr->src)));

#if LWIP_DHCP
  pcb = NULL;
  /* when LWIP_DHCP is active, packets to DHCP_CLIENT_PORT may only be processed by
     the dhcp module, no other UDP pcb may use the local UDP port DHCP_CLIENT_PORT */
  if (dest == DHCP_CLIENT_PORT) {
    /* all packets for DHCP_CLIENT_PORT not coming from DHCP_SERVER_PORT are dropped! */
    if (src == DHCP_SERVER_PORT) {
      if ((inp->dhcp != NULL) && (inp->dhcp->pcb != NULL)) {
        /* accept the packe if 
           (- broadcast or directed to us) -> DHCP is link-layer-addressed, local ip is always ANY!
           - inp->dhcp->pcb->remote == ANY or iphdr->src */
        if ((ip_addr_isany(&inp->dhcp->pcb->remote_ip) ||
           ip_addr_cmp(&(inp->dhcp->pcb->remote_ip), &current_iphdr_src))) {
          pcb = inp->dhcp->pcb;
        }
      }
    }
  } else
#endif /* LWIP_DHCP */
  {
    prev = NULL;
    local_match = 0;
    uncon_pcb = NULL;
    /* Iterate through the UDP pcb list for a matching pcb.
     * 'Perfect match' pcbs (connected to the remote port & ip address) are
     * preferred. If no perfect match is found, the first unconnected pcb that
     * matches the local port and ip address gets the datagram. */
      /* 开始查找匹配的控制块 第一查找目标为目的端口号和目的IP地址匹配且处于连接的状态控制块
          如果找不到 则查找与目的端口号和目的IP地址匹配的第一个处于非链接的状态控制块*/
    for (pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
      local_match = 0;
      /* print the PCB local and remote address */
      LWIP_DEBUGF(UDP_DEBUG,
                  ("pcb (%"U16_F".%"U16_F".%"U16_F".%"U16_F", %"U16_F") --- "
                   "(%"U16_F".%"U16_F".%"U16_F".%"U16_F", %"U16_F")\n",
                   ip4_addr1_16(&pcb->local_ip), ip4_addr2_16(&pcb->local_ip),
                   ip4_addr3_16(&pcb->local_ip), ip4_addr4_16(&pcb->local_ip), pcb->local_port,
                   ip4_addr1_16(&pcb->remote_ip), ip4_addr2_16(&pcb->remote_ip),
                   ip4_addr3_16(&pcb->remote_ip), ip4_addr4_16(&pcb->remote_ip), pcb->remote_port));

      /* compare PCB local addr+port to UDP destination addr+port */
      if (pcb->local_port == dest) {    //如果本地端口号匹配
        if (    //判断控制块中记录的本地端口号 IP地址 与数据报中记录的目的端口号  目的IP地址是否匹配
           (!broadcast && ip_addr_isany(&pcb->local_ip)) ||
           ip_addr_cmp(&(pcb->local_ip), &current_iphdr_dest) ||
#if LWIP_IGMP
           ip_addr_ismulticast(&current_iphdr_dest) ||
#endif /* LWIP_IGMP */
#if IP_SOF_BROADCAST_RECV
            (broadcast && ip_get_option(pcb, SOF_BROADCAST) &&
             (ip_addr_isany(&pcb->local_ip) ||
              ip_addr_netcmp(&pcb->local_ip, ip_current_dest_addr(), &inp->netmask)))) {
#else /* IP_SOF_BROADCAST_RECV */
            (broadcast &&
             (ip_addr_isany(&pcb->local_ip) ||
              ip_addr_netcmp(&pcb->local_ip, ip_current_dest_addr(), &inp->netmask)))) {
#endif /* IP_SOF_BROADCAST_RECV */ 
          local_match = 1;  //如果都匹配
          if ((uncon_pcb == NULL) && 
              ((pcb->flags & UDP_FLAGS_CONNECTED) == 0)) {
            /* the first unconnected matching PCB */
            uncon_pcb = pcb;    //第一个不连接匹配的控制块
          }
        }
      }
      /* compare PCB remote addr+port to UDP source addr+port */
      /*如果匹配成功 则继续匹配控制块中记录的源端口号 源IP地址与数据报中记录的
        源端口号 源IP地址是否匹配 以便找到一个处于连接状态的的控制块*/
      if ((local_match != 0) && //前阶段匹配成功 
          (pcb->remote_port == src) &&  //源端口号匹配
          (ip_addr_isany(&pcb->remote_ip) ||    //目的端口号匹配
           ip_addr_cmp(&(pcb->remote_ip), &current_iphdr_src))) {   
               /* 到这里我们找到了一个完全匹配的控制块 如果当前控制块不再链表首部 则移到链表首部 加快下次查找速度*/
        /* the first fully matching PCB */
        if (prev != NULL) {     //当前控制块不是链表首部
          /* move the pcb to the front of udp_pcbs so that is
             found faster next time */
          prev->next = pcb->next;   //将当前控制块移动到链表首部
          pcb->next = udp_pcbs;
          udp_pcbs = pcb;
        } else {
          UDP_STATS_INC(udp.cachehit);
        }
        break; //跳出for循环 结束查找过程
      }
      prev = pcb;
    }
    /* no fully matching pcb found? then look for an unconnected pcb */
    if (pcb == NULL) {
      pcb = uncon_pcb;  //如果没有找到完全匹配的控制块 则将第一个非链接状态的控制块返回作为匹配结果
    }
  }
    /* 到这里 如果找到了控制块或者找不到控制块 但是数据确实是给本地
        对于找到了 则调用用户注册的回掉函数进行处理
        对于后者 为源主机返回一个端口不可达的差错报文 先进行校验和验证*/
  /* Check checksum if this is a match or if it was directed at us. */
  if (pcb != NULL || ip_addr_cmp(&inp->ip_addr, &current_iphdr_dest)) {
    LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, ("udp_input: calculating checksum\n"));
#if LWIP_UDPLITE
    if (IPH_PROTO(iphdr) == IP_PROTO_UDPLITE) {
      /* Do the UDP Lite checksum */
#if CHECKSUM_CHECK_UDP
      u16_t chklen = ntohs(udphdr->len);
      if (chklen < sizeof(struct udp_hdr)) {
        if (chklen == 0) {
          /* For UDP-Lite, checksum length of 0 means checksum
             over the complete packet (See RFC 3828 chap. 3.1) */
          chklen = p->tot_len;
        } else {
          /* At least the UDP-Lite header must be covered by the
             checksum! (Again, see RFC 3828 chap. 3.1) */
          UDP_STATS_INC(udp.chkerr);
          UDP_STATS_INC(udp.drop);
          snmp_inc_udpinerrors();
          pbuf_free(p);
          goto end;
        }
      }
      if (inet_chksum_pseudo_partial(p, &current_iphdr_src, &current_iphdr_dest,
                             IP_PROTO_UDPLITE, p->tot_len, chklen) != 0) {
       LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                   ("udp_input: UDP Lite datagram discarded due to failing checksum\n"));
        UDP_STATS_INC(udp.chkerr);
        UDP_STATS_INC(udp.drop);
        snmp_inc_udpinerrors();
        pbuf_free(p);
        goto end;
      }
#endif /* CHECKSUM_CHECK_UDP */
    } else
#endif /* LWIP_UDPLITE */
    {
#if CHECKSUM_CHECK_UDP
      if (udphdr->chksum != 0) {    //数据报中填写了校验字段 则必须要进行校验
        if (inet_chksum_pseudo(p, ip_current_src_addr(), ip_current_dest_addr(),
                               IP_PROTO_UDP, p->tot_len) != 0) {    //如果校验失败
          LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                      ("udp_input: UDP datagram discarded due to failing checksum\n"));
          UDP_STATS_INC(udp.chkerr);
          UDP_STATS_INC(udp.drop);
          snmp_inc_udpinerrors();
          pbuf_free(p); //释放pbuf 并返回
          goto end;
        }
      }
#endif /* CHECKSUM_CHECK_UDP */
    }
    /*如果校验成功过 则将数据递交给用户程序处理 */
    if(pbuf_header(p, -UDP_HLEN)) { //先移动payload指针 如果移动失败 则出错返回
      /* Can we cope with this failing? Just assert for now */
      LWIP_ASSERT("pbuf_header failed\n", 0);
      UDP_STATS_INC(udp.drop);
      snmp_inc_udpinerrors();
      pbuf_free(p);
      goto end;
    }
    if (pcb != NULL) {  //如果pcb不为空 说明成功匹配到了控制块
      snmp_inc_udpindatagrams();
#if SO_REUSE && SO_REUSE_RXTOALL
      if ((broadcast || ip_addr_ismulticast(&current_iphdr_dest)) &&
          ip_get_option(pcb, SOF_REUSEADDR)) {
        /* pass broadcast- or multicast packets to all multicast pcbs
           if SOF_REUSEADDR is set on the first match */
        struct udp_pcb *mpcb;
        u8_t p_header_changed = 0;
        for (mpcb = udp_pcbs; mpcb != NULL; mpcb = mpcb->next) {
          if (mpcb != pcb) {
            /* compare PCB local addr+port to UDP destination addr+port */
            if ((mpcb->local_port == dest) &&
                ((!broadcast && ip_addr_isany(&mpcb->local_ip)) ||
                 ip_addr_cmp(&(mpcb->local_ip), &current_iphdr_dest) ||
#if LWIP_IGMP
                 ip_addr_ismulticast(&current_iphdr_dest) ||
#endif /* LWIP_IGMP */
#if IP_SOF_BROADCAST_RECV
                 (broadcast && ip_get_option(mpcb, SOF_BROADCAST)))) {
#else  /* IP_SOF_BROADCAST_RECV */
                 (broadcast))) {
#endif /* IP_SOF_BROADCAST_RECV */
              /* pass a copy of the packet to all local matches */
              if (mpcb->recv != NULL) { //如果注册了用户处理程序
                struct pbuf *q;
                /* for that, move payload to IP header again */
                if (p_header_changed == 0) {
                  pbuf_header(p, (s16_t)((IPH_HL(iphdr) * 4) + UDP_HLEN));
                  p_header_changed = 1;
                }
                q = pbuf_alloc(PBUF_RAW, p->tot_len, PBUF_RAM);
                if (q != NULL) {
                  err_t err = pbuf_copy(q, p);
                  if (err == ERR_OK) {
                    /* move payload to UDP data */
                    pbuf_header(q, -(s16_t)((IPH_HL(iphdr) * 4) + UDP_HLEN));
                    mpcb->recv(mpcb->recv_arg, mpcb, q, ip_current_src_addr(), src);    //调用用户处理程序  重点！
                  }
                }
              }
            }
          }
        }
        if (p_header_changed) {
          /* and move payload to UDP data again */
          pbuf_header(p, -(s16_t)((IPH_HL(iphdr) * 4) + UDP_HLEN));
        }
      }
#endif /* SO_REUSE && SO_REUSE_RXTOALL */
      /* callback */
      if (pcb->recv != NULL) {
        /* now the recv function is responsible for freeing p */
        pcb->recv(pcb->recv_arg, pcb, p, ip_current_src_addr(), src);
      } else {
        /* no recv function registered? then we have to free the pbuf! */
        pbuf_free(p);   //如果没有注册用户处理程序 则直接释放pbuf并返回
        goto end;
      }
    } else {    //如果没有匹配到控制块 则返回一个端口不可达的差错报文
      LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, ("udp_input: not for us.\n"));

#if LWIP_ICMP
      /* No match was found, send ICMP destination port unreachable unless
         destination address was broadcast/multicast. */
      if (!broadcast &&
          !ip_addr_ismulticast(&current_iphdr_dest)) {  //不是多播报和广播包
        /* move payload pointer back to ip header */
        pbuf_header(p, (IPH_HL(iphdr) * 4) + UDP_HLEN);
        LWIP_ASSERT("p->payload == iphdr", (p->payload == iphdr));
        icmp_dest_unreach(p, ICMP_DUR_PORT);    //发送端口不可达报文
      }
#endif /* LWIP_ICMP */
      UDP_STATS_INC(udp.proterr);
      UDP_STATS_INC(udp.drop);
      snmp_inc_udpnoports();
      pbuf_free(p);         //释放数据报
    }
  } else {
    pbuf_free(p);
  }
end:
  PERF_STOP("udp_input");
}

/**
 * Send data using UDP.
 *
 * @param pcb UDP PCB used to send the data.
 * @param p chain of pbuf's to be sent.
 *                  发送函数
 * The datagram will be sent to the current remote_ip & remote_port
 * stored in pcb. If the pcb is not bound to a port, it will
 * automatically be bound to a random port. 如果当前pcb没有绑定端口号 则绑定一个随机端口号
 *
 * @return lwIP error code.
 * - ERR_OK. Successful. No error occured.
 * - ERR_MEM. Out of memory.
 * - ERR_RTE. Could not find route to destination address.
 * - More errors could be returned by lower protocol layers.
 *
 * @see udp_disconnect() udp_sendto()
 */
err_t
udp_send(struct udp_pcb *pcb, struct pbuf *p)
{
  /* send to the packet using remote ip and port stored in the pcb */
  return udp_sendto(pcb, p, &pcb->remote_ip, pcb->remote_port);
}

#if LWIP_CHECKSUM_ON_COPY
/** Same as udp_send() but with checksum
 */
err_t
udp_send_chksum(struct udp_pcb *pcb, struct pbuf *p,
                u8_t have_chksum, u16_t chksum)
{
  /* send to the packet using remote ip and port stored in the pcb */
  return udp_sendto_chksum(pcb, p, &pcb->remote_ip, pcb->remote_port,
    have_chksum, chksum);
}
#endif /* LWIP_CHECKSUM_ON_COPY */

/**
 * Send data to a specified address using UDP.
 *  UDP发送函数 
 * @param pcb UDP PCB used to send the data.  发送的uudp控制块
 * @param p chain of pbuf's to be sent.    需要发送的数据打包到pbuf中
 * @param dst_ip Destination IP address. 目的IP
 * @param dst_port Destination UDP port. 目的端口号
 *
 * dst_ip & dst_port are expected to be in the same byte order as in the pcb.
 *
 * If the PCB already has a remote address association, it will
 * be restored after the data is sent.
 * 
 * @return lwIP error code (@see udp_send for possible error codes)
 *
 * @see udp_disconnect() udp_send()
 */
err_t
udp_sendto(struct udp_pcb *pcb, struct pbuf *p,
  ip_addr_t *dst_ip, u16_t dst_port)
{
#if LWIP_CHECKSUM_ON_COPY
  return udp_sendto_chksum(pcb, p, dst_ip, dst_port, 0, 0);
}

/** Same as udp_sendto(), but with checksum 带校验的发送函数*/
err_t
udp_sendto_chksum(struct udp_pcb *pcb, struct pbuf *p, ip_addr_t *dst_ip,
                  u16_t dst_port, u8_t have_chksum, u16_t chksum)
{
#endif /* LWIP_CHECKSUM_ON_COPY */
  struct netif *netif;

  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, ("udp_send\n"));

  /* find the outgoing network interface for this packet */
#if LWIP_IGMP
  netif = ip_route((ip_addr_ismulticast(dst_ip))?(&(pcb->multicast_ip)):(dst_ip)); //通过目的地址寻找一个合适的网卡
#else
  netif = ip_route(dst_ip);     //通过目的IP找到一个合适的网卡
#endif /* LWIP_IGMP */

  /* no outgoing network interface could be found? */
  if (netif == NULL) {  //如果没有找到 则直接返回
    LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("udp_send: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
      ip4_addr1_16(dst_ip), ip4_addr2_16(dst_ip), ip4_addr3_16(dst_ip), ip4_addr4_16(dst_ip)));
    UDP_STATS_INC(udp.rterr);
    return ERR_RTE;
  }
#if LWIP_CHECKSUM_ON_COPY       //如果带了校验功能
  return udp_sendto_if_chksum(pcb, p, dst_ip, dst_port, netif, have_chksum, chksum);
#else /* LWIP_CHECKSUM_ON_COPY */
  return udp_sendto_if(pcb, p, dst_ip, dst_port, netif);    //调用该函数组装并发送报文
#endif /* LWIP_CHECKSUM_ON_COPY */
}

/**
 * Send data to a specified address using UDP.
 * The netif used for sending can be specified.
 *
 * This function exists mainly for DHCP, to be able to send UDP packets
 * on a netif that is still down.
 *
 * @param pcb UDP PCB used to send the data.
 * @param p chain of pbuf's to be sent.
 * @param dst_ip Destination IP address.
 * @param dst_port Destination UDP port.
 * @param netif the netif used for sending.
 *
 * dst_ip & dst_port are expected to be in the same byte order as in the pcb.
 *
 * @return lwIP error code (@see udp_send for possible error codes)
 *
 * @see udp_disconnect() udp_send()
 */
err_t
udp_sendto_if(struct udp_pcb *pcb, struct pbuf *p,
  ip_addr_t *dst_ip, u16_t dst_port, struct netif *netif)
{
#if LWIP_CHECKSUM_ON_COPY
  return udp_sendto_if_chksum(pcb, p, dst_ip, dst_port, netif, 0, 0);
}

/** Same as udp_sendto_if(), but with checksum */
err_t
udp_sendto_if_chksum(struct udp_pcb *pcb, struct pbuf *p, ip_addr_t *dst_ip,
                     u16_t dst_port, struct netif *netif, u8_t have_chksum,
                     u16_t chksum)
{
#endif /* LWIP_CHECKSUM_ON_COPY */
  struct udp_hdr *udphdr;   //udp首部结构
  ip_addr_t *src_ip;
  err_t err;
  struct pbuf *q; /* q will be sent down the stack */

#if IP_SOF_BROADCAST
  /* broadcast filter? */
  if (!ip_get_option(pcb, SOF_BROADCAST) && ip_addr_isbroadcast(dst_ip, netif)) {
    LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
      ("udp_sendto_if: SOF_BROADCAST not enabled on pcb %p\n", (void *)pcb));
    return ERR_VAL;
  }
#endif /* IP_SOF_BROADCAST */

  /* if the PCB is not yet bound to a port, bind it here 如果还没有绑定端口号 则在这里绑定*/
  if (pcb->local_port == 0) {
    LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, ("udp_send: not yet bound to a port, binding now\n"));
    err = udp_bind(pcb, &pcb->local_ip, pcb->local_port);
    if (err != ERR_OK) {
      LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS, ("udp_send: forced port bind failed\n"));
      return err;
    }
  }
    /*这里开始构造udp的首部 如果首部用户数据区pbuf数据区前面放不下udp首部空间 则为首部空间重新申请一个首部pbuf空间*/
  /* not enough space to add an UDP header to first pbuf in given p chain? */
  if (pbuf_header(p, UDP_HLEN)) {   //如果移动指针失败
    /* allocate header in a separate new pbuf */
    q = pbuf_alloc(PBUF_IP, UDP_HLEN, PBUF_RAM);    //重新申请一个pbuf空间用来放udp首部
    /* new header pbuf could not be allocated? */
    if (q == NULL) {    //申请失败则返回
      LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS, ("udp_send: could not allocate header\n"));
      return ERR_MEM;
    }
    if (p->tot_len != 0) {  //如果数据区中有数据
      /* chain header q in front of given pbuf p (only if p contains data) */
      pbuf_chain(q, p); //将q和p连接起来
    }
    /* first pbuf q points to header pbuf */
    LWIP_DEBUGF(UDP_DEBUG,
                ("udp_send: added header pbuf %p before given pbuf %p\n", (void *)q, (void *)p));
  } else {  //否则能放的下
    /* adding space for header within p succeeded */
    /* first pbuf q equals given pbuf */
    q = p;  //q指向pbuf 注意这里我们已经调整了p中的payload指针指向了udp首部首地址

    LWIP_DEBUGF(UDP_DEBUG, ("udp_send: added header in given pbuf %p\n", (void *)p));
  }
  LWIP_ASSERT("check that first pbuf can hold struct udp_hdr",
              (q->len >= sizeof(struct udp_hdr)));
  /* q now represents the packet to be sent */
 /*到这里 q都指向了pbuf 且保证pbuf中有足够的空间来放得下udp的首部 注意：p的指针已经被移动过了*/
  udphdr = (struct udp_hdr *)q->payload; //指向udp头部
  udphdr->src = htons(pcb->local_port); //填充本地端口号
  udphdr->dest = htons(dst_port);           //填充远端端口号
  /* in UDP, 0 checksum means 'no checksum' */
  udphdr->chksum = 0x0000;      // 0 表示没有校验

  /* Multicast Loop? */
#if LWIP_IGMP
  if (ip_addr_ismulticast(dst_ip) && ((pcb->flags & UDP_FLAGS_MULTICAST_LOOP) != 0)) {
    q->flags |= PBUF_FLAG_MCASTLOOP;
  }
#endif /* LWIP_IGMP */


  /* PCB local address is IP_ANY_ADDR? */
  if (ip_addr_isany(&pcb->local_ip)) {  //如果绑定了任意的IP地址 则分配当前网卡的IP地址
    /* use outgoing network interface IP address as source address */
    src_ip = &(netif->ip_addr); //网卡中的ip地址为伪首部的IP地址
  } else { //如果控制块中记录了IP地址 但是该IP地址和网卡接口的IP地址不一致 说明控制块是旧的无效地址
    /* check if UDP PCB local IP address is correct
     * this could be an old address if netif->ip_addr has changed */
    if (!ip_addr_cmp(&(pcb->local_ip), &(netif->ip_addr))) {
      /* local_ip doesn't match, drop the packet */
      if (q != p) { //如果申请了q 
        /* free the header pbuf */
        pbuf_free(q);   //释放掉q 注意：这里的p不会被释放 需要调用者自己去释放
        q = NULL;
        /* p is still referenced by the caller, and will live on */
      }
      return ERR_VAL;
    }
    /* use UDP PCB local IP address as source address */
    src_ip = &(pcb->local_ip);  //控制块中记录的IP地址为伪首部的IP地址
  }

  LWIP_DEBUGF(UDP_DEBUG, ("udp_send: sending datagram of length %"U16_F"\n", q->tot_len));

#if LWIP_UDPLITE
  /* UDP Lite protocol? */
  if (pcb->flags & UDP_FLAGS_UDPLITE) {
    u16_t chklen, chklen_hdr;
    LWIP_DEBUGF(UDP_DEBUG, ("udp_send: UDP LITE packet length %"U16_F"\n", q->tot_len));
    /* set UDP message length in UDP header */
    chklen_hdr = chklen = pcb->chksum_len_tx;
    if ((chklen < sizeof(struct udp_hdr)) || (chklen > q->tot_len)) {
      if (chklen != 0) {
        LWIP_DEBUGF(UDP_DEBUG, ("udp_send: UDP LITE pcb->chksum_len is illegal: %"U16_F"\n", chklen));
      }
      /* For UDP-Lite, checksum length of 0 means checksum
         over the complete packet. (See RFC 3828 chap. 3.1)
         At least the UDP-Lite header must be covered by the
         checksum, therefore, if chksum_len has an illegal
         value, we generate the checksum over the complete
         packet to be safe. */
      chklen_hdr = 0;
      chklen = q->tot_len;
    }
    udphdr->len = htons(chklen_hdr);
    /* calculate checksum */
#if CHECKSUM_GEN_UDP
    udphdr->chksum = inet_chksum_pseudo_partial(q, src_ip, dst_ip,
      IP_PROTO_UDPLITE, q->tot_len,
#if !LWIP_CHECKSUM_ON_COPY
      chklen);
#else /* !LWIP_CHECKSUM_ON_COPY */
      (have_chksum ? UDP_HLEN : chklen));
    if (have_chksum) {
      u32_t acc;
      acc = udphdr->chksum + (u16_t)~(chksum);
      udphdr->chksum = FOLD_U32T(acc);
    }
#endif /* !LWIP_CHECKSUM_ON_COPY */

    /* chksum zero must become 0xffff, as zero means 'no checksum' */
    if (udphdr->chksum == 0x0000) { //如果checksum是0 则必须要设置为0xffff 因为0 表示没有校验
      udphdr->chksum = 0xffff;
    }
#endif /* CHECKSUM_GEN_UDP */
    /* output to IP */
    LWIP_DEBUGF(UDP_DEBUG, ("udp_send: ip_output_if (,,,,IP_PROTO_UDPLITE,)\n"));
    NETIF_SET_HWADDRHINT(netif, &pcb->addr_hint);
    err = ip_output_if(q, src_ip, dst_ip, pcb->ttl, pcb->tos, IP_PROTO_UDPLITE, netif);
    NETIF_SET_HWADDRHINT(netif, NULL);
  } else
#endif /* LWIP_UDPLITE */
  {      /* UDP  接下来填充其他字段并校验*/
    LWIP_DEBUGF(UDP_DEBUG, ("udp_send: UDP packet length %"U16_F"\n", q->tot_len));
    udphdr->len = htons(q->tot_len);    //udp头部字段 总长度
    /* calculate checksum */
#if CHECKSUM_GEN_UDP
    if ((pcb->flags & UDP_FLAGS_NOCHKSUM) == 0) {   //如果控制块的flags字段允许计算校验和 则开始计算校验和
      u16_t udpchksum;
#if LWIP_CHECKSUM_ON_COPY
      if (have_chksum) {    //如果已经有了校验和
        u32_t acc;
        udpchksum = inet_chksum_pseudo_partial(q, src_ip, dst_ip, IP_PROTO_UDP,
          q->tot_len, UDP_HLEN); //再计算一次
        acc = udpchksum + (u16_t)~(chksum);
        udpchksum = FOLD_U32T(acc);
      } else
#endif /* LWIP_CHECKSUM_ON_COPY */
      { //校验和计算函数 传入的参数依次是：数据区首地址 源IP地址 目的Ip地址 协议类型 总长度
        udpchksum = inet_chksum_pseudo(q, src_ip, dst_ip, IP_PROTO_UDP, q->tot_len); //调用函数计算校验和
      }

      /* chksum zero must become 0xffff, as zero means 'no checksum' */
      if (udpchksum == 0x0000) { //如果为0 则取反
        udpchksum = 0xffff;
      }
      udphdr->chksum = udpchksum;  //填充校验和字段
    }
#endif /* CHECKSUM_GEN_UDP */
    LWIP_DEBUGF(UDP_DEBUG, ("udp_send: UDP checksum 0x%04"X16_F"\n", udphdr->chksum));
    LWIP_DEBUGF(UDP_DEBUG, ("udp_send: ip_output_if (,,,,IP_PROTO_UDP,)\n"));
    /* output to IP */
    NETIF_SET_HWADDRHINT(netif, &pcb->addr_hint);
    err = ip_output_if(q, src_ip, dst_ip, pcb->ttl, pcb->tos, IP_PROTO_UDP, netif); //调用IP层发送函数 填写IP首部 发送Ip数据
    NETIF_SET_HWADDRHINT(netif, NULL);
  }
  /* TODO: must this be increased even if error occured? */
  snmp_inc_udpoutdatagrams();

  /* did we chain a separate header pbuf earlier? */
  if (q != p) {
    /* free the header pbuf */
    pbuf_free(q);   //释放申请的空间
    q = NULL;
    /* p is still referenced by the caller, and will live on 注意：这里的p占用的空间依旧存在 需要调用者自己去释放*/
  }
    
  UDP_STATS_INC(udp.xmit);
  return err;
}

/**
 * Bind an UDP PCB.
 * 为UDP控制块绑定一个本地IP地址和端口号
 * @param pcb UDP PCB to be bound with a local address ipaddr and port. 指向要操作的控制块
 * @param ipaddr local IP address to bind with. Use IP_ADDR_ANY to
 * bind to all local interfaces.    本地IP地址 若为IP_ADDR_ANY(0) 表示任意网络接口结构的IP地址 （LwIP可以使用多个网卡）
 * @param port local UDP port to bind with. Use 0 to automatically bind
 * to a random port between UDP_LOCAL_PORT_RANGE_START and
 * UDP_LOCAL_PORT_RANGE_END.    
 * 希望绑定的端口号  如果为0 函数会自动分配一个短暂随机端口号给当前的UDP
 * ipaddr & port are expected to be in the same byte order as in the pcb.
 *
 * @return lwIP error code.
 * - ERR_OK. Successful. No error occured.
 * - ERR_USE. The specified ipaddr and port are already bound to by
 * another UDP PCB. 
 *
 * @see udp_disconnect()
 */
err_t
udp_bind(struct udp_pcb *pcb, ip_addr_t *ipaddr, u16_t port)
{
  struct udp_pcb *ipcb;
  u8_t rebind;  //表示控制块是否已经在链表udp_pcbs

  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, ("udp_bind(ipaddr = "));
  ip_addr_debug_print(UDP_DEBUG, ipaddr);
  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, (", port = %"U16_F")\n", port));

  rebind = 0;
  /* Check for double bind and rebind of the same pcb */
    /*遍历整个链表 查找控制块pcb 若控制块已经在链表中 则后续不再进行链表插入操作 
     * 同时查找对应的IP地址和端口号是否已经被其他控制块绑定 */
  for (ipcb = udp_pcbs; ipcb != NULL; ipcb = ipcb->next) {
    /* is this UDP PCB already on active list? */
    if (pcb == ipcb) {  //如果控制块已经在链表中
      /* pcb may occur at most once in active list */
      LWIP_ASSERT("rebind == 0", rebind == 0);
      /* pcb already in list, just rebind */
      rebind = 1;   //置位
    }

    /* By default, we don't allow to bind to a port that any other udp
       PCB is alread bound to, unless *all* PCBs with that port have tha
       REUSEADDR flag set. */
#if SO_REUSE
    else if (!ip_get_option(pcb, SOF_REUSEADDR) &&
             !ip_get_option(ipcb, SOF_REUSEADDR)) {
#else /* SO_REUSE */
    /* port matches that of PCB in list and REUSEADDR not set -> reject */
    else {
#endif /* SO_REUSE */
      if ((ipcb->local_port == port) &&
          /* IP address matches, or one is IP_ADDR_ANY? */
          (ip_addr_isany(&(ipcb->local_ip)) ||
           ip_addr_isany(ipaddr) ||
           ip_addr_cmp(&(ipcb->local_ip), ipaddr))) {
        /* other PCB already binds to this local IP and port */
        LWIP_DEBUGF(UDP_DEBUG,
                    ("udp_bind: local port %"U16_F" already bound by another pcb\n", port));
        return ERR_USE; // 匹配 则返回端口号已经被占用错误
      }
    }
  }

  ip_addr_set(&pcb->local_ip, ipaddr);  //绑定控制块本地Ip地址字段

  /* no port specified? */
  if (port == 0) {  //如果端口号为0 则表明希望系统自动分配一个端口号给我们
    port = udp_new_port();  //从第一个短暂端口开始 一次判断该端口号是否已经被占用 如果没有被占用  则返回
    if (port == 0) {
      /* no more ports available in local range */
      LWIP_DEBUGF(UDP_DEBUG, ("udp_bind: out of free UDP ports\n"));
      return ERR_USE;
    }
  }
  pcb->local_port = port;   //绑定本地端口号
  snmp_insert_udpidx_tree(pcb);
  /* pcb not active yet? */
  if (rebind == 0) {    //如果控制块没有在链表中 则将他插入链表的头部
    /* place the PCB on the active list if not already there */
    pcb->next = udp_pcbs;
    udp_pcbs = pcb;
  }
  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
              ("udp_bind: bound to %"U16_F".%"U16_F".%"U16_F".%"U16_F", port %"U16_F"\n",
               ip4_addr1_16(&pcb->local_ip), ip4_addr2_16(&pcb->local_ip),
               ip4_addr3_16(&pcb->local_ip), ip4_addr4_16(&pcb->local_ip),
               pcb->local_port));
  return ERR_OK;
}
/**
 * Connect an UDP PCB.
 * 为UDP控制块绑定一个远端端口和IP地址
 * This will associate the UDP PCB with the remote address.
 *
 * @param pcb UDP PCB to be connected with remote address ipaddr and port. 指向要操作的pcb控制块
 * @param ipaddr remote IP address to connect with. 远端IP地址
 * @param port remote UDP port to connect with. 远端端口号
 *  
 * @return lwIP error code
 *
 * ipaddr & port are expected to be in the same byte order as in the pcb.
 *
 * The udp pcb is bound to a random local port if not already bound.
 *
 * @see udp_disconnect()
 */
err_t
udp_connect(struct udp_pcb *pcb, ip_addr_t *ipaddr, u16_t port)
{
  struct udp_pcb *ipcb;

  if (pcb->local_port == 0) { //如果没有绑定本地端口号
    err_t err = udp_bind(pcb, &pcb->local_ip, pcb->local_port); //则调用bind函数绑定本地端口号
    if (err != ERR_OK) {    //如果绑定失败 则返回错误码
      return err;
    }
  }

  ip_addr_set(&pcb->remote_ip, ipaddr); //绑定远端IP地址
  pcb->remote_port = port;          //绑定远端端口号
  pcb->flags |= UDP_FLAGS_CONNECTED;  //控制块状态置为连接状态
/** TODO: this functionality belongs in upper layers */
#ifdef LWIP_UDP_TODO
  /* Nail down local IP for netconn_addr()/getsockname() */
  if (ip_addr_isany(&pcb->local_ip) && !ip_addr_isany(&pcb->remote_ip)) {
    struct netif *netif;

    if ((netif = ip_route(&(pcb->remote_ip))) == NULL) {
      LWIP_DEBUGF(UDP_DEBUG, ("udp_connect: No route to 0x%lx\n", pcb->remote_ip.addr));
      UDP_STATS_INC(udp.rterr);
      return ERR_RTE;
    }
    /** TODO: this will bind the udp pcb locally, to the interface which
        is used to route output packets to the remote address. However, we
        might want to accept incoming packets on any interface! */
    pcb->local_ip = netif->ip_addr;
  } else if (ip_addr_isany(&pcb->remote_ip)) {
    pcb->local_ip.addr = 0;
  }
#endif
  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
              ("udp_connect: connected to %"U16_F".%"U16_F".%"U16_F".%"U16_F",port %"U16_F"\n",
               ip4_addr1_16(&pcb->local_ip), ip4_addr2_16(&pcb->local_ip),
               ip4_addr3_16(&pcb->local_ip), ip4_addr4_16(&pcb->local_ip),
               pcb->local_port));

  /* Insert UDP PCB into the list of active UDP PCBs. */
  /*遍历链表 查找是否控制块已经在链表中*/
  for (ipcb = udp_pcbs; ipcb != NULL; ipcb = ipcb->next) {
    if (pcb == ipcb) { //如果在链表中直接返回
      /* already on the list, just return */
      return ERR_OK;
    }
  }
  /* PCB not yet on the list, add PCB now */
  /*如果没有在链表中 则插入头部*/
  pcb->next = udp_pcbs;
  udp_pcbs = pcb;
  return ERR_OK;
}

/**
 * Disconnect a UDP PCB
 * 断开连接
 * @param pcb the udp pcb to disconnect.
 */
void
udp_disconnect(struct udp_pcb *pcb)
{
  /* reset remote address association */
  ip_addr_set_any(&pcb->remote_ip); //清除远端IP地址
  pcb->remote_port = 0;                 //清楚远端端口号
  /* mark PCB as unconnected */
  pcb->flags &= ~UDP_FLAGS_CONNECTED;   //设置flags字段为断开连接状态
}

/**
 * Set a receive callback for a UDP PCB
 *
 * This callback will be called when receiving a datagram for the pcb.
 * 为控制块注册回掉函数 注意这里的回掉函数需要在处理完成数据后释放pbuf空间
 * @param pcb the pcb for wich to set the recv callback UDP控制块
 * @param recv function pointer of the callback function    用户自定义的数据报处理函数
 * @param recv_arg additional argument to pass to the callback function 
 */
void
udp_recv(struct udp_pcb *pcb, udp_recv_fn recv, void *recv_arg)
{
  /* remember recv() callback and user data */
  pcb->recv = recv; //绑定控制块的recv字段
  pcb->recv_arg = recv_arg; //绑定控制块的recv_arg字段
}

/**
 * Remove an UDP PCB.
 * 将一个控制块从控制块链表中删除 并释放相应的内存空间
 * @param pcb UDP PCB to be removed. The PCB is removed from the list of
 * UDP PCB's and the data structure is freed from memory.
 *
 * @see udp_new()
 */
void
udp_remove(struct udp_pcb *pcb)
{
  struct udp_pcb *pcb2;

  snmp_delete_udpidx_tree(pcb);
  /* pcb to be removed is first in list? */
  if (udp_pcbs == pcb) {    //如果UDP控制块在链表的头部 
    /* make list start at 2nd pcb */
    udp_pcbs = udp_pcbs->next;  //从链表上删除
    /* pcb not 1st in list */
  } else {  //否则 依次遍历查找链表
    for (pcb2 = udp_pcbs; pcb2 != NULL; pcb2 = pcb2->next) {
      /* find pcb in udp_pcbs list */
      if (pcb2->next != NULL && pcb2->next == pcb) {    //如果找到了
        /* remove pcb from list */
        pcb2->next = pcb->next;  //从链表上删除
      }
    }
  }
  memp_free(MEMP_UDP_PCB, pcb); //释放内存池空间
}

/**
 * Create a UDP PCB.
 *新建一个UDP控制块
 * @return The UDP PCB which was created. NULL if the PCB data structure
 * could not be allocated.
 *
 * @see udp_remove()
 */
struct udp_pcb *
udp_new(void)
{
  struct udp_pcb *pcb;
    /*为UDP控制块申请一个内存池空间*/
  pcb = (struct udp_pcb *)memp_malloc(MEMP_UDP_PCB);
  /* could allocate UDP PCB? */
  if (pcb != NULL) {    //如果申请成功 
    /* UDP Lite: by initializing to all zeroes, chksum_len is set to 0
     * which means checksum is generated over the whole datagram per default
     * (recommended as default by RFC 3828). */
    /* initialize PCB to all zeroes */
    memset(pcb, 0, sizeof(struct udp_pcb));  //全部初始化为0
    pcb->ttl = UDP_TTL;     //设置控制块中的TTL字段
  }
  return pcb;   //返回控制块的指针
}

#if UDP_DEBUG
/**
 * Print UDP header information for debug purposes.
 *
 * @param udphdr pointer to the udp header in memory.
 */
void
udp_debug_print(struct udp_hdr *udphdr)
{
  LWIP_DEBUGF(UDP_DEBUG, ("UDP header:\n"));
  LWIP_DEBUGF(UDP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(UDP_DEBUG, ("|     %5"U16_F"     |     %5"U16_F"     | (src port, dest port)\n",
                          ntohs(udphdr->src), ntohs(udphdr->dest)));
  LWIP_DEBUGF(UDP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(UDP_DEBUG, ("|     %5"U16_F"     |     0x%04"X16_F"    | (len, chksum)\n",
                          ntohs(udphdr->len), ntohs(udphdr->chksum)));
  LWIP_DEBUGF(UDP_DEBUG, ("+-------------------------------+\n"));
}
#endif /* UDP_DEBUG */

#endif /* LWIP_UDP */
