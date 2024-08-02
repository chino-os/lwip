// Copyright (c) SunnyCase. All rights reserved.
// Licensed under the Apache license. See LICENSE file in the project root for full license information.
#ifndef LWIP_LWIPOPTS_H
#define LWIP_LWIPOPTS_H

/*
 * Include user defined options first. Anything not defined in these files
 * will be set to standard values. Override anything you don't like!
 */
#include "lwipopts.h"
#include "lwip/debug.h"

// Platform specific locking
#define SYS_LIGHTWEIGHT_PROT            0

#define NO_SYS                          0

// Memory options
#define MEM_ALIGNMENT                   1U
#define MEM_SIZE                        1600

// Internal Memory Pool Sizes
#define MEMP_NUM_PBUF                   16
#define MEMP_NUM_RAW_PCB                4
#define MEMP_NUM_UDP_PCB                4
#define MEMP_NUM_TCP_PCB                4
#define MEMP_NUM_TCP_PCB_LISTEN         4
#define MEMP_NUM_TCP_SEG                16
#define MEMP_NUM_REASSDATA              1
#define MEMP_NUM_ARP_QUEUE              2
#define MEMP_NUM_SYS_TIMEOUT            8
#define MEMP_NUM_NETBUF                 2
#define MEMP_NUM_NETCONN               32
#define MEMP_NUM_TCPIP_MSG_API          8
#define MEMP_NUM_TCPIP_MSG_INPKT        8

#define PBUF_POOL_SIZE                  8

// ARP options
#define LWIP_ARP                        1

// IP options
#define IP_FORWARD                      0
#define IP_OPTIONS_ALLOWED              1
#define IP_REASSEMBLY                   1
#define IP_FRAG                         1
#define IP_REASS_MAXAGE                 3
#define IP_REASS_MAX_PBUFS              4
#define IP_FRAG_USES_STATIC_BUF         0
#define IP_DEFAULT_TTL                  255

// ICMP options
#define LWIP_ICMP                       1

// IPv6 options
#define LWIP_IPV6                       1

// RAW options
#define LWIP_RAW                        1

// DHCP options
#define LWIP_DHCP                       0

// AUTOIP options
#define LWIP_AUTOIP                     0

// SNMP options
#define LWIP_SNMP                       0

// IGMP options
#define LWIP_IGMP                       0

// DNS options
#define LWIP_DNS                        0

// UDP options
#define LWIP_UDP                        1

// TCP options
#define LWIP_TCP                        1
#define TCP_LISTEN_BACKLOG              0

// Pbuf options
#define PBUF_LINK_HLEN                  16
#define PBUF_POOL_BUFSIZE               LWIP_MEM_ALIGN_SIZE(TCP_MSS+40+PBUF_LINK_HLEN)

// LOOPIF options
#define LWIP_HAVE_LOOPIF                1
#define LWIP_NETIF_LOOPBACK             1

// Sequential layer options
#define LWIP_NETCONN                    1

// Socket options
#define LWIP_SOCKET                     0
#define LWIP_COMPAT_SOCKETS             0
#define SO_REUSE                        1
#define LWIP_SO_RCVTIMEO                1

/* User posix socket headers */
#define LWIP_SOCKET_EXTERNAL_HEADERS            1
#define LWIP_SOCKET_EXTERNAL_HEADER_SOCKETS_H   "posix/sockets.h"
#define LWIP_SOCKET_EXTERNAL_HEADER_INET_H      "posix/inet.h"
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS   1

// Statistics options
#define LWIP_STATS                      0

// PPP options
#define PPP_SUPPORT                     0

// Threading options
#define LWIP_TCPIP_CORE_LOCKING         1

void sys_check_core_locking(void);
#define LWIP_ASSERT_CORE_LOCKED()  sys_check_core_locking()

#endif /* LWIP_LWIPOPTS_H */
