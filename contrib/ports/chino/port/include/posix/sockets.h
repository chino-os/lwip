// Copyright (c) SunnyCase. All rights reserved.
// Licensed under the Apache license. See LICENSE file in the project root for full license information.

#include <errno.h>
#include <sys/socket.h>
#include LWIP_SOCKET_EXTERNAL_HEADER_INET_H
typedef size_t msg_iovlen_t;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _HAVE_SA_LEN
#define HAVE_SA_LEN _HAVE_SA_LEN
#else
#define HAVE_SA_LEN 0
#endif /* _HAVE_SA_LEN */

#define __SOCKADDR_COMMON_SIZE (sizeof(sa_family_t))

/* Address length safe read and write */
#if HAVE_SA_LEN
#define IP4ADDR_SOCKADDR_SET_LEN(sin) (sin)->sin_len = sizeof(struct sockaddr_in)
#define IP6ADDR_SOCKADDR_SET_LEN(sin6) (sin6)->sin6_len = sizeof(struct sockaddr_in6)
#define IPADDR_SOCKADDR_GET_LEN(addr) (addr)->sa.sa_len
#else
#define IP4ADDR_SOCKADDR_SET_LEN(addr)
#define IP6ADDR_SOCKADDR_SET_LEN(addr)
#define IPADDR_SOCKADDR_GET_LEN(addr)                                                                                  \
    ((addr)->sa.sa_family == AF_INET ? sizeof(struct sockaddr_in)                                                      \
                                     : ((addr)->sa.sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : 0))
#endif /* HAVE_SA_LEN */

#define SIN_ZERO_LEN sizeof(struct sockaddr) - __SOCKADDR_COMMON_SIZE - sizeof(in_port_t) - sizeof(struct in_addr)

#if !defined IOV_MAX
#define IOV_MAX 0xFFFF
#elif IOV_MAX > 0xFFFF
#error "IOV_MAX larger than supported by LwIP"
#endif /* IOV_MAX */

#define LWIP_SELECT_MAXNFDS (FD_SETSIZE + LWIP_SOCKET_OFFSET)

#if LWIP_UDP && LWIP_UDPLITE
/*
 * Options for level IPPROTO_UDPLITE
 */
#define UDPLITE_SEND_CSCOV 0x01 /* sender checksum coverage */
#define UDPLITE_RECV_CSCOV 0x02 /* minimal receiver checksum coverage */
#endif                          /* LWIP_UDP && LWIP_UDPLITE*/

#if 0
void lwip_socket_thread_init(void); /* LWIP_NETCONN_SEM_PER_THREAD==1: initialize thread-local semaphore */
void lwip_socket_thread_cleanup(void); /* LWIP_NETCONN_SEM_PER_THREAD==1: destroy thread-local semaphore */

int lwip_accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int lwip_bind(int s, const struct sockaddr *name, socklen_t namelen);
int lwip_shutdown(int s, int how);
int lwip_getpeername (int s, struct sockaddr *name, socklen_t *namelen);
int lwip_getsockname (int s, struct sockaddr *name, socklen_t *namelen);
int lwip_getsockopt (int s, int level, int optname, void *optval, socklen_t *optlen);
int lwip_setsockopt (int s, int level, int optname, const void *optval, socklen_t optlen);
 int lwip_close(int s);
int lwip_connect(int s, const struct sockaddr *name, socklen_t namelen);
int lwip_listen(int s, int backlog);
ssize_t lwip_recv(int s, void *mem, size_t len, int flags);
ssize_t lwip_read(int s, void *mem, size_t len);
ssize_t lwip_readv(int s, const struct iovec *iov, int iovcnt);
ssize_t lwip_recvfrom(int s, void *mem, size_t len, int flags,
      struct sockaddr *from, socklen_t *fromlen);
ssize_t lwip_recvmsg(int s, struct msghdr *message, int flags);
ssize_t lwip_send(int s, const void *dataptr, size_t size, int flags);
ssize_t lwip_sendmsg(int s, const struct msghdr *message, int flags);
ssize_t lwip_sendto(int s, const void *dataptr, size_t size, int flags,
    const struct sockaddr *to, socklen_t tolen);
int lwip_socket(int domain, int type, int protocol);
ssize_t lwip_write(int s, const void *dataptr, size_t size);
ssize_t lwip_writev(int s, const struct iovec *iov, int iovcnt);
#if LWIP_SOCKET_SELECT
int lwip_select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset,
                struct timeval *timeout);
#endif
#if LWIP_SOCKET_POLL
int lwip_poll(struct pollfd *fds, nfds_t nfds, int timeout);
#endif
int lwip_ioctl(int s, long cmd, void *argp);
int lwip_fcntl(int s, int cmd, int val);
const char *lwip_inet_ntop(int af, const void *src, char *dst, socklen_t size);
int lwip_inet_pton(int af, const char *src, void *dst);
#endif

/* Unsupported identifiers */
#ifndef SO_NO_CHECK
#define SO_NO_CHECK 0xFF
#endif
#ifndef SO_BINDTODEVICE
#define SO_BINDTODEVICE 0xFE
#endif
#ifndef MSG_MORE
#define MSG_MORE 0x0
#endif
#ifndef TCP_KEEPALIVE
#define TCP_KEEPALIVE 0xFF
#endif
#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE 0xFE
#endif
#ifndef TCP_KEEPINTVL
#define TCP_KEEPINTVL 0xFD
#endif
#ifndef TCP_KEEPCNT
#define TCP_KEEPCNT 0xFC
#endif

#ifdef __cplusplus
}
#endif
