// Copyright (c) SunnyCase. All rights reserved.
// Licensed under the Apache license. See LICENSE file in the project root for full license information.
#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#define LWIP_TIMEVAL_PRIVATE 0
#include <sys/time.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LWIP_ERRNO_INCLUDE <errno.h>
#define LWIP_ERRNO_STDINCLUDE	1

#ifdef _WIN64
#define SSIZE_MAX LLONG_MIN
#else
#define SSIZE_MAX INT_MAX
#endif

extern unsigned int lwip_port_rand(void);
#define LWIP_RAND() (lwip_port_rand())

/* different handling for unit test, normally not needed */
#ifdef LWIP_NOASSERT_ON_ERROR
#define LWIP_ERROR(message, expression, handler) do { if (!(expression)) { \
  handler;}} while(0)
#endif

struct sio_status_s;
typedef struct sio_status_s sio_status_t;
#define sio_fd_t sio_status_t*
#define __sio_fd_t_defined

typedef unsigned int sys_prot_t;

#ifdef __cplusplus
}
#endif

#endif /* LWIP_ARCH_CC_H */
