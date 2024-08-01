// Copyright (c) SunnyCase. All rights reserved.
// Licensed under the Apache license. See LICENSE file in the project root for full license information.
#ifndef LWIP_ARCH_SYS_ARCH_H
#define LWIP_ARCH_SYS_ARCH_H

extern "C++" {
#include <chino/os/processapi.h>
#include "../../../../os/kernel/ps/task/thread.h"
}

#ifdef __cplusplus
extern "C" {
#endif

#define SYS_INVALID (uint32_t) - 1
#define SYS_MBOX_SIZE 8

/*typedef u32_t sys_prot_t;*/

typedef union sys_sem {
    constexpr sys_sem() noexcept : invalid(SYS_INVALID) {}
    uint32_t invalid;
    chino::os::event event;
} sys_sem_t;
#define sys_sem_valid(sem)             ((sem)->invalid != SYS_INVALID)
#define sys_sem_valid_val(sem)         ((sem).invalid != SYS_INVALID)
#define sys_sem_set_invalid(sem)       ((sem)->invalid = SYS_INVALID)
#define sys_sem_set_invalid_val(sem)   ((sem).invalid = SYS_INVALID)

typedef union sys_mutex {
    constexpr sys_mutex() noexcept : invalid(SYS_INVALID) {}
    uint32_t invalid;
    chino::os::mutex mutex;
} sys_mutex_t;
#define sys_mutex_valid(mutex)         ((mutex)->invalid != SYS_INVALID)
#define sys_mutex_set_invalid(mutex)   ((mutex)->invalid = SYS_INVALID)

typedef struct sys_mbox {
    constexpr sys_mbox() noexcept : first(0), last(0), msgs{}, wait_send(0) {}
    int first, last;
    void *msgs[SYS_MBOX_SIZE];
    sys_sem_t not_empty;
    sys_sem_t not_full;
    sys_mutex_t mutex;
    int wait_send;
} sys_mbox_t;
#define sys_mbox_valid(mbox)           ((mbox)->first != SYS_INVALID)
#define sys_mbox_valid_val(mbox)       ((mbox).first != SYS_INVALID)
#define sys_mbox_set_invalid(mbox)     ((mbox)->first = SYS_INVALID)
#define sys_mbox_set_invalid_val(mbox) ((mbox).first = SYS_INVALID)

struct sys_thread;
typedef struct sys_thread * sys_thread_t;

#if LWIP_NETCONN_SEM_PER_THREAD
sys_sem_t* sys_arch_netconn_sem_get(void);
void sys_arch_netconn_sem_alloc(void);
void sys_arch_netconn_sem_free(void);
#define LWIP_NETCONN_THREAD_SEM_GET()   sys_arch_netconn_sem_get()
#define LWIP_NETCONN_THREAD_SEM_ALLOC() sys_arch_netconn_sem_alloc()
#define LWIP_NETCONN_THREAD_SEM_FREE()  sys_arch_netconn_sem_free()
#endif /* #if LWIP_NETCONN_SEM_PER_THREAD */

/*
   ---------------------------------------
   ---------- Threading options ----------
   ---------------------------------------
*/

void sys_mark_tcpip_thread(void);
#define LWIP_MARK_TCPIP_THREAD()   sys_mark_tcpip_thread()

#if LWIP_TCPIP_CORE_LOCKING
void sys_lock_tcpip_core(void);
#define LOCK_TCPIP_CORE()          sys_lock_tcpip_core()
void sys_unlock_tcpip_core(void);
#define UNLOCK_TCPIP_CORE()        sys_unlock_tcpip_core()
#endif

#ifdef __cplusplus
}
#endif

#endif /* LWIP_ARCH_SYS_ARCH_H */
