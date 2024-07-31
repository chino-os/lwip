// Copyright (c) SunnyCase. All rights reserved.
// Licensed under the Apache license. See LICENSE file in the project root for full license information.
#ifndef LWIP_ARCH_SYS_ARCH_H
#define LWIP_ARCH_SYS_ARCH_H

#ifdef __cplusplus
extern "C" {
#endif

#define SYS_MBOX_NULL NULL
#define SYS_SEM_NULL  NULL

/*typedef u32_t sys_prot_t;*/

struct sys_sem;
typedef struct sys_sem * sys_sem_t;
#define sys_sem_valid(sem)             (((sem) != NULL) && (*(sem) != NULL))
#define sys_sem_valid_val(sem)         ((sem) != NULL)
#define sys_sem_set_invalid(sem)       do { if((sem) != NULL) { *(sem) = NULL; }}while(0)
#define sys_sem_set_invalid_val(sem)   do { (sem) = NULL; }while(0)

struct sys_mutex;
typedef struct sys_mutex * sys_mutex_t;
#define sys_mutex_valid(mutex)         sys_sem_valid(mutex)
#define sys_mutex_set_invalid(mutex)   sys_sem_set_invalid(mutex)

struct sys_mbox;
typedef struct sys_mbox * sys_mbox_t;
#define sys_mbox_valid(mbox)           sys_sem_valid(mbox)
#define sys_mbox_valid_val(mbox)       sys_sem_valid_val(mbox)
#define sys_mbox_set_invalid(mbox)     sys_sem_set_invalid(mbox)
#define sys_mbox_set_invalid_val(mbox) sys_sem_set_invalid_val(mbox)

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

#define LWIP_EXAMPLE_APP_ABORT() lwip_unix_keypressed()
int lwip_unix_keypressed(void);

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
