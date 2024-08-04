// Copyright (c) SunnyCase. All rights reserved.
// Licensed under the Apache license. See LICENSE file in the project root for full license information.
#include "../../../../../kernel/ps/task/thread.h"
#include "lwip/debug.h"
#include <chino/os/kernel/ke.h>
#include <chino/os/processapi.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwip/def.h"

#include "lwip/opt.h"
#include "lwip/stats.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"

using namespace chino;
using namespace chino::os;
using namespace chino::os::kernel;

#if LWIP_NETCONN_SEM_PER_THREAD
/* pthread key to *our* thread local storage entry */
static pthread_key_t sys_thread_sem_key;
#endif

/* Return code for an interrupted timed wait */
#define SYS_ARCH_INTR 0xfffffffeUL

u32_t lwip_port_rand(void) { return (u32_t)rand(); }

#if !NO_SYS
void sys_thread_new(chino::os::lazy_construct<chino::os::kernel::ps::thread> &sys_thread, std::span<uintptr_t> stack,
                    const char *name, lwip_thread_fn thread, void *arg, int prio) {
    LWIP_UNUSED_ARG(name);
    LWIP_UNUSED_ARG(prio);
    sys_thread.construct(chino::os::kernel::ps::thread_create_options{
        .process = &kernel::ke_process(),
        .priority = thread_priority::high,
        .not_owned_stack = true,
        .stack = {reinterpret_cast<uintptr_t *>(stack.data()), stack.size_bytes() / sizeof(uintptr_t)},
        .entry_point = (thread_start_t)thread,
        .entry_arg = arg});
}

#if LWIP_TCPIP_CORE_LOCKING
static ps::thread *lwip_core_lock_holder_thread_id;
void sys_lock_tcpip_core(void) {
    sys_mutex_lock(&lock_tcpip_core);
    lwip_core_lock_holder_thread_id = &ps::current_thread();
}

void sys_unlock_tcpip_core(void) {
    lwip_core_lock_holder_thread_id = nullptr;
    sys_mutex_unlock(&lock_tcpip_core);
}
#endif /* LWIP_TCPIP_CORE_LOCKING */

static ps::thread *lwip_tcpip_thread_id;
void sys_mark_tcpip_thread(void) { lwip_tcpip_thread_id = &ps::current_thread(); }

void sys_check_core_locking(void) {
    /* Embedded systems should check we are NOT in an interrupt context here */

    if (lwip_tcpip_thread_id != 0) {
        ps::thread *current_thread_id = &ps::current_thread();

#if LWIP_TCPIP_CORE_LOCKING
        LWIP_ASSERT("Function called without core lock", current_thread_id == lwip_core_lock_holder_thread_id);
#else  /* LWIP_TCPIP_CORE_LOCKING */
        LWIP_ASSERT("Function called from wrong thread", current_thread_id == lwip_tcpip_thread_id);
#endif /* LWIP_TCPIP_CORE_LOCKING */
    }
}

/*-----------------------------------------------------------------------------------*/
/* Mailbox */
err_t sys_mbox_new(sys_mbox_t *mb, int size) {
    LWIP_UNUSED_ARG(size);
    mb->first = mb->last = 0;
    sys_sem_new(&mb->not_empty, 0);
    sys_sem_new(&mb->not_full, 0);
    sys_mutex_new(&mb->mutex);
    mb->wait_send = 0;

    SYS_STATS_INC_USED(mbox);
    return ERR_OK;
}

void sys_mbox_free(sys_mbox_t *mb) {
    if (mb != NULL) {
        SYS_STATS_DEC(mbox.used);
        sys_sem_free(&mb->not_empty);
        sys_sem_free(&mb->not_full);
        sys_mutex_free(&mb->mutex);
    }
}

err_t sys_mbox_trypost(sys_mbox_t *mb, void *msg) {
    u8_t first;
    LWIP_ASSERT("invalid mbox", (mb != NULL) && sys_mbox_valid(mb));

    sys_mutex_lock(&mb->mutex);

    LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_trypost: mbox %p msg %p\n", (void *)mb, (void *)msg));

    if ((mb->last + 1) >= (mb->first + SYS_MBOX_SIZE)) {
        sys_mutex_unlock(&mb->mutex);
        return ERR_MEM;
    }

    mb->msgs[mb->last % SYS_MBOX_SIZE] = msg;

    if (mb->last == mb->first) {
        first = 1;
    } else {
        first = 0;
    }

    mb->last++;

    if (first) {
        sys_sem_signal(&mb->not_empty);
    }

    sys_mutex_unlock(&mb->mutex);

    return ERR_OK;
}

err_t sys_mbox_trypost_fromisr(sys_mbox_t *q, void *msg) { return sys_mbox_trypost(q, msg); }

void sys_mbox_post(sys_mbox_t *mb, void *msg) {
    u8_t first;
    LWIP_ASSERT("invalid mbox", (mb != NULL) && sys_mbox_valid(mb));

    sys_mutex_lock(&mb->mutex);

    LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_post: mbox %p msg %p\n", (void *)mb, (void *)msg));

    while ((mb->last + 1) >= (mb->first + SYS_MBOX_SIZE)) {
        mb->wait_send++;
        sys_mutex_unlock(&mb->mutex);
        sys_arch_sem_wait(&mb->not_full, 0);
        sys_mutex_lock(&mb->mutex);
        mb->wait_send--;
    }

    mb->msgs[mb->last % SYS_MBOX_SIZE] = msg;

    if (mb->last == mb->first) {
        first = 1;
    } else {
        first = 0;
    }

    mb->last++;

    if (first) {
        sys_sem_signal(&mb->not_empty);
    }

    sys_mutex_unlock(&mb->mutex);
}

u32_t sys_arch_mbox_tryfetch(sys_mbox_t *mb, void **msg) {
    LWIP_ASSERT("invalid mbox", (mb != NULL) && sys_mbox_valid(mb));

    sys_mutex_lock(&mb->mutex);

    if (mb->first == mb->last) {
        sys_mutex_unlock(&mb->mutex);
        return SYS_MBOX_EMPTY;
    }

    if (msg != NULL) {
        LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_tryfetch: mbox %p msg %p\n", (void *)mb, *msg));
        *msg = mb->msgs[mb->first % SYS_MBOX_SIZE];
    } else {
        LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_tryfetch: mbox %p, null msg\n", (void *)mb));
    }

    mb->first++;

    if (mb->wait_send) {
        sys_sem_signal(&mb->not_full);
    }

    sys_mutex_unlock(&mb->mutex);

    return 0;
}

u32_t sys_arch_mbox_fetch(sys_mbox_t *mb, void **msg, u32_t timeout) {
    u32_t time_needed = 0;
    LWIP_ASSERT("invalid mbox", (mb != NULL) && sys_mbox_valid(mb));

    /* The mutex lock is quick so we don't bother with the timeout
       stuff here. */
    sys_mutex_lock(&mb->mutex);

    while (mb->first == mb->last) {
        sys_mutex_unlock(&mb->mutex);

        /* We block while waiting for a mail to arrive in the mailbox. We
           must be prepared to timeout. */
        if (timeout != 0) {
            time_needed = sys_arch_sem_wait(&mb->not_empty, timeout);

            if (time_needed == SYS_ARCH_TIMEOUT) {
                return SYS_ARCH_TIMEOUT;
            }
        } else {
            sys_arch_sem_wait(&mb->not_empty, 0);
        }

        sys_mutex_lock(&mb->mutex);
    }

    if (msg != NULL) {
        LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_fetch: mbox %p msg %p\n", (void *)mb, *msg));
        *msg = mb->msgs[mb->first % SYS_MBOX_SIZE];
    } else {
        LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_fetch: mbox %p, null msg\n", (void *)mb));
    }

    mb->first++;

    if (mb->wait_send) {
        sys_sem_signal(&mb->not_full);
    }

    sys_mutex_unlock(&mb->mutex);

    return time_needed;
}

/*-----------------------------------------------------------------------------------*/
/* Semaphore */

err_t sys_sem_new(sys_sem_t *sem, u8_t count) {
    LWIP_ASSERT("invalid count", count < 2);
    SYS_STATS_INC_USED(sem);
    std::construct_at(&sem->event, count);
    return ERR_OK;
}

u32_t sys_arch_sem_wait(sys_sem_t *sem, u32_t timeout) {
    LWIP_ASSERT("invalid sem", (sem != NULL) && sys_sem_valid(sem));
    return sem->event.wait(timeout ? std::make_optional(std::chrono::milliseconds(timeout)) : std::nullopt).is_ok()
               ? 0
               : SYS_ARCH_TIMEOUT;
}

void sys_sem_signal(sys_sem_t *sem) {
    LWIP_ASSERT("invalid sem", (sem != NULL) && sys_sem_valid(sem));
    sem->event.notify_one();
}

void sys_sem_free(sys_sem_t *sem) {
    if (sem != NULL) {
        SYS_STATS_DEC(sem.used);
        std::destroy_at(&sem->event);
    }
}

/*-----------------------------------------------------------------------------------*/
/* Mutex */
/** Create a new mutex
 * @param mutex pointer to the mutex to create
 * @return a new mutex */
err_t sys_mutex_new(sys_mutex *mtx) {
    std::construct_at(&mtx->mutex);
    return ERR_OK;
}

/** Lock a mutex
 * @param mutex the mutex to lock */
void sys_mutex_lock(sys_mutex *mtx) { (void)mtx->mutex.lock(); }

/** Unlock a mutex
 * @param mutex the mutex to unlock */
void sys_mutex_unlock(sys_mutex *mtx) { mtx->mutex.unlock(); }

/** Delete a mutex
 * @param mutex the mutex to delete */
void sys_mutex_free(sys_mutex *mtx) { std::destroy_at(&mtx->mutex); }

#endif /* !NO_SYS */

#if LWIP_NETCONN_SEM_PER_THREAD
/*-----------------------------------------------------------------------------------*/
/* Semaphore per thread located TLS */

static void sys_thread_sem_free(void *data) {
    sys_sem_t *sem = (sys_sem_t *)(data);

    if (sem) {
        sys_sem_free(sem);
        free(sem);
    }
}

static sys_sem_t *sys_thread_sem_alloc(void) {
    sys_sem_t *sem;
    err_t err;
    int ret;

    sem = (sys_sem_t *)malloc(sizeof(sys_sem_t *));
    LWIP_ASSERT("failed to allocate memory for TLS semaphore", sem != NULL);
    err = sys_sem_new(sem, 0);
    LWIP_ASSERT("failed to initialise TLS semaphore", err == ERR_OK);
    ret = pthread_setspecific(sys_thread_sem_key, sem);
    LWIP_ASSERT("failed to initialise TLS semaphore storage", ret == 0);
    return sem;
}

sys_sem_t *sys_arch_netconn_sem_get(void) {
    sys_sem_t *sem = (sys_sem_t *)pthread_getspecific(sys_thread_sem_key);
    if (!sem) {
        sem = sys_thread_sem_alloc();
    }
    LWIP_DEBUGF(SYS_DEBUG, ("sys_thread_sem_get s=%p\n", (void *)sem));
    return sem;
}

void sys_arch_netconn_sem_alloc(void) {
    sys_sem_t *sem = sys_thread_sem_alloc();
    LWIP_DEBUGF(SYS_DEBUG, ("sys_thread_sem created s=%p\n", (void *)sem));
}

void sys_arch_netconn_sem_free(void) {
    int ret;

    sys_sem_t *sem = (sys_sem_t *)pthread_getspecific(sys_thread_sem_key);
    sys_thread_sem_free(sem);
    ret = pthread_setspecific(sys_thread_sem_key, NULL);
    LWIP_ASSERT("failed to de-init TLS semaphore storage", ret == 0);
}
#endif /* LWIP_NETCONN_SEM_PER_THREAD */

/*-----------------------------------------------------------------------------------*/
/* Time */
u32_t sys_now(void) { return (u32_t)(hal::arch_t::current_cpu_time().count() / 1000000); }

/*-----------------------------------------------------------------------------------*/
/* Init */

void sys_init(void) {
#if LWIP_NETCONN_SEM_PER_THREAD
    pthread_key_create(&sys_thread_sem_key, sys_thread_sem_free);
#endif
}

/*-----------------------------------------------------------------------------------*/
/* Critical section */
#if SYS_LIGHTWEIGHT_PROT
/** sys_prot_t sys_arch_protect(void)

This optional function does a "fast" critical region protection and returns
the previous protection level. This function is only called during very short
critical regions. An embedded system which supports ISR-based drivers might
want to implement this function by disabling interrupts. Task-based systems
might want to implement this by using a mutex or disabling tasking. This
function should support recursive calls from the same task or interrupt. In
other words, sys_arch_protect() could be called while already protected. In
that case the return value indicates that it is already protected.

sys_arch_protect() is only required if your port is supporting an operating
system.
*/
sys_prot_t sys_arch_protect(void) {
    /* Note that for the UNIX port, we are using a lightweight mutex, and our
     * own counter (which is locked by the mutex). The return code is not actually
     * used. */
    if (lwprot_thread != pthread_self()) {
        /* We are locking the mutex where it has not been locked before *
         * or is being locked by another thread */
        pthread_mutex_lock(&lwprot_mutex);
        lwprot_thread = pthread_self();
        lwprot_count = 1;
    } else
        /* It is already locked by THIS thread */
        lwprot_count++;
    return 0;
}

/** void sys_arch_unprotect(sys_prot_t pval)

This optional function does a "fast" set of critical region protection to the
value specified by pval. See the documentation for sys_arch_protect() for
more information. This function is only required if your port is supporting
an operating system.
*/
void sys_arch_unprotect(sys_prot_t pval) {
    LWIP_UNUSED_ARG(pval);
    if (lwprot_thread == pthread_self()) {
        lwprot_count--;
        if (lwprot_count == 0) {
            lwprot_thread = (pthread_t)0xDEAD;
            pthread_mutex_unlock(&lwprot_mutex);
        }
    }
}
#endif /* SYS_LIGHTWEIGHT_PROT */
