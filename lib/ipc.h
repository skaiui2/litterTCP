#ifndef IPC_H
#define IPC_H

#include <pthread.h>
#include <semaphore.h>

typedef sem_t ipc_sem_t;
typedef pthread_mutex_t ipc_mutex_t;

/* semaphore */
int  ipc_sem_init(ipc_sem_t *s, int val);
void ipc_sem_destroy(ipc_sem_t *s);
void ipc_sem_wait(ipc_sem_t *s);
void ipc_sem_post(ipc_sem_t *s);

/* mutex */
int  ipc_mutex_init(ipc_mutex_t *m);
void ipc_mutex_destroy(ipc_mutex_t *m);
void ipc_mutex_lock(ipc_mutex_t *m);
void ipc_mutex_unlock(ipc_mutex_t *m);

#endif /* IPC_H */
