#include "ipc.h"

int ipc_sem_init(ipc_sem_t *s, int val)
{
    return sem_init(s, 0, val);
}

void ipc_sem_destroy(ipc_sem_t *s)
{
    sem_destroy(s);
}

void ipc_sem_wait(ipc_sem_t *s)
{
    sem_wait(s);
}

void ipc_sem_post(ipc_sem_t *s)
{
    sem_post(s);
}

int ipc_mutex_init(ipc_mutex_t *m)
{
    return pthread_mutex_init(m, NULL);
}

void ipc_mutex_destroy(ipc_mutex_t *m)
{
    pthread_mutex_destroy(m);
}

void ipc_mutex_lock(ipc_mutex_t *m)
{
    pthread_mutex_lock(m);
}

void ipc_mutex_unlock(ipc_mutex_t *m)
{
    pthread_mutex_unlock(m);
}
