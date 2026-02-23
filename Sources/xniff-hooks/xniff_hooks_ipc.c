#include "xniff_hooks_ipc.h"

#include <pthread.h>

#include "../shared/xniff_ipc.h"

static pthread_mutex_t g_ipc_lock = PTHREAD_MUTEX_INITIALIZER;

void xniff_hooks_ipc_lock(void) {
    pthread_mutex_lock(&g_ipc_lock);
}

void xniff_hooks_ipc_unlock(void) {
    pthread_mutex_unlock(&g_ipc_lock);
}

int xniff_hooks_ipc_write_locked(const void *buf, size_t len) {
    return xniff_ipc_ring_write(buf, len);
}
