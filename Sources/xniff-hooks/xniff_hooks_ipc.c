#include "xniff_hooks_ipc.h"

#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#include "../shared/xniff_ipc.h"

static int g_ipc_fd = -1;
static uint64_t g_next_connect_ns = 0;
static pthread_mutex_t g_ipc_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t now_monotonic_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

void xniff_hooks_ipc_lock(void) {
    pthread_mutex_lock(&g_ipc_lock);
}

void xniff_hooks_ipc_unlock(void) {
    pthread_mutex_unlock(&g_ipc_lock);
}

void xniff_hooks_ipc_drop_locked(void) {
    if (g_ipc_fd == -1) return;
    close(g_ipc_fd);
    g_ipc_fd = -1;
}

int xniff_hooks_ipc_ensure_fd_locked(void) {
    if (g_ipc_fd != -1) return g_ipc_fd;
    uint64_t now = now_monotonic_ns();
    if (now && now < g_next_connect_ns) return -1;
    int fd = xniff_ipc_client_connect(getpid());
    if (fd >= 0) {
        g_ipc_fd = fd;
    } else {
        // Avoid hammering connect() if the listener is gone.
        if (now) g_next_connect_ns = now + 250ull * 1000ull * 1000ull;
    }
    return g_ipc_fd;
}
