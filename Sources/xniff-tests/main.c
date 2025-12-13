#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>

#include "xniff_ctx.h"
#include "xniff_ipc.h"

static volatile sig_atomic_t g_got_sigpipe = 0;

static void sigpipe_handler(int signo) {
    (void)signo;
    g_got_sigpipe = 1;
}

typedef struct {
    int sfd;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int accepted;
} ipc_sigpipe_ctx_t;

static void *ipc_sigpipe_server_thread(void *arg) {
    ipc_sigpipe_ctx_t *ctx = (ipc_sigpipe_ctx_t *)arg;
    int cfd = xniff_ipc_accept(ctx->sfd);
    pthread_mutex_lock(&ctx->mu);
    ctx->accepted = 1;
    pthread_cond_signal(&ctx->cv);
    pthread_mutex_unlock(&ctx->mu);
    if (cfd >= 0) {
        shutdown(cfd, SHUT_RDWR);
        close(cfd);
    }
    return NULL;
}

static int selftest_ipc_sigpipe(void) {
#ifndef SO_NOSIGPIPE
    printf("SKIP: SO_NOSIGPIPE not available on this platform.\n");
    return 0;
#else
    struct sigaction sa = {0};
    sa.sa_handler = sigpipe_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) != 0) {
        perror("sigaction(SIGPIPE)");
        return 1;
    }

    ipc_sigpipe_ctx_t ctx = {0};
    ctx.accepted = 0;
    pthread_mutex_init(&ctx.mu, NULL);
    pthread_cond_init(&ctx.cv, NULL);

    ctx.sfd = xniff_ipc_server_listen(getpid());
    if (ctx.sfd < 0) {
        perror("xniff_ipc_server_listen");
        return 1;
    }

    pthread_t th;
    if (pthread_create(&th, NULL, ipc_sigpipe_server_thread, &ctx) != 0) {
        perror("pthread_create");
        close(ctx.sfd);
        return 1;
    }

    int fd = xniff_ipc_client_connect(getpid());
    if (fd < 0) {
        perror("xniff_ipc_client_connect");
        close(ctx.sfd);
        return 1;
    }

    pthread_mutex_lock(&ctx.mu);
    while (!ctx.accepted) pthread_cond_wait(&ctx.cv, &ctx.mu);
    pthread_mutex_unlock(&ctx.mu);
    pthread_join(th, NULL);
    close(ctx.sfd);

    errno = 0;
    char payload[16] = "hello";
    int rc = xniff_ipc_send_all(fd, payload, sizeof(payload));
    int e = errno;
    close(fd);

    if (g_got_sigpipe) {
        fprintf(stderr, "FAIL: SIGPIPE delivered during send\n");
        return 1;
    }
    if (rc == 0) {
        fprintf(stderr, "WARN: send succeeded unexpectedly (peer close not observed)\n");
        return 0;
    }
    printf("OK: send failed with errno=%d (%s) and no SIGPIPE\n", e, strerror(e));
    return 0;
#endif
}

// Exported, noinline function we can patch remotely.
__attribute__((used, noinline, visibility("default")))
int do_something_useful(int count) {
    // Force a few instructions before the ADRP/ADD used for the printf string,
    // so the entry patch can safely resume after 12 bytes without skipping it.
#if defined(__aarch64__) || defined(__arm64__)
    // __asm__ volatile("nop\n\t"
    //                  "nop\n\t"
    //                  "nop\n\t"
    //                  "nop\n\t");
#endif
    printf("do_something_useful: doing some work with the secret counter\n\n");
    return count * 2;
}

// Exported remote hook that the CLI will call via a trampoline.
__attribute__((used, noinline, visibility("default")))
void xniff_remote_entry_hook(xniff_ctx_frame_t *ctx) {
    int count = (ctx != NULL) ? (int)ctx->x[0] : -1;
    printf("::: passed secret counter value: %d\n", count);
}

__attribute__((used, noinline, visibility("default")))
void xniff_remote_exit_hook(uint64_t ret, xniff_ctx_frame_t* ctx) {
    printf("::: function returned %llu", (unsigned long long)ret);
}

int main(int argc, char **argv) {
    // Lightweight self-tests (no remote patching).
    // Example: ./xniff-test --ipc-sigpipe
    if (getenv("XNIFF_TEST_IPC_SIGPIPE")) {
        return selftest_ipc_sigpipe();
    }
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ipc-sigpipe") == 0) {
            return selftest_ipc_sigpipe();
        }
    }

    printf("xniff-test: waiting for patch...\n");
    fflush(stdout);
    sleep(2);

    int counter = 0;

    while (1) {
        counter++;
        do_something_useful(counter);
        fflush(stdout);
        sleep(1);
    }
    return 0;
}
