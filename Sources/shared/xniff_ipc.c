#include "xniff_ipc.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>

#ifndef SUN_LEN
#define SUN_LEN(su) (offsetof(struct sockaddr_un, sun_path) + strlen((su)->sun_path))
#endif

static void set_nosigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#else
    (void)fd;
#endif
}

static void set_send_timeout_ms(int fd, int ms) {
    if (ms <= 0) return;
    struct timeval tv = {0};
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

int xniff_ipc_path_for_pid(pid_t pid, char *out, size_t outsz) {
    if (!out || outsz == 0) return -1;
    int n = snprintf(out, outsz, "/tmp/xniff-%d.sock", (int)pid);
    if (n <= 0 || (size_t)n >= outsz) return -1;
    return 0;
}

int xniff_ipc_client_connect(pid_t pid) {
    char path[108];
    if (xniff_ipc_path_for_pid(pid, path, sizeof(path)) != 0) return -1;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    set_nosigpipe(fd);
    // Don't let an instrumented target block forever if the listener stalls.
    // If this times out, callers should drop the connection and retry later.
    set_send_timeout_ms(fd, 50);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, SUN_LEN(&addr)) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

int xniff_ipc_server_listen(pid_t pid) {
    char path[108];
    if (xniff_ipc_path_for_pid(pid, path, sizeof(path)) != 0) return -1;

    // Remove stale
    unlink(path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, SUN_LEN(&addr)) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }

    // Make the socket broadly accessible so differently-sandboxed targets can connect.
    // NOTE: This relaxes permissions; if undesired, tighten to 0600 or gate by a flag.
    (void)chmod(path, 0666);

    if (listen(fd, 4) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }

    return fd;
}

int xniff_ipc_accept(int server_fd) {
    int fd = accept(server_fd, NULL, NULL);
    if (fd >= 0) set_nosigpipe(fd);
    return fd;
}

int xniff_ipc_send_all_nb(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t left = len;
    while (left > 0) {
        ssize_t n = send(fd, p, left, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return -1; // caller may drop
            return -1;
        }
        if (n == 0) return -1;
        p += (size_t)n;
        left -= (size_t)n;
    }
    return 0;
}

int xniff_ipc_send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t left = len;
    while (left > 0) {
        ssize_t n = send(fd, p, left, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += (size_t)n;
        left -= (size_t)n;
    }
    return 0;
}
