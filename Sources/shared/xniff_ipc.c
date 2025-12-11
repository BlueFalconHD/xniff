#include "xniff_ipc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifndef SUN_LEN
#define SUN_LEN(su) (offsetof(struct sockaddr_un, sun_path) + strlen((su)->sun_path))
#endif

int xniff_ipc_path_for_pid(pid_t pid, char *out, size_t outsz) {
    if (!out || outsz == 0) return -1;
    int n = snprintf(out, outsz, "/tmp/xniff-%d.sock", (int)pid);
    if (n <= 0 || (size_t)n >= outsz) return -1;
    return 0;
}

static int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
    return 0;
}

int xniff_ipc_client_connect(pid_t pid) {
    char path[108];
    if (xniff_ipc_path_for_pid(pid, path, sizeof(path)) != 0) return -1;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

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
    // Make client non-blocking best-effort
    (void)set_nonblock(fd);
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

    if (listen(fd, 4) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }

    return fd;
}

int xniff_ipc_accept(int server_fd) {
    return accept(server_fd, NULL, NULL);
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
