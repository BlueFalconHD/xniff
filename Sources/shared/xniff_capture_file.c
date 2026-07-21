#include "xniff_capture_file.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xniff_ipc_v2.h"

static pthread_once_t g_capture_file_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_capture_file_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_capture_file_fd = -1;
static bool g_capture_file_requested = false;

static int write_all(int fd, const void *bytes, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, (const uint8_t *)bytes + offset, length - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return -1;
        offset += (size_t)written;
    }
    return 0;
}

static void capture_file_initialize(void) {
    const char *path = getenv("XNIFF_CAPTURE_FILE");
    if (!path || !*path) return;
    g_capture_file_requested = true;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    xniff_bin_file_hdr_t header = {
        .magic = XNIFF_BIN_FILE_MAGIC,
        .version = XNIFF_BIN_FILE_VERSION,
        .reserved = 0,
    };
    if (write_all(fd, &header, sizeof(header)) != 0) {
        close(fd);
        return;
    }
    g_capture_file_fd = fd;
}

bool xniff_capture_file_is_configured(void) {
    (void)pthread_once(&g_capture_file_once, capture_file_initialize);
    return g_capture_file_requested;
}

int xniff_capture_file_write(const void *record, size_t record_len) {
    (void)pthread_once(&g_capture_file_once, capture_file_initialize);
    if (!g_capture_file_requested || g_capture_file_fd < 0) {
        errno = g_capture_file_requested ? EIO : ENOENT;
        return -1;
    }
    pthread_mutex_lock(&g_capture_file_lock);
    int result = write_all(g_capture_file_fd, record, record_len);
    pthread_mutex_unlock(&g_capture_file_lock);
    return result;
}
