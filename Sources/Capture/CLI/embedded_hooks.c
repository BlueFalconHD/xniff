#include "embedded_hooks.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern const struct mach_header_64 _mh_execute_header;

int xniff_extract_embedded_hooks(char *path_out, size_t path_out_size) {
    if (!path_out || path_out_size == 0) {
        errno = EINVAL;
        return -1;
    }

    unsigned long payload_size = 0;
    const uint8_t *payload = getsectiondata(&_mh_execute_header,
                                            "__DATA",
                                            "__xniff_hooks",
                                            &payload_size);
    if (!payload || payload_size == 0) {
        errno = ENOENT;
        return -1;
    }

    char path[] = "/private/tmp/xniff-hooks.XXXXXX.dylib";
    int fd = mkstemps(path, 6);
    if (fd < 0) return -1;

    int rc = 0;
    size_t written = 0;
    while (written < (size_t)payload_size) {
        ssize_t n = write(fd, payload + written, (size_t)payload_size - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            rc = -1;
            break;
        }
        written += (size_t)n;
    }
    if (rc == 0 && fchmod(fd, 0755) != 0) rc = -1;
    if (close(fd) != 0 && rc == 0) rc = -1;

    if (rc != 0 || strlen(path) + 1 > path_out_size) {
        int saved = rc != 0 ? errno : ENAMETOOLONG;
        unlink(path);
        errno = saved;
        return -1;
    }
    memcpy(path_out, path, strlen(path) + 1);
    return 0;
}
