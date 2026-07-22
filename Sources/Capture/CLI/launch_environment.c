#include "launch_environment.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "xniff_transport.h"

extern char **environ;

static const char *environment_value(const char *name) {
    size_t name_len = strlen(name);
    for (char **item = environ; item && *item; item++) {
        if (strncmp(*item, name, name_len) == 0 && (*item)[name_len] == '=') {
            return *item + name_len + 1;
        }
    }
    return NULL;
}

static bool is_replaced_variable(const char *value) {
    return strncmp(value, "DYLD_INSERT_LIBRARIES=", 22) == 0 ||
           strncmp(value, XNIFF_CAPTURE_MODE_ENV "=", sizeof(XNIFF_CAPTURE_MODE_ENV)) == 0 ||
           strncmp(value, XNIFF_RING_FD_ENV "=", sizeof(XNIFF_RING_FD_ENV)) == 0 ||
           strncmp(value, XNIFF_WAKE_FD_ENV "=", sizeof(XNIFF_WAKE_FD_ENV)) == 0;
}

int xniff_launch_environment_create(const char *hooks_path, int mode,
                                    int ring_fd, int wake_fd,
                                    xniff_launch_environment_t *environment) {
    if (!hooks_path || ring_fd < 0 || wake_fd < 0 || !environment) return -1;
    memset(environment, 0, sizeof(*environment));

    size_t count = 0;
    while (environ && environ[count]) count++;
    environment->values = (char **)calloc(count + 5, sizeof(char *));
    if (!environment->values) return -1;

    const char *existing_insert = environment_value("DYLD_INSERT_LIBRARIES");
    if (existing_insert && *existing_insert) {
        if (asprintf(&environment->dyld_insert, "DYLD_INSERT_LIBRARIES=%s:%s",
                     hooks_path, existing_insert) < 0) {
            xniff_launch_environment_destroy(environment);
            return -1;
        }
    } else if (asprintf(&environment->dyld_insert, "DYLD_INSERT_LIBRARIES=%s", hooks_path) < 0) {
        xniff_launch_environment_destroy(environment);
        return -1;
    }

    const char *mode_name = mode == XNIFF_CAPTURE_MODE_XPC ? "xpc" : "mach";
    if (asprintf(&environment->capture_mode, "XNIFF_CAPTURE_MODE=%s", mode_name) < 0) {
        xniff_launch_environment_destroy(environment);
        return -1;
    }
    if (asprintf(&environment->ring_fd, "%s=%d", XNIFF_RING_FD_ENV, ring_fd) < 0 ||
        asprintf(&environment->wake_fd, "%s=%d", XNIFF_WAKE_FD_ENV, wake_fd) < 0) {
        xniff_launch_environment_destroy(environment);
        return -1;
    }
    size_t out = 0;
    for (size_t i = 0; i < count; i++) {
        if (!is_replaced_variable(environ[i])) environment->values[out++] = environ[i];
    }
    environment->values[out++] = environment->dyld_insert;
    environment->values[out++] = environment->capture_mode;
    environment->values[out++] = environment->ring_fd;
    environment->values[out++] = environment->wake_fd;
    environment->values[out] = NULL;
    return 0;
}

void xniff_launch_environment_destroy(xniff_launch_environment_t *environment) {
    if (!environment) return;
    free(environment->dyld_insert);
    free(environment->capture_mode);
    free(environment->ring_fd);
    free(environment->wake_fd);
    free(environment->values);
    memset(environment, 0, sizeof(*environment));
}
