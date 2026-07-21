#pragma once

typedef struct {
    char **values;
    char *dyld_insert;
    char *capture_mode;
    char *capture_file;
} xniff_launch_environment_t;

int xniff_launch_environment_create(const char *hooks_path, int mode, const char *capture_file,
                                    xniff_launch_environment_t *environment);
void xniff_launch_environment_destroy(xniff_launch_environment_t *environment);
