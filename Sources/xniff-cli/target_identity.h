#pragma once

#include <limits.h>
#include <sys/types.h>

typedef struct {
    uid_t uid;
    gid_t gid;
    char name[256];
    char home[PATH_MAX];
    char shell[PATH_MAX];
} xniff_target_identity_t;

int xniff_target_identity_resolve(const char *specifier, xniff_target_identity_t *identity);
int xniff_target_identity_apply(const xniff_target_identity_t *identity);
