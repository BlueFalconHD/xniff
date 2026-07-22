#include "target_identity.h"

#include <errno.h>
#include <grp.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
    XNIFF_PASSWD_BUFFER_SIZE = 16 * 1024,
};

static int copy_string(char *destination, size_t capacity, const char *source) {
    if (!destination || capacity == 0 || !source) {
        errno = EINVAL;
        return -1;
    }
    size_t length = strlen(source);
    if (length >= capacity) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(destination, source, length + 1);
    return 0;
}

static int parse_id(const char *value, uintmax_t maximum, uintmax_t *result) {
    if (!value || !*value || !result || value[0] == '-') {
        errno = EINVAL;
        return -1;
    }
    char *end = NULL;
    errno = 0;
    uintmax_t parsed = strtoumax(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed > maximum) {
        errno = EINVAL;
        return -1;
    }
    *result = parsed;
    return 0;
}

static int identity_from_passwd(const struct passwd *entry,
                                gid_t gid,
                                xniff_target_identity_t *identity) {
    if (!entry || !identity) {
        errno = EINVAL;
        return -1;
    }
    memset(identity, 0, sizeof(*identity));
    identity->uid = entry->pw_uid;
    identity->gid = gid;
    if (copy_string(identity->name, sizeof(identity->name), entry->pw_name) != 0 ||
        copy_string(identity->home, sizeof(identity->home), entry->pw_dir) != 0 ||
        copy_string(identity->shell, sizeof(identity->shell), entry->pw_shell) != 0) {
        memset(identity, 0, sizeof(*identity));
        return -1;
    }
    return 0;
}

static int identity_from_uid(uid_t uid,
                             const char *gid_override,
                             xniff_target_identity_t *identity) {
    char buffer[XNIFF_PASSWD_BUFFER_SIZE];
    struct passwd entry;
    struct passwd *result = NULL;
    int lookup = getpwuid_r(uid, &entry, buffer, sizeof(buffer), &result);
    if (lookup != 0 || !result) {
        errno = lookup != 0 ? lookup : ENOENT;
        return -1;
    }

    gid_t gid = entry.pw_gid;
    if (gid_override && *gid_override) {
        uintmax_t parsed_gid = 0;
        if (parse_id(gid_override, (uintmax_t)(gid_t)-1, &parsed_gid) != 0) return -1;
        gid = (gid_t)parsed_gid;
    }
    return identity_from_passwd(&entry, gid, identity);
}

int xniff_target_identity_resolve(const char *specifier, xniff_target_identity_t *identity) {
    if (!specifier || !*specifier || !identity) {
        errno = EINVAL;
        return -1;
    }

    if (strcmp(specifier, "sudo") == 0) {
        const char *sudo_uid = getenv("SUDO_UID");
        uintmax_t parsed_uid = 0;
        if (parse_id(sudo_uid, (uintmax_t)(uid_t)-1, &parsed_uid) != 0) {
            errno = ENOENT;
            return -1;
        }
        return identity_from_uid((uid_t)parsed_uid, getenv("SUDO_GID"), identity);
    }

    uintmax_t parsed_uid = 0;
    if (parse_id(specifier, (uintmax_t)(uid_t)-1, &parsed_uid) == 0) {
        return identity_from_uid((uid_t)parsed_uid, NULL, identity);
    }

    char buffer[XNIFF_PASSWD_BUFFER_SIZE];
    struct passwd entry;
    struct passwd *result = NULL;
    int lookup = getpwnam_r(specifier, &entry, buffer, sizeof(buffer), &result);
    if (lookup != 0 || !result) {
        errno = lookup != 0 ? lookup : ENOENT;
        return -1;
    }
    return identity_from_passwd(&entry, entry.pw_gid, identity);
}

static int set_identity_environment(const xniff_target_identity_t *identity) {
    if (setenv("HOME", identity->home, 1) != 0 ||
        setenv("USER", identity->name, 1) != 0 ||
        setenv("LOGNAME", identity->name, 1) != 0 ||
        (identity->shell[0] != '\0' && setenv("SHELL", identity->shell, 1) != 0)) {
        return -1;
    }
    unsetenv("SUDO_COMMAND");
    unsetenv("SUDO_GID");
    unsetenv("SUDO_HOME");
    unsetenv("SUDO_UID");
    unsetenv("SUDO_USER");
    return 0;
}

int xniff_target_identity_apply(const xniff_target_identity_t *identity) {
    if (!identity || identity->name[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    if (geteuid() == 0) {
        if (initgroups(identity->name, identity->gid) != 0 ||
            setgid(identity->gid) != 0 ||
            setuid(identity->uid) != 0) {
            return -1;
        }
    } else if (geteuid() != identity->uid || getegid() != identity->gid) {
        errno = EPERM;
        return -1;
    }

    if (getuid() != identity->uid || geteuid() != identity->uid ||
        getgid() != identity->gid || getegid() != identity->gid) {
        errno = EPERM;
        return -1;
    }
    return set_identity_environment(identity);
}
