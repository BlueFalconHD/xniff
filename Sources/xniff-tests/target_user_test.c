#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../xniff-cli/cli_options.h"
#include "../xniff-cli/target_identity.h"

int selftest_target_user_options(void) {
    char *argv[] = {
        "xniff-cli",
        "launch",
        "--xpc",
        "--target-user",
        "sudo",
        "--",
        "/bin/echo",
        "hello",
        NULL,
    };
    xniff_cli_options_t options;
    int result = xniff_cli_parse(8, argv, &options);
    if (result != 0 || options.command != XNIFF_CLI_LAUNCH ||
        options.target_user == NULL || strcmp(options.target_user, "sudo") != 0 ||
        options.launch_argv == NULL || strcmp(options.launch_argv[0], "/bin/echo") != 0) {
        fprintf(stderr, "FAIL: --target-user launch option was not parsed\n");
        return 1;
    }
    printf("OK: --target-user launch option parsed\n");
    return 0;
}

static bool identity_matches(const xniff_target_identity_t *identity,
                             const struct passwd *entry) {
    return identity && entry &&
           identity->uid == entry->pw_uid &&
           identity->gid == entry->pw_gid &&
           strcmp(identity->name, entry->pw_name) == 0 &&
           strcmp(identity->home, entry->pw_dir) == 0;
}

int selftest_target_identity(void) {
    struct passwd *entry = getpwuid(getuid());
    if (!entry) {
        perror("getpwuid");
        return 1;
    }

    char name[256];
    char home[PATH_MAX];
    char shell[PATH_MAX];
    char uid[32];
    char gid[32];
    snprintf(name, sizeof(name), "%s", entry->pw_name);
    snprintf(home, sizeof(home), "%s", entry->pw_dir);
    snprintf(shell, sizeof(shell), "%s", entry->pw_shell);
    snprintf(uid, sizeof(uid), "%u", (unsigned int)entry->pw_uid);
    snprintf(gid, sizeof(gid), "%u", (unsigned int)entry->pw_gid);

    xniff_target_identity_t by_name;
    xniff_target_identity_t by_uid;
    xniff_target_identity_t by_sudo;
    if (xniff_target_identity_resolve(name, &by_name) != 0 ||
        xniff_target_identity_resolve(uid, &by_uid) != 0 ||
        setenv("SUDO_UID", uid, 1) != 0 ||
        setenv("SUDO_GID", gid, 1) != 0 ||
        setenv("SUDO_USER", name, 1) != 0 ||
        xniff_target_identity_resolve("sudo", &by_sudo) != 0 ||
        !identity_matches(&by_name, entry) ||
        !identity_matches(&by_uid, entry) ||
        !identity_matches(&by_sudo, entry)) {
        fprintf(stderr, "FAIL: target identity resolution mismatch\n");
        return 1;
    }

    pid_t child = fork();
    if (child == 0) {
        const char *actual_home = NULL;
        const char *actual_user = NULL;
        const char *actual_logname = NULL;
        const char *actual_shell = NULL;
        if (xniff_target_identity_apply(&by_sudo) != 0 ||
            getuid() != by_sudo.uid || geteuid() != by_sudo.uid ||
            getgid() != by_sudo.gid || getegid() != by_sudo.gid ||
            !(actual_home = getenv("HOME")) || strcmp(actual_home, home) != 0 ||
            !(actual_user = getenv("USER")) || strcmp(actual_user, name) != 0 ||
            !(actual_logname = getenv("LOGNAME")) || strcmp(actual_logname, name) != 0 ||
            !(actual_shell = getenv("SHELL")) || strcmp(actual_shell, shell) != 0 ||
            getenv("SUDO_UID") != NULL) {
            _exit(1);
        }
        _exit(0);
    }
    if (child < 0) {
        perror("fork");
        return 1;
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL: target identity application failed\n");
        return 1;
    }

    printf("OK: target identity resolved and applied\n");
    return 0;
}
