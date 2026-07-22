#include "dylib_staging.h"

#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    XNIFF_PASSWD_BUFFER_SIZE = 16 * 1024,
    XNIFF_STAGE_ATTEMPTS = 16,
};

static int copy_file(const char *source_path, const char *destination_path) {
    int source = open(source_path, O_RDONLY);
    if (source < 0) return -1;

    int destination = open(destination_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (destination < 0) {
        close(source);
        return -1;
    }

    uint8_t buffer[64 * 1024];
    int result = 0;
    for (;;) {
        ssize_t count = read(source, buffer, sizeof(buffer));
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            result = -1;
            break;
        }

        size_t offset = 0;
        while (offset < (size_t)count) {
            ssize_t written = write(destination, buffer + offset,
                                    (size_t)count - offset);
            if (written < 0) {
                if (errno == EINTR) continue;
                result = -1;
                break;
            }
            offset += (size_t)written;
        }
        if (result != 0) break;
    }

    if (result == 0 && fchmod(destination, 0644) != 0) result = -1;
    if (result == 0 && fsync(destination) != 0) result = -1;
    int saved_errno = errno;
    if (close(destination) != 0 && result == 0) {
        result = -1;
        saved_errno = errno;
    }
    close(source);

    if (result != 0) {
        (void)unlink(destination_path);
        errno = saved_errno;
    }
    return result;
}

static int stage_in_directory(const char *source_path,
                              const char *directory,
                              char *output_path,
                              size_t output_path_size) {
    if (!source_path || !directory || !directory[0] || !output_path ||
        output_path_size == 0) {
        errno = EINVAL;
        return -1;
    }

    for (int attempt = 0; attempt < XNIFF_STAGE_ATTEMPTS; attempt++) {
        char candidate[PATH_MAX];
        unsigned int salt = arc4random() & 0xffff;
        int length = snprintf(candidate, sizeof(candidate),
                              "%s/xniff-hooks-%d-%u.dylib",
                              directory, (int)getpid(), salt);
        if (length <= 0 || (size_t)length >= sizeof(candidate)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        if ((size_t)length >= output_path_size) {
            errno = ENAMETOOLONG;
            return -1;
        }
        if (copy_file(source_path, candidate) != 0) continue;

        memcpy(output_path, candidate, (size_t)length + 1);
        return 0;
    }
    return -1;
}

int xniff_stage_dylib_in_home(const char *source_path,
                              const char *home_directory,
                              char *output_path,
                              size_t output_path_size) {
    if (!source_path || !home_directory || !home_directory[0] ||
        !output_path || output_path_size == 0) {
        errno = EINVAL;
        return -1;
    }

    char staging_directory[PATH_MAX];
    int length = snprintf(staging_directory, sizeof(staging_directory),
                          "%s/.Trash/.xniff", home_directory);
    if (length <= 0 || (size_t)length >= sizeof(staging_directory)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (mkdir(staging_directory, 0755) != 0 && errno != EEXIST) return -1;

    struct stat status;
    if (stat(staging_directory, &status) != 0) return -1;
    if (!S_ISDIR(status.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    return stage_in_directory(source_path, staging_directory,
                              output_path, output_path_size);
}

static int home_directory_for_process(pid_t target_pid,
                                      char *home_directory,
                                      size_t home_directory_size) {
    struct proc_bsdinfo process_info = {0};
    int size = proc_pidinfo(target_pid, PROC_PIDTBSDINFO, 0,
                            &process_info, sizeof(process_info));
    if (size != sizeof(process_info)) {
        if (size >= 0) errno = ESRCH;
        return -1;
    }

    char buffer[XNIFF_PASSWD_BUFFER_SIZE];
    struct passwd entry;
    struct passwd *result = NULL;
    int lookup = getpwuid_r(process_info.pbi_uid, &entry, buffer,
                            sizeof(buffer), &result);
    if (lookup != 0 || !result || !entry.pw_dir || !entry.pw_dir[0]) {
        errno = lookup != 0 ? lookup : ENOENT;
        return -1;
    }

    size_t length = strlen(entry.pw_dir);
    if (length >= home_directory_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(home_directory, entry.pw_dir, length + 1);
    return 0;
}

int xniff_stage_dylib_for_process(pid_t target_pid,
                                  const char *source_path,
                                  char *output_path,
                                  size_t output_path_size) {
    if (target_pid <= 0 || !source_path || !output_path ||
        output_path_size == 0) {
        errno = EINVAL;
        return -1;
    }

    char target_home[PATH_MAX] = {0};
    if (home_directory_for_process(target_pid, target_home,
                                   sizeof(target_home)) == 0 &&
        xniff_stage_dylib_in_home(source_path, target_home,
                                  output_path, output_path_size) == 0) {
        return 0;
    }

    const char *caller_home = getenv("HOME");
    if (caller_home && caller_home[0] && strcmp(caller_home, target_home) != 0 &&
        xniff_stage_dylib_in_home(source_path, caller_home,
                                  output_path, output_path_size) == 0) {
        return 0;
    }

    const char *fallback_directories[] = {
        "/tmp",
        "/private/tmp",
        "/private/var/tmp",
        "/Users/Shared",
    };
    for (size_t index = 0;
         index < sizeof(fallback_directories) / sizeof(fallback_directories[0]);
         index++) {
        if (stage_in_directory(source_path, fallback_directories[index],
                               output_path, output_path_size) == 0) {
            return 0;
        }
    }

    output_path[0] = '\0';
    return -1;
}
