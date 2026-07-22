#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dylib_staging.h"

static bool write_source_file(const char *path,
                              const uint8_t *contents,
                              size_t contents_size) {
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor < 0) return false;
    ssize_t written = write(descriptor, contents, contents_size);
    int close_result = close(descriptor);
    bool result = written == (ssize_t)contents_size && close_result == 0;
    if (!result) (void)unlink(path);
    return result;
}

int selftest_dylib_staging(void) {
    char home[] = "/tmp/xniff-stage-test.XXXXXX";
    if (!mkdtemp(home)) {
        perror("mkdtemp");
        return 1;
    }

    char trash[PATH_MAX];
    char staging_directory[PATH_MAX];
    char source_path[PATH_MAX];
    snprintf(trash, sizeof(trash), "%s/.Trash", home);
    snprintf(staging_directory, sizeof(staging_directory), "%s/.xniff", trash);
    snprintf(source_path, sizeof(source_path), "%s/hooks.dylib", home);

    const uint8_t expected[] = {0xca, 0xfe, 0xba, 0xbe};
    char staged_path[PATH_MAX] = {0};
    bool passed = mkdir(trash, 0700) == 0 &&
                  write_source_file(source_path, expected, sizeof(expected)) &&
                  xniff_stage_dylib_in_home(source_path, home, staged_path,
                                            sizeof(staged_path)) == 0;

    char expected_prefix[PATH_MAX];
    snprintf(expected_prefix, sizeof(expected_prefix), "%s/", staging_directory);
    passed = passed &&
             strncmp(staged_path, expected_prefix, strlen(expected_prefix)) == 0;

    uint8_t actual[sizeof(expected)] = {0};
    struct stat status = {0};
    int descriptor = passed ? open(staged_path, O_RDONLY) : -1;
    passed = passed && descriptor >= 0 &&
             read(descriptor, actual, sizeof(actual)) == sizeof(actual) &&
             fstat(descriptor, &status) == 0 &&
             (status.st_mode & 0777) == 0644 &&
             memcmp(actual, expected, sizeof(expected)) == 0;
    if (descriptor >= 0) close(descriptor);

    if (staged_path[0]) (void)unlink(staged_path);
    (void)unlink(source_path);
    (void)rmdir(staging_directory);
    (void)rmdir(trash);
    (void)rmdir(home);

    if (!passed) {
        fprintf(stderr, "FAIL: dylib was not staged in the home Trash directory\n");
        return 1;
    }
    printf("OK: dylib sandbox staging uses the home Trash directory\n");
    return 0;
}
