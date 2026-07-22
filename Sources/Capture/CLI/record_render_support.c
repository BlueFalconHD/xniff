#include "record_render_support.h"

#include <libproc.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef struct {
    pid_t pid;
    char name[128];
} process_name_cache_entry_t;

static process_name_cache_entry_t g_process_names[128];
static size_t g_next_process_name = 0;

void xniff_format_timestamp(char *buffer,
                            size_t buffer_size,
                            double *monotonic_seconds_out) {
    struct timespec realtime = {0};
    struct timespec monotonic = {0};
    clock_gettime(CLOCK_REALTIME, &realtime);
#ifdef CLOCK_MONOTONIC_RAW
    clock_gettime(CLOCK_MONOTONIC_RAW, &monotonic);
#else
    clock_gettime(CLOCK_MONOTONIC, &monotonic);
#endif

    struct tm local_time = {0};
    time_t seconds = realtime.tv_sec;
    localtime_r(&seconds, &local_time);
    size_t length = strftime(buffer, buffer_size, "%F %T", &local_time);
    if (length > 0 && length < buffer_size) {
        snprintf(buffer + length, buffer_size - length, ".%03ld",
                 realtime.tv_nsec / 1000000);
    }
    if (monotonic_seconds_out) {
        *monotonic_seconds_out = (double)monotonic.tv_sec +
                                 (double)monotonic.tv_nsec / 1e9;
    }
}

const char *xniff_process_name(pid_t pid) {
    if (pid <= 0) return NULL;

    size_t capacity = sizeof(g_process_names) / sizeof(g_process_names[0]);
    for (size_t index = 0; index < capacity; index++) {
        if (g_process_names[index].pid == pid &&
            g_process_names[index].name[0] != '\0') {
            return g_process_names[index].name;
        }
    }

    char name[128] = {0};
    if (proc_name(pid, name, (uint32_t)sizeof(name)) <= 0) return NULL;
    name[sizeof(name) - 1] = '\0';

    process_name_cache_entry_t *entry =
        &g_process_names[g_next_process_name++ % capacity];
    entry->pid = pid;
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->name[sizeof(entry->name) - 1] = '\0';
    return entry->name;
}
