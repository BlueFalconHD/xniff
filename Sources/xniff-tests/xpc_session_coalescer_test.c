#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "xpc_session_coalescer.h"

typedef struct {
    uint64_t message;
    bool matched;
} coalescer_thread_result_t;

static void *check_thread_isolation(void *context) {
    coalescer_thread_result_t *result = (coalescer_thread_result_t *)context;
    uint64_t call_id = 0;
    result->matched = xniff_xpc_session_scope_match(result->message, &call_id);
    return NULL;
}

int selftest_xpc_session_coalescer(void) {
    const uint64_t outer_call_id = 41;
    const uint64_t outer_message = 0x1000;
    const uint64_t inner_call_id = 42;
    const uint64_t inner_message = 0x2000;
    uint64_t matched_call_id = 0;
    xniff_xpc_session_scope_t outer = {0};
    xniff_xpc_session_scope_t inner = {0};

    bool passed = !xniff_xpc_session_scope_match(outer_message, &matched_call_id);
    xniff_xpc_session_scope_enter(&outer, outer_call_id, outer_message);
    passed = passed &&
             xniff_xpc_session_scope_match(outer_message, &matched_call_id) &&
             matched_call_id == outer_call_id &&
             !xniff_xpc_session_scope_match(inner_message, &matched_call_id);

    coalescer_thread_result_t thread_result = {.message = outer_message};
    pthread_t thread;
    int thread_result_code = pthread_create(&thread, NULL, check_thread_isolation, &thread_result);
    if (thread_result_code == 0) thread_result_code = pthread_join(thread, NULL);
    passed = passed && thread_result_code == 0 && !thread_result.matched;

    xniff_xpc_session_scope_enter(&inner, inner_call_id, inner_message);
    passed = passed &&
             xniff_xpc_session_scope_match(inner_message, &matched_call_id) &&
             matched_call_id == inner_call_id &&
             !xniff_xpc_session_scope_match(outer_message, &matched_call_id);

    xniff_xpc_session_scope_leave(&inner);
    passed = passed &&
             xniff_xpc_session_scope_match(outer_message, &matched_call_id) &&
             matched_call_id == outer_call_id;
    xniff_xpc_session_scope_leave(&outer);
    passed = passed && !xniff_xpc_session_scope_match(outer_message, &matched_call_id);

    if (!passed) {
        fprintf(stderr, "FAIL: XPC session/connection call coalescing state was incorrect\n");
        return 1;
    }
    printf("OK: XPC session/connection calls coalesce by message and thread\n");
    return 0;
}
