#include "xpc_reply_tracker.h"

#include <pthread.h>
#include <stddef.h>
#include <string.h>

enum {
    XNIFF_XPC_REPLY_TRACKER_CAPACITY = 8192,
    XNIFF_XPC_REPLY_SLOT_EMPTY = 0,
    XNIFF_XPC_REPLY_SLOT_OCCUPIED = 1,
    XNIFF_XPC_REPLY_SLOT_TOMBSTONE = 2,
};

typedef struct {
    uint64_t context;
    uint64_t call_id;
    uint64_t generation;
    uint8_t state;
} xniff_xpc_reply_slot_t;

static pthread_mutex_t g_reply_tracker_mutex = PTHREAD_MUTEX_INITIALIZER;
static xniff_xpc_reply_slot_t g_reply_slots[XNIFF_XPC_REPLY_TRACKER_CAPACITY];
static size_t g_reply_count = 0;
static uint64_t g_reply_generation = 0;

static size_t xniff_xpc_reply_hash(uint64_t context) {
    context ^= context >> 33;
    context *= 0xff51afd7ed558ccdULL;
    context ^= context >> 33;
    return (size_t)context & (XNIFF_XPC_REPLY_TRACKER_CAPACITY - 1u);
}

bool xniff_xpc_reply_tracker_record(uint64_t context, uint64_t call_id) {
    if (context == 0 || call_id == 0) return false;

    pthread_mutex_lock(&g_reply_tracker_mutex);
    size_t start = xniff_xpc_reply_hash(context);
    size_t first_tombstone = XNIFF_XPC_REPLY_TRACKER_CAPACITY;
    for (size_t probe = 0; probe < XNIFF_XPC_REPLY_TRACKER_CAPACITY; probe++) {
        size_t index = (start + probe) & (XNIFF_XPC_REPLY_TRACKER_CAPACITY - 1u);
        xniff_xpc_reply_slot_t *slot = &g_reply_slots[index];
        if (slot->state == XNIFF_XPC_REPLY_SLOT_OCCUPIED) {
            if (slot->context == context) {
                slot->call_id = call_id;
                slot->generation = ++g_reply_generation;
                pthread_mutex_unlock(&g_reply_tracker_mutex);
                return true;
            }
            continue;
        }
        if (slot->state == XNIFF_XPC_REPLY_SLOT_TOMBSTONE) {
            if (first_tombstone == XNIFF_XPC_REPLY_TRACKER_CAPACITY) {
                first_tombstone = index;
            }
            continue;
        }

        if (first_tombstone != XNIFF_XPC_REPLY_TRACKER_CAPACITY) {
            slot = &g_reply_slots[first_tombstone];
        }
        slot->context = context;
        slot->call_id = call_id;
        slot->generation = ++g_reply_generation;
        slot->state = XNIFF_XPC_REPLY_SLOT_OCCUPIED;
        g_reply_count++;
        pthread_mutex_unlock(&g_reply_tracker_mutex);
        return true;
    }

    if (first_tombstone != XNIFF_XPC_REPLY_TRACKER_CAPACITY) {
        xniff_xpc_reply_slot_t *slot = &g_reply_slots[first_tombstone];
        slot->context = context;
        slot->call_id = call_id;
        slot->generation = ++g_reply_generation;
        slot->state = XNIFF_XPC_REPLY_SLOT_OCCUPIED;
        g_reply_count++;
        pthread_mutex_unlock(&g_reply_tracker_mutex);
        return true;
    }

    size_t oldest_index = 0;
    for (size_t index = 1; index < XNIFF_XPC_REPLY_TRACKER_CAPACITY; index++) {
        if (g_reply_slots[index].generation < g_reply_slots[oldest_index].generation) {
            oldest_index = index;
        }
    }
    xniff_xpc_reply_slot_t *oldest = &g_reply_slots[oldest_index];
    oldest->context = context;
    oldest->call_id = call_id;
    oldest->generation = ++g_reply_generation;
    oldest->state = XNIFF_XPC_REPLY_SLOT_OCCUPIED;
    pthread_mutex_unlock(&g_reply_tracker_mutex);
    return true;
}

bool xniff_xpc_reply_tracker_take(uint64_t context, uint64_t *call_id_out) {
    if (context == 0 || call_id_out == NULL) return false;

    pthread_mutex_lock(&g_reply_tracker_mutex);
    size_t start = xniff_xpc_reply_hash(context);
    for (size_t probe = 0; probe < XNIFF_XPC_REPLY_TRACKER_CAPACITY; probe++) {
        size_t index = (start + probe) & (XNIFF_XPC_REPLY_TRACKER_CAPACITY - 1u);
        xniff_xpc_reply_slot_t *slot = &g_reply_slots[index];
        if (slot->state == XNIFF_XPC_REPLY_SLOT_EMPTY) break;
        if (slot->state != XNIFF_XPC_REPLY_SLOT_OCCUPIED || slot->context != context) {
            continue;
        }

        *call_id_out = slot->call_id;
        slot->call_id = 0;
        slot->context = 0;
        slot->generation = 0;
        slot->state = XNIFF_XPC_REPLY_SLOT_TOMBSTONE;
        g_reply_count--;
        if (g_reply_count == 0) {
            memset(g_reply_slots, 0, sizeof(g_reply_slots));
        }
        pthread_mutex_unlock(&g_reply_tracker_mutex);
        return true;
    }

    pthread_mutex_unlock(&g_reply_tracker_mutex);
    return false;
}

void xniff_xpc_reply_tracker_clear(void) {
    pthread_mutex_lock(&g_reply_tracker_mutex);
    memset(g_reply_slots, 0, sizeof(g_reply_slots));
    g_reply_count = 0;
    g_reply_generation = 0;
    pthread_mutex_unlock(&g_reply_tracker_mutex);
}
