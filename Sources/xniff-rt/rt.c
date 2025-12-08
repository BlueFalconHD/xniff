#include "rt.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct frame_stack {
    xniff_ctx_frame_t* frames;
    size_t depth;
    size_t cap;
    int capture_fp;
} frame_stack_t;

static pthread_key_t g_tls_key;
static pthread_once_t g_tls_once = PTHREAD_ONCE_INIT;

static void tls_destructor(void* p) {
    frame_stack_t* st = (frame_stack_t*)p;
    if (st) {
        free(st->frames);
        free(st);
    }
}

static void tls_init_once(void) {
    (void)pthread_key_create(&g_tls_key, tls_destructor);
}

static frame_stack_t* get_stack(void) {
    (void)pthread_once(&g_tls_once, tls_init_once);
    frame_stack_t* st = (frame_stack_t*)pthread_getspecific(g_tls_key);
    if (!st) {
        st = (frame_stack_t*)calloc(1, sizeof(*st));
        if (!st) return NULL;
        st->cap = 8;
        st->frames = (xniff_ctx_frame_t*)calloc(st->cap, sizeof(xniff_ctx_frame_t));
        if (!st->frames) { free(st); return NULL; }
        pthread_setspecific(g_tls_key, st);
    }
    return st;
}

const char* xniff_rt_version(void) {
    return "xniff-rt/0.1.0";
}

void xniff_rt_set_capture_fp(int enable) {
    frame_stack_t* st = get_stack();
    if (st) st->capture_fp = (enable != 0);
}

static int ensure_capacity(frame_stack_t* st) {
    if (st->depth < st->cap) return 0;
    size_t new_cap = st->cap ? st->cap * 2 : 8;
    xniff_ctx_frame_t* nf = (xniff_ctx_frame_t*)realloc(st->frames, new_cap * sizeof(xniff_ctx_frame_t));
    if (!nf) return -1;
    // zero new region
    memset(nf + st->cap, 0, (new_cap - st->cap) * sizeof(xniff_ctx_frame_t));
    st->frames = nf;
    st->cap = new_cap;
    return 0;
}

xniff_ctx_frame_t* xniff_ctx_enter(void) {
    frame_stack_t* st = get_stack();
    if (!st) return NULL;
    if (ensure_capacity(st) != 0) return NULL;
    xniff_ctx_frame_t* f = &st->frames[st->depth++];
    memset(f, 0, sizeof(*f));
    f->depth = st->depth; // 1-based depth
    return f;
}

xniff_ctx_frame_t* xniff_ctx_exit(void) {
    frame_stack_t* st = get_stack();
    if (!st || st->depth == 0) return NULL;
    xniff_ctx_frame_t* f = &st->frames[st->depth - 1];
    // Do not zero the frame so caller can inspect; it will be overwritten on next enter at same depth.
    st->depth--;
    return f;
}

void xniff_exit_hook(uint64_t ret_value, const xniff_ctx_frame_t* ctx) {
    (void)ret_value;
    (void)ctx;
    // Default no-op. Users may patch the trampoline to call their own hook.
}

