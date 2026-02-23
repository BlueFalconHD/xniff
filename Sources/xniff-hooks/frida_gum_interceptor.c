#include "frida-gum.h"

#include <pthread.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xniff_hooks_emit.h"
#include "xniff_hooks_ipc.h"
#include "../shared/xniff_ipc.h"

typedef struct _XniffListener XniffListener;
typedef enum _XniffHookId XniffHookId;

struct _XniffListener {
  GObject parent;
};

enum _XniffHookId {
  XNIFF_HOOK_MACH_MSG,
  XNIFF_HOOK_MACH_MSG_TRAP,
  XNIFF_HOOK_MACH_MSG_OVERWRITE,
  XNIFF_HOOK_MACH_MSG_OVERWRITE_TRAP,
  XNIFF_HOOK_MACH_MSG2_INTERNAL,
  XNIFF_HOOK_MACH_MSG2_TRAP,
  XNIFF_HOOK_XPC_CONNECTION_CREATE,
  XNIFF_HOOK_XPC_PIPE_ROUTINE,
  XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE,
  XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE_WITH_REPLY,
  XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC,
  XNIFF_HOOK_XPC_CONNECTION_CALL_EVENT_HANDLER,
};

static void xniff_listener_iface_init(gpointer g_iface, gpointer iface_data);

#define XNIFF_TYPE_LISTENER (xniff_listener_get_type())
G_DECLARE_FINAL_TYPE(XniffListener, xniff_listener, XNIFF, LISTENER, GObject)
G_DEFINE_TYPE_EXTENDED(XniffListener,
                       xniff_listener,
                       G_TYPE_OBJECT,
                       0,
                       G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER, xniff_listener_iface_init))

static GumInterceptor *g_interceptor = NULL;
static GumInvocationListener *g_listener = NULL;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_attach_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_enter_count = 0;
static uint64_t g_leave_count = 0;
static gboolean g_event_handler_hook_attached = FALSE;

typedef struct {
  const char *name;
  XniffHookId hook_id;
  gboolean attached;
} XniffExportHookSpec;

static gboolean xniff_hook_event_handler_enabled(void);
static gboolean xniff_attach_event_handler_hook_locked(void);

static XniffExportHookSpec g_export_hooks[] = {
  { "mach_msg", XNIFF_HOOK_MACH_MSG, FALSE },
  { "mach_msg_trap", XNIFF_HOOK_MACH_MSG_TRAP, FALSE },
  { "mach_msg_overwrite", XNIFF_HOOK_MACH_MSG_OVERWRITE, FALSE },
  { "mach_msg_overwrite_trap", XNIFF_HOOK_MACH_MSG_OVERWRITE_TRAP, FALSE },
  { "mach_msg2_internal", XNIFF_HOOK_MACH_MSG2_INTERNAL, FALSE },
  { "mach_msg2_trap", XNIFF_HOOK_MACH_MSG2_TRAP, FALSE },
  { "xpc_connection_create", XNIFF_HOOK_XPC_CONNECTION_CREATE, FALSE },
  { "xpc_pipe_routine", XNIFF_HOOK_XPC_PIPE_ROUTINE, FALSE },
  { "xpc_connection_send_message", XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE, FALSE },
  { "xpc_connection_send_message_with_reply", XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE_WITH_REPLY, FALSE },
  { "xpc_connection_send_message_with_reply_sync", XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC, FALSE },
};

typedef struct {
  uint64_t args[8];
} XniffInvocationData;

static void xniff_hooks_debug_log(const char *fmt, ...) {
  char line[1024];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(line, sizeof(line), fmt, ap);
  va_end(ap);
  if (n <= 0) return;

  size_t msg_len = (size_t)n;
  if (msg_len >= sizeof(line)) msg_len = sizeof(line) - 1;

  xniff_ipc_hdr_t hdr = {0};
  hdr.magic = XNIFF_IPC_MAGIC;
  hdr.version = XNIFF_IPC_VERSION;
  hdr.kind = XNIFF_EVT_DEBUG_LOG;
  hdr.pid = (uint32_t)getpid();
  hdr.tid_low = (uint32_t)(uintptr_t)pthread_self();
  hdr.payload_len = (uint32_t)(sizeof(xniff_ipc_debug_payload_t) + msg_len);

  xniff_ipc_debug_payload_t pl = {0};
  pl.api = XNIFF_API_DEBUG;
  pl.level = 0;
  pl.msg_len = (uint32_t)msg_len;

  xniff_hooks_ipc_lock();
  int ok = 0;
  ok |= xniff_hooks_ipc_write_locked(&hdr, sizeof(hdr));
  ok |= xniff_hooks_ipc_write_locked(&pl, sizeof(pl));
  if (msg_len != 0) ok |= xniff_hooks_ipc_write_locked(line, msg_len);
  xniff_hooks_ipc_unlock();
  (void)ok;
}

static inline void xniff_read_args_u64(GumInvocationContext *ic, uint64_t out[8]) {
  for (int i = 0; i < 8; i++) {
    out[i] = (uint64_t)GPOINTER_TO_SIZE(gum_invocation_context_get_nth_argument(ic, (guint)i));
  }
}

static void xniff_listener_on_enter(GumInvocationListener *listener, GumInvocationContext *ic) {
  (void)listener;
  XniffHookId hook_id = (XniffHookId)GPOINTER_TO_SIZE(gum_invocation_context_get_listener_function_data(ic));
  XniffInvocationData *inv = GUM_IC_GET_INVOCATION_DATA(ic, XniffInvocationData);
  if (inv != NULL) {
    xniff_read_args_u64(ic, inv->args);
  }
  const uint64_t *args = (inv != NULL) ? inv->args : NULL;

  uint64_t n = __atomic_add_fetch(&g_enter_count, 1, __ATOMIC_RELAXED);
  if (n <= 16 || (n & 0xFFFu) == 1u) {
    xniff_hooks_debug_log("enter #%llu hook_id=%d", (unsigned long long)n, (int)hook_id);
  }

  if (g_interceptor != NULL) gum_interceptor_ignore_current_thread(g_interceptor);
  switch (hook_id) {
    case XNIFF_HOOK_MACH_MSG:
    case XNIFF_HOOK_MACH_MSG_TRAP:
    case XNIFF_HOOK_MACH_MSG_OVERWRITE:
    case XNIFF_HOOK_MACH_MSG_OVERWRITE_TRAP:
      xniff_emit_mach_msg_entry(args);
      break;
    case XNIFF_HOOK_MACH_MSG2_INTERNAL:
    case XNIFF_HOOK_MACH_MSG2_TRAP:
      xniff_emit_mach_msg2_entry(args);
      break;
    case XNIFF_HOOK_XPC_CONNECTION_CREATE:
      xniff_emit_xpc_connection_create_entry(args);
      break;
    case XNIFF_HOOK_XPC_PIPE_ROUTINE:
      xniff_emit_xpc_pipe_routine_entry(args);
      break;
    case XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE:
      xniff_emit_xpc_connection_send_message_entry(args);
      break;
    case XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE_WITH_REPLY:
      xniff_emit_xpc_connection_send_message_with_reply_entry(args);
      break;
    case XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC:
      xniff_emit_xpc_connection_send_message_with_reply_sync_entry(args);
      break;
    case XNIFF_HOOK_XPC_CONNECTION_CALL_EVENT_HANDLER:
      xniff_emit_xpc_connection_call_event_handler_entry(args);
      break;
  }
}

static void xniff_listener_on_leave(GumInvocationListener *listener, GumInvocationContext *ic) {
  (void)listener;
  XniffHookId hook_id = (XniffHookId)GPOINTER_TO_SIZE(gum_invocation_context_get_listener_function_data(ic));
  XniffInvocationData *inv = GUM_IC_GET_INVOCATION_DATA(ic, XniffInvocationData);
  const uint64_t *args = (inv != NULL) ? inv->args : NULL;
  uint64_t ret = (uint64_t)GPOINTER_TO_SIZE(gum_invocation_context_get_return_value(ic));

  uint64_t n = __atomic_add_fetch(&g_leave_count, 1, __ATOMIC_RELAXED);
  if (n <= 16 || (n & 0xFFFu) == 1u) {
    xniff_hooks_debug_log("leave #%llu hook_id=%d ret=0x%llx", (unsigned long long)n, (int)hook_id, (unsigned long long)ret);
  }

  switch (hook_id) {
    case XNIFF_HOOK_MACH_MSG:
    case XNIFF_HOOK_MACH_MSG_TRAP:
      xniff_emit_mach_msg_exit(ret, args, 0);
      break;
    case XNIFF_HOOK_MACH_MSG_OVERWRITE:
    case XNIFF_HOOK_MACH_MSG_OVERWRITE_TRAP:
      xniff_emit_mach_msg_exit(ret, args, 1);
      break;
    case XNIFF_HOOK_MACH_MSG2_INTERNAL:
    case XNIFF_HOOK_MACH_MSG2_TRAP:
      xniff_emit_mach_msg2_exit(ret, args);
      break;
    case XNIFF_HOOK_XPC_CONNECTION_CREATE:
      xniff_emit_xpc_connection_create_exit(ret, args);
      break;
    case XNIFF_HOOK_XPC_PIPE_ROUTINE:
      xniff_emit_xpc_pipe_routine_exit(ret, args);
      break;
    case XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE:
      break;
    case XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE_WITH_REPLY:
      break;
    case XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC:
      xniff_emit_xpc_connection_send_message_with_reply_sync_exit(ret, args);
      break;
    case XNIFF_HOOK_XPC_CONNECTION_CALL_EVENT_HANDLER:
      xniff_emit_xpc_connection_call_event_handler_exit(ret, args);
      break;
  }
  if (g_interceptor != NULL) gum_interceptor_unignore_current_thread(g_interceptor);
}

static void xniff_listener_class_init(XniffListenerClass *klass) {
  (void)klass;
  (void)XNIFF_IS_LISTENER;
  (void)glib_autoptr_cleanup_XniffListener;
}

static void xniff_listener_iface_init(gpointer g_iface, gpointer iface_data) {
  (void)iface_data;
  GumInvocationListenerInterface *iface = g_iface;
  iface->on_enter = xniff_listener_on_enter;
  iface->on_leave = xniff_listener_on_leave;
}

static void xniff_listener_init(XniffListener *self) {
  (void)self;
}

typedef struct {
  const char *name;
  GumAddress addr;
} XniffSymFindCtx;

typedef struct {
  const char *module_query;
  const char *symbol_name;
  GumAddress addr;
  char matched_module[512];
} XniffModuleSymSearchCtx;

static gboolean xniff_module_matches_query(const GumModuleDetails *details, const char *query) {
  if (details == NULL) return FALSE;
  if (query == NULL || query[0] == '\0') return TRUE;
  if (details->name != NULL && strstr(details->name, query) != NULL) return TRUE;
  if (details->path != NULL && strstr(details->path, query) != NULL) return TRUE;
  return FALSE;
}

static gboolean xniff_find_func_symbol_cb(const GumSymbolDetails *details, gpointer user_data) {
  XniffSymFindCtx *ctx = (XniffSymFindCtx *)user_data;
  if (details == NULL || ctx == NULL || ctx->name == NULL) return TRUE;
  if (details->name == NULL) return TRUE;
  if (details->type != GUM_SYMBOL_FUNCTION) return TRUE;
  if (strcmp(details->name, ctx->name) != 0) return TRUE;
  ctx->addr = details->address;
  return FALSE; // stop enumeration
}

static GumAddress xniff_find_function_symbol(const char *module_name, const char *name) {
  if (module_name == NULL || name == NULL || name[0] == '\0') return 0;

  XniffSymFindCtx ctx = {0};
  ctx.name = name;
  gum_module_enumerate_symbols(module_name, xniff_find_func_symbol_cb, &ctx);
  if (ctx.addr != 0) return ctx.addr;

  if (name[0] == '_') {
    ctx.name = name + 1;
    ctx.addr = 0;
    gum_module_enumerate_symbols(module_name, xniff_find_func_symbol_cb, &ctx);
    if (ctx.addr != 0) return ctx.addr;
  } else {
    char alt[256];
    int n = snprintf(alt, sizeof(alt), "_%s", name);
    if (n > 0 && (size_t)n < sizeof(alt)) {
      ctx.name = alt;
      ctx.addr = 0;
      gum_module_enumerate_symbols(module_name, xniff_find_func_symbol_cb, &ctx);
      if (ctx.addr != 0) return ctx.addr;
    }
  }

  return 0;
}

static GumAddress xniff_find_symbol_in_module_with_spelling(const char *module_name, const char *name) {
  if (module_name == NULL || name == NULL || name[0] == '\0') return 0;

  GumAddress a = gum_module_find_symbol_by_name(module_name, name);
  if (a != 0) return a;
  a = gum_module_find_export_by_name(module_name, name);
  if (a != 0) return a;
  a = xniff_find_function_symbol(module_name, name);
  if (a != 0) return a;

  if (name[0] == '_') {
    const char *alt = name + 1;
    a = gum_module_find_symbol_by_name(module_name, alt);
    if (a != 0) return a;
    a = gum_module_find_export_by_name(module_name, alt);
    if (a != 0) return a;
    a = xniff_find_function_symbol(module_name, alt);
    if (a != 0) return a;
  } else {
    char alt[256];
    int n = snprintf(alt, sizeof(alt), "_%s", name);
    if (n > 0 && (size_t)n < sizeof(alt)) {
      a = gum_module_find_symbol_by_name(module_name, alt);
      if (a != 0) return a;
      a = gum_module_find_export_by_name(module_name, alt);
      if (a != 0) return a;
      a = xniff_find_function_symbol(module_name, alt);
      if (a != 0) return a;
    }
  }

  return 0;
}

static gboolean xniff_find_symbol_in_matching_module_cb(const GumModuleDetails *details, gpointer user_data) {
  XniffModuleSymSearchCtx *ctx = (XniffModuleSymSearchCtx *)user_data;
  if (ctx == NULL || ctx->symbol_name == NULL) return TRUE;
  if (ctx->addr != 0) return FALSE;
  if (!xniff_module_matches_query(details, ctx->module_query)) return TRUE;
  if (details == NULL || details->name == NULL) return TRUE;

  GumAddress addr = xniff_find_symbol_in_module_with_spelling(details->name, ctx->symbol_name);
  if (addr == 0) return TRUE;

  ctx->addr = addr;
  if (details->path != NULL && details->path[0] != '\0') {
    snprintf(ctx->matched_module, sizeof(ctx->matched_module), "%s", details->path);
  } else {
    snprintf(ctx->matched_module, sizeof(ctx->matched_module), "%s", details->name);
  }
  return FALSE; // stop enumeration
}

static GumAddress xniff_find_symbol_in_modules(const char *module_query, const char *symbol_name,
                                               char *matched_module, size_t matched_module_size) {
  XniffModuleSymSearchCtx ctx = {0};
  ctx.module_query = module_query;
  ctx.symbol_name = symbol_name;
  gum_process_enumerate_modules(xniff_find_symbol_in_matching_module_cb, &ctx);

  if (matched_module != NULL && matched_module_size > 0) {
    if (ctx.matched_module[0] != '\0')
      snprintf(matched_module, matched_module_size, "%s", ctx.matched_module);
    else
      matched_module[0] = '\0';
  }
  return ctx.addr;
}

static gboolean xniff_attach_export_if_present(const char *name, XniffHookId hook_id) {
  gpointer target = GSIZE_TO_POINTER(gum_module_find_export_by_name(NULL, name));
  if (target == NULL) {
    xniff_hooks_debug_log("attach export: %s not found", name ? name : "<null>");
    return FALSE;
  }
  GumAttachReturn ar = gum_interceptor_attach(g_interceptor, target, g_listener, GSIZE_TO_POINTER(hook_id));
  xniff_hooks_debug_log("attach export: %s => %p (%d)", name ? name : "<null>", target, (int)ar);
  return ar == GUM_ATTACH_OK || ar == GUM_ATTACH_ALREADY_ATTACHED;
}

static gboolean xniff_attach_export_hook_locked(XniffExportHookSpec *spec) {
  if (spec == NULL) return FALSE;
  if (spec->attached) return TRUE;
  if (g_interceptor == NULL || g_listener == NULL) return FALSE;
  if (xniff_attach_export_if_present(spec->name, spec->hook_id)) {
    spec->attached = TRUE;
    return TRUE;
  }
  return FALSE;
}

static gboolean xniff_attach_all_core_hooks_locked(void) {
  gboolean all_attached = TRUE;
  for (gsize i = 0; i < G_N_ELEMENTS(g_export_hooks); i++) {
    if (!xniff_attach_export_hook_locked(&g_export_hooks[i])) {
      all_attached = FALSE;
    }
  }
  if (xniff_hook_event_handler_enabled() && !xniff_attach_event_handler_hook_locked()) {
    all_attached = FALSE;
  }
  return all_attached;
}

static guint xniff_count_pending_hooks(void) {
  guint pending = 0;
  for (gsize i = 0; i < G_N_ELEMENTS(g_export_hooks); i++) {
    if (!g_export_hooks[i].attached) pending++;
  }
  if (xniff_hook_event_handler_enabled() && !g_event_handler_hook_attached) pending++;
  return pending;
}

static gboolean xniff_attach_private_function_if_present(const char *module_name, const char *name, XniffHookId hook_id) {
  char matched_module[512] = {0};
  gpointer target = GSIZE_TO_POINTER(xniff_find_symbol_in_modules(module_name, name, matched_module, sizeof(matched_module)));
  if (target == NULL) {
    xniff_hooks_debug_log("attach private: module_query=%s symbol=%s not found",
                          module_name ? module_name : "<any>", name ? name : "<null>");
    return FALSE;
  }
  GumAttachReturn ar = gum_interceptor_attach(g_interceptor, target, g_listener, GSIZE_TO_POINTER(hook_id));
  xniff_hooks_debug_log("attach private: module_query=%s resolved_module=%s symbol=%s => %p (%d)",
                        module_name ? module_name : "<any>",
                        matched_module[0] ? matched_module : "<unknown>",
                        name ? name : "<null>", target, (int)ar);
  return ar == GUM_ATTACH_OK || ar == GUM_ATTACH_ALREADY_ATTACHED;
}

static gboolean xniff_hook_event_handler_enabled(void) {
  const char *e = getenv("XNIFF_HOOK_XPC_EVENT_HANDLER");
  if (e && *e && strcmp(e, "0") == 0) return FALSE;
  return TRUE;
}

static gboolean xniff_attach_event_handler_hook_locked(void) {
  if (g_event_handler_hook_attached) return TRUE;
  if (!xniff_hook_event_handler_enabled()) return FALSE;
  if (g_interceptor == NULL || g_listener == NULL) return FALSE;
  if (xniff_attach_private_function_if_present("libxpc", "_xpc_connection_call_event_handler",
                                               XNIFF_HOOK_XPC_CONNECTION_CALL_EVENT_HANDLER)) {
    g_event_handler_hook_attached = TRUE;
    xniff_hooks_debug_log("event-handler hook: attached");
    return TRUE;
  }
  return FALSE;
}

static void *xniff_event_handler_retry_thread(void *arg) {
  (void)arg;
  // Retry for ~60s in case libxpc symbols appear after constructor-time injection.
  for (int i = 0; i < 600; i++) {
    if (g_interceptor == NULL || g_listener == NULL) break;

    pthread_mutex_lock(&g_attach_mutex);
    gum_interceptor_begin_transaction(g_interceptor);
    gboolean ok = xniff_attach_all_core_hooks_locked();
    gum_interceptor_end_transaction(g_interceptor);
    pthread_mutex_unlock(&g_attach_mutex);
    if (ok) {
      xniff_hooks_debug_log("hook retry: all hooks attached");
      return NULL;
    }
    if (i < 10 || (i % 20) == 19 || i == 599) {
      xniff_hooks_debug_log("hook retry: attempt %d pending_hooks=%u", i + 1, xniff_count_pending_hooks());
    }
    usleep(100 * 1000);
  }
  guint pending = xniff_count_pending_hooks();
  if (pending != 0) {
    xniff_hooks_debug_log("hook retry: gave up with pending_hooks=%u", pending);
  }
  return NULL;
}

static void xniff_install_hooks_once(void) {
  xniff_hooks_debug_log("xniff_install_hooks_once: begin");
  gum_init_embedded();

  g_interceptor = gum_interceptor_obtain();
  g_listener = g_object_new(XNIFF_TYPE_LISTENER, NULL);

  pthread_mutex_lock(&g_attach_mutex);
  gum_interceptor_begin_transaction(g_interceptor);
  gboolean all_attached = xniff_attach_all_core_hooks_locked();
  gum_interceptor_end_transaction(g_interceptor);
  pthread_mutex_unlock(&g_attach_mutex);

  if (!all_attached) {
    xniff_hooks_debug_log("xniff_install_hooks_once: deferred attach pending_hooks=%u", xniff_count_pending_hooks());
    pthread_t t;
    if (pthread_create(&t, NULL, xniff_event_handler_retry_thread, NULL) == 0) {
      (void)pthread_detach(t);
    }
  }

  xniff_hooks_debug_log("xniff_install_hooks_once: done");
}

__attribute__((constructor)) static void xniff_frida_gum_ctor(void) {
  xniff_hooks_debug_log("ctor: entered");
  xniff_hooks_debug_log("ctor: running install inline");
  (void)pthread_once(&g_once, xniff_install_hooks_once);
}

__attribute__((destructor)) static void xniff_frida_gum_dtor(void) {
  // During process shutdown, explicit detach/deinit can race active libxpc
  // threads and crash in patched code pages. Default to leak-on-exit.
  // Set XNIFF_DETACH_ON_EXIT=1 to force explicit cleanup for debugging.
  const char *detach_on_exit = getenv("XNIFF_DETACH_ON_EXIT");
  if (!(detach_on_exit && *detach_on_exit && strcmp(detach_on_exit, "0") != 0)) {
    g_listener = NULL;
    g_interceptor = NULL;
    return;
  }

  if (g_interceptor != NULL && g_listener != NULL) {
    gum_interceptor_detach(g_interceptor, g_listener);
  }

  if (g_listener != NULL) {
    g_object_unref(g_listener);
    g_listener = NULL;
  }
  if (g_interceptor != NULL) {
    g_object_unref(g_interceptor);
    g_interceptor = NULL;
  }

  gum_deinit_embedded();
}
