#include "frida-gum.h"

#include <pthread.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xniff_hooks_emit.h"

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
static uint64_t g_enter_count = 0;
static uint64_t g_leave_count = 0;

typedef struct {
  uint64_t args[8];
} XniffInvocationData;

static int xniff_hooks_debug_enabled(void) {
  const char *e = getenv("XNIFF_HOOKS_DEBUG");
  return (e && *e && strcmp(e, "0") != 0) ? 1 : 0;
}

static void xniff_hooks_debug_log(const char *fmt, ...) {
  if (!xniff_hooks_debug_enabled()) return;
  char path[128];
  snprintf(path, sizeof(path), "/tmp/xniff-hooks-%d.log", (int)getpid());
  FILE *fp = fopen(path, "a");
  if (!fp) return;
  va_list ap;
  va_start(ap, fmt);
  vfprintf(fp, fmt, ap);
  va_end(ap);
  fputc('\n', fp);
  fclose(fp);
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

  if (xniff_hooks_debug_enabled()) {
    uint64_t n = __atomic_add_fetch(&g_enter_count, 1, __ATOMIC_RELAXED);
    if (n <= 16 || (n & 0xFFFu) == 1u) {
      xniff_hooks_debug_log("enter #%llu hook_id=%d", (unsigned long long)n, (int)hook_id);
    }
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
  }
}

static void xniff_listener_on_leave(GumInvocationListener *listener, GumInvocationContext *ic) {
  (void)listener;
  XniffHookId hook_id = (XniffHookId)GPOINTER_TO_SIZE(gum_invocation_context_get_listener_function_data(ic));
  XniffInvocationData *inv = GUM_IC_GET_INVOCATION_DATA(ic, XniffInvocationData);
  const uint64_t *args = (inv != NULL) ? inv->args : NULL;
  uint64_t ret = (uint64_t)GPOINTER_TO_SIZE(gum_invocation_context_get_return_value(ic));

  if (xniff_hooks_debug_enabled()) {
    uint64_t n = __atomic_add_fetch(&g_leave_count, 1, __ATOMIC_RELAXED);
    if (n <= 16 || (n & 0xFFFu) == 1u) {
      xniff_hooks_debug_log("leave #%llu hook_id=%d ret=0x%llx", (unsigned long long)n, (int)hook_id, (unsigned long long)ret);
    }
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

static void xniff_attach_if_present(const char *name, XniffHookId hook_id) {
  gpointer target = GSIZE_TO_POINTER(gum_module_find_export_by_name(NULL, name));
  if (target == NULL) {
    xniff_hooks_debug_log("attach: %s not found", name);
    return;
  }
  GumAttachReturn ar = gum_interceptor_attach(g_interceptor, target, g_listener, GSIZE_TO_POINTER(hook_id));
  xniff_hooks_debug_log("attach: %s => %p (%d)", name, target, (int)ar);
}

static void xniff_install_hooks_once(void) {
  xniff_hooks_debug_log("xniff_install_hooks_once: begin");
  gum_init_embedded();

  g_interceptor = gum_interceptor_obtain();
  g_listener = g_object_new(XNIFF_TYPE_LISTENER, NULL);

  gum_interceptor_begin_transaction(g_interceptor);
  xniff_attach_if_present("mach_msg", XNIFF_HOOK_MACH_MSG);
  xniff_attach_if_present("mach_msg_trap", XNIFF_HOOK_MACH_MSG_TRAP);
  xniff_attach_if_present("mach_msg_overwrite", XNIFF_HOOK_MACH_MSG_OVERWRITE);
  xniff_attach_if_present("mach_msg_overwrite_trap", XNIFF_HOOK_MACH_MSG_OVERWRITE_TRAP);
  xniff_attach_if_present("mach_msg2_internal", XNIFF_HOOK_MACH_MSG2_INTERNAL);
  xniff_attach_if_present("mach_msg2_trap", XNIFF_HOOK_MACH_MSG2_TRAP);
  xniff_attach_if_present("xpc_connection_create", XNIFF_HOOK_XPC_CONNECTION_CREATE);
  xniff_attach_if_present("xpc_pipe_routine", XNIFF_HOOK_XPC_PIPE_ROUTINE);
  xniff_attach_if_present("xpc_connection_send_message", XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE);
  xniff_attach_if_present("xpc_connection_send_message_with_reply", XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE_WITH_REPLY);
  xniff_attach_if_present("xpc_connection_send_message_with_reply_sync", XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC);
  gum_interceptor_end_transaction(g_interceptor);

  xniff_hooks_debug_log("xniff_install_hooks_once: done");
}

static void *xniff_install_hooks_thread(void *arg) {
  (void)arg;
  (void)pthread_once(&g_once, xniff_install_hooks_once);
  return NULL;
}

__attribute__((constructor)) static void xniff_frida_gum_ctor(void) {
  pthread_t t;
  if (pthread_create(&t, NULL, xniff_install_hooks_thread, NULL) == 0) {
    (void)pthread_detach(t);
  } else {
    (void)pthread_once(&g_once, xniff_install_hooks_once);
  }
}

__attribute__((destructor)) static void xniff_frida_gum_dtor(void) {
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
