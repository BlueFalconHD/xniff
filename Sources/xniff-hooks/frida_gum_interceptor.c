#include "frida-gum.h"

#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <Block.h>
#include <xpc/xpc.h>

#include "xniff_hooks_emit.h"
#include "xniff_hooks_ipc.h"
#include "xpc_reply_tracker.h"
#include "../shared/xniff_ipc.h"
#include "../shared/xniff_ipc_v2.h"

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
  XNIFF_HOOK_XPC_CONNECTION_PACK_MESSAGE,
  XNIFF_HOOK_XPC_CONNECTION_CALL_REPLY_ASYNC,
  XNIFF_HOOK_XPC_CONNECTION_CHECK_IN,
  XNIFF_HOOK_XPC_DICTIONARY_SEND_REPLY,
  XNIFF_HOOK_XPC_SESSION_SEND_MESSAGE,
  XNIFF_HOOK_XPC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC,
  XNIFF_HOOK_XPC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC,
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
static gboolean g_pack_message_hook_attached = FALSE;
static gboolean g_call_reply_async_hook_attached = FALSE;
static uint64_t g_next_call_id = 0;
static __thread uint32_t g_async_connection_send_depth = 0;

typedef struct {
  thread_t *threads;
  mach_msg_type_number_t count;
} XniffSuspendedThreadSet;

static XniffSuspendedThreadSet g_suspended_threads = {0};

typedef struct {
  const char *module_query;
  const char *name;
  XniffHookId hook_id;
  gboolean attached;
} XniffExportHookSpec;

static gboolean xniff_hook_event_handler_enabled(void);
static gboolean xniff_attach_event_handler_hook_locked(void);
static gboolean xniff_attach_pack_message_hook_locked(void);
static gboolean xniff_attach_call_reply_async_hook_locked(void);
static void xniff_attach_optional_check_in_hook_once(void);

static gboolean xniff_internal_reply_hooks_ready(void) {
  return g_pack_message_hook_attached && g_call_reply_async_hook_attached;
}

static XniffExportHookSpec g_export_hooks[] = {
  { NULL, "mach_msg", XNIFF_HOOK_MACH_MSG, FALSE },
  { NULL, "mach_msg_trap", XNIFF_HOOK_MACH_MSG_TRAP, FALSE },
  { NULL, "mach_msg_overwrite", XNIFF_HOOK_MACH_MSG_OVERWRITE, FALSE },
  { NULL, "mach_msg_overwrite_trap", XNIFF_HOOK_MACH_MSG_OVERWRITE_TRAP, FALSE },
  { NULL, "mach_msg2_internal", XNIFF_HOOK_MACH_MSG2_INTERNAL, FALSE },
  { NULL, "mach_msg2_trap", XNIFF_HOOK_MACH_MSG2_TRAP, FALSE },
  { "libxpc", "xpc_connection_create", XNIFF_HOOK_XPC_CONNECTION_CREATE, FALSE },
  { "libxpc", "xpc_pipe_routine", XNIFF_HOOK_XPC_PIPE_ROUTINE, FALSE },
  { "libxpc", "xpc_connection_send_message", XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE, FALSE },
  { "libxpc", "xpc_connection_send_message_with_reply", XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE_WITH_REPLY, FALSE },
  { "libxpc", "xpc_connection_send_message_with_reply_sync", XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC, FALSE },
  { "libxpc", "xpc_dictionary_send_reply", XNIFF_HOOK_XPC_DICTIONARY_SEND_REPLY, FALSE },
  { "libxpc", "xpc_session_send_message", XNIFF_HOOK_XPC_SESSION_SEND_MESSAGE, FALSE },
  { "libxpc", "xpc_session_send_message_with_reply_async", XNIFF_HOOK_XPC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC, FALSE },
  { "libxpc", "xpc_session_send_message_with_reply_sync", XNIFF_HOOK_XPC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC, FALSE },
};

typedef struct {
  uint64_t args[8];
  uint64_t call_id;
  uint64_t parent_call_id;
  void *replacement_block;
  uint8_t emit_enabled;
  uint8_t tracks_async_reply;
} XniffInvocationData;

static void xniff_hooks_debug_log(const char *fmt, ...) {
  if (!xniff_hooks_debug_is_enabled() || !xniff_hooks_streaming_is_enabled()) return;
  char line[1024];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(line, sizeof(line), fmt, ap);
  va_end(ap);
  if (n <= 0) return;

  size_t msg_len = (size_t)n;
  if (msg_len >= sizeof(line)) msg_len = sizeof(line) - 1;

  xniff_ipc_v2_builder_t b;
  xniff_ipc_v2_builder_init(&b);
  if (xniff_ipc_v2_begin(&b,
                         XNIFF_V2_ENTRY_DIAG,
                         (uint32_t)getpid(),
                         (uint32_t)(uintptr_t)pthread_self(),
                         0,
                         0,
                         XNIFF_API_DEBUG,
                         0) == 0) {
    xniff_ipc_v2_diag_t d = {0};
    d.msg_len = (uint32_t)msg_len;
    d.level = 0;
    size_t sec_len = sizeof(d) + msg_len;
    uint8_t *sec = (uint8_t *)malloc(sec_len);
    if (sec) {
      memcpy(sec, &d, sizeof(d));
      if (msg_len != 0) memcpy(sec + sizeof(d), line, msg_len);
      (void)xniff_ipc_v2_add_section(&b, XNIFF_V2_SEC_HOOK_DIAG, 0, sec, sec_len);
      free(sec);
      (void)xniff_ipc_v2_write(&b);
    }
  }
  xniff_ipc_v2_builder_free(&b);
}

static void xniff_suspend_all_other_threads(void) {
  thread_act_array_t threads = NULL;
  mach_msg_type_number_t count = 0;
  kern_return_t kr = task_threads(mach_task_self(), &threads, &count);
  if (kr != KERN_SUCCESS || threads == NULL || count == 0) {
    return;
  }

  thread_t self = mach_thread_self();
  thread_t *kept = (thread_t *)calloc((size_t)count, sizeof(thread_t));
  if (kept == NULL) {
    for (mach_msg_type_number_t i = 0; i < count; i++) {
      mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(),
                  (vm_address_t)(uintptr_t)threads,
                  (vm_size_t)((size_t)count * sizeof(thread_t)));
    mach_port_deallocate(mach_task_self(), self);
    return;
  }

  mach_msg_type_number_t kept_count = 0;
  for (mach_msg_type_number_t i = 0; i < count; i++) {
    thread_t t = threads[i];
    if (t == self) {
      mach_port_deallocate(mach_task_self(), t);
      continue;
    }
    if (thread_suspend(t) == KERN_SUCCESS) {
      kept[kept_count++] = t; // keep send right for later resume
    } else {
      mach_port_deallocate(mach_task_self(), t);
    }
  }

  vm_deallocate(mach_task_self(),
                (vm_address_t)(uintptr_t)threads,
                (vm_size_t)((size_t)count * sizeof(thread_t)));
  mach_port_deallocate(mach_task_self(), self);

  g_suspended_threads.threads = kept;
  g_suspended_threads.count = kept_count;
}

static void xniff_resume_suspended_threads(void) {
  if (g_suspended_threads.threads == NULL) return;
  for (mach_msg_type_number_t i = 0; i < g_suspended_threads.count; i++) {
    thread_t t = g_suspended_threads.threads[i];
    if (t == MACH_PORT_NULL) continue;
    (void)thread_resume(t);
    mach_port_deallocate(mach_task_self(), t);
  }
  free(g_suspended_threads.threads);
  g_suspended_threads.threads = NULL;
  g_suspended_threads.count = 0;
}

static inline void xniff_read_args_u64(GumInvocationContext *ic, uint64_t out[8]) {
  for (int i = 0; i < 8; i++) {
    out[i] = (uint64_t)GPOINTER_TO_SIZE(gum_invocation_context_get_nth_argument(ic, (guint)i));
  }
}

static bool xniff_hook_is_mach(XniffHookId hook_id) {
  return hook_id <= XNIFF_HOOK_MACH_MSG2_TRAP;
}

static bool xniff_hook_capture_enabled(XniffHookId hook_id) {
  uint32_t mode = xniff_hook_is_mach(hook_id) ? XNIFF_CAPTURE_MODE_MACH : XNIFF_CAPTURE_MODE_XPC;
  return xniff_hooks_capture_mode_enabled(mode);
}

static void xniff_ignore_current_thread(void) {
  if (g_interceptor != NULL) gum_interceptor_ignore_current_thread(g_interceptor);
}

static void xniff_unignore_current_thread(void) {
  if (g_interceptor != NULL) gum_interceptor_unignore_current_thread(g_interceptor);
}

typedef void (^XniffConnectionReplyHandler)(xpc_object_t reply);
typedef void (^XniffSessionReplyHandler)(xpc_object_t reply, xpc_object_t error);

static void xniff_install_connection_reply_wrapper(GumInvocationContext *ic,
                                                    XniffInvocationData *inv) {
  if (ic == NULL || inv == NULL || inv->args[3] == 0) return;
  XniffConnectionReplyHandler original = (XniffConnectionReplyHandler)(uintptr_t)inv->args[3];
  uint64_t call_id = inv->call_id;
  XniffConnectionReplyHandler wrapper = Block_copy(^(xpc_object_t reply) {
    // The caller may release its connection and message immediately after the
    // send returns. Only the reply is guaranteed to be live in this fallback.
    uint64_t args[8] = {0};
    uint64_t previous_call_id = xniff_hooks_current_call_id();
    xniff_hooks_set_current_call_id(call_id);
    xniff_ignore_current_thread();
    xniff_emit_xpc_connection_send_message_with_reply_async_response(
        (uint64_t)(uintptr_t)reply, args);
    xniff_unignore_current_thread();
    xniff_hooks_set_current_call_id(previous_call_id);
    original(reply);
  });
  if (wrapper == NULL) return;
  inv->replacement_block = wrapper;
  gum_invocation_context_replace_nth_argument(ic, 3, (gpointer)wrapper);
}

static void xniff_install_session_reply_wrapper(GumInvocationContext *ic,
                                                 XniffInvocationData *inv) {
  if (ic == NULL || inv == NULL || inv->args[2] == 0) return;
  XniffSessionReplyHandler original = (XniffSessionReplyHandler)(uintptr_t)inv->args[2];
  uint64_t call_id = inv->call_id;
  uint64_t session = inv->args[0];
  XniffSessionReplyHandler wrapper = Block_copy(^(xpc_object_t reply, xpc_object_t error) {
    // The request may have been released before this asynchronous callback.
    // Preserve its call ID, but only serialize the live reply or error object.
    uint64_t args[8] = { session, 0, 0, 0, 0, 0, 0, 0 };
    uint64_t previous_call_id = xniff_hooks_current_call_id();
    xniff_hooks_set_current_call_id(call_id);
    xniff_ignore_current_thread();
    xniff_emit_xpc_session_send_message_with_reply_async_response(
        (uint64_t)(uintptr_t)reply, (uint64_t)(uintptr_t)error, args);
    xniff_unignore_current_thread();
    xniff_hooks_set_current_call_id(previous_call_id);
    original(reply, error);
  });
  if (wrapper == NULL) return;
  inv->replacement_block = wrapper;
  gum_invocation_context_replace_nth_argument(ic, 2, (gpointer)wrapper);
}

static void xniff_release_reply_wrapper(XniffInvocationData *inv) {
  if (inv == NULL || inv->replacement_block == NULL) return;
  Block_release(inv->replacement_block);
  inv->replacement_block = NULL;
}

static void xniff_leave_async_reply_scope(XniffInvocationData *inv) {
  if (inv == NULL || inv->tracks_async_reply == 0) return;
  if (g_async_connection_send_depth != 0) g_async_connection_send_depth--;
  inv->tracks_async_reply = 0;
}

static void xniff_listener_on_enter(GumInvocationListener *listener, GumInvocationContext *ic) {
  (void)listener;
  XniffHookId hook_id = (XniffHookId)GPOINTER_TO_SIZE(gum_invocation_context_get_listener_function_data(ic));
  XniffInvocationData *inv = GUM_IC_GET_INVOCATION_DATA(ic, XniffInvocationData);
  bool enabled = xniff_hook_capture_enabled(hook_id);
  if (inv != NULL) {
    inv->parent_call_id = xniff_hooks_current_call_id();
    inv->emit_enabled = enabled ? 1u : 0u;
    inv->call_id = 0;
    inv->replacement_block = NULL;
    inv->tracks_async_reply = 0;
  }
  if (!enabled) return;
  if (inv != NULL) {
    xniff_read_args_u64(ic, inv->args);
  }
  const uint64_t *args = (inv != NULL) ? inv->args : NULL;

  if ((hook_id == XNIFF_HOOK_XPC_CONNECTION_PACK_MESSAGE ||
       hook_id == XNIFF_HOOK_XPC_CONNECTION_CALL_REPLY_ASYNC) &&
      !xniff_internal_reply_hooks_ready()) {
    if (inv != NULL) inv->emit_enabled = 0;
    return;
  }

  uint64_t pending_reply_call_id = 0;
  if (inv != NULL) {
    if ((hook_id == XNIFF_HOOK_XPC_DICTIONARY_SEND_REPLY ||
         hook_id == XNIFF_HOOK_XPC_CONNECTION_PACK_MESSAGE) &&
        inv->parent_call_id != 0) {
      inv->call_id = inv->parent_call_id;
    } else if (hook_id == XNIFF_HOOK_XPC_CONNECTION_CALL_REPLY_ASYNC &&
               xniff_xpc_reply_tracker_take(inv->args[1], &pending_reply_call_id)) {
      inv->call_id = pending_reply_call_id;
    } else {
      inv->call_id = __atomic_add_fetch(&g_next_call_id, 1, __ATOMIC_RELAXED);
    }
    if (hook_id == XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE_WITH_REPLY &&
        xniff_internal_reply_hooks_ready()) {
      g_async_connection_send_depth++;
      inv->tracks_async_reply = 1;
    }
  }

  uint64_t n = __atomic_add_fetch(&g_enter_count, 1, __ATOMIC_RELAXED);
  if (xniff_hooks_debug_is_enabled() && (n <= 16 || (n & 0xFFFu) == 1u)) {
    xniff_hooks_debug_log("enter #%llu hook_id=%d", (unsigned long long)n, (int)hook_id);
  }

  xniff_hooks_set_current_call_id(inv != NULL ? inv->call_id : 0);
  xniff_ignore_current_thread();
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
      if (!xniff_internal_reply_hooks_ready()) {
        xniff_install_connection_reply_wrapper(ic, inv);
      }
      xniff_emit_xpc_connection_send_message_with_reply_entry(args);
      break;
    case XNIFF_HOOK_XPC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC:
      xniff_emit_xpc_connection_send_message_with_reply_sync_entry(args);
      break;
    case XNIFF_HOOK_XPC_CONNECTION_CALL_EVENT_HANDLER:
      xniff_emit_xpc_connection_call_event_handler_entry(args);
      break;
    case XNIFF_HOOK_XPC_CONNECTION_PACK_MESSAGE:
      break;
    case XNIFF_HOOK_XPC_CONNECTION_CALL_REPLY_ASYNC: {
      // The decoded reply and connection are live here. The original message
      // was captured on entry and may already have been released by its caller.
      uint64_t response_args[8] = {
        args[0],
        0,
        args[1],
        0, 0, 0, 0, 0,
      };
      xniff_emit_xpc_connection_send_message_with_reply_async_response(args[2],
                                                                        response_args);
      break;
    }
    case XNIFF_HOOK_XPC_CONNECTION_CHECK_IN:
      xniff_emit_xpc_connection_check_in_entry(args);
      break;
    case XNIFF_HOOK_XPC_DICTIONARY_SEND_REPLY:
      xniff_emit_xpc_dictionary_send_reply_entry(args);
      break;
    case XNIFF_HOOK_XPC_SESSION_SEND_MESSAGE:
      xniff_emit_xpc_session_send_message_entry(args);
      break;
    case XNIFF_HOOK_XPC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC:
      xniff_install_session_reply_wrapper(ic, inv);
      xniff_emit_xpc_session_send_message_with_reply_async_entry(args);
      break;
    case XNIFF_HOOK_XPC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC:
      xniff_emit_xpc_session_send_message_with_reply_sync_entry(args);
      break;
  }
  xniff_unignore_current_thread();
  // Keep the call active while the intercepted implementation runs. Nested
  // xpc_dictionary_send_reply calls can then inherit an incoming request ID.
  xniff_hooks_set_current_call_id(inv != NULL ? inv->call_id : 0);
}

static void xniff_listener_on_leave(GumInvocationListener *listener, GumInvocationContext *ic) {
  (void)listener;
  XniffHookId hook_id = (XniffHookId)GPOINTER_TO_SIZE(gum_invocation_context_get_listener_function_data(ic));
  XniffInvocationData *inv = GUM_IC_GET_INVOCATION_DATA(ic, XniffInvocationData);
  if (inv != NULL && inv->emit_enabled == 0) {
    xniff_leave_async_reply_scope(inv);
    return;
  }
  if (!xniff_hook_capture_enabled(hook_id)) {
    xniff_release_reply_wrapper(inv);
    xniff_leave_async_reply_scope(inv);
    xniff_hooks_set_current_call_id(inv != NULL ? inv->parent_call_id : 0);
    return;
  }
  const uint64_t *args = (inv != NULL) ? inv->args : NULL;
  uint64_t ret = (uint64_t)GPOINTER_TO_SIZE(gum_invocation_context_get_return_value(ic));

  uint64_t n = __atomic_add_fetch(&g_leave_count, 1, __ATOMIC_RELAXED);
  if (xniff_hooks_debug_is_enabled() && (n <= 16 || (n & 0xFFFu) == 1u)) {
    xniff_hooks_debug_log("leave #%llu hook_id=%d ret=0x%llx", (unsigned long long)n, (int)hook_id, (unsigned long long)ret);
  }

  xniff_hooks_set_current_call_id(inv != NULL ? inv->call_id : 0);
  xniff_ignore_current_thread();
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
      break;
    case XNIFF_HOOK_XPC_CONNECTION_PACK_MESSAGE:
      // arg2 is the newly allocated async reply port; the return value is the
      // serializer later supplied as arg1 to call_reply_async.
      if (g_async_connection_send_depth != 0 && args[2] != 0 && ret != 0 &&
          inv != NULL && inv->call_id != 0) {
        (void)xniff_xpc_reply_tracker_record(ret, inv->call_id);
      }
      break;
    case XNIFF_HOOK_XPC_CONNECTION_CALL_REPLY_ASYNC:
      break;
    case XNIFF_HOOK_XPC_CONNECTION_CHECK_IN:
      xniff_emit_xpc_connection_check_in_exit(ret, args);
      break;
    case XNIFF_HOOK_XPC_DICTIONARY_SEND_REPLY:
    case XNIFF_HOOK_XPC_SESSION_SEND_MESSAGE:
    case XNIFF_HOOK_XPC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC:
      break;
    case XNIFF_HOOK_XPC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC:
      xniff_emit_xpc_session_send_message_with_reply_sync_exit(ret, args);
      break;
  }
  xniff_unignore_current_thread();
  xniff_hooks_set_current_call_id(inv != NULL ? inv->parent_call_id : 0);
  xniff_release_reply_wrapper(inv);
  xniff_leave_async_reply_scope(inv);
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

static gboolean xniff_attach_export_if_present(const char *module_query, const char *name, XniffHookId hook_id) {
  char matched_module[512] = {0};
  gpointer target = NULL;
  if (module_query != NULL && module_query[0] != '\0') {
    target = GSIZE_TO_POINTER(xniff_find_symbol_in_modules(module_query, name,
                                                           matched_module, sizeof(matched_module)));
  } else {
    target = GSIZE_TO_POINTER(gum_module_find_export_by_name(NULL, name));
  }
  if (target == NULL) {
    xniff_hooks_debug_log("attach export: module_query=%s symbol=%s not found",
                          module_query ? module_query : "<any>",
                          name ? name : "<null>");
    return FALSE;
  }
  GumAttachReturn ar = gum_interceptor_attach(g_interceptor, target, g_listener, GSIZE_TO_POINTER(hook_id));
  xniff_hooks_debug_log("attach export: module_query=%s resolved_module=%s symbol=%s => %p (%d)",
                        module_query ? module_query : "<any>",
                        matched_module[0] ? matched_module : "<unknown>",
                        name ? name : "<null>",
                        target, (int)ar);
  return ar == GUM_ATTACH_OK || ar == GUM_ATTACH_ALREADY_ATTACHED;
}

static gboolean xniff_attach_export_hook_locked(XniffExportHookSpec *spec) {
  if (spec == NULL) return FALSE;
  if (spec->attached) return TRUE;
  if (g_interceptor == NULL || g_listener == NULL) return FALSE;
  if (xniff_attach_export_if_present(spec->module_query, spec->name, spec->hook_id)) {
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
  if (!xniff_attach_pack_message_hook_locked()) all_attached = FALSE;
  if (!xniff_attach_call_reply_async_hook_locked()) all_attached = FALSE;
  return all_attached;
}

static guint xniff_count_pending_hooks(void) {
  guint pending = 0;
  for (gsize i = 0; i < G_N_ELEMENTS(g_export_hooks); i++) {
    if (!g_export_hooks[i].attached) pending++;
  }
  if (xniff_hook_event_handler_enabled() && !g_event_handler_hook_attached) pending++;
  if (!g_pack_message_hook_attached) pending++;
  if (!g_call_reply_async_hook_attached) pending++;
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

static gboolean xniff_attach_pack_message_hook_locked(void) {
  if (g_pack_message_hook_attached) return TRUE;
  if (g_interceptor == NULL || g_listener == NULL) return FALSE;
  if (xniff_attach_private_function_if_present("libxpc", "_xpc_connection_pack_message",
                                               XNIFF_HOOK_XPC_CONNECTION_PACK_MESSAGE)) {
    g_pack_message_hook_attached = TRUE;
    xniff_hooks_debug_log("reply-context hook: attached pack-message");
    return TRUE;
  }
  return FALSE;
}

static gboolean xniff_attach_call_reply_async_hook_locked(void) {
  if (g_call_reply_async_hook_attached) return TRUE;
  if (g_interceptor == NULL || g_listener == NULL) return FALSE;
  if (xniff_attach_private_function_if_present("libxpc", "_xpc_connection_call_reply_async",
                                               XNIFF_HOOK_XPC_CONNECTION_CALL_REPLY_ASYNC)) {
    g_call_reply_async_hook_attached = TRUE;
    xniff_hooks_debug_log("reply-context hook: attached call-reply-async");
    return TRUE;
  }
  return FALSE;
}

static void xniff_attach_available_hooks(void) {
  const int max_attempts = 10;
  for (int i = 0; i < max_attempts; i++) {
    pthread_mutex_lock(&g_attach_mutex);
    gum_interceptor_begin_transaction(g_interceptor);
    gboolean ok = xniff_attach_all_core_hooks_locked();
    guint pending = xniff_count_pending_hooks();
    gum_interceptor_end_transaction(g_interceptor);
    pthread_mutex_unlock(&g_attach_mutex);
    if (ok) {
      if (i != 0) {
        xniff_hooks_debug_log("hook install: all hooks attached after %d retries", i);
      }
      return;
    }
    if (xniff_hooks_debug_is_enabled()) {
      xniff_hooks_debug_log("hook install: waiting for hooks (pending=%u, retries=%d)", pending, i + 1);
    }
    usleep(25 * 1000);
  }
  xniff_hooks_debug_log("hook install: continuing with unavailable optional hooks");
}

static void xniff_attach_optional_check_in_hook_once(void) {
  if (g_interceptor == NULL || g_listener == NULL) return;
  pthread_mutex_lock(&g_attach_mutex);
  gum_interceptor_begin_transaction(g_interceptor);
  gboolean ok = xniff_attach_private_function_if_present("libxpc",
                                                         "_xpc_connection_check_in",
                                                         XNIFF_HOOK_XPC_CONNECTION_CHECK_IN);
  gum_interceptor_end_transaction(g_interceptor);
  pthread_mutex_unlock(&g_attach_mutex);
  xniff_hooks_debug_log("check-in hook: %s", ok ? "attached" : "unavailable");
}

static void xniff_install_hooks_once(void) {
  xniff_hooks_debug_log("xniff_install_hooks_once: begin");
  gum_init_embedded();

  g_interceptor = gum_interceptor_obtain();
  g_listener = g_object_new(XNIFF_TYPE_LISTENER, NULL);
  xniff_attach_available_hooks();
  xniff_attach_optional_check_in_hook_once();
  xniff_hooks_debug_log("xniff_install_hooks_once: done");
}

__attribute__((constructor)) static void xniff_frida_gum_ctor(void) {
  xniff_hooks_configure_capture_mode_from_environment();
  xniff_hooks_set_streaming_enabled(false);
  xniff_suspend_all_other_threads();
  (void)pthread_once(&g_once, xniff_install_hooks_once);
  xniff_resume_suspended_threads();
  xniff_hooks_set_streaming_enabled(true);
  xniff_hooks_debug_log("ctor: all hooks attached; resumed halted threads");
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
