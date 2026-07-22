#ifndef XNIFF_PAYLOAD_H
#define XNIFF_PAYLOAD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Payload for XNIFF_SECTION_MACH_HEADER_OPTIONS.
typedef struct {
    uint32_t api;
    uint32_t direction;
    uint32_t option_lo;
    uint32_t option_hi;
    uint32_t msgh_size;
    uint32_t copy_len;
    uint64_t msg_addr;
    uint64_t aux_addr;
    uint64_t ret_value;
    uint32_t desc_count;
    uint32_t priority;
    uint64_t timeout;
    uint64_t args[8];
} xniff_mach_payload_t;

// Payload for XNIFF_SECTION_XPC_CALL_META, followed by four byte strings.
typedef struct {
    uint32_t api;
    uint32_t direction;
    uint32_t func;
    uint32_t conn_pid;
    uint64_t ret_value;
    uint64_t args[8];
    uint32_t str0_len;
    uint32_t str1_len;
    uint32_t str2_len;
    uint32_t str3_len;
} xniff_xpc_payload_t;

enum {
    XNIFF_XPC_FUNC_CONNECTION_CREATE = 1,
    XNIFF_XPC_FUNC_PIPE_ROUTINE = 2,
    XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE = 3,
    XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY = 4,
    XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC = 5,
    XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER = 6,
    XNIFF_XPC_FUNC_CONNECTION_CHECK_IN = 7,
    XNIFF_XPC_FUNC_DICTIONARY_SEND_REPLY = 8,
    XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE = 9,
    XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC = 10,
    XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC = 11,
    XNIFF_XPC_FUNC_CONNECTION_CREATE_MACH_SERVICE = 12,
    XNIFF_XPC_FUNC_CONNECTION_CREATE_FROM_ENDPOINT = 13,
    XNIFF_XPC_FUNC_ARRAY_CREATE_CONNECTION = 14,
    XNIFF_XPC_FUNC_DICTIONARY_CREATE_CONNECTION = 15,
    XNIFF_XPC_FUNC_SESSION_CREATE_XPC_SERVICE = 16,
    XNIFF_XPC_FUNC_SESSION_CREATE_MACH_SERVICE = 17,
    XNIFF_XPC_FUNC_CONNECTION_ACTIVATE = 18,
    XNIFF_XPC_FUNC_CONNECTION_RESUME = 19,
    XNIFF_XPC_FUNC_CONNECTION_CANCEL = 20,
    XNIFF_XPC_FUNC_SESSION_ACTIVATE = 21,
    XNIFF_XPC_FUNC_SESSION_CANCEL = 22,
};

enum {
    XNIFF_XPC_OBJECT_REF_VERSION = 1,
    XNIFF_XPC_OBJECT_CONNECTION = 1,
    XNIFF_XPC_OBJECT_SESSION = 2,
    XNIFF_XPC_OBJECT_OBSERVED = 0,
    XNIFF_XPC_OBJECT_CREATED = 1,
    XNIFF_XPC_OBJECT_CANCELLED = 2,
};

typedef struct {
    uint32_t version;
    uint16_t kind;
    uint16_t lifecycle;
    uint64_t object;
} xniff_xpc_object_ref_t;

_Static_assert(sizeof(xniff_xpc_object_ref_t) == 16,
               "xniff_xpc_object_ref_t must be 16 bytes");

typedef struct {
    uint8_t slot;
    uint8_t format;
    uint16_t flags;
    uint32_t original_len;
    uint32_t stored_len;
} xniff_xpc_serialized_t;

enum {
    XNIFF_XPC_SERIAL_SLOT_MESSAGE = 1,
    XNIFF_XPC_SERIAL_SLOT_REPLY = 2,
    XNIFF_XPC_SERIAL_SLOT_EVENT = 3,
    XNIFF_XPC_SERIAL_FORMAT_LIBXPC_V5 = 1,
};

enum {
    XNIFF_XPC_CONN_META_VERSION = 1,
};

enum {
    XNIFF_XPC_CONN_META_HAS_NAME_PUBLIC = (1u << 0),
    XNIFF_XPC_CONN_META_HAS_NAME_PRIVATE = (1u << 1),
    XNIFF_XPC_CONN_META_HAS_PID_PUBLIC = (1u << 2),
    XNIFF_XPC_CONN_META_HAS_PID_PRIVATE = (1u << 3),
    XNIFF_XPC_CONN_META_HAS_INSTANCE = (1u << 4),
    XNIFF_XPC_CONN_META_HAS_PEER_INSTANCE = (1u << 5),
    XNIFF_XPC_CONN_META_HAS_FILTER_POLICY_ID = (1u << 6),
    XNIFF_XPC_CONN_META_HAS_EUID_PUBLIC = (1u << 7),
    XNIFF_XPC_CONN_META_HAS_EUID_PRIVATE = (1u << 8),
    XNIFF_XPC_CONN_META_HAS_EGID_PUBLIC = (1u << 9),
    XNIFF_XPC_CONN_META_HAS_EGID_PRIVATE = (1u << 10),
    XNIFF_XPC_CONN_META_HAS_CONTEXT_PUBLIC = (1u << 11),
    XNIFF_XPC_CONN_META_HAS_CONTEXT_PRIVATE = (1u << 12),
    XNIFF_XPC_CONN_META_HAS_BS_TYPE = (1u << 13),
    XNIFF_XPC_CONN_META_HAS_AUDIT_TOKEN = (1u << 14),
    XNIFF_XPC_CONN_META_HAS_ASID_PUBLIC = (1u << 15),
    XNIFF_XPC_CONN_META_HAS_ASID_PRIVATE = (1u << 16),
};

typedef struct {
    uint32_t version;
    uint32_t flags;
    uint32_t pid_public;
    uint32_t pid_private;
    uint32_t euid_public;
    uint32_t euid_private;
    uint32_t egid_public;
    uint32_t egid_private;
    uint32_t asid_public;
    uint32_t asid_private;
    uint64_t instance;
    uint64_t peer_instance;
    uint64_t filter_policy_id;
    uint64_t bs_type;
    uint64_t context_public;
    uint64_t context_private;
    uint32_t audit_token[8];
    uint32_t name_public_len;
    uint32_t name_private_len;
} xniff_xpc_conn_meta_t;

_Static_assert(sizeof(xniff_mach_payload_t) == 128,
               "Mach payload wire size changed");
_Static_assert(sizeof(xniff_xpc_payload_t) == 104,
               "XPC payload wire size changed");
_Static_assert(sizeof(xniff_xpc_serialized_t) == 12,
               "XPC serialized metadata wire size changed");
_Static_assert(sizeof(xniff_xpc_conn_meta_t) == 128,
               "XPC connection metadata wire size changed");

#ifdef __cplusplus
}
#endif

#endif
