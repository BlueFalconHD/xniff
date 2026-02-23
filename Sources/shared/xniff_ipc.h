// Shared wire/event structs and in-target ring IPC primitives.
#ifndef XNIFF_IPC_H
#define XNIFF_IPC_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XNIFF_IPC_VERSION 1u
#define XNIFF_IPC_MAGIC 0x58495043u /* 'XIPC' */
#define XNIFF_IPC_RING_MAGIC 0x58495247u /* 'XIRG' */
#define XNIFF_IPC_RING_VERSION 1u
#define XNIFF_IPC_RING_CAPACITY (1u << 20) /* 1 MiB stream buffer */

// Event kinds for Mach message hooks
enum {
    XNIFF_EVT_MACH_ENTRY  = 1,
    XNIFF_EVT_MACH_EXIT   = 2,
    XNIFF_EVT_MACH2_ENTRY = 3,
    XNIFF_EVT_MACH2_EXIT  = 4,
    // High-level libxpc hooks
    XNIFF_EVT_XPC_ENTRY   = 5,
    XNIFF_EVT_XPC_EXIT    = 6,
    // Hook-side diagnostic log line
    XNIFF_EVT_DEBUG_LOG   = 7,
};

typedef struct {
    uint32_t magic;        // 'XIPC' 0x58495043
    uint16_t version;      // 1
    uint16_t kind;         // XNIFF_EVT_*
    uint32_t pid;          // sender PID
    uint32_t tid_low;      // low bits of thread id (optional)
    uint32_t payload_len;  // length of following payload
} xniff_ipc_hdr_t;

typedef struct {
    uint32_t magic;        // XNIFF_IPC_RING_MAGIC
    uint16_t version;      // XNIFF_IPC_RING_VERSION
    uint16_t reserved0;
    uint32_t capacity;     // bytes in data[]
    uint32_t reserved1;
    uint64_t write_idx;    // monotonic producer byte counter
    uint64_t read_idx;     // monotonic consumer byte counter
    uint64_t dropped_bytes;
    uint64_t dropped_events;
} xniff_ipc_ring_hdr_t;

typedef struct {
    xniff_ipc_ring_hdr_t hdr;
    uint8_t data[XNIFF_IPC_RING_CAPACITY];
} xniff_ipc_ring_t;

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(offsetof(xniff_ipc_ring_t, data) == sizeof(xniff_ipc_ring_hdr_t),
               "ring header must be contiguous with data");
#endif

// Exported from the injected hooks image; the CLI resolves this symbol in-target
// and polls it via mach_vm_read_overwrite / mach_vm_write.
extern xniff_ipc_ring_t xniff_ipc_ring;

// Guard against accidental struct packing/ABI mismatches between components.
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(xniff_ipc_hdr_t) == 20, "xniff_ipc_hdr_t must be 20 bytes");
_Static_assert(offsetof(xniff_ipc_hdr_t, magic) == 0, "xniff_ipc_hdr_t.magic offset");
_Static_assert(offsetof(xniff_ipc_hdr_t, version) == 4, "xniff_ipc_hdr_t.version offset");
_Static_assert(offsetof(xniff_ipc_hdr_t, kind) == 6, "xniff_ipc_hdr_t.kind offset");
_Static_assert(offsetof(xniff_ipc_hdr_t, pid) == 8, "xniff_ipc_hdr_t.pid offset");
_Static_assert(offsetof(xniff_ipc_hdr_t, tid_low) == 12, "xniff_ipc_hdr_t.tid_low offset");
_Static_assert(offsetof(xniff_ipc_hdr_t, payload_len) == 16, "xniff_ipc_hdr_t.payload_len offset");
#endif

// Payload used for XNIFF_EVT_MACH_ENTRY/EXIT
// API identifier for payload interpretation
enum {
    XNIFF_API_MACH_MSG  = 1,
    XNIFF_API_MACH_MSG2 = 2,
    XNIFF_API_XPC_HL    = 3,
    XNIFF_API_DEBUG     = 4,
};

// Direction: entry or exit
enum {
    XNIFF_DIR_ENTRY = 0,
    XNIFF_DIR_EXIT  = 1,
};

// Payload describing a mach message event (v1 or v2). Followed by:
//  - msg bytes: copy_len bytes of the mach_msg_header_t and inline body
//  - zero or more TLVs containing OOL buffers/ports (for COMPLEX messages)
typedef struct {
    uint32_t api;          // XNIFF_API_*
    uint32_t direction;    // XNIFF_DIR_*
    uint32_t option_lo;    // mach_msg_option_t (v1) or lower 32 bits of option64 (v2)
    uint32_t option_hi;    // 0 for v1; high 32 bits for v2 option64
    uint32_t msgh_size;    // original message size
    uint32_t copy_len;     // bytes of message that follow
    uint64_t msg_addr;     // pointer to message in sender address space
    uint64_t aux_addr;     // msg2 aux pointer (or 0)
    uint64_t ret_value;    // function return value on exit; 0 on entry
    uint32_t desc_count;   // descriptor count if known; else 0
    uint32_t priority;     // msg2 priority (0 for v1)
    uint64_t timeout;      // timeout value if provided (0 otherwise)
    uint64_t args[8];      // raw X0..X7 if available; else 0
} xniff_ipc_mach_payload_t;

// High-level XPC hook payload. Followed by up to 4 byte strings (not NUL-terminated)
// in this order: str0, str1, str2, str3 (lengths below). Interpretation depends on func.
typedef struct {
    uint32_t api;          // XNIFF_API_XPC_HL
    uint32_t direction;    // XNIFF_DIR_*
    uint32_t func;         // XNIFF_XPC_FUNC_*
    uint32_t conn_pid;     // xpc_connection_get_pid(connection) when available
    uint64_t ret_value;    // return value on exit; 0 on entry
    uint64_t args[8];      // raw X0..X7 snapshot
    uint32_t str0_len;     // bytes of str0
    uint32_t str1_len;     // bytes of str1
    uint32_t str2_len;     // bytes of str2
    uint32_t str3_len;     // bytes of str3
} xniff_ipc_xpc_payload_t;

enum {
    XNIFF_XPC_FUNC_CONNECTION_CREATE                = 1,
    XNIFF_XPC_FUNC_PIPE_ROUTINE                     = 2,
    XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE          = 3,
    XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY = 4,
    XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC = 5,
    XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER    = 6,
};

// TLV framing for attachments following the message bytes
typedef struct {
    uint16_t type;         // see XNIFF_TLV_*
    uint16_t reserved;
    uint32_t length;       // length of the TLV value that follows (not including this header)
} xniff_ipc_tlv_t;

enum {
    XNIFF_TLV_OOL_DATA  = 1, // value: xniff_ool_data_t + bytes
    XNIFF_TLV_OOL_PORTS = 2, // value: xniff_ool_ports_t + bytes
};

typedef struct {
    uint32_t index;        // descriptor index in message
    uint32_t flags;        // packed: bit0=deallocate, bit1=copy
    uint64_t address;      // source address in sender space
    uint32_t size;         // byte length of following data
    uint32_t reserved;     // align
} xniff_ool_data_t;

typedef struct {
    uint32_t index;        // descriptor index in message
    uint32_t count;        // number of mach_port_t elements
    uint64_t address;      // source address in sender space
    uint32_t elem_size;    // sizeof(mach_port_t)
    uint32_t reserved;     // align
} xniff_ool_ports_t;

// Payload for XNIFF_EVT_DEBUG_LOG, followed by msg_len bytes (not NUL-terminated).
typedef struct {
    uint32_t api;          // XNIFF_API_DEBUG
    uint32_t level;        // reserved for future use (0=debug/info)
    uint32_t msg_len;      // bytes of message following this struct
} xniff_ipc_debug_payload_t;

// Append bytes to the process-local ring buffer (producer-side).
// Returns 0 on success, -1 on failure (e.g. ENOBUFS when ring is full).
int xniff_ipc_ring_write(const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif // XNIFF_IPC_H
