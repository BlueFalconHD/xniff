#ifndef XNIFF_IPC_V2_H
#define XNIFF_IPC_V2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XNIFF_IPC_V2_VERSION 1u
#define XNIFF_BIN_FILE_MAGIC 0x584e4246u
#define XNIFF_BIN_FILE_VERSION 2u

typedef struct {
    uint32_t magic;      // 'XNBF'
    uint16_t version;
    uint16_t reserved;
} xniff_bin_file_hdr_t;

enum {
    XNIFF_V2_ENTRY_MACH = 1,
    XNIFF_V2_ENTRY_XPC = 2,
    XNIFF_V2_ENTRY_DIAG = 3,
};

enum {
    XNIFF_V2_SEC_MACH_HEADER_OPTIONS = 1,
    XNIFF_V2_SEC_MACH_INLINE_BYTES = 2,
    XNIFF_V2_SEC_MACH_TRAILER_BYTES = 3,
    XNIFF_V2_SEC_MACH_DESC_META = 4,
    XNIFF_V2_SEC_MACH_DESC_OOL_BYTES = 5,
    XNIFF_V2_SEC_MACH_DESC_PORT_ARRAY = 6,
    XNIFF_V2_SEC_XPC_SERIALIZED = 7,
    XNIFF_V2_SEC_XPC_CONN_META = 8,
    XNIFF_V2_SEC_HOOK_DIAG = 9,
    XNIFF_V2_SEC_XPC_CALL_META = 10,
    XNIFF_V2_SEC_BACKTRACE = 11,
    XNIFF_V2_SEC_BACKTRACE_SYMBOLS = 12,
    XNIFF_V2_SEC_CALL_ID = 13,
    XNIFF_V2_SEC_XPC_OBJECT_REF = 14,
};

#define XNIFF_V2_BACKTRACE_MAX_FRAMES 32u

typedef struct {
    uint32_t entry_len;  // full bytes including this header
    uint16_t entry_type; // XNIFF_V2_ENTRY_*
    uint16_t version;    // XNIFF_IPC_V2_VERSION
    uint64_t seq;        // per-process monotonic sequence number
} xniff_ipc_v2_entry_hdr_t;

typedef struct {
    uint32_t pid;
    uint32_t tid_low;
    uint64_t timestamp_ns;
    uint16_t direction;  // XNIFF_DIR_*
    uint16_t api;        // XNIFF_API_*
    uint32_t function;   // API function discriminator
} xniff_ipc_v2_fixed_hdr_t;

typedef struct {
    uint16_t sec_type;   // XNIFF_V2_SEC_*
    uint16_t flags;
    uint32_t sec_len;    // payload bytes after this section header
} xniff_ipc_v2_section_hdr_t;

typedef struct {
    uint32_t index;
    uint16_t desc_type;
    uint16_t desc_flags;
    uint64_t address;
    uint32_t size_bytes;
    uint32_t count;
    uint32_t elem_size;
    uint32_t port_name;
    uint32_t port_disposition;
    uint32_t reserved;
} xniff_ipc_v2_desc_meta_t;

typedef struct {
    uint32_t msg_len;
    uint32_t level;
} xniff_ipc_v2_diag_t;

typedef struct {
    uint32_t count;
    uint32_t reserved;
    uint64_t pcs[XNIFF_V2_BACKTRACE_MAX_FRAMES];
} xniff_ipc_v2_backtrace_t;

typedef struct {
    uint32_t count;
    uint32_t strings_len;
} xniff_ipc_v2_backtrace_symbols_hdr_t;

typedef struct {
    uint64_t pc;
    uint64_t sym_addr;
    uint32_t name_len;
    uint32_t image_len;
} xniff_ipc_v2_backtrace_symbol_t;

typedef struct {
    uint8_t *buf;
    size_t len;
    size_t cap;
} xniff_ipc_v2_builder_t;

void xniff_ipc_v2_builder_init(xniff_ipc_v2_builder_t *b);
void xniff_ipc_v2_builder_free(xniff_ipc_v2_builder_t *b);

int xniff_ipc_v2_begin(xniff_ipc_v2_builder_t *b,
                       uint16_t entry_type,
                       uint32_t pid,
                       uint32_t tid_low,
                       uint64_t timestamp_ns,
                       uint16_t direction,
                       uint16_t api,
                       uint32_t function);
int xniff_ipc_v2_add_section(xniff_ipc_v2_builder_t *b,
                             uint16_t sec_type,
                             uint16_t flags,
                             const void *payload,
                             size_t payload_len);
int xniff_ipc_v2_write(xniff_ipc_v2_builder_t *b);

#ifdef __cplusplus
}
#endif

#endif // XNIFF_IPC_V2_H
