#ifndef XNIFF_RECORD_H
#define XNIFF_RECORD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XNIFF_RECORD_VERSION 1u
#define XNIFF_CAPTURE_FILE_MAGIC 0x584e4246u
#define XNIFF_CAPTURE_FILE_VERSION 2u

typedef struct {
    uint32_t magic;      // 'XNBF'
    uint16_t version;
    uint16_t reserved;
} xniff_capture_file_header_t;

enum {
    XNIFF_RECORD_TYPE_MACH = 1,
    XNIFF_RECORD_TYPE_XPC = 2,
    XNIFF_RECORD_TYPE_DIAG = 3,
};

enum {
    XNIFF_API_MACH_MSG = 1,
    XNIFF_API_MACH_MSG2 = 2,
    XNIFF_API_XPC = 3,
    XNIFF_API_DEBUG = 4,
};

enum {
    XNIFF_DIRECTION_ENTRY = 0,
    XNIFF_DIRECTION_EXIT = 1,
};

enum {
    XNIFF_SECTION_MACH_HEADER_OPTIONS = 1,
    XNIFF_SECTION_MACH_INLINE_BYTES = 2,
    XNIFF_SECTION_MACH_TRAILER_BYTES = 3,
    XNIFF_SECTION_MACH_DESC_META = 4,
    XNIFF_SECTION_MACH_DESC_OOL_BYTES = 5,
    XNIFF_SECTION_MACH_DESC_PORT_ARRAY = 6,
    XNIFF_SECTION_XPC_SERIALIZED = 7,
    XNIFF_SECTION_XPC_CONN_META = 8,
    XNIFF_SECTION_HOOK_DIAG = 9,
    XNIFF_SECTION_XPC_CALL_META = 10,
    XNIFF_SECTION_BACKTRACE = 11,
    XNIFF_SECTION_BACKTRACE_SYMBOLS = 12,
    XNIFF_SECTION_CALL_ID = 13,
    XNIFF_SECTION_XPC_OBJECT_REF = 14,
};

#define XNIFF_BACKTRACE_MAX_FRAMES 32u

typedef struct {
    uint32_t length;
    uint16_t type;
    uint16_t version;
    uint64_t sequence;
} xniff_record_header_t;

typedef struct {
    uint32_t pid;
    uint32_t tid_low;
    uint64_t timestamp_ns;
    uint16_t direction;
    uint16_t api;
    uint32_t function;
} xniff_record_fixed_header_t;

typedef struct {
    uint16_t type;
    uint16_t flags;
    uint32_t length;
} xniff_record_section_header_t;

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
} xniff_mach_descriptor_section_t;

typedef struct {
    uint32_t msg_len;
    uint32_t level;
} xniff_diagnostic_section_t;

typedef struct {
    uint32_t count;
    uint32_t reserved;
    uint64_t pcs[XNIFF_BACKTRACE_MAX_FRAMES];
} xniff_backtrace_section_t;

typedef struct {
    uint32_t count;
    uint32_t strings_len;
} xniff_backtrace_symbols_header_t;

typedef struct {
    uint64_t pc;
    uint64_t sym_addr;
    uint32_t name_len;
    uint32_t image_len;
} xniff_backtrace_symbol_t;

_Static_assert(sizeof(xniff_capture_file_header_t) == 8,
               "capture file header wire size changed");
_Static_assert(sizeof(xniff_record_header_t) == 16,
               "record header wire size changed");
_Static_assert(sizeof(xniff_record_fixed_header_t) == 24,
               "fixed record header wire size changed");
_Static_assert(sizeof(xniff_record_section_header_t) == 8,
               "section header wire size changed");
_Static_assert(sizeof(xniff_mach_descriptor_section_t) == 40,
               "Mach descriptor section wire size changed");
_Static_assert(sizeof(xniff_diagnostic_section_t) == 8,
               "diagnostic section wire size changed");
_Static_assert(sizeof(xniff_backtrace_symbol_t) == 24,
               "backtrace symbol wire size changed");

typedef struct {
    uint8_t *buf;
    size_t len;
    size_t cap;
} xniff_record_builder_t;

typedef struct {
    const uint8_t *cursor;
    size_t remaining;
} xniff_record_section_iterator_t;

typedef struct {
    uint16_t type;
    uint16_t flags;
    const uint8_t *data;
    size_t length;
} xniff_record_section_t;

void xniff_record_builder_init(xniff_record_builder_t *b);
void xniff_record_builder_free(xniff_record_builder_t *b);
bool xniff_record_type_matches_api(uint16_t type, uint16_t api);

int xniff_record_begin(xniff_record_builder_t *b,
                       uint16_t type,
                       uint32_t pid,
                       uint32_t tid_low,
                       uint64_t timestamp_ns,
                       uint16_t direction,
                       uint16_t api,
                       uint32_t function);
int xniff_record_add_section(xniff_record_builder_t *b,
                             uint16_t type,
                             uint16_t flags,
                             const void *payload,
                             size_t payload_len);
int xniff_record_finish(xniff_record_builder_t *b,
                        const uint8_t **data,
                        size_t *length);

void xniff_record_section_iterator_init(
    xniff_record_section_iterator_t *iterator,
    const void *sections,
    size_t length);
int xniff_record_section_next(xniff_record_section_iterator_t *iterator,
                              xniff_record_section_t *section);

#ifdef __cplusplus
}
#endif

#endif
