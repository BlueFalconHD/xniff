#ifndef XPCDESERT_H
#define XPCDESERT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Public types reflecting parsed XPC objects.
// These mirror the reverse‑engineered wire format and are intentionally simple.

typedef enum {
    XPC_ID_NULL = 0,
    XPC_ID_BOOL = 1,
    XPC_ID_INT64 = 2,
    XPC_ID_UINT64 = 3,
    XPC_ID_DOUBLE = 4,
    XPC_ID_PTR = 5,
    XPC_ID_DATE = 6,
    XPC_ID_DATA = 7,
    XPC_ID_STRING = 8,
    XPC_ID_UUID = 9,
    XPC_ID_FILE = 10,
    XPC_ID_SHMEM = 11,
    XPC_ID_MACH_SEND = 12,
    XPC_ID_ARRAY = 13,
    XPC_ID_DICT = 14,

    XPC_ID_UNIMP = 0xDEAD
} xpcd_type_t;

typedef uint8_t  xpcd_bool_t;
typedef int64_t  xpcd_int64_t;
typedef uint64_t xpcd_uint64_t;
typedef double   xpcd_double_t;
typedef uint64_t xpcd_date_t;

typedef struct { uint32_t length; uint8_t *data; } xpcd_data_t;
typedef struct { uint32_t length; char *str;    } xpcd_string_t;
typedef struct { uint8_t  bytes[16];          } xpcd_uuid_t;

// Forward decls for containers
typedef struct xpcd_object_s xpcd_object_t;
typedef struct xpcd_array_s  xpcd_array_t;
typedef struct xpcd_dict_s   xpcd_dict_t;

typedef struct xpcd_array_item_s xpcd_array_item_t;
struct xpcd_array_item_s {
    xpcd_object_t    *item;
    xpcd_array_item_t *next;
};

struct xpcd_array_s {
    uint32_t         num_items;
    xpcd_array_item_t *head;
};

typedef struct xpcd_dict_entry_s xpcd_dict_entry_t;
struct xpcd_dict_entry_s {
    xpcd_string_t     key;   // NUL-terminated string with recorded length (excludes NUL)
    xpcd_object_t    *value;
    xpcd_dict_entry_t *next;
};

struct xpcd_dict_s {
    uint32_t           num_entries;
    xpcd_dict_entry_t *entries;
};

struct xpcd_object_s {
    xpcd_type_t type;
    uint32_t    raw_type_header; // raw 32-bit header as found on the wire
    union {
        xpcd_bool_t   bool_value;
        xpcd_int64_t  int64_value;
        xpcd_uint64_t uint64_value;
        xpcd_double_t double_value;
        xpcd_date_t   date_value;
        xpcd_data_t   data_value;
        xpcd_string_t string_value;
        xpcd_uuid_t   uuid_value;
        int           file_value; // placeholder
        xpcd_array_t *array_value;
        xpcd_dict_t  *dict_value;
    } value;
};

// Scan for an XPC payload magic ('CPX@' little‑endian) within a buffer.
// If found and version appears valid (5), returns 0 and sets *offset_out to the location.
// max_scan limits search window from start of buf; pass 0 to search entire buffer.
int xpcd_find_payload(const uint8_t *buf, size_t len, size_t max_scan, size_t *offset_out);

// Parse an XPC payload starting exactly at the magic. Returns heap object tree or NULL on error.
xpcd_object_t *xpcd_parse(const uint8_t *buf, size_t len);

// Free a parsed object tree.
void xpcd_free(xpcd_object_t *obj);

// Format a parsed tree into a newly-allocated string (pretty‑printed JSON‑like).
// Caller must free() the returned string.
char *xpcd_format(const xpcd_object_t *obj);

#ifdef __cplusplus
}
#endif

#endif // XPCDESERT_H

