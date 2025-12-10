#include "stream.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#define XPC_MAGIC_LE 0x40585043

typedef enum {
    // in vtables base is before but we don't care about it
    XPC_ID_NULL = 0,
    XPC_ID_BOOL = 1,
    XPC_ID_INT64 = 2,
    XPC_ID_UINT64 = 3,
    XPC_ID_DOUBLE = 4,
    XPC_ID_PTR = 5, // exists in libxpc, but impls are unimplemented (return 0xfff... or 0 always), probably removed bc ASLR leaks
    XPC_ID_DATE = 6,
    XPC_ID_DATA = 7,
    XPC_ID_STRING = 8,
    XPC_ID_UUID = 9,
    XPC_ID_FILE = 10, // doesn't include data inline, does stuff with mach message raw
    XPC_ID_SHMEM = 11, // doesn't include data inline, does stuff with mach message raw -> __xpc_shmem_deserialize
    XPC_ID_MACH_SEND = 12, // same here -> __xpc_mach_send_deserialize
    XPC_ID_ARRAY = 13,
    XPC_ID_DICT = 14,

    XPC_ID_UNIMP = 0xDEAD
} xpc_type_t;

typedef uint8_t xpc_bool_t;
typedef int64_t xpc_int64_t;
typedef uint64_t xpc_uint64_t;
typedef double xpc_double_t;
typedef uint64_t xpc_date_t;

typedef struct xpc_data_s {
    uint32_t length;
    uint8_t *data;
} xpc_data_t;

typedef struct xpc_string_s {
    uint32_t length;
    char *str;
} xpc_string_t;

typedef struct xpc_uuid_s {
    uint8_t bytes[16];
} xpc_uuid_t;

typedef int xpc_file_t; // idk if there is data after, in the example i've seen there isn't

// forward decl of array and dict for object
typedef struct xpc_array_s xpc_array_t;
typedef struct xpc_dict_s xpc_dict_t;

typedef struct xpc_object_s {
    xpc_type_t type;
    uint32_t raw_type_header; // raw 32-bit header as read from stream
    union {
        xpc_bool_t bool_value;
        xpc_int64_t int64_value;
        xpc_uint64_t uint64_value;
        xpc_double_t double_value;
        xpc_date_t date_value;
        xpc_data_t data_value;
        xpc_string_t string_value;
        xpc_uuid_t uuid_value;
        xpc_file_t file_value;
        xpc_array_t *array_value;
        xpc_dict_t *dict_value;
    } value;
} xpc_object_t;

typedef struct xpc_array_item_s xpc_array_item_t;

typedef struct xpc_array_item_s {
    xpc_object_t *item;
    xpc_array_item_t *next;
} xpc_array_item_t;

typedef struct xpc_array_s {
    uint32_t num_items;
    xpc_array_item_t *head;
} xpc_array_t;

typedef struct xpc_dict_entry_s xpc_dict_entry_t;

typedef struct xpc_dict_entry_s {
    xpc_string_t key;
    xpc_object_t *value;
    xpc_dict_entry_t *next;
} xpc_dict_entry_t;

typedef struct xpc_dict_s {
    uint32_t num_entries;
    xpc_dict_entry_t *entries;
} xpc_dict_t;

// New forward declarations for recursive parsing and cleanup
static xpc_object_t *deserialize_xpc_object(stream_t *stream);
static xpc_dict_t   *deserialize_xpc_dict(stream_t *stream);
static xpc_array_t  *deserialize_xpc_array(stream_t *stream);
static void          free_xpc_object(xpc_object_t *obj);
static void          print_xpc_object(const xpc_object_t *obj, int indent);

static void align4(stream_t *stream) {
    size_t pos = stream_tell(stream);
    size_t aligned = (pos + 3u) & ~3u;
    if (aligned > pos) {
        (void)stream_seek(stream, aligned);
    }
}

xpc_type_t parse_xpc_type(stream_t *stream) {
    uint32_t type = (stream_read_u32_le(stream) - 0x1000) >> 12; // similar calculation as in vtable lookup in libxpc, just changed from 0x2000 to 0x1000 to allow null type

    switch (type) {
        case 0x00: return XPC_ID_NULL;
        case 0x01: return XPC_ID_BOOL;
        case 0x02: return XPC_ID_INT64;
        case 0x03: return XPC_ID_UINT64;
        case 0x04: return XPC_ID_DOUBLE;
        case 0x05: return XPC_ID_PTR;
        case 0x06: return XPC_ID_DATE;
        case 0x07: return XPC_ID_DATA;
        case 0x08: return XPC_ID_STRING;
        case 0x09: return XPC_ID_UUID;
        case 0x0A: return XPC_ID_FILE;
        case 0x0B: return XPC_ID_SHMEM;
        case 0x0C: return XPC_ID_MACH_SEND;
        case 0x0D: return XPC_ID_ARRAY;
        case 0x0E: return XPC_ID_DICT;
        default:   return XPC_ID_UNIMP;
    }
}

uint32_t xpc_type_wire_length(xpc_type_t type, stream_t *stream) {
    switch (type) {
        case XPC_ID_NULL:
            return 0;
        case XPC_ID_BOOL:
            return 4;

        case XPC_ID_INT64:
        case XPC_ID_UINT64:
        case XPC_ID_DOUBLE:
        case XPC_ID_DATE:
            return 8;

        case XPC_ID_DATA: {
            uint32_t length = stream_read_u32_le(stream);
            return 4 + length; // 4 bytes for length + data
        }
        case XPC_ID_STRING: {
            uint32_t length = stream_read_u32_le(stream);
            return 4 + length; // 4 bytes for length + string
        }
        case XPC_ID_UUID:
            return 16;
        case XPC_ID_FILE:
            return 0; // does weird stuff, looking into it later
        case XPC_ID_ARRAY:
        case XPC_ID_DICT: {
            uint32_t total_bytes = stream_read_u32_le(stream);
            return 4 + total_bytes; // 4 bytes for entry_count + content
        }
        default:
            return 0;
    }
}

stream_t *slice_stream(stream_t *stream, size_t length) {
    uint8_t *buffer = (uint8_t *)malloc(length);
    if (!buffer) {
        return NULL;
    }
    size_t read_bytes = stream_read(stream, buffer, length);
    if (read_bytes != length) {
        free(buffer);
        return NULL;
    }
    stream_t *sliced = stream_create(buffer, length);
    if (!sliced) {
        free(buffer);
        return NULL;
    }
    return sliced;
}


// Read a NUL-terminated C string used for dict keys
static char *read_cstring(stream_t *stream, uint32_t *out_len_nonnull) {
    size_t cap = 32;
    size_t len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;

    for (;;) {
        if (stream_remaining(stream) == 0) {
            free(buf);
            return NULL;
        }
        char c = (char)stream_read_u8(stream);
        if (len + 1 >= cap) {
            size_t new_cap = cap * 2;
            char *tmp = (char *)realloc(buf, new_cap);
            if (!tmp) { free(buf); return NULL; }
            buf = tmp;
            cap = new_cap;
        }
        buf[len++] = c;
        if (c == '\0') break;
    }
    if (len == 0 || buf[len - 1] != '\0') { // ensure
        if (len + 1 >= cap) {
            char *tmp = (char *)realloc(buf, cap + 1);
            if (!tmp) { free(buf); return NULL; }
            buf = tmp;
        }
        buf[len++] = '\0';
    }
    if (out_len_nonnull) {
        *out_len_nonnull = (uint32_t)(len ? (len - 1) : 0);
    }
    return buf;
}

static xpc_array_t *deserialize_xpc_array(stream_t *stream) {
    uint32_t total_bytes = stream_read_u32_le(stream);
    uint32_t num_items   = stream_read_u32_le(stream);

    size_t start = stream_tell(stream);
    size_t end   = start + (size_t)(total_bytes - 4u); // total includes 4 bytes for count

    xpc_array_t *arr = (xpc_array_t *)calloc(1, sizeof(xpc_array_t));
    if (!arr) return NULL;
    arr->num_items = 0;
    arr->head = NULL;

    xpc_array_item_t *tail = NULL;
    for (uint32_t i = 0; i < num_items; i++) {
        if (stream_tell(stream) > end) break;

        // Elements may be 4-byte aligned in practice; align defensively
        align4(stream);

        xpc_object_t *elem = deserialize_xpc_object(stream);
        if (!elem) {
            // cleanup
            xpc_array_item_t *it = arr->head;
            while (it) { xpc_array_item_t *n = it->next; free_xpc_object(it->item); free(it); it = n; }
            free(arr);
            return NULL;
        }

        xpc_array_item_t *node = (xpc_array_item_t *)calloc(1, sizeof(xpc_array_item_t));
        if (!node) {
            free_xpc_object(elem);
            xpc_array_item_t *it = arr->head;
            while (it) { xpc_array_item_t *n = it->next; free_xpc_object(it->item); free(it); it = n; }
            free(arr);
            return NULL;
        }
        node->item = elem;
        node->next = NULL;
        if (!arr->head) arr->head = node; else tail->next = node;
        tail = node;
        arr->num_items++;
    }

    // ensure we're at the end of this array block
    if (stream_tell(stream) < end) (void)stream_seek(stream, end);

    return arr;
}

static xpc_dict_t *deserialize_xpc_dict(stream_t *stream) {
    uint32_t total_bytes = stream_read_u32_le(stream);
    uint32_t num_entries = stream_read_u32_le(stream);

    size_t content_start = stream_tell(stream);
    size_t content_end   = content_start + (size_t)(total_bytes - 4u); // total includes 4 bytes for count

    xpc_dict_t *dict = (xpc_dict_t *)calloc(1, sizeof(xpc_dict_t));
    if (!dict) return NULL;
    dict->num_entries = 0;
    dict->entries = NULL;

    xpc_dict_entry_t *tail = NULL;
    for (uint32_t i = 0; i < num_entries; i++) {
        if (stream_tell(stream) >= content_end) break;

        uint32_t key_len = 0;
        char *key = read_cstring(stream, &key_len);
        if (!key) {
            // cleanup
            xpc_dict_entry_t *e = dict->entries;
            while (e) { xpc_dict_entry_t *n = e->next; free(e->key.str); free_xpc_object(e->value); free(e); e = n; }
            free(dict);
            return NULL;
        }

        align4(stream);

        xpc_object_t *val = deserialize_xpc_object(stream);
        if (!val) {
            free(key);
            xpc_dict_entry_t *e = dict->entries;
            while (e) { xpc_dict_entry_t *n = e->next; free(e->key.str); free_xpc_object(e->value); free(e); e = n; }
            free(dict);
            return NULL;
        }

        xpc_dict_entry_t *entry = (xpc_dict_entry_t *)calloc(1, sizeof(xpc_dict_entry_t));
        if (!entry) {
            free(key);
            free_xpc_object(val);
            xpc_dict_entry_t *e = dict->entries;
            while (e) { xpc_dict_entry_t *n = e->next; free(e->key.str); free_xpc_object(e->value); free(e); e = n; }
            free(dict);
            return NULL;
        }
        entry->key.length = key_len; // length without NUL
        entry->key.str = key;         // NUL-terminated
        entry->value = val;
        entry->next = NULL;

        if (!dict->entries) dict->entries = entry; else tail->next = entry;
        tail = entry;
        dict->num_entries++;

        size_t pos = stream_tell(stream);
        size_t aligned = (pos + 3u) & ~3u;
        if (aligned <= content_end) {
            (void)stream_seek(stream, aligned);
        }
    }

    if (stream_tell(stream) < content_end) (void)stream_seek(stream, content_end);

    return dict;
}

static xpc_object_t *xpc_object_create(xpc_type_t type) {
    xpc_object_t *obj = (xpc_object_t *)calloc(1, sizeof(xpc_object_t));
    if (!obj) return NULL;
    obj->type = type;
    obj->raw_type_header = 0;
    return obj;
}

static xpc_object_t *deserialize_xpc_object(stream_t *stream) {
    // Read and decode the 32-bit type header so we can retain raw bytes
    uint32_t raw = stream_read_u32_le(stream);
    uint32_t code = (raw - 0x1000u) >> 12; // see notes and parse_xpc_type
    xpc_type_t type;
    switch (code) {
        case 0x00: type = XPC_ID_NULL;      break;
        case 0x01: type = XPC_ID_BOOL;      break;
        case 0x02: type = XPC_ID_INT64;     break;
        case 0x03: type = XPC_ID_UINT64;    break;
        case 0x04: type = XPC_ID_DOUBLE;    break;
        case 0x05: type = XPC_ID_PTR;       break;
        case 0x06: type = XPC_ID_DATE;      break;
        case 0x07: type = XPC_ID_DATA;      break;
        case 0x08: type = XPC_ID_STRING;    break;
        case 0x09: type = XPC_ID_UUID;      break;
        case 0x0A: type = XPC_ID_FILE;      break;
        case 0x0B: type = XPC_ID_SHMEM;     break;
        case 0x0C: type = XPC_ID_MACH_SEND; break;
        case 0x0D: type = XPC_ID_ARRAY;     break;
        case 0x0E: type = XPC_ID_DICT;      break;
        default:   type = XPC_ID_UNIMP;     break;
    }

    xpc_object_t *obj = xpc_object_create(type);
    if (!obj) return NULL;
    obj->raw_type_header = raw;

    switch (type) {
        case XPC_ID_NULL:
            break;
        case XPC_ID_BOOL: {
            uint32_t v = stream_read_u32_le(stream);
            obj->value.bool_value = (v != 0) ? 1 : 0;
            break;
        }
        case XPC_ID_INT64: {
            uint64_t uv = stream_read_u64_le(stream);
            obj->value.int64_value = (int64_t)uv;
            break;
        }
        case XPC_ID_UINT64: {
            obj->value.uint64_value = stream_read_u64_le(stream);
            break;
        }
        case XPC_ID_DOUBLE: {
            union { uint64_t u; double d; } conv;
            conv.u = stream_read_u64_le(stream);
            obj->value.double_value = conv.d;
            break;
        }
        case XPC_ID_DATE: {
            obj->value.date_value = stream_read_u64_le(stream);
            break;
        }
        case XPC_ID_DATA: {
            uint32_t len = stream_read_u32_le(stream);
            uint8_t *data = NULL;
            if (len > 0) {
                data = (uint8_t *)malloc(len);
                if (!data) { free(obj); return NULL; }
                size_t got = stream_read(stream, data, len);
                if (got != len) { free(data); free(obj); return NULL; }
            }
            obj->value.data_value.length = len;
            obj->value.data_value.data = data;
            break;
        }
        case XPC_ID_STRING: {
            uint32_t len_incl_nul = stream_read_u32_le(stream);
            char *s = NULL;
            if (len_incl_nul > 0) {
                s = (char *)malloc(len_incl_nul);
                if (!s) { free(obj); return NULL; }
                size_t got = stream_read(stream, s, len_incl_nul);
                if (got != len_incl_nul) { free(s); free(obj); return NULL; }
                s[len_incl_nul - 1] = '\0';
            }
            obj->value.string_value.length = len_incl_nul;
            obj->value.string_value.str = s;
            break;
        }
        case XPC_ID_UUID: {
            uint8_t tmp[16];
            size_t got = stream_read(stream, tmp, sizeof(tmp));
            if (got != sizeof(tmp)) { free(obj); return NULL; }
            memcpy(obj->value.uuid_value.bytes, tmp, sizeof(tmp));
            break;
        }
        case XPC_ID_FILE: {
            obj->value.file_value = 0; // no inline data observed
            break;
        }
        case XPC_ID_ARRAY: {
            xpc_array_t *arr = deserialize_xpc_array(stream);
            if (!arr) { free(obj); return NULL; }
            obj->value.array_value = arr;
            break;
        }
        case XPC_ID_DICT: {
            xpc_dict_t *dict = deserialize_xpc_dict(stream);
            if (!dict) { free(obj); return NULL; }
            obj->value.dict_value = dict;
            break;
        }
        case XPC_ID_PTR:
        case XPC_ID_SHMEM:
        case XPC_ID_MACH_SEND:
        default:
            // Unimplemented/unknown: assume no inline payload
            break;
    }

    return obj;
}

static void free_xpc_array(xpc_array_t *arr) {
    if (!arr) return;
    xpc_array_item_t *it = arr->head;
    while (it) { xpc_array_item_t *n = it->next; free_xpc_object(it->item); free(it); it = n; }
    free(arr);
}

static void free_xpc_dict(xpc_dict_t *dict) {
    if (!dict) return;
    xpc_dict_entry_t *e = dict->entries;
    while (e) {
        xpc_dict_entry_t *n = e->next;
        free(e->key.str);
        free_xpc_object(e->value);
        free(e);
        e = n;
    }
    free(dict);
}

static void free_xpc_object(xpc_object_t *obj) {
    if (!obj) return;
    switch (obj->type) {
        case XPC_ID_DATA:
            free(obj->value.data_value.data);
            break;
        case XPC_ID_STRING:
            free(obj->value.string_value.str);
            break;
        case XPC_ID_ARRAY:
            free_xpc_array(obj->value.array_value);
            break;
        case XPC_ID_DICT:
            free_xpc_dict(obj->value.dict_value);
            break;
        default:
            break;
    }
    free(obj);
}

static xpc_object_t *deserialize_xpc_payload(stream_t *stream) {
    // read first 4 bytes as le. expect XPC_MAGIC_LE
    uint32_t magic = stream_read_u32_le(stream);
    if (magic != XPC_MAGIC_LE) {
        fprintf(stderr, "Error: invalid magic number: 0x%08X\n",
                magic);
        return NULL;
    }

    // next 4 bytes (le) are version, should == 5
    uint32_t version = stream_read_u32_le(stream);
    if (version != 5) {
        fprintf(stderr, "Error: unsupported version: %u\n", version);
        return NULL;
    }

    // Parse the root XPC object
    xpc_object_t *root = deserialize_xpc_object(stream);
    if (!root) {
        fprintf(stderr, "Error: failed to parse XPC root object\n");
        return NULL;
    }
    return root;
}

static void indent_spaces(int indent) {
    for (int i = 0; i < indent; i++) putchar(' ');
}

static void print_uuid(const uint8_t b[16]) {
    // standard 8-4-4-4-12
    printf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
           b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9],
           b[10], b[11], b[12], b[13], b[14], b[15]);
}

static void print_escaped_cstr(const char *s) {
    putchar('"');
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
            if (*p == '\n') {
                putchar('\\');
                putchar('n');
            } else {
                putchar(*p);
            }
        }
    }
    putchar('"');
}

static void print_xpc_array(const xpc_array_t *arr, int indent) {
    indent_spaces(indent);
    printf("[\n");
    const xpc_array_item_t *it = arr ? arr->head : NULL;
    while (it) {
        print_xpc_object(it->item, indent + 2);
        if (it->next) printf(",");
        printf("\n");
        it = it->next;
    }
    indent_spaces(indent);
    printf("]");
}

static void print_xpc_dict(const xpc_dict_t *dict, int indent) {
    indent_spaces(indent);
    printf("{\n");
    const xpc_dict_entry_t *e = dict ? dict->entries : NULL;
    while (e) {
        indent_spaces(indent + 2);
        print_escaped_cstr(e->key.str ? e->key.str : "");
        printf(": ");
        print_xpc_object(e->value, indent + 2);
        if (e->next) printf(",");
        printf("\n");
        e = e->next;
    }
    indent_spaces(indent);
    printf("}");
}

static void print_xpc_object(const xpc_object_t *obj, int indent) {
    if (!obj) { indent_spaces(indent); printf("null"); return; }
    switch (obj->type) {
        case XPC_ID_NULL:
            indent_spaces(indent); printf("null");
            break;
        case XPC_ID_BOOL:
            indent_spaces(indent); printf("%s", obj->value.bool_value ? "true" : "false");
            break;
        case XPC_ID_INT64:
            indent_spaces(indent); printf("%" PRId64, obj->value.int64_value);
            break;
        case XPC_ID_UINT64:
            indent_spaces(indent); printf("%" PRIu64, obj->value.uint64_value);
            break;
        case XPC_ID_DOUBLE:
            indent_spaces(indent); printf("%g", obj->value.double_value);
            break;
        case XPC_ID_DATE:
            indent_spaces(indent); printf("date(%" PRIu64 ")", obj->value.date_value);
            break;
        case XPC_ID_DATA: {
            indent_spaces(indent);
            printf("data[%u]", (unsigned)obj->value.data_value.length);
            break;
        }
        case XPC_ID_STRING: {
            indent_spaces(indent);
            const char *s = obj->value.string_value.str ? obj->value.string_value.str : "";
            print_escaped_cstr(s);
            break;
        }
        case XPC_ID_UUID: {
            indent_spaces(indent);
            printf("uuid(");
            print_uuid(obj->value.uuid_value.bytes);
            printf(")");
            break;
        }
        case XPC_ID_FILE:
            indent_spaces(indent); printf("file");
            break;
        case XPC_ID_ARRAY:
            print_xpc_array(obj->value.array_value, indent);
            break;
        case XPC_ID_DICT:
            print_xpc_dict(obj->value.dict_value, indent);
            break;
        case XPC_ID_UNIMP: {
            indent_spaces(indent);
            uint32_t raw = obj->raw_type_header;
            printf("<unknown type hdr=0x%08x bytes=%02x %02x %02x %02x>",
                   raw,
                   (unsigned)(raw & 0xFFu),
                   (unsigned)((raw >> 8) & 0xFFu),
                   (unsigned)((raw >> 16) & 0xFFu),
                   (unsigned)((raw >> 24) & 0xFFu));
            break;
        }
        default:
            indent_spaces(indent); printf("<unimplemented type 0x%x>", (unsigned)obj->type);
            break;
    }
}

/* removed unused stub parse_xpc_dict; use deserialize_xpc_dict instead */

xpc_object_t *parse_xpc_payload(stream_t *stream) {
    return deserialize_xpc_payload(stream);
}


int main(int argc, char *argv[]) {
    // take in file path as argument, open it, and pass it to parse_xpc_payload
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "Error: failed to open '%s'\n", path);
        perror("fopen");
        return 1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(fp);
        return 1;
    }

    long file_size_long = ftell(fp);
    if (file_size_long < 0) {
        perror("ftell");
        fclose(fp);
        return 1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror("fseek");
        fclose(fp);
        return 1;
    }

    size_t file_size = (size_t)file_size_long;
    uint8_t *buffer = NULL;
    if (file_size > 0) {
        buffer = (uint8_t *)malloc(file_size);
        if (!buffer) {
            fprintf(stderr, "Error: failed to allocate %zu bytes\n", file_size);
            fclose(fp);
            return 1;
        }

        size_t read_bytes = fread(buffer, 1, file_size, fp);
        if (read_bytes != file_size) {
            fprintf(stderr, "Error: short read (%zu/%zu)\n", read_bytes, file_size);
            free(buffer);
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);

    stream_t *stream = stream_create(buffer, file_size);
    if (!stream) {
        fprintf(stderr, "Error: failed to create stream\n");
        free(buffer);
        return 1;
    }

    xpc_object_t *root = parse_xpc_payload(stream);

    stream_destroy(stream);
    free(buffer);

    if (!root) {
        return 1;
    }

    // Pretty-print the parsed object
    print_xpc_object(root, 0);
    putchar('\n');

    free_xpc_object(root);
    return 0;
}
