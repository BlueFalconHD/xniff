#include "xpcdesert.h"
#include "stream.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define XPC_MAGIC_LE 0x40585043u /* 'CPX@' */

// Forward decls of internal helpers borrowed from existing implementation
static xpcd_object_t *deserialize_xpc_object(stream_t *stream);
static void           free_xpc_object(xpcd_object_t *obj);
static char          *format_object(const xpcd_object_t *obj, int indent);

int xpcd_find_payload(const uint8_t *buf, size_t len, size_t max_scan, size_t *offset_out) {
    if (!buf || len < 8) return -1;
    size_t limit = (max_scan && max_scan < len) ? max_scan : len;
    for (size_t i = 0; i + 8 <= limit; i++) {
        uint32_t magic;
        memcpy(&magic, buf + i, sizeof(magic));
        if (magic == XPC_MAGIC_LE) {
            uint32_t ver = 0;
            memcpy(&ver, buf + i + 4, sizeof(ver));
            if (ver == 5) {
                if (offset_out) *offset_out = i;
                return 0;
            }
        }
    }
    return -1;
}

xpcd_object_t *xpcd_parse(const uint8_t *buf, size_t len) {
    if (!buf || len < 8) return NULL;
    stream_t *s = stream_create((uint8_t *)buf, len);
    if (!s) return NULL;

    uint32_t magic = stream_read_u32_le(s);
    if (magic != XPC_MAGIC_LE) { stream_destroy(s); return NULL; }
    uint32_t version = stream_read_u32_le(s);
    if (version != 5)           { stream_destroy(s); return NULL; }

    xpcd_object_t *root = deserialize_xpc_object(s);
    stream_destroy(s);
    return root;
}

void xpcd_free(xpcd_object_t *obj) {
    free_xpc_object(obj);
}

char *xpcd_format(const xpcd_object_t *obj) {
    return format_object(obj, 0);
}

// ============ Minimal parser lifted from main.c with renamed types ============

static void align4(stream_t *stream) {
    size_t pos = stream_tell(stream);
    size_t aligned = (pos + 3u) & ~3u;
    if (aligned > pos) (void)stream_seek(stream, aligned);
}

static xpcd_object_t *xpc_object_create(xpcd_type_t type) {
    xpcd_object_t *obj = (xpcd_object_t *)calloc(1, sizeof(xpcd_object_t));
    if (!obj) return NULL;
    obj->type = type;
    obj->raw_type_header = 0;
    return obj;
}

static xpcd_array_t *deserialize_xpc_array(stream_t *stream) {
    uint32_t total_bytes = stream_read_u32_le(stream);
    uint32_t num_items   = stream_read_u32_le(stream);
    size_t end   = stream_tell(stream) + (size_t)(total_bytes - 4u);

    xpcd_array_t *arr = (xpcd_array_t *)calloc(1, sizeof(xpcd_array_t));
    if (!arr) return NULL;
    xpcd_array_item_t *tail = NULL;
    for (uint32_t i = 0; i < num_items; i++) {
        if (stream_tell(stream) > end) break;
        align4(stream);
        xpcd_object_t *elem = deserialize_xpc_object(stream);
        if (!elem) { free(arr); return NULL; }
        xpcd_array_item_t *node = (xpcd_array_item_t *)calloc(1, sizeof(xpcd_array_item_t));
        if (!node) { free(elem); free(arr); return NULL; }
        node->item = elem; node->next = NULL;
        if (!arr->head) arr->head = node; else tail->next = node; tail = node; arr->num_items++;
    }
    if (stream_tell(stream) < end) (void)stream_seek(stream, end);
    return arr;
}

static xpcd_dict_t *deserialize_xpc_dict(stream_t *stream) {
    uint32_t total_bytes = stream_read_u32_le(stream);
    uint32_t num_entries = stream_read_u32_le(stream);
    size_t content_end   = stream_tell(stream) + (size_t)(total_bytes - 4u);

    xpcd_dict_t *dict = (xpcd_dict_t *)calloc(1, sizeof(xpcd_dict_t));
    if (!dict) return NULL;
    xpcd_dict_entry_t *tail = NULL;
    for (uint32_t i = 0; i < num_entries; i++) {
        if (stream_tell(stream) >= content_end) break;

        // Read NUL-terminated key
        size_t cap = 32, len = 0; char *key = (char *)malloc(cap); if (!key) { free(dict); return NULL; }
        for (;;) {
            if (stream_remaining(stream) == 0) { free(key); free(dict); return NULL; }
            char c = (char)stream_read_u8(stream);
            if (len + 1 >= cap) { size_t nc = cap * 2; char *t = (char *)realloc(key, nc); if (!t) { free(key); free(dict); return NULL; } key = t; cap = nc; }
            key[len++] = c; if (c == '\0') break;
        }
        align4(stream);
        xpcd_object_t *val = deserialize_xpc_object(stream);
        if (!val) { free(key); free(dict); return NULL; }
        xpcd_dict_entry_t *entry = (xpcd_dict_entry_t *)calloc(1, sizeof(xpcd_dict_entry_t));
        if (!entry) { free(key); free(val); free(dict); return NULL; }
        entry->key.length = (uint32_t)(len ? (len - 1) : 0);
        entry->key.str = key; entry->value = val; entry->next = NULL;
        if (!dict->entries) dict->entries = entry; else tail->next = entry; tail = entry; dict->num_entries++;
        size_t pos = stream_tell(stream); size_t aligned = (pos + 3u) & ~3u; (void)stream_seek(stream, aligned);
    }
    if (stream_tell(stream) < content_end) (void)stream_seek(stream, content_end);
    return dict;
}

static xpcd_object_t *deserialize_xpc_object(stream_t *stream) {
    uint32_t raw = stream_read_u32_le(stream);
    uint32_t code = (raw - 0x1000u) >> 12;
    xpcd_type_t type;
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
    xpcd_object_t *obj = xpc_object_create(type);
    if (!obj) return NULL;
    obj->raw_type_header = raw;
    switch (type) {
        case XPC_ID_BOOL:   { uint32_t v = stream_read_u32_le(stream); obj->value.bool_value   = (v != 0); break; }
        case XPC_ID_INT64:  { uint64_t v = stream_read_u64_le(stream); obj->value.int64_value  = (int64_t)v; break; }
        case XPC_ID_UINT64: { uint64_t v = stream_read_u64_le(stream); obj->value.uint64_value = (uint64_t)v; break; }
        case XPC_ID_DOUBLE: { union { uint64_t u; double d; } cv; cv.u = stream_read_u64_le(stream); obj->value.double_value = cv.d; break; }
        case XPC_ID_DATE:   { obj->value.date_value = stream_read_u64_le(stream); break; }
        case XPC_ID_DATA:   { uint32_t n = stream_read_u32_le(stream); uint8_t *b = NULL; if (n) { b = (uint8_t *)malloc(n); if (!b) { free(obj); return NULL; } size_t got = stream_read(stream, b, n); if (got != n) { free(b); free(obj); return NULL; } } obj->value.data_value.length = n; obj->value.data_value.data = b; break; }
        case XPC_ID_STRING: { uint32_t n = stream_read_u32_le(stream); char *s = NULL; if (n) { s = (char *)malloc(n); if (!s) { free(obj); return NULL; } size_t got = stream_read(stream, s, n); if (got != n) { free(s); free(obj); return NULL; } if (n) s[n-1] = '\0'; } obj->value.string_value.length = n; obj->value.string_value.str = s; break; }
        case XPC_ID_UUID:   { uint8_t t[16]; size_t got = stream_read(stream, t, sizeof(t)); if (got != sizeof(t)) { free(obj); return NULL; } memcpy(obj->value.uuid_value.bytes, t, sizeof(t)); break; }
        case XPC_ID_ARRAY:  { xpcd_array_t *a = deserialize_xpc_array(stream); if (!a) { free(obj); return NULL; } obj->value.array_value = a; break; }
        case XPC_ID_DICT:   { xpcd_dict_t *d = deserialize_xpc_dict(stream); if (!d) { free(obj); return NULL; } obj->value.dict_value = d; break; }
        default: break;
    }
    return obj;
}

static void free_xpc_array(xpcd_array_t *arr) {
    if (!arr) return; xpcd_array_item_t *it = arr->head; while (it) { xpcd_array_item_t *n = it->next; free_xpc_object(it->item); free(it); it = n; } free(arr);
}
static void free_xpc_dict(xpcd_dict_t *dict) {
    if (!dict) return; xpcd_dict_entry_t *e = dict->entries; while (e) { xpcd_dict_entry_t *n = e->next; free(e->key.str); free_xpc_object(e->value); free(e); e = n; } free(dict);
}
static void free_xpc_object(xpcd_object_t *obj) {
    if (!obj) return; switch (obj->type) { case XPC_ID_DATA: free(obj->value.data_value.data); break; case XPC_ID_STRING: free(obj->value.string_value.str); break; case XPC_ID_ARRAY: free_xpc_array(obj->value.array_value); break; case XPC_ID_DICT: free_xpc_dict(obj->value.dict_value); break; default: break; } free(obj);
}

// ---- formatting ----
static void fmt_indent(char **dst, size_t *cap, size_t *len, int n) {
    if (*len + (size_t)n + 1 >= *cap) { size_t nc = (*cap)*2 + (size_t)n + 64; char *t = (char *)realloc(*dst, nc); if (!t) return; *dst = t; *cap = nc; }
    for (int i = 0; i < n; i++) (*dst)[(*len)++] = ' ';
}
static void fmt_puts(char **dst, size_t *cap, size_t *len, const char *s) {
    size_t sl = strlen(s); if (*len + sl + 1 >= *cap) { size_t nc = (*cap)*2 + sl + 64; char *t = (char *)realloc(*dst, nc); if (!t) return; *dst = t; *cap = nc; }
    memcpy(*dst + *len, s, sl); *len += sl; (*dst)[*len] = '\0';
}
static void fmt_escape_cstr(char **dst, size_t *cap, size_t *len, const char *s) {
    fmt_puts(dst, cap, len, "\"");
    if (s) { for (const unsigned char *p = (const unsigned char *)s; *p; ++p) { if (*p == '\n') fmt_puts(dst, cap, len, "\\n"); else { char c[2] = {(char)*p, 0}; fmt_puts(dst, cap, len, c); } } }
    fmt_puts(dst, cap, len, "\"");
}

static void format_object_inner(const xpcd_object_t *obj, int indent, char **dst, size_t *cap, size_t *len);

static void format_array(const xpcd_array_t *arr, int indent, char **dst, size_t *cap, size_t *len) {
    fmt_indent(dst, cap, len, indent); fmt_puts(dst, cap, len, "[\n");
    const xpcd_array_item_t *it = arr ? arr->head : NULL; while (it) {
        format_object_inner(it->item, indent + 2, dst, cap, len);
        if (it->next) fmt_puts(dst, cap, len, ","); fmt_puts(dst, cap, len, "\n"); it = it->next;
    }
    fmt_indent(dst, cap, len, indent); fmt_puts(dst, cap, len, "]");
}

static void format_dict(const xpcd_dict_t *dict, int indent, char **dst, size_t *cap, size_t *len) {
    fmt_indent(dst, cap, len, indent); fmt_puts(dst, cap, len, "{\n");
    const xpcd_dict_entry_t *e = dict ? dict->entries : NULL; while (e) {
        fmt_indent(dst, cap, len, indent + 2); fmt_escape_cstr(dst, cap, len, e->key.str ? e->key.str : ""); fmt_puts(dst, cap, len, ": ");
        format_object_inner(e->value, indent + 2, dst, cap, len);
        if (e->next) fmt_puts(dst, cap, len, ","); fmt_puts(dst, cap, len, "\n"); e = e->next;
    }
    fmt_indent(dst, cap, len, indent); fmt_puts(dst, cap, len, "}");
}

static void format_object_inner(const xpcd_object_t *obj, int indent, char **dst, size_t *cap, size_t *len) {
    char buf[128];
    if (!obj) { fmt_indent(dst, cap, len, indent); fmt_puts(dst, cap, len, "null"); return; }
    switch (obj->type) {
        case XPC_ID_NULL:   fmt_indent(dst, cap, len, indent); fmt_puts(dst, cap, len, "null"); break;
        case XPC_ID_BOOL:   fmt_indent(dst, cap, len, indent); fmt_puts(dst, cap, len, obj->value.bool_value ? "true" : "false"); break;
        case XPC_ID_INT64:  fmt_indent(dst, cap, len, indent); snprintf(buf, sizeof(buf), "%lld", (long long)obj->value.int64_value); fmt_puts(dst, cap, len, buf); break;
        case XPC_ID_UINT64: fmt_indent(dst, cap, len, indent); snprintf(buf, sizeof(buf), "%llu", (unsigned long long)obj->value.uint64_value); fmt_puts(dst, cap, len, buf); break;
        case XPC_ID_DOUBLE: fmt_indent(dst, cap, len, indent); snprintf(buf, sizeof(buf), "%g", obj->value.double_value); fmt_puts(dst, cap, len, buf); break;
        case XPC_ID_DATE:   fmt_indent(dst, cap, len, indent); snprintf(buf, sizeof(buf), "date(%llu)", (unsigned long long)obj->value.date_value); fmt_puts(dst, cap, len, buf); break;
        case XPC_ID_DATA:   fmt_indent(dst, cap, len, indent); snprintf(buf, sizeof(buf), "data[%u]", (unsigned)obj->value.data_value.length); fmt_puts(dst, cap, len, buf); break;
        case XPC_ID_STRING: fmt_indent(dst, cap, len, indent); fmt_escape_cstr(dst, cap, len, obj->value.string_value.str ? obj->value.string_value.str : ""); break;
        case XPC_ID_UUID:   fmt_indent(dst, cap, len, indent); snprintf(buf, sizeof(buf), "uuid(%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x)",
                                   obj->value.uuid_value.bytes[0], obj->value.uuid_value.bytes[1], obj->value.uuid_value.bytes[2], obj->value.uuid_value.bytes[3],
                                   obj->value.uuid_value.bytes[4], obj->value.uuid_value.bytes[5], obj->value.uuid_value.bytes[6], obj->value.uuid_value.bytes[7],
                                   obj->value.uuid_value.bytes[8], obj->value.uuid_value.bytes[9], obj->value.uuid_value.bytes[10], obj->value.uuid_value.bytes[11],
                                   obj->value.uuid_value.bytes[12], obj->value.uuid_value.bytes[13], obj->value.uuid_value.bytes[14], obj->value.uuid_value.bytes[15]);
                          fmt_puts(dst, cap, len, buf); break;
        case XPC_ID_FILE:   fmt_indent(dst, cap, len, indent); fmt_puts(dst, cap, len, "file"); break;
        case XPC_ID_ARRAY:  format_array(obj->value.array_value, indent, dst, cap, len); break;
        case XPC_ID_DICT:   format_dict(obj->value.dict_value, indent, dst, cap, len); break;
        case XPC_ID_UNIMP:  fmt_indent(dst, cap, len, indent); snprintf(buf, sizeof(buf), "<unknown type hdr=0x%08x>", obj->raw_type_header); fmt_puts(dst, cap, len, buf); break;
        default:            fmt_indent(dst, cap, len, indent); snprintf(buf, sizeof(buf), "<unimplemented type 0x%x>", (unsigned)obj->type); fmt_puts(dst, cap, len, buf); break;
    }
}

static char *format_object(const xpcd_object_t *obj, int indent) {
    (void)indent; size_t cap = 256, len = 0; char *dst = (char *)malloc(cap); if (!dst) return NULL; dst[0] = '\0';
    format_object_inner(obj, 0, &dst, &cap, &len); dst[len] = '\0';
    return dst;
}

