#include <xniff/macho.h>

#include <limits.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/task_info.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Debug logging (enable via XNIFF_DEBUG=1)
static int xniff_debug_enabled(void) {
    const char *e = getenv("XNIFF_DEBUG");
    return (e && *e && strcmp(e, "0") != 0) ? 1 : 0;
}
#define DLOG(fmt, ...) do { if (xniff_debug_enabled()) fprintf(stderr, "[xniff][sym] " fmt "\n", ##__VA_ARGS__); } while(0)

typedef struct image_info {
    mach_vm_address_t header;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t filetype;
    mach_vm_address_t slide;
} image_info_t;

typedef struct parsed_image {
    image_info_t info;
    struct segment_command_64 text;
    struct segment_command_64 linkedit;
    struct symtab_command symtab;
    struct dysymtab_command dysymtab;
    struct dyld_info_command dyldinfo;
    uint32_t exports_off; // from LC_DYLD_EXPORTS_TRIE if present
    uint32_t exports_size;
    bool have_text, have_linkedit, have_symtab, have_dysymtab;
    bool have_dyldinfo, have_exports_trie;
} parsed_image_t;

// Forward declarations for helpers used by caching fast-path
static bool remote_read(mach_port_t task, mach_vm_address_t addr, void *buf, size_t size);
static bool remote_read_alloc(mach_port_t task, mach_vm_address_t addr, size_t size, void **out_buf);
static bool compute_linkedit_base(parsed_image_t *img, mach_vm_address_t *out);
static bool parse_image_at(mach_port_t task, mach_vm_address_t header_addr, parsed_image_t *out);

// ----------------------------
// Symbol cache (per image)
// ----------------------------

typedef struct sym_entry {
    uint32_t name_off;               // offset into strtab
    mach_vm_address_t runtime;       // resolved runtime address (with slide)
} sym_entry_t;

typedef struct image_cache {
    mach_port_t task;
    mach_vm_address_t header;        // image header address (runtime)
    mach_vm_address_t slide;
    mach_vm_address_t text_start;
    mach_vm_address_t text_end;

    // Classic LC_SYMTAB cache
    char       *strtab;              // local copy of string table
    size_t      strsize;
    sym_entry_t *syms;               // filtered, sorted by name (strcmp)
    size_t      nsyms;

    // Exports trie cache (optional, for stripped images)
    uint8_t    *exports;             // raw trie data
    size_t      exports_size;
    uint32_t    exports_off;         // file offset (for reference)
    int         have_exports;

    // Bookkeeping
    int         initialized;         // set when cache is fully built
} image_cache_t;

typedef struct task_cache {
    mach_port_t task;
    uint64_t    fingerprint;         // simple fingerprint of images list for invalidation
    image_cache_t *images;           // dynamic array
    size_t      count;
    size_t      cap;
} task_cache_t;

static task_cache_t *g_tasks = NULL;
static size_t g_tasks_count = 0, g_tasks_cap = 0;

static void free_image_cache(image_cache_t *ic) {
    if (!ic) return;
    free(ic->strtab); ic->strtab = NULL; ic->strsize = 0;
    free(ic->syms);   ic->syms = NULL;   ic->nsyms = 0;
    ic->initialized = 0;
}

static void free_task_cache(task_cache_t *tc) {
    if (!tc) return;
    for (size_t i = 0; i < tc->count; i++) free_image_cache(&tc->images[i]);
    free(tc->images); tc->images = NULL; tc->count = tc->cap = 0; tc->fingerprint = 0;
}

static task_cache_t* ensure_task_cache(mach_port_t task) {
    for (size_t i = 0; i < g_tasks_count; i++) if (g_tasks[i].task == task) return &g_tasks[i];
    if (g_tasks_count == g_tasks_cap) {
        size_t nc = g_tasks_cap ? g_tasks_cap * 2 : 4;
        task_cache_t *nt = (task_cache_t*)realloc(g_tasks, nc * sizeof(*nt));
        if (!nt) return NULL;
        memset(nt + g_tasks_cap, 0, (nc - g_tasks_cap) * sizeof(*nt));
        g_tasks = nt; g_tasks_cap = nc;
    }
    task_cache_t *tc = &g_tasks[g_tasks_count++];
    memset(tc, 0, sizeof(*tc));
    tc->task = task;
    return tc;
}

static image_cache_t* find_image_cache(task_cache_t *tc, mach_vm_address_t header) {
    for (size_t i = 0; i < tc->count; i++) if (tc->images[i].header == header) return &tc->images[i];
    return NULL;
}

static image_cache_t* add_image_cache(task_cache_t *tc, mach_vm_address_t header) {
    if (tc->count == tc->cap) {
        size_t nc = tc->cap ? tc->cap * 2 : 8;
        image_cache_t *ni = (image_cache_t*)realloc(tc->images, nc * sizeof(*ni));
        if (!ni) return NULL;
        memset(ni + tc->cap, 0, (nc - tc->cap) * sizeof(*ni));
        tc->images = ni; tc->cap = nc;
    }
    image_cache_t *ic = &tc->images[tc->count++];
    memset(ic, 0, sizeof(*ic));
    ic->task = tc->task; ic->header = header;
    return ic;
}

static const char *g_sort_strtab = NULL; // only used during qsort comparator
static int sym_entry_cmp_by_name(const void *a, const void *b) {
    const sym_entry_t *ea = (const sym_entry_t*)a;
    const sym_entry_t *eb = (const sym_entry_t*)b;
    const char *sa = g_sort_strtab + ea->name_off;
    const char *sb = g_sort_strtab + eb->name_off;
    return strcmp(sa, sb);
}

static int build_image_symtab_cache(mach_port_t task, const parsed_image_t *img, image_cache_t *ic) {
    if (!img->have_symtab) return -1;
    mach_vm_address_t linkedit_base = 0;
    if (!img || !ic) return -1;
    if (!compute_linkedit_base((parsed_image_t*)img, &linkedit_base)) return -1;

    // Load string table
    ic->strsize = img->symtab.strsize;
    ic->strtab = (char*)malloc(ic->strsize);
    if (!ic->strtab) return -1;
    if (!remote_read(task, linkedit_base + img->symtab.stroff, ic->strtab, ic->strsize)) {
        free(ic->strtab); ic->strtab = NULL; ic->strsize = 0; return -1;
    }

    // Load nlist and filter entries to defined extern functions in __TEXT
    size_t nsyms = img->symtab.nsyms;
    struct nlist_64 *nls = (struct nlist_64 *)malloc(nsyms * sizeof(struct nlist_64));
    if (!nls) { free(ic->strtab); ic->strtab = NULL; ic->strsize = 0; return -1; }
    if (!remote_read(task, linkedit_base + img->symtab.symoff, nls, nsyms * sizeof(struct nlist_64))) {
        free(nls); free(ic->strtab); ic->strtab = NULL; ic->strsize = 0; return -1;
    }

    ic->text_start = img->text.vmaddr + img->info.slide;
    ic->text_end   = ic->text_start + img->text.vmsize;
    ic->slide      = img->info.slide;

    // First pass: count
    size_t keep = 0;
    for (size_t i = 0; i < nsyms; i++) {
        const struct nlist_64 *nl = &nls[i];
        if (!(nl->n_type & N_EXT)) continue;
        if ((nl->n_type & N_TYPE) != N_SECT) continue;
        if (nl->n_sect == NO_SECT || nl->n_value == 0) continue;
        if ((size_t)nl->n_un.n_strx >= ic->strsize) continue;
        mach_vm_address_t runtime = (mach_vm_address_t)nl->n_value + ic->slide;
        if (runtime < ic->text_start || runtime >= ic->text_end) continue; // keep only text
        keep++;
    }

    ic->syms = (sym_entry_t*)malloc(keep * sizeof(sym_entry_t));
    if (!ic->syms) { free(nls); free(ic->strtab); ic->strtab = NULL; ic->strsize = 0; return -1; }

    // Second pass: fill
    size_t j = 0;
    for (size_t i = 0; i < nsyms; i++) {
        const struct nlist_64 *nl = &nls[i];
        if (!(nl->n_type & N_EXT)) continue;
        if ((nl->n_type & N_TYPE) != N_SECT) continue;
        if (nl->n_sect == NO_SECT || nl->n_value == 0) continue;
        if ((size_t)nl->n_un.n_strx >= ic->strsize) continue;
        mach_vm_address_t runtime = (mach_vm_address_t)nl->n_value + ic->slide;
        if (runtime < ic->text_start || runtime >= ic->text_end) continue;
        ic->syms[j].name_off = nl->n_un.n_strx;
        ic->syms[j].runtime  = runtime;
        j++;
    }
    ic->nsyms = j;

    // Sort entries by name for fast binary search
    g_sort_strtab = ic->strtab;
    qsort(ic->syms, ic->nsyms, sizeof(sym_entry_t), sym_entry_cmp_by_name);
    g_sort_strtab = NULL;

    free(nls);
    ic->initialized = 1;
    return 0;
}

static int ensure_exports_cache(mach_port_t task, const parsed_image_t *img, image_cache_t *ic) {
    if (ic->exports || !img) return 0; // already cached or nothing to do
    mach_vm_address_t linkedit_base = 0;
    if (!compute_linkedit_base((parsed_image_t*)img, &linkedit_base)) return -1;
    uint32_t exp_off = 0, exp_size = 0;
    if (img->have_exports_trie) { exp_off = img->exports_off; exp_size = img->exports_size; }
    else if (img->have_dyldinfo) { exp_off = img->dyldinfo.export_off; exp_size = img->dyldinfo.export_size; }
    if (exp_off == 0 || exp_size == 0) return -1;
    void *buf = NULL;
    if (!remote_read_alloc(task, linkedit_base + exp_off, exp_size, &buf)) return -1;
    ic->exports = (uint8_t*)buf;
    ic->exports_size = exp_size;
    ic->exports_off = exp_off;
    ic->have_exports = 1;
    return 0;
}

static bool read_uleb128_local(const uint8_t **pp, const uint8_t *end, uint64_t *out) {
    const uint8_t *p = *pp; uint64_t v = 0; int shift = 0;
    while (p < end) {
        uint8_t b = *p++;
        v |= ((uint64_t)(b & 0x7F)) << shift;
        if ((b & 0x80) == 0) { *pp = p; *out = v; return true; }
        shift += 7; if (shift > 63) return false;
    }
    return false;
}

// Fast targeted traversal of the export trie for a single symbol name.
static bool lookup_export_trie_by_name(const image_cache_t *ic, const char *symbol, mach_vm_address_t slide, mach_vm_address_t text_start, mach_vm_address_t text_end, mach_vm_address_t *out_addr) {
    if (!ic || !ic->exports || ic->exports_size == 0 || !symbol) return false;
    const uint8_t *base = ic->exports;
    const uint8_t *end  = ic->exports + ic->exports_size;
    const uint8_t *node = base; // start at offset 0
    size_t idx = 0; size_t name_len = strlen(symbol);

    while (node && node < end) {
        const uint8_t *p = node;
        // terminal size and info
        uint64_t term = 0; if (!read_uleb128_local(&p, end, &term)) return false;
        const uint8_t *term_info = p; p += term; if (p > end) return false;

        // If we've consumed the whole name, check terminal for an address
        if (idx == name_len && term > 0) {
            const uint8_t *tp = term_info; const uint8_t *tend = term_info + term;
            uint64_t flags = 0; (void)read_uleb128_local(&tp, tend, &flags);
            bool is_reexport = (flags & 0x08) != 0;
            bool is_stub_or_resolver = (flags & 0x10) != 0 || (flags & 0x20) != 0;
            if (!is_reexport && !is_stub_or_resolver) {
                uint64_t addr = 0; if (read_uleb128_local(&tp, tend, &addr)) {
                    mach_vm_address_t runtime = (mach_vm_address_t)addr + slide;
                    if (runtime >= text_start && runtime < text_end) { *out_addr = runtime; return true; }
                }
            }
            return false; // reached terminal but not usable
        }

        if (p >= end) return false;
        uint8_t childCount = *p++;

        // Try to match one child edge whose label matches symbol[idx..]
        const uint8_t *match_child_after_off = NULL;
        uint64_t match_child_off = 0;
        size_t match_advance = 0;

        for (uint8_t i = 0; i < childCount; i++) {
            // read label (c-string) and child off
            const uint8_t *s = p; while (s < end && *s) s++;
            if (s >= end) return false;
            size_t edge_len = (size_t)(s - p);
            const char *edge = (const char *)p;
            const uint8_t *after_name = s + 1;
            const uint8_t *q = after_name;
            uint64_t childOff = 0; if (!read_uleb128_local(&q, end, &childOff)) return false;

            // Compare symbol substring with edge
            if (idx + edge_len <= name_len && memcmp(symbol + idx, edge, edge_len) == 0) {
                match_child_after_off = q; match_child_off = childOff; match_advance = edge_len;
                // Prefer exact match of longest edge; but edges are unique, so take first match
                break;
            }
            p = q; // advance to next child
        }

        if (!match_child_after_off) {
            return false; // no matching edge at this depth
        }

        // Descend
        idx += match_advance;
        node = base + match_child_off;
    }
    return false;
}

static int cached_lookup_in_image(image_cache_t *ic, const char *symbol, mach_vm_address_t *out_addr) {
    if (!ic || !ic->initialized || !symbol) return -1;
    size_t lo = 0, hi = ic->nsyms;
    while (lo < hi) {
        size_t mid = lo + ((hi - lo) >> 1);
        const char *name = ic->strtab + ic->syms[mid].name_off;
        int c = strcmp(name, symbol);
        if (c == 0) { *out_addr = ic->syms[mid].runtime; return 0; }
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return -1;
}

static bool remote_read(mach_port_t task, mach_vm_address_t addr, void *buf, size_t size) {
    mach_vm_size_t out = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, addr, size, (mach_vm_address_t)(uintptr_t)buf, &out);
    return (kr == KERN_SUCCESS) && (out == size);
}

static bool remote_read_alloc(mach_port_t task, mach_vm_address_t addr, size_t size, void **out_buf) {
    void *buf = malloc(size);
    if (!buf) return false;
    if (!remote_read(task, addr, buf, size)) { free(buf); return false; }
    *out_buf = buf; return true;
}

static bool remote_read_cstring(mach_port_t task, mach_vm_address_t addr, char *out, size_t max_len) {
    if (!out || max_len == 0) return false;
    size_t off = 0;
    while (off + 1 < max_len) {
        char chunk[64];
        size_t to_read = (max_len - 1 - off) < sizeof(chunk) ? (max_len - 1 - off) : sizeof(chunk);
        if (!remote_read(task, addr + off, chunk, to_read)) {
            break;
        }
        for (size_t i = 0; i < to_read; i++) {
            out[off++] = chunk[i];
            if (chunk[i] == '\0') { return true; }
            if (off + 1 >= max_len) break;
        }
        if (to_read < sizeof(chunk)) break;
    }
    if (off < max_len) out[off] = '\0';
    return false;
}

static bool load_image_info(mach_port_t task, mach_vm_address_t header_addr, image_info_t *out) {
    struct mach_header_64 mh;
    if (!remote_read(task, header_addr, &mh, sizeof(mh))) return false;
    if (mh.magic != MH_MAGIC_64 && mh.magic != MH_CIGAM_64) return false;
    out->header = header_addr;
    out->ncmds = mh.ncmds;
    out->sizeofcmds = mh.sizeofcmds;
    out->filetype = mh.filetype;
    out->slide = 0; // computed after parsing __TEXT
    return true;
}

static bool parse_load_commands(mach_port_t task, parsed_image_t *img) {
    size_t cmds_size = img->info.sizeofcmds;
    void *buf = NULL;
    if (!remote_read_alloc(task, img->info.header + sizeof(struct mach_header_64), cmds_size, &buf)) {
        return false;
    }
    const uint8_t *p = (const uint8_t *)buf;
    for (uint32_t i = 0; i < img->info.ncmds; i++) {
        if (p + sizeof(struct load_command) > (const uint8_t *)buf + cmds_size) break;
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
            if (strcmp(seg->segname, SEG_TEXT) == 0) { img->text = *seg; img->have_text = true; }
            if (strcmp(seg->segname, SEG_LINKEDIT) == 0) { img->linkedit = *seg; img->have_linkedit = true; }
        } else if (lc->cmd == LC_SYMTAB) {
            img->symtab = *(const struct symtab_command *)p; img->have_symtab = true;
        } else if (lc->cmd == LC_DYSYMTAB) {
            img->dysymtab = *(const struct dysymtab_command *)p; img->have_dysymtab = true;
        } else if (lc->cmd == LC_DYLD_INFO || lc->cmd == LC_DYLD_INFO_ONLY) {
            img->dyldinfo = *(const struct dyld_info_command *)p; img->have_dyldinfo = true;
#ifdef LC_DYLD_EXPORTS_TRIE
        } else if (lc->cmd == LC_DYLD_EXPORTS_TRIE) {
            const struct linkedit_data_command *ed = (const struct linkedit_data_command *)p;
            img->exports_off = ed->dataoff;
            img->exports_size = ed->datasize;
            img->have_exports_trie = true;
#endif
        }
        if (lc->cmdsize == 0) break;
        p += lc->cmdsize;
    }
    free(buf);
    if (img->have_text) {
        img->info.slide = (mach_vm_address_t)(img->info.header) - img->text.vmaddr;
        DLOG("image 0x%llx: __TEXT vmaddr=0x%llx vmsize=0x%llx slide=0x%llx",
             (unsigned long long)img->info.header,
             (unsigned long long)img->text.vmaddr,
             (unsigned long long)img->text.vmsize,
             (unsigned long long)img->info.slide);
    }
    return true;
}

static bool compute_linkedit_base(parsed_image_t *img, mach_vm_address_t *out) {
    if (!img->have_linkedit) return false;
    mach_vm_address_t linkedit_runtime = img->linkedit.vmaddr + img->info.slide;
    *out = linkedit_runtime - img->linkedit.fileoff;
    return true;
}

static bool read_uleb128(const uint8_t **pp, const uint8_t *end, uint64_t *out) {
    const uint8_t *p = *pp; uint64_t v = 0; int shift = 0;
    while (p < end) {
        uint8_t b = *p++;
        v |= ((uint64_t)(b & 0x7F)) << shift;
        if ((b & 0x80) == 0) { *pp = p; *out = v; return true; }
        shift += 7; if (shift > 63) return false;
    }
    return false;
}

static bool find_symbol_in_image(mach_port_t task, parsed_image_t *img, const char *symbol, mach_vm_address_t *out_addr) {
    // 1) Cached SYMTAB lookup (fast path)
    // Build (or reuse) per-image cache and do a binary search
    // NOTE: The caller (higher level) will manage invalidation across image list changes.
    // Here we only cache within this TU for the specific image header.
    // To get per-task cache, higher-level finders call this per image.
    // We'll lazily keep a small LRU via task_cache list.
    // We piggyback on the task_cache APIs defined above.
    task_cache_t *tcache = ensure_task_cache(task);
    if (!tcache) return false;
    image_cache_t *ic = find_image_cache(tcache, img->info.header);
    if (!ic) ic = add_image_cache(tcache, img->info.header);
    if (!ic) return false;
    if (!ic->initialized) {
        if (build_image_symtab_cache(task, img, ic) != 0) {
            // Fallback to slow path below (exports)
        }
    }
    if (ic->initialized) {
        mach_vm_address_t addr = 0;
        if (cached_lookup_in_image(ic, symbol, &addr) == 0) { *out_addr = addr; return true; }
    }

    // 2) Fast export-trie lookup (cached per image)
    if (!ic->have_exports) (void)ensure_exports_cache(task, img, ic);
    if (ic->have_exports) {
        mach_vm_address_t addr = 0;
        if (lookup_export_trie_by_name(ic, symbol, img->info.slide,
                                       img->text.vmaddr + img->info.slide,
                                       img->text.vmaddr + img->info.slide + img->text.vmsize,
                                       &addr)) {
            *out_addr = addr; return true;
        }
    }
    return false;
}

static bool enumerate_images(mach_port_t task, struct dyld_all_image_infos *out_infos,
                             struct dyld_image_info **out_local_array, uint32_t *out_count) {
    task_dyld_info_data_t dyldInfo;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
    if (kr != KERN_SUCCESS) {
        return false;
    }
    if (!remote_read(task, dyldInfo.all_image_info_addr, out_infos, sizeof(*out_infos))) {
        return false;
    }
    uint32_t imageCount = out_infos->infoArrayCount;
    struct dyld_image_info *remoteArray = (struct dyld_image_info *)out_infos->infoArray;
    size_t arrSize = imageCount * sizeof(struct dyld_image_info);
    struct dyld_image_info *localArray = (struct dyld_image_info *)malloc(arrSize);
    if (!localArray) return false;
    if (!remote_read(task, (mach_vm_address_t)(uintptr_t)remoteArray, localArray, arrSize)) {
        free(localArray); return false;
    }
    *out_local_array = localArray;
    *out_count = imageCount;
    DLOG("enumerate_images: count=%u, infos@0x%llx array@0x%llx",
         imageCount,
         (unsigned long long)out_infos->infoArray,
         (unsigned long long)(uintptr_t)localArray);
    return true;
}

int xniff_dump_task_images(mach_port_t task) {
    struct dyld_all_image_infos infos;
    struct dyld_image_info *arr = NULL;
    uint32_t count = 0;
    if (!enumerate_images(task, &infos, &arr, &count)) {
        fprintf(stderr, "[xniff] enumerate_images failed\n");
        return -1;
    }
    fprintf(stderr, "[xniff] dyld images: %u total\n", count);
    for (uint32_t i = 0; i < count; i++) {
        mach_vm_address_t header = (mach_vm_address_t)(uintptr_t)arr[i].imageLoadAddress;
        parsed_image_t img; char path[PATH_MAX] = {0};
        (void)remote_read_cstring(task, (mach_vm_address_t)(uintptr_t)arr[i].imageFilePath, path, sizeof(path));
        if (parse_image_at(task, header, &img)) {
            fprintf(stderr,
                    "[xniff]  [%4u] header=0x%llx slide=0x%llx type=%u path=%s\n",
                    i,
                    (unsigned long long)header,
                    (unsigned long long)img.info.slide,
                    img.info.filetype,
                    path[0] ? path : "<unknown>");
        } else {
            // Print at least basic info if parsing fails
            fprintf(stderr,
                    "[xniff]  [%4u] header=0x%llx slide=? type=? path=%s (parse failed)\n",
                    i,
                    (unsigned long long)header,
                    path[0] ? path : "<unknown>");
        }
    }
    free(arr);
    return 0;
}

int xniff_image_exists_exact(mach_port_t task, const char *exact_path) {
    if (!exact_path || !*exact_path) return -1;
    struct dyld_all_image_infos infos; struct dyld_image_info *arr = NULL; uint32_t count = 0;
    if (!enumerate_images(task, &infos, &arr, &count)) return -1;
    int found = 0;
    for (uint32_t i = 0; i < count; i++) {
        char path[PATH_MAX] = {0};
        (void)remote_read_cstring(task, (mach_vm_address_t)(uintptr_t)arr[i].imageFilePath, path, sizeof(path));
        if (*path && strcmp(path, exact_path) == 0) { found = 1; break; }
    }
    free(arr);
    return found;
}

int xniff_image_exists_contains(mach_port_t task, const char *substring) {
    if (!substring || !*substring) return -1;
    struct dyld_all_image_infos infos; struct dyld_image_info *arr = NULL; uint32_t count = 0;
    if (!enumerate_images(task, &infos, &arr, &count)) return -1;
    int found = 0;
    for (uint32_t i = 0; i < count; i++) {
        char path[PATH_MAX] = {0};
        (void)remote_read_cstring(task, (mach_vm_address_t)(uintptr_t)arr[i].imageFilePath, path, sizeof(path));
        if (*path && strstr(path, substring)) { found = 1; break; }
    }
    free(arr);
    return found;
}

static bool parse_image_at(mach_port_t task, mach_vm_address_t header_addr, parsed_image_t *out) {
    memset(out, 0, sizeof(*out));
    if (!load_image_info(task, header_addr, &out->info)) return false;
    if (!parse_load_commands(task, out)) return false;
    return true;
}

int xniff_find_symbol_in_main_image(mach_port_t task, const char *symbol, mach_vm_address_t *out_addr) {
    struct dyld_all_image_infos infos;
    struct dyld_image_info *localArray = NULL;
    uint32_t count = 0;
    if (!enumerate_images(task, &infos, &localArray, &count)) {
        return -1;
    }

    // Compute fingerprint and manage per-task cache/invalidation
    uint64_t fp = ((uint64_t)count << 32);
    for (uint32_t i = 0; i < count; i++) {
        fp ^= (uint64_t)(uintptr_t)localArray[i].imageLoadAddress;
        fp = (fp << 7) | (fp >> (64 - 7));
    }
    task_cache_t *tc = ensure_task_cache(task);
    if (tc) {
        if (tc->fingerprint != fp) {
            DLOG("image list changed: invalidating cache (fp=0x%llx -> 0x%llx)", (unsigned long long)tc->fingerprint, (unsigned long long)fp);
            free_task_cache(tc);
            tc->task = task; // free_task_cache resets fields
        }
        tc->fingerprint = fp;
    }

    int rc = -1;
    for (uint32_t i = 0; i < count; i++) {
        mach_vm_address_t header_addr = (mach_vm_address_t)(uintptr_t)localArray[i].imageLoadAddress;
        parsed_image_t img;
        if (!parse_image_at(task, header_addr, &img)) continue;
        if (img.info.filetype == MH_EXECUTE) {
            char path[PATH_MAX] = {0};
            (void)remote_read_cstring(task, (mach_vm_address_t)(uintptr_t)localArray[i].imageFilePath, path, sizeof(path));
            DLOG("search main image: %s (header=0x%llx) for %s",
                 path[0] ? path : "<unknown>", (unsigned long long)header_addr, symbol);
            if (find_symbol_in_image(task, &img, symbol, out_addr)) {
                rc = 0;
                DLOG("resolved %s in main image %s => 0x%llx",
                     symbol, path[0] ? path : "<unknown>", (unsigned long long)*out_addr);
            }
            break;
        }
    }

    free(localArray);
    return rc;
}

int xniff_find_symbol_in_task(mach_port_t task, const char *symbol, mach_vm_address_t *out_addr) {
    struct dyld_all_image_infos infos;
    struct dyld_image_info *localArray = NULL;
    uint32_t count = 0;
    if (!enumerate_images(task, &infos, &localArray, &count)) {
        return -1;
    }

    // Manage per-task cache / invalidation
    uint64_t fp = ((uint64_t)count << 32);
    for (uint32_t i = 0; i < count; i++) {
        fp ^= (uint64_t)(uintptr_t)localArray[i].imageLoadAddress;
        fp = (fp << 7) | (fp >> (64 - 7));
    }
    task_cache_t *tc = ensure_task_cache(task);
    if (tc) {
        if (tc->fingerprint != fp) {
            DLOG("image list changed: invalidating cache (fp=0x%llx -> 0x%llx)", (unsigned long long)tc->fingerprint, (unsigned long long)fp);
            free_task_cache(tc);
            tc->task = task;
        }
        tc->fingerprint = fp;
    }

    int rc = -1;
    DLOG("search task for symbol %s", symbol);
    for (uint32_t i = 0; i < count; i++) {
        mach_vm_address_t header_addr = (mach_vm_address_t)(uintptr_t)localArray[i].imageLoadAddress;
        parsed_image_t img;
        if (!parse_image_at(task, header_addr, &img)) continue;
        char path[PATH_MAX] = {0};
        (void)remote_read_cstring(task, (mach_vm_address_t)(uintptr_t)localArray[i].imageFilePath, path, sizeof(path));
        DLOG("scan image[%u]: %s (header=0x%llx filetype=%u)",
             i, path[0] ? path : "<unknown>", (unsigned long long)header_addr, img.info.filetype);
        if (find_symbol_in_image(task, &img, symbol, out_addr)) {
            rc = 0;
            DLOG("resolved %s in %s => 0x%llx",
                 symbol, path[0] ? path : "<unknown>", (unsigned long long)*out_addr);
            break;
        }
    }
    free(localArray);
    return rc;
}

int xniff_find_symbol_in_image_path_contains(mach_port_t task,
                                            const char *path_substring,
                                            const char *symbol,
                                            mach_vm_address_t *out_addr) {
    if (!path_substring || !*path_substring || !symbol || !out_addr) return -1;
    struct dyld_all_image_infos infos; struct dyld_image_info *arr = NULL; uint32_t count = 0;
    if (!enumerate_images(task, &infos, &arr, &count)) return -1;
    int rc = -1;
    for (uint32_t i = 0; i < count; i++) {
        char path[PATH_MAX] = {0};
        (void)remote_read_cstring(task, (mach_vm_address_t)(uintptr_t)arr[i].imageFilePath, path, sizeof(path));
        if (!*path || !strstr(path, path_substring)) continue;
        parsed_image_t img; if (!parse_image_at(task, (mach_vm_address_t)(uintptr_t)arr[i].imageLoadAddress, &img)) continue;
        if (find_symbol_in_image(task, &img, symbol, out_addr)) { rc = 0; break; }
    }
    free(arr); return rc;
}

int xniff_find_symbol_in_image_exact_path(mach_port_t task,
                                          const char *exact_path,
                                          const char *symbol,
                                          mach_vm_address_t *out_addr) {
    if (!exact_path || !*exact_path || !symbol || !out_addr) return -1;
    struct dyld_all_image_infos infos; struct dyld_image_info *arr = NULL; uint32_t count = 0;
    if (!enumerate_images(task, &infos, &arr, &count)) return -1;
    int rc = -1;
    for (uint32_t i = 0; i < count; i++) {
        char path[PATH_MAX] = {0};
        (void)remote_read_cstring(task, (mach_vm_address_t)(uintptr_t)arr[i].imageFilePath, path, sizeof(path));
        if (*path && strcmp(path, exact_path) == 0) {
            parsed_image_t img; if (!parse_image_at(task, (mach_vm_address_t)(uintptr_t)arr[i].imageLoadAddress, &img)) continue;
            if (find_symbol_in_image(task, &img, symbol, out_addr)) { rc = 0; break; }
        }
    }
    free(arr); return rc;
}
