#include <xniff/macho.h>

#if defined(__APPLE__)
  #include <mach/task_info.h>
  #include <mach-o/loader.h>
  #include <mach-o/nlist.h>
  #include <mach-o/dyld_images.h>
  #include <stdlib.h>
  #include <string.h>
  #include <stdio.h>
  #include <limits.h>

// Debug logging (enable via XNIFF_DEBUG=1)
static int xniff_debug_enabled(void) {
    return 1;
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
    // 1) Try classic symtab
    if (img->have_symtab) {
        mach_vm_address_t linkedit_base = 0;
        if (!compute_linkedit_base(img, &linkedit_base)) return false;

        size_t strsize = img->symtab.strsize;
        void *strtab = NULL;
        if (!remote_read_alloc(task, linkedit_base + img->symtab.stroff, strsize, &strtab)) return false;

        size_t nsyms = img->symtab.nsyms;
        struct nlist_64 *nls = (struct nlist_64 *)malloc(nsyms * sizeof(struct nlist_64));
        if (!nls) { free(strtab); return false; }
        if (!remote_read(task, linkedit_base + img->symtab.symoff, nls, nsyms * sizeof(struct nlist_64))) {
            free(strtab); free(nls); return false;
        }
        for (size_t i = 0; i < nsyms; i++) {
            const struct nlist_64 *nl = &nls[i];
            if (!(nl->n_type & N_EXT)) continue;
            const char *name = (nl->n_un.n_strx < strsize) ? ((const char *)strtab + nl->n_un.n_strx) : NULL;
            if (!name) continue;
            if (strcmp(name, symbol) == 0) {
                uint8_t type = (uint8_t)(nl->n_type & N_TYPE);
                // Only accept defined-in-section symbols (not undefined/re-exports)
                if (type != N_SECT || nl->n_sect == NO_SECT || nl->n_value == 0) {
                    DLOG("skip SYMTAB match for %s in image 0x%llx: type=0x%x sect=%u n_value=0x%llx",
                         symbol,
                         (unsigned long long)img->info.header,
                         (unsigned int)type, (unsigned int)nl->n_sect,
                         (unsigned long long)nl->n_value);
                    continue;
                }
                mach_vm_address_t runtime = (mach_vm_address_t)nl->n_value + img->info.slide;
                // Validate within __TEXT range
                mach_vm_address_t text_start = img->text.vmaddr + img->info.slide;
                mach_vm_address_t text_end   = text_start + img->text.vmsize;
                if (runtime < text_start || runtime >= text_end) {
                    DLOG("reject SYMTAB candidate for %s in image 0x%llx: runtime=0x%llx not in __TEXT [0x%llx,0x%llx)",
                         symbol,
                         (unsigned long long)img->info.header,
                         (unsigned long long)runtime,
                         (unsigned long long)text_start,
                         (unsigned long long)text_end);
                    continue;
                }
                DLOG("found %s via SYMTAB in image 0x%llx: n_value=0x%llx runtime=0x%llx",
                     symbol,
                     (unsigned long long)img->info.header,
                     (unsigned long long)nl->n_value,
                     (unsigned long long)runtime);
                *out_addr = runtime;
                free(strtab); free(nls); return true;
            }
        }
        free(strtab); free(nls);
    }

    // 2) Try export trie via dyld info or LC_DYLD_EXPORTS_TRIE
    mach_vm_address_t linkedit_base = 0;
    if (!compute_linkedit_base(img, &linkedit_base)) return false;
    uint32_t exp_off = 0, exp_size = 0;
    if (img->have_exports_trie) { exp_off = img->exports_off; exp_size = img->exports_size; }
    else if (img->have_dyldinfo) { exp_off = img->dyldinfo.export_off; exp_size = img->dyldinfo.export_size; }
    if (exp_off == 0 || exp_size == 0) return false;

    uint8_t *trie = NULL;
    if (!remote_read_alloc(task, linkedit_base + exp_off, exp_size, (void **)&trie)) return false;

    // DFS stack nodes: pair of (offset, name_len)
    typedef struct { uint32_t off; size_t name_len; } stack_item_t;
    stack_item_t stack[512]; size_t sp = 0;
    char namebuf[1024]; namebuf[0] = '\0';
    stack[sp++] = (stack_item_t){ .off = 0, .name_len = 0 };
    bool found = false;
    mach_vm_address_t found_addr = 0;

    while (sp && !found) {
        stack_item_t it = stack[--sp];
        const uint8_t *node = trie + it.off; const uint8_t *end = trie + exp_size;
        const uint8_t *p = node; if (p >= end) continue;
        // terminal size
        uint64_t term = 0; if (!read_uleb128(&p, end, &term)) continue;
        const uint8_t *term_info = p; p += term; if (p > end) continue;
        // children count
        if (p >= end) continue;
        uint8_t childCount = *p++;
        // terminal match
        if (term > 0) {
            const uint8_t *tp = term_info; const uint8_t *tend = term_info + term;
            uint64_t flags = 0; (void)read_uleb128(&tp, tend, &flags);
            // export flags of interest:
            //  - 0x08: re-export (no address in this image)
            //  - 0x10: stub and resolver (not a concrete function body to patch)
            //  - 0x20: resolver (legacy; treat as not patchable)
            bool is_reexport = (flags & 0x08) != 0;
            bool is_stub_or_resolver = (flags & 0x10) != 0 || (flags & 0x20) != 0;
            if (!is_reexport && !is_stub_or_resolver) {
                uint64_t addr = 0;
                if (read_uleb128(&tp, tend, &addr)) {
                    namebuf[it.name_len] = '\0';
                    if (strcmp(namebuf, symbol) == 0) {
                        // Validate that the address is in the __TEXT segment to avoid bogus 0 addrs
                        mach_vm_address_t runtime_addr = (mach_vm_address_t)addr + img->info.slide;
                        mach_vm_address_t text_start = img->text.vmaddr + img->info.slide;
                        mach_vm_address_t text_end   = text_start + img->text.vmsize;
                        if (runtime_addr >= text_start && runtime_addr < text_end) {
                            DLOG("found %s via EXPORTS in image 0x%llx: addr=0x%llx runtime=0x%llx flags=0x%llx",
                                 symbol,
                                 (unsigned long long)img->info.header,
                                 (unsigned long long)addr,
                                 (unsigned long long)runtime_addr,
                                 (unsigned long long)flags);
                            found = true; found_addr = runtime_addr; break;
                        } else {
                            DLOG("reject export candidate for %s in image 0x%llx: runtime=0x%llx not in __TEXT [0x%llx,0x%llx)",
                                 symbol,
                                 (unsigned long long)img->info.header,
                                 (unsigned long long)runtime_addr,
                                 (unsigned long long)text_start,
                                 (unsigned long long)text_end);
                        }
                    }
                }
            }
            else {
                namebuf[it.name_len] = '\0';
                if (strcmp(namebuf, symbol) == 0) {
                    DLOG("skip export for %s in image 0x%llx due to flags=0x%llx (reexport/stub)",
                         symbol, (unsigned long long)img->info.header, (unsigned long long)flags);
                }
            }
        }
        // iterate children
        for (uint8_t i = 0; i < childCount; i++) {
            const uint8_t *s = p; while (s < end && *s) s++;
            if (s >= end) break; size_t edge_len = (size_t)(s - p);
            const uint8_t *after_name = s + 1; // skip NUL
            uint64_t childOff = 0; const uint8_t *after_off = after_name; if (!read_uleb128(&after_off, end, &childOff)) break;
            // push child if name fits
            if (it.name_len + edge_len + 1 < sizeof(namebuf) && sp < (sizeof(stack)/sizeof(stack[0]) - 1)) {
                memcpy(namebuf + it.name_len, p, edge_len);
                namebuf[it.name_len + edge_len] = '\0';
                stack[sp++] = (stack_item_t){ .off = (uint32_t)childOff, .name_len = it.name_len + edge_len };
            }
            p = after_off;
        }
    }
    free(trie);
    if (found) { *out_addr = found_addr; return true; }
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

#else
int xniff_find_symbol_in_main_image(mach_port_t task, const char *symbol, mach_vm_address_t *out_addr) {
    (void)task; (void)symbol; (void)out_addr; return -1;
}
int xniff_find_symbol_in_task(mach_port_t task, const char *symbol, mach_vm_address_t *out_addr) {
    (void)task; (void)symbol; (void)out_addr; return -1;
}
#endif
