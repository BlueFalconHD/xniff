#include <xniff/macho.h>

#if defined(__APPLE__)
  #include <mach/task_info.h>
  #include <mach-o/loader.h>
  #include <mach-o/nlist.h>
  #include <mach-o/dyld_images.h>
  #include <stdlib.h>
  #include <string.h>

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
    bool have_text, have_linkedit, have_symtab, have_dysymtab;
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
        }
        if (lc->cmdsize == 0) break;
        p += lc->cmdsize;
    }
    free(buf);
    if (img->have_text) {
        img->info.slide = (mach_vm_address_t)(img->info.header) - img->text.vmaddr;
    }
    return true;
}

static bool compute_linkedit_base(parsed_image_t *img, mach_vm_address_t *out) {
    if (!img->have_linkedit) return false;
    mach_vm_address_t linkedit_runtime = img->linkedit.vmaddr + img->info.slide;
    *out = linkedit_runtime - img->linkedit.fileoff;
    return true;
}

static bool find_symbol_in_image(mach_port_t task, parsed_image_t *img, const char *symbol, mach_vm_address_t *out_addr) {
    if (!img->have_symtab) return false;
    mach_vm_address_t linkedit_base = 0;
    if (!compute_linkedit_base(img, &linkedit_base)) return false;

    // Load string table
    size_t strsize = img->symtab.strsize;
    void *strtab = NULL;
    if (!remote_read_alloc(task, linkedit_base + img->symtab.stroff, strsize, &strtab)) return false;

    // Load symtab entries
    size_t nsyms = img->symtab.nsyms;
    struct nlist_64 *nls = (struct nlist_64 *)malloc(nsyms * sizeof(struct nlist_64));
    if (!nls) { free(strtab); return false; }
    if (!remote_read(task, linkedit_base + img->symtab.symoff, nls, nsyms * sizeof(struct nlist_64))) {
        free(strtab); free(nls); return false;
    }

    bool found = false;
    for (size_t i = 0; i < nsyms; i++) {
        const struct nlist_64 *nl = &nls[i];
        if (!(nl->n_type & N_EXT)) continue;
        const char *name = (nl->n_un.n_strx < strsize) ? ((const char *)strtab + nl->n_un.n_strx) : NULL;
        if (!name) continue;
        if (strcmp(name, symbol) == 0) {
            *out_addr = (mach_vm_address_t)nl->n_value + img->info.slide;
            found = true;
            break;
        }
    }

    free(strtab); free(nls);
    return found;
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
            if (find_symbol_in_image(task, &img, symbol, out_addr)) {
                rc = 0;
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
    for (uint32_t i = 0; i < count; i++) {
        mach_vm_address_t header_addr = (mach_vm_address_t)(uintptr_t)localArray[i].imageLoadAddress;
        parsed_image_t img;
        if (!parse_image_at(task, header_addr, &img)) continue;
        if (find_symbol_in_image(task, &img, symbol, out_addr)) {
            rc = 0;
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
