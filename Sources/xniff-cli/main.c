// xniff-cli: attach to a target process, find symbols, and patch
// a function with a trampoline that calls our hook.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>

#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld_images.h>

#include "patch.h"

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

typedef struct image_info {
    mach_vm_address_t header;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t filetype;
    mach_vm_address_t slide;
} image_info_t;

static bool load_image_info(mach_port_t task, mach_vm_address_t header_addr, image_info_t *out) {
    struct mach_header_64 mh;
    if (!remote_read(task, header_addr, &mh, sizeof(mh))) return false;
    if (mh.magic != MH_MAGIC_64 && mh.magic != MH_CIGAM_64) return false;
    out->header = header_addr;
    out->ncmds = mh.ncmds;
    out->sizeofcmds = mh.sizeofcmds;
    out->filetype = mh.filetype;
    // We'll compute slide later using __TEXT
    out->slide = 0;
    return true;
}

typedef struct parsed_image {
    image_info_t info;
    struct segment_command_64 text;
    struct segment_command_64 linkedit;
    struct symtab_command symtab;
    struct dysymtab_command dysymtab;
    bool have_text, have_linkedit, have_symtab, have_dysymtab;
} parsed_image_t;

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
    // linkedit_runtime = linkedit.vmaddr + slide
    // linkedit_base = linkedit_runtime - fileoff
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
            // n_value is unslid
            *out_addr = (mach_vm_address_t)nl->n_value + img->info.slide;
            found = true;
            break;
        }
    }

    free(strtab); free(nls);
    return found;
}

static int attach_and_get_task(pid_t pid, mach_port_t *out_task) {
    // Attempt to get the task port first; if allowed, we can avoid ptrace.
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr == KERN_SUCCESS) {
        printf("got task port for pid %d without attach\n", pid);
        *out_task = task;
        return 0;
    }

    printf("attaching to pid %d\n", pid);
    if (ptrace(PT_ATTACHEXC, pid, 0, 0) != 0) {
        perror("ptrace(PT_ATTACHEXC)");
        return -1;
    }

    // Retry task_for_pid after attach instead of relying on waitpid semantics.
    for (int i = 0; i < 40; i++) { // up to ~2s
        kr = task_for_pid(mach_task_self(), pid, &task);
        if (kr == KERN_SUCCESS) break;
        if (i == 5) (void)kill(pid, SIGSTOP);
        usleep(50 * 1000);
    }
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid failed after attach: %d\n", kr);
        (void)ptrace(PT_DETACH, pid, 0, 0);
        return -1;
    }
    printf("getting task port for pid %d\n", pid);
    *out_task = task;
    return 0;
}

static int detach_process(pid_t pid) {
    if (ptrace(PT_DETACH, pid, 0, 0) != 0) {
        // If we never attached (e.g., obtained task port directly), PT_DETACH
        // can fail with EPERM/ESRCH. Treat as non-fatal.
        return -1;
    }
    return 0;
}

static int patch_mach_msg_overwrite(pid_t pid) {
    mach_port_t task;
    if (attach_and_get_task(pid, &task) != 0) return -1;

    bool did_suspend = false;
    kern_return_t kr_suspend = task_suspend(task);
    if (kr_suspend == KERN_SUCCESS) {
        did_suspend = true;
    } else {
        fprintf(stderr, "warning: task_suspend failed (%d); proceeding without suspend\n", kr_suspend);
    }

    // Get dyld image info
    task_dyld_info_data_t dyldInfo;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_info(TASK_DYLD_INFO) failed: %d\n", kr);
        if (did_suspend) task_resume(task);
        detach_process(pid);
        return -1;
    }

    struct dyld_all_image_infos infos;
    if (!remote_read(task, dyldInfo.all_image_info_addr, &infos, sizeof(infos))) {
        fprintf(stderr, "failed to read dyld_all_image_infos\n");
        if (did_suspend) task_resume(task);
        detach_process(pid);
        return -1;
    }

    uint32_t imageCount = infos.infoArrayCount;
    struct dyld_image_info *remoteArray = (struct dyld_image_info *)infos.infoArray;
    size_t arrSize = imageCount * sizeof(struct dyld_image_info);
    struct dyld_image_info *localArray = (struct dyld_image_info *)malloc(arrSize);
    if (!localArray) { if (did_suspend) task_resume(task); detach_process(pid); return -1; }
    if (!remote_read(task, (mach_vm_address_t)(uintptr_t)remoteArray, localArray, arrSize)) {
        fprintf(stderr, "failed to read dyld_image_info array\n");
        free(localArray); if (did_suspend) task_resume(task); detach_process(pid); return -1;
    }

    parsed_image_t main_img = {0};
    bool main_found = false;
    for (uint32_t i = 0; i < imageCount; i++) {
        mach_vm_address_t header_addr = (mach_vm_address_t)(uintptr_t)localArray[i].imageLoadAddress;
        parsed_image_t img = {0};
        if (!load_image_info(task, header_addr, &img.info)) continue;
        if (!parse_load_commands(task, &img)) continue;
        if (img.info.filetype == MH_EXECUTE) {
            main_img = img;
            main_found = true;
            break;
        }
    }

    if (!main_found) {
        fprintf(stderr, "could not find main image\n");
        free(localArray); if (did_suspend) task_resume(task); detach_process(pid); return -1;
    }

    // Find our hook symbol in the main image
    mach_vm_address_t hook_addr = 0;
    if (!find_symbol_in_image(task, &main_img, "_xniff_remote_hook", &hook_addr)) {
        fprintf(stderr, "hook symbol _xniff_remote_hook not found in target\n");
        free(localArray); if (did_suspend) task_resume(task); detach_process(pid); return -1;
    }

    // Find mach_msg_overwrite in any image
    mach_vm_address_t mmov_addr = 0;
    for (uint32_t i = 0; i < imageCount && mmov_addr == 0; i++) {
        parsed_image_t img = {0};
        mach_vm_address_t header_addr = (mach_vm_address_t)(uintptr_t)localArray[i].imageLoadAddress;
        if (!load_image_info(task, header_addr, &img.info)) continue;
        if (!parse_load_commands(task, &img)) continue;
        if (find_symbol_in_image(task, &img, "_mach_msg_overwrite", &mmov_addr)) break;
    }

    if (mmov_addr == 0) {
        fprintf(stderr, "could not locate _mach_msg_overwrite in target\n");
        free(localArray); if (did_suspend) task_resume(task); detach_process(pid); return -1;
    }

    printf("found hook at 0x%llx, mach_msg_overwrite at 0x%llx\n",
           (unsigned long long)hook_addr, (unsigned long long)mmov_addr);

    trampoline_bank_t bank;
    if (trampoline_bank_init_task(&bank, task, 8, 0) != 0) {
        fprintf(stderr, "failed to init remote trampoline bank\n");
        free(localArray); if (did_suspend) task_resume(task); detach_process(pid); return -1;
    }

    size_t idx = 0;
    if (trampoline_bank_install_task(&bank, mmov_addr, hook_addr, &idx) != 0) {
        fprintf(stderr, "failed to install remote trampoline\n");
        trampoline_bank_deinit(&bank);
        free(localArray); if (did_suspend) task_resume(task); detach_process(pid); return -1;
    }
    printf("installed remote trampoline at slot %zu\n", idx);

    trampoline_bank_deinit(&bank);
    free(localArray);

    // Detach and let process run
    if (did_suspend) task_resume(task);
    detach_process(pid);
    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <pid>\n", prog);
}

int main(int argc, char **argv) {
    if (argc != 2) { usage(argv[0]); return 2; }
    pid_t pid = (pid_t)strtol(argv[1], NULL, 10);
    if (pid <= 0) { usage(argv[0]); return 2; }
    int rc = patch_mach_msg_overwrite(pid);
    return (rc == 0) ? 0 : 1;
}
