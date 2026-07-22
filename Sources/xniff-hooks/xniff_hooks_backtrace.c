#include "xniff_hooks_backtrace.h"

#include <dlfcn.h>
#include <execinfo.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "xniff_hooks_runtime.h"

void xniff_hooks_add_backtrace(xniff_record_builder_t *builder) {
    if (!builder || !xniff_hooks_backtrace_is_enabled()) return;

    void *frames[XNIFF_BACKTRACE_MAX_FRAMES + 8u] = {0};
    int frame_count = backtrace(frames, (int)(sizeof(frames) / sizeof(frames[0])));
    if (frame_count <= 2) return;

    xniff_backtrace_section_t backtrace_section = {0};
    void *captured[XNIFF_BACKTRACE_MAX_FRAMES] = {0};
    for (int index = 2;
         index < frame_count && backtrace_section.count < XNIFF_BACKTRACE_MAX_FRAMES;
         index++) {
        void *pc = frames[index];
        captured[backtrace_section.count] = pc;
        backtrace_section.pcs[backtrace_section.count++] = (uint64_t)(uintptr_t)pc;
    }
    if (backtrace_section.count == 0) return;

    (void)xniff_record_add_section(builder, XNIFF_SECTION_BACKTRACE, 0,
                                   &backtrace_section, sizeof(backtrace_section));

    xniff_backtrace_symbols_header_t header = {
        .count = backtrace_section.count,
    };
    xniff_backtrace_symbol_t symbols[XNIFF_BACKTRACE_MAX_FRAMES] = {0};
    const char *names[XNIFF_BACKTRACE_MAX_FRAMES] = {0};
    const char *images[XNIFF_BACKTRACE_MAX_FRAMES] = {0};
    bool has_symbols = false;

    for (uint32_t index = 0; index < header.count; index++) {
        Dl_info info = {0};
        symbols[index].pc = (uint64_t)(uintptr_t)captured[index];
        if (dladdr(captured[index], &info) == 0) continue;
        if (info.dli_saddr) {
            symbols[index].sym_addr = (uint64_t)(uintptr_t)info.dli_saddr;
            has_symbols = true;
        }
        if (info.dli_sname) {
            symbols[index].name_len = (uint32_t)strnlen(info.dli_sname, 255u);
            names[index] = info.dli_sname;
            has_symbols |= symbols[index].name_len != 0;
        }
        if (info.dli_fname) {
            symbols[index].image_len = (uint32_t)strnlen(info.dli_fname, 255u);
            images[index] = info.dli_fname;
            has_symbols |= symbols[index].image_len != 0;
        }
        header.strings_len += symbols[index].name_len + symbols[index].image_len;
    }
    if (!has_symbols) return;

    size_t symbols_size = (size_t)header.count * sizeof(symbols[0]);
    size_t section_size = sizeof(header) + symbols_size + header.strings_len;
    uint8_t *section = malloc(section_size);
    if (!section) return;
    memcpy(section, &header, sizeof(header));
    memcpy(section + sizeof(header), symbols, symbols_size);

    size_t offset = sizeof(header) + symbols_size;
    for (uint32_t index = 0; index < header.count; index++) {
        if (symbols[index].name_len != 0) {
            memcpy(section + offset, names[index], symbols[index].name_len);
            offset += symbols[index].name_len;
        }
        if (symbols[index].image_len != 0) {
            memcpy(section + offset, images[index], symbols[index].image_len);
            offset += symbols[index].image_len;
        }
    }
    (void)xniff_record_add_section(builder, XNIFF_SECTION_BACKTRACE_SYMBOLS, 0,
                                   section, offset);
    free(section);
}
