#include "xpcdesert.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror("fopen"); return 1; }
    if (fseek(fp, 0, SEEK_END) != 0) { perror("fseek"); fclose(fp); return 1; }
    long fl = ftell(fp); if (fl < 0) { perror("ftell"); fclose(fp); return 1; }
    if (fseek(fp, 0, SEEK_SET) != 0) { perror("fseek"); fclose(fp); return 1; }
    size_t sz = (size_t)fl; uint8_t *buf = (uint8_t *)malloc(sz ? sz : 1); if (!buf) { fclose(fp); return 1; }
    size_t rd = fread(buf, 1, sz, fp); fclose(fp); if (rd != sz) { free(buf); fprintf(stderr, "short read\n"); return 1; }

    size_t off = 0; xpcd_object_t *root = NULL;
    if (xpcd_find_payload(buf, sz, 0, &off) == 0) root = xpcd_parse(buf + off, sz - off);
    else root = xpcd_parse(buf, sz);
    if (!root) { free(buf); fprintf(stderr, "parse failed\n"); return 1; }
    char *pretty = xpcd_format(root);
    if (pretty) { printf("%s\n", pretty); free(pretty); }
    xpcd_free(root); free(buf); return 0;
}

