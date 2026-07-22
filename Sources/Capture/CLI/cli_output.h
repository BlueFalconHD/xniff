#ifndef XNIFF_CLI_OUTPUT_H
#define XNIFF_CLI_OUTPUT_H

#include <stdbool.h>
#include <stdio.h>

bool xniff_output_color_enabled(FILE *stream);
bool xniff_output_verbose_enabled(void);

void xniff_output_section(FILE *stream, const char *title);
void xniff_output_status(const char *label, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
void xniff_output_success(const char *label, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
void xniff_output_warning(const char *format, ...)
    __attribute__((format(printf, 1, 2)));
void xniff_output_error(const char *format, ...)
    __attribute__((format(printf, 1, 2)));
void xniff_output_detail(const char *label, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

#endif
