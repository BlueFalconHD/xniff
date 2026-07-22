#include "cli_output.h"

#include <stdarg.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

typedef enum {
    XNIFF_OUTPUT_STYLE_INFO,
    XNIFF_OUTPUT_STYLE_SUCCESS,
    XNIFF_OUTPUT_STYLE_WARNING,
    XNIFF_OUTPUT_STYLE_ERROR,
    XNIFF_OUTPUT_STYLE_DETAIL,
} xniff_output_style_t;

static bool value_matches(const char *value, const char *expected) {
    return value && strcasecmp(value, expected) == 0;
}

static bool value_disables(const char *value) {
    return value_matches(value, "0") || value_matches(value, "false") ||
           value_matches(value, "no") || value_matches(value, "never") ||
           value_matches(value, "off");
}

static bool value_enables(const char *value) {
    return value_matches(value, "1") || value_matches(value, "true") ||
           value_matches(value, "yes") || value_matches(value, "always") ||
           value_matches(value, "on");
}

bool xniff_output_color_enabled(FILE *stream) {
    const char *xniff_color = getenv("XNIFF_COLOR");
    if (value_disables(xniff_color)) return false;
    if (value_enables(xniff_color)) return true;

    const char *no_color = getenv("NO_COLOR");
    if (no_color && *no_color) return false;

    const char *clicolor = getenv("CLICOLOR");
    if (value_disables(clicolor)) return false;

    const char *force_color = getenv("FORCE_COLOR");
    if (force_color) return !value_disables(force_color);

    const char *clicolor_force = getenv("CLICOLOR_FORCE");
    if (clicolor_force && !value_disables(clicolor_force)) return true;

    if (value_matches(getenv("TERM"), "dumb")) return false;
    return stream && isatty(fileno(stream));
}

bool xniff_output_verbose_enabled(void) {
    const char *value = getenv("XNIFF_VERBOSE");
    return value && *value && !value_disables(value);
}

static const char *style_sequence(xniff_output_style_t style) {
    switch (style) {
        case XNIFF_OUTPUT_STYLE_INFO:
            return "\033[1;36m";
        case XNIFF_OUTPUT_STYLE_SUCCESS:
            return "\033[1;32m";
        case XNIFF_OUTPUT_STYLE_WARNING:
            return "\033[1;33m";
        case XNIFF_OUTPUT_STYLE_ERROR:
            return "\033[1;31m";
        case XNIFF_OUTPUT_STYLE_DETAIL:
            return "\033[2m";
    }
    return "";
}

static void output_line(xniff_output_style_t style, const char *label,
                        const char *format, va_list arguments) {
    char message[2048];
    vsnprintf(message, sizeof(message), format, arguments);
    bool color = xniff_output_color_enabled(stderr);
    if (color) {
        fprintf(stderr, "%s%-9s\033[0m%s\n", style_sequence(style), label,
                message);
    } else {
        fprintf(stderr, "%-9s%s\n", label, message);
    }
    fflush(stderr);
}

void xniff_output_section(FILE *stream, const char *title) {
    if (!stream || !title) return;
    bool color = xniff_output_color_enabled(stream);
    if (color) fputs("\033[1;4m", stream);
    fputs(title, stream);
    if (color) fputs("\033[0m", stream);
    fputc('\n', stream);
}

void xniff_output_status(const char *label, const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    output_line(XNIFF_OUTPUT_STYLE_INFO, label, format, arguments);
    va_end(arguments);
}

void xniff_output_success(const char *label, const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    output_line(XNIFF_OUTPUT_STYLE_SUCCESS, label, format, arguments);
    va_end(arguments);
}

void xniff_output_warning(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    output_line(XNIFF_OUTPUT_STYLE_WARNING, "warning", format, arguments);
    va_end(arguments);
}

void xniff_output_error(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    output_line(XNIFF_OUTPUT_STYLE_ERROR, "error", format, arguments);
    va_end(arguments);
}

void xniff_output_detail(const char *label, const char *format, ...) {
    if (!xniff_output_verbose_enabled()) return;
    va_list arguments;
    va_start(arguments, format);
    output_line(XNIFF_OUTPUT_STYLE_DETAIL, label, format, arguments);
    va_end(arguments);
}
