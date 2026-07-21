#pragma once

#include <stdbool.h>
#include <stddef.h>

bool xniff_capture_file_is_configured(void);
int xniff_capture_file_write(const void *record, size_t record_len);

