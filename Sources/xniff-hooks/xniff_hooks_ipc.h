#pragma once

#include <stddef.h>

// Shared ring write lock for xniff-hooks.

// Lock/unlock around a send sequence.
void xniff_hooks_ipc_lock(void);
void xniff_hooks_ipc_unlock(void);

// Write bytes to the in-process ring while lock is held.
int xniff_hooks_ipc_write_locked(const void *buf, size_t len);
