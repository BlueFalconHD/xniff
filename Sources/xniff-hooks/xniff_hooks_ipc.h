#pragma once

// Shared IPC connection state for xniff-hooks (single connection per target process).
// Ensures writes are serialized and avoids multiple clients competing for the same listener.

// Lock/unlock around a send sequence.
void xniff_hooks_ipc_lock(void);
void xniff_hooks_ipc_unlock(void);

// Ensure a connected fd while the lock is held.
// Returns the connected fd (>= 0) or -1 on failure/backoff.
int xniff_hooks_ipc_ensure_fd_locked(void);

// Drop the current connection while the lock is held.
void xniff_hooks_ipc_drop_locked(void);
