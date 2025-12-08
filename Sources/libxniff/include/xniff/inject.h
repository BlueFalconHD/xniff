#ifndef XNIFF_INJECT_H
#define XNIFF_INJECT_H

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Inject a dylib into a remote task by creating a thread that calls dlopen(path, RTLD_NOW).
 * On success, returns 0 and optionally sets out_handle to the return value of dlopen (best-effort).
 * May require task suspension by caller to avoid racing with target.
 */
int xniff_inject_dylib_task(mach_port_t task, const char *dylib_path, mach_vm_address_t *out_handle);

/* Load the xniff runtime (xniff-rt) into a remote task and resolve helper symbols.
 * Returns 0 on success and fills out addresses if non-NULL; otherwise returns -1.
 */
int xniff_load_runtime_task(mach_port_t task, const char *runtime_dylib_path,
                            mach_vm_address_t *out_ctx_enter,
                            mach_vm_address_t *out_ctx_exit,
                            mach_vm_address_t *out_exit_hook);

#ifdef __cplusplus
}
#endif

#endif /* XNIFF_INJECT_H */

