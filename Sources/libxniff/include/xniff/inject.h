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

#ifdef __cplusplus
}
#endif

#endif /* XNIFF_INJECT_H */
