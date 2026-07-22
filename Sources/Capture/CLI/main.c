#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "cli_output.h"
#include "cli_options.h"
#include "embedded_hooks.h"
#include "process_control.h"

int main(int argc, char **argv) {
    xniff_output_banner();

    xniff_cli_options_t options;
    int parse_result = xniff_cli_parse(argc, argv, &options);
    if (parse_result != 0) {
        xniff_cli_usage(argv[0]);
        return parse_result > 0 ? 0 : 2;
    }

    char embedded_hooks[PATH_MAX] = {0};
    const char *hooks_path = options.hooks_path;
    if (hooks_path == NULL) {
        if (xniff_extract_embedded_hooks(embedded_hooks, sizeof(embedded_hooks)) != 0) {
            xniff_output_error("failed to extract embedded hooks: %s", strerror(errno));
            return 1;
        }
        hooks_path = embedded_hooks;
    }

    int result = -1;
    switch (options.command) {
        case XNIFF_CLI_ATTACH:
            result = xniff_attach(options.pid, hooks_path, options.capture_mode,
                                  &options.listener);
            break;
        case XNIFF_CLI_LAUNCH:
            result = xniff_launch(hooks_path, options.capture_mode,
                                  options.target_user,
                                  (char *const *)options.launch_argv,
                                  &options.listener);
            break;
        default:
            break;
    }
    if (embedded_hooks[0] != '\0') unlink(embedded_hooks);
    return result == 0 ? 0 : 1;
}
