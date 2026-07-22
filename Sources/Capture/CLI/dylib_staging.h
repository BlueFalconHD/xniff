#pragma once

#include <stddef.h>
#include <sys/types.h>

int xniff_stage_dylib_in_home(const char *source_path,
                              const char *home_directory,
                              char *output_path,
                              size_t output_path_size);

int xniff_stage_dylib_for_process(pid_t target_pid,
                                  const char *source_path,
                                  char *output_path,
                                  size_t output_path_size);
