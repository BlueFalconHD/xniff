# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file LICENSE.rst or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/Users/hayes/Stores/repos/bluefalconhd/xniff/_deps/frida_gum_devkit-src")
  file(MAKE_DIRECTORY "/Users/hayes/Stores/repos/bluefalconhd/xniff/_deps/frida_gum_devkit-src")
endif()
file(MAKE_DIRECTORY
  "/Users/hayes/Stores/repos/bluefalconhd/xniff/_deps/frida_gum_devkit-build"
  "/Users/hayes/Stores/repos/bluefalconhd/xniff/_deps/frida_gum_devkit-subbuild/frida_gum_devkit-populate-prefix"
  "/Users/hayes/Stores/repos/bluefalconhd/xniff/_deps/frida_gum_devkit-subbuild/frida_gum_devkit-populate-prefix/tmp"
  "/Users/hayes/Stores/repos/bluefalconhd/xniff/_deps/frida_gum_devkit-subbuild/frida_gum_devkit-populate-prefix/src/frida_gum_devkit-populate-stamp"
  "/Users/hayes/Stores/repos/bluefalconhd/xniff/_deps/frida_gum_devkit-subbuild/frida_gum_devkit-populate-prefix/src"
  "/Users/hayes/Stores/repos/bluefalconhd/xniff/_deps/frida_gum_devkit-subbuild/frida_gum_devkit-populate-prefix/src/frida_gum_devkit-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/Users/hayes/Stores/repos/bluefalconhd/xniff/_deps/frida_gum_devkit-subbuild/frida_gum_devkit-populate-prefix/src/frida_gum_devkit-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/Users/hayes/Stores/repos/bluefalconhd/xniff/_deps/frida_gum_devkit-subbuild/frida_gum_devkit-populate-prefix/src/frida_gum_devkit-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
