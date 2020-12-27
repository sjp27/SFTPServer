# MIT License
#
# Copyright (c) 2020 Steve Pickford
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# FindLibSSH.cmake
# This will set the following variables:-
# LIBSSH_FOUND - LibSSH has been found
# LIBSSH_INCLUDE_DIRS - LibSSH include directories
# LIBSSH_LIBRARIES - LibSSH libraries to link

if(LIBSSH_LIBRARIES AND LIBSSH_INCLUDE_DIRS)
    set(LIBSSH_FOUND TRUE)
else(LIBSSH_LIBRARIES AND LIBSSH_INCLUDE_DIRS)
    find_path(LIBSSH_INCLUDE_DIR
        NAMES
        libssh/libssh.h
        PATHS
        ${CMAKE_INCLUDE_PATH}
    )
    find_path(LIBSSH_BUILT_INCLUDE_DIR
        NAMES
        libssh/libssh_version.h
        PATHS
        ${CMAKE_LIBRARY_PATH}
        PATH_SUFFIXES
        include
    )
    find_library(SSH_LIBRARY
        NAMES
        ssh
        PATHS
        ${CMAKE_LIBRARY_PATH}
        PATH_SUFFIXES
        lib
    )
    if(LIBSSH_INCLUDE_DIR AND SSH_LIBRARY)
        set(SSH_FOUND TRUE)
    endif(LIBSSH_INCLUDE_DIR AND SSH_LIBRARY)

    if(LIBSSH_BUILT_INCLUDE_DIR)
        set(LIBSSH_INCLUDE_DIRS ${LIBSSH_INCLUDE_DIR} ${LIBSSH_BUILT_INCLUDE_DIR})
    else(LIBSSH_BUILT_INCLUDE_DIR)
        set(LIBSSH_INCLUDE_DIRS ${LIBSSH_INCLUDE_DIR})
    endif(LIBSSH_BUILT_INCLUDE_DIR)

    if(SSH_FOUND)
        set(LIBSSH_LIBRARIES ${LIBSSH_LIBRARIES} ${SSH_LIBRARY})
    endif(SSH_FOUND)
endif(LIBSSH_LIBRARIES AND LIBSSH_INCLUDE_DIRS)