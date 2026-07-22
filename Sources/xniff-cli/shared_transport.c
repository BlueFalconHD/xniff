#include "shared_transport.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fileport.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <xniff/macho.h>

static void close_fd(int *fd) {
    if (!fd || *fd < 0) return;
    close(*fd);
    *fd = -1;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return -1;
    return 0;
}

static int set_close_on_exec(int fd, bool enabled) {
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0) return -1;
    if (enabled) flags |= FD_CLOEXEC;
    else flags &= ~FD_CLOEXEC;
    return fcntl(fd, F_SETFD, flags);
}

static int create_ring_backing(void) {
    char path[] = "/tmp/xniff-ring.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return -1;
    (void)unlink(path);
    if (ftruncate(fd, (off_t)sizeof(xniff_ipc_ring_t)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int xniff_shared_transport_create(xniff_shared_transport_t *transport) {
    if (!transport) {
        errno = EINVAL;
        return -1;
    }
    memset(transport, 0, sizeof(*transport));
    transport->ring_fd = -1;
    transport->wake_read_fd = -1;
    transport->wake_write_fd = -1;
    transport->ring_size = sizeof(xniff_ipc_ring_t);

    transport->ring_fd = create_ring_backing();
    if (transport->ring_fd < 0) goto fail;
    transport->ring = mmap(NULL, transport->ring_size, PROT_READ | PROT_WRITE,
                           MAP_SHARED, transport->ring_fd, 0);
    if (transport->ring == MAP_FAILED) {
        transport->ring = NULL;
        goto fail;
    }
    xniff_ipc_ring_initialize(transport->ring);

    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) goto fail;
    transport->wake_read_fd = sockets[0];
    transport->wake_write_fd = sockets[1];
    if (set_nonblocking(transport->wake_read_fd) != 0 ||
        set_nonblocking(transport->wake_write_fd) != 0 ||
        set_close_on_exec(transport->ring_fd, false) != 0 ||
        set_close_on_exec(transport->wake_write_fd, false) != 0) {
        goto fail;
    }
    int no_sigpipe = 1;
    (void)setsockopt(transport->wake_write_fd, SOL_SOCKET, SO_NOSIGPIPE,
                     &no_sigpipe, sizeof(no_sigpipe));
    return 0;

fail:
    xniff_shared_transport_destroy(transport);
    return -1;
}

void xniff_shared_transport_destroy(xniff_shared_transport_t *transport) {
    if (!transport) return;
    close_fd(&transport->ring_fd);
    close_fd(&transport->wake_read_fd);
    close_fd(&transport->wake_write_fd);
    if (transport->ring) {
        munmap(transport->ring, transport->ring_size);
        transport->ring = NULL;
    }
    transport->ring_size = 0;
}

void xniff_shared_transport_prepare_target_child(xniff_shared_transport_t *transport) {
    if (!transport) return;
    close_fd(&transport->wake_read_fd);
}

void xniff_shared_transport_prepare_listener_child(xniff_shared_transport_t *transport) {
    if (!transport) return;
    close_fd(&transport->ring_fd);
    close_fd(&transport->wake_write_fd);
}

void xniff_shared_transport_release_controller_reader(xniff_shared_transport_t *transport) {
    if (!transport) return;
    close_fd(&transport->wake_read_fd);
}

void xniff_shared_transport_release_controller_producer(xniff_shared_transport_t *transport) {
    if (!transport) return;
    close_fd(&transport->ring_fd);
    close_fd(&transport->wake_write_fd);
}

static int insert_send_right(mach_port_t task,
                             mach_port_t local_right,
                             mach_port_name_t *remote_name) {
    for (unsigned int attempt = 0; attempt < 16; attempt++) {
        mach_port_name_t name = MACH_PORT_NULL;
        kern_return_t kr = mach_port_allocate(task, MACH_PORT_RIGHT_DEAD_NAME, &name);
        if (kr != KERN_SUCCESS) return -1;
        kr = mach_port_mod_refs(task, name, MACH_PORT_RIGHT_DEAD_NAME, -1);
        if (kr != KERN_SUCCESS) return -1;
        kr = mach_port_insert_right(task, name, local_right, MACH_MSG_TYPE_COPY_SEND);
        if (kr == KERN_SUCCESS) {
            *remote_name = name;
            return 0;
        }
        if (kr != KERN_NAME_EXISTS) return -1;
    }
    return -1;
}

static int write_remote(mach_port_t task,
                        mach_vm_address_t address,
                        const void *value,
                        size_t length) {
    return mach_vm_write(task, address, (vm_offset_t)(uintptr_t)value,
                         (mach_msg_type_number_t)length) == KERN_SUCCESS ? 0 : -1;
}

int xniff_shared_transport_configure_target(xniff_shared_transport_t *transport,
                                            mach_port_t task,
                                            uint32_t capture_mode) {
    if (!transport || !transport->ring || transport->wake_write_fd < 0 ||
        task == MACH_PORT_NULL || capture_mode == XNIFF_CAPTURE_MODE_NONE) {
        errno = EINVAL;
        return -1;
    }

    mach_vm_address_t config_address = 0;
    if (xniff_find_symbol_in_image_path_contains(task, "xniff-hooks",
                                                  "_xniff_ipc_transport_config",
                                                  &config_address) != 0 &&
        xniff_find_symbol_in_image_path_contains(task, "xniff-hooks",
                                                  "xniff_ipc_transport_config",
                                                  &config_address) != 0) {
        return -1;
    }

    mach_vm_address_t remote_ring = 0;
    vm_prot_t current_protection = VM_PROT_NONE;
    vm_prot_t maximum_protection = VM_PROT_NONE;
    kern_return_t kr = mach_vm_remap(task, &remote_ring, transport->ring_size, 0,
                                    VM_FLAGS_ANYWHERE, mach_task_self(),
                                    (mach_vm_address_t)(uintptr_t)transport->ring,
                                    false, &current_protection, &maximum_protection,
                                    VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) return -1;

    fileport_t fileport = FILEPORT_NULL;
    if (fileport_makeport(transport->wake_write_fd, &fileport) != 0) {
        (void)mach_vm_deallocate(task, remote_ring, transport->ring_size);
        return -1;
    }

    bool suspended = task_suspend(task) == KERN_SUCCESS;
    mach_port_name_t remote_fileport = MACH_PORT_NULL;
    int result = insert_send_right(task, fileport, &remote_fileport);
    if (result == 0) {
        xniff_ipc_transport_config_t config = {0};
        config.magic = XNIFF_IPC_TRANSPORT_MAGIC;
        config.version = XNIFF_IPC_TRANSPORT_VERSION;
        config.struct_size = (uint16_t)sizeof(config);
        config.ring_address = remote_ring;
        config.wake_fd = -1;
        config.wake_fileport = remote_fileport;
        config.capture_mode = capture_mode;
        config.ready = 0;
        result = write_remote(task, config_address, &config, sizeof(config));
        if (result == 0) {
            const uint64_t ready = 1;
            result = write_remote(task,
                                  config_address + offsetof(xniff_ipc_transport_config_t, ready),
                                  &ready, sizeof(ready));
        }
    }
    if (suspended) (void)task_resume(task);
    (void)mach_port_deallocate(mach_task_self(), fileport);

    if (result != 0) {
        if (remote_fileport != MACH_PORT_NULL) {
            (void)mach_port_deallocate(task, remote_fileport);
        }
        (void)mach_vm_deallocate(task, remote_ring, transport->ring_size);
    }
    return result;
}

int xniff_shared_transport_pull(xniff_shared_transport_t *transport,
                                uint64_t *read_index,
                                uint8_t **stream,
                                size_t *stream_length,
                                size_t *stream_capacity) {
    if (!transport || !transport->ring || !read_index || !stream ||
        !stream_length || !stream_capacity) {
        errno = EINVAL;
        return -1;
    }
    xniff_ipc_ring_t *ring = transport->ring;
    uint64_t write_index = __atomic_load_n(&ring->hdr.write_idx, __ATOMIC_ACQUIRE);
    uint64_t capacity = ring->hdr.capacity;
    if (write_index < *read_index || write_index - *read_index > capacity) {
        errno = EOVERFLOW;
        return -1;
    }
    uint64_t available = write_index - *read_index;
    if (available == 0) return 0;
    if (available > SIZE_MAX - *stream_length) {
        errno = EOVERFLOW;
        return -1;
    }

    size_t needed = *stream_length + (size_t)available;
    if (*stream_capacity < needed) {
        size_t new_capacity = *stream_capacity ? *stream_capacity : 64u * 1024u;
        while (new_capacity < needed) {
            if (new_capacity > SIZE_MAX / 2) {
                errno = EOVERFLOW;
                return -1;
            }
            new_capacity *= 2;
        }
        uint8_t *resized = realloc(*stream, new_capacity);
        if (!resized) return -1;
        *stream = resized;
        *stream_capacity = new_capacity;
    }

    uint64_t offset = *read_index % capacity;
    uint64_t first = capacity - offset;
    if (first > available) first = available;
    memcpy(*stream + *stream_length, ring->data + offset, (size_t)first);
    if (available > first) {
        memcpy(*stream + *stream_length + first, ring->data,
               (size_t)(available - first));
    }
    *stream_length += (size_t)available;
    *read_index = write_index;
    __atomic_store_n(&ring->hdr.read_idx, write_index, __ATOMIC_RELEASE);
    return 1;
}

int xniff_shared_transport_wait(xniff_shared_transport_t *transport,
                                bool *producer_closed) {
    if (!transport || transport->wake_read_fd < 0 || !producer_closed) {
        errno = EINVAL;
        return -1;
    }
    struct pollfd poll_fd = {
        .fd = transport->wake_read_fd,
        .events = POLLIN | POLLHUP,
    };
    while (poll(&poll_fd, 1, -1) < 0) {
        if (errno != EINTR) return -1;
    }

    uint8_t buffer[256];
    for (;;) {
        ssize_t count = recv(transport->wake_read_fd, buffer, sizeof(buffer), 0);
        if (count > 0) continue;
        if (count == 0) {
            *producer_closed = true;
            return 0;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        return -1;
    }
    if ((poll_fd.revents & POLLHUP) != 0) *producer_closed = true;
    return 0;
}

bool xniff_shared_transport_is_drained(const xniff_shared_transport_t *transport,
                                       uint64_t read_index) {
    if (!transport || !transport->ring) return true;
    return __atomic_load_n(&transport->ring->hdr.write_idx, __ATOMIC_ACQUIRE) == read_index;
}
