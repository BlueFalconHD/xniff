#include <xpc/xpc.h>
#include <dispatch/dispatch.h>

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

typedef struct {
    pid_t pid;
    uint32_t id;
    xpc_connection_t conn; // may be NULL until connected
} peer_info_t;

typedef struct {
    pthread_mutex_t mu;
    peer_info_t *peers;
    size_t count;
    size_t cap;
} peer_set_t;

static void peers_init(peer_set_t *ps) {
    memset(ps, 0, sizeof(*ps));
    pthread_mutex_init(&ps->mu, NULL);
}

static void peers_destroy(peer_set_t *ps) {
    if (!ps) return;
    pthread_mutex_lock(&ps->mu);
    for (size_t i = 0; i < ps->count; i++) {
        if (ps->peers[i].conn) xpc_release(ps->peers[i].conn);
    }
    free(ps->peers);
    ps->peers = NULL;
    ps->count = ps->cap = 0;
    pthread_mutex_unlock(&ps->mu);
    pthread_mutex_destroy(&ps->mu);
}

static peer_info_t *peers_find_by_pid_locked(peer_set_t *ps, pid_t pid) {
    for (size_t i = 0; i < ps->count; i++) {
        if (ps->peers[i].pid == pid) return &ps->peers[i];
    }
    return NULL;
}

static peer_info_t *peers_find_by_id_locked(peer_set_t *ps, uint32_t id) {
    for (size_t i = 0; i < ps->count; i++) {
        if (ps->peers[i].id == id) return &ps->peers[i];
    }
    return NULL;
}

static peer_info_t *peers_upsert_meta(peer_set_t *ps, pid_t pid, uint32_t id) {
    pthread_mutex_lock(&ps->mu);
    peer_info_t *p = peers_find_by_pid_locked(ps, pid);
    if (!p) {
        if (ps->count == ps->cap) {
            size_t nc = ps->cap ? ps->cap * 2 : 8;
            peer_info_t *np = (peer_info_t *)realloc(ps->peers, nc * sizeof(*np));
            if (!np) {
                pthread_mutex_unlock(&ps->mu);
                return NULL;
            }
            ps->peers = np;
            ps->cap = nc;
        }
        p = &ps->peers[ps->count++];
        memset(p, 0, sizeof(*p));
        p->pid = pid;
    }
    p->id = id;
    pthread_mutex_unlock(&ps->mu);
    return p;
}

static void peers_set_conn(peer_set_t *ps, pid_t pid, xpc_connection_t conn) {
    pthread_mutex_lock(&ps->mu);
    peer_info_t *p = peers_find_by_pid_locked(ps, pid);
    if (!p) {
        if (ps->count == ps->cap) {
            size_t nc = ps->cap ? ps->cap * 2 : 8;
            peer_info_t *np = (peer_info_t *)realloc(ps->peers, nc * sizeof(*np));
            if (!np) {
                pthread_mutex_unlock(&ps->mu);
                return;
            }
            ps->peers = np;
            ps->cap = nc;
        }
        p = &ps->peers[ps->count++];
        memset(p, 0, sizeof(*p));
        p->pid = pid;
        p->id = 0;
    }
    if (p->conn) xpc_release(p->conn);
    p->conn = conn;
    if (p->conn) xpc_retain(p->conn);
    pthread_mutex_unlock(&ps->mu);
}

static xpc_connection_t peers_pick_random_conn(peer_set_t *ps, uint32_t self_id, uint32_t *peer_id_out) {
    xpc_connection_t picked = NULL;
    pthread_mutex_lock(&ps->mu);
    size_t eligible = 0;
    for (size_t i = 0; i < ps->count; i++) {
        if (ps->peers[i].conn && ps->peers[i].id != self_id) eligible++;
    }
    if (eligible == 0) {
        pthread_mutex_unlock(&ps->mu);
        return NULL;
    }
    uint32_t idx = arc4random_uniform((uint32_t)eligible);
    for (size_t i = 0; i < ps->count; i++) {
        if (!ps->peers[i].conn) continue;
        if (ps->peers[i].id == self_id) continue;
        if (idx == 0) {
            picked = ps->peers[i].conn;
            if (peer_id_out) *peer_id_out = ps->peers[i].id;
            xpc_retain(picked);
            break;
        }
        idx--;
    }
    pthread_mutex_unlock(&ps->mu);
    return picked;
}

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static void fill_random_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)arc4random_uniform(256);
}

static xpc_object_t make_complex_payload(uint32_t from_id, uint32_t to_id, uint64_t seq) {
    xpc_object_t root = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(root, "from", from_id);
    xpc_dictionary_set_uint64(root, "to", to_id);
    xpc_dictionary_set_uint64(root, "seq", seq);
    xpc_dictionary_set_uint64(root, "mono_ms", monotonic_ms());
    xpc_dictionary_set_bool(root, "flag", (seq & 1) != 0);
    xpc_dictionary_set_double(root, "ratio", (double)(seq % 1000) / 1000.0);

    xpc_object_t meta = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(meta, "tag", "xniff-xpc-stress");
    xpc_dictionary_set_uint64(meta, "pid", (uint64_t)getpid());
    xpc_dictionary_set_uint64(meta, "tid", (uint64_t)(uintptr_t)pthread_self());
    xpc_dictionary_set_value(root, "meta", meta);
    xpc_release(meta);

    // Nested array with mixed types.
    xpc_object_t arr = xpc_array_create(NULL, 0);
    for (int i = 0; i < 8; i++) {
        xpc_object_t d = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_int64(d, "i", i);
        xpc_dictionary_set_uint64(d, "r", arc4random());
        xpc_dictionary_set_bool(d, "b", (arc4random() & 1) != 0);
        xpc_array_append_value(arr, d);
        xpc_release(d);
    }
    xpc_dictionary_set_value(root, "items", arr);
    xpc_release(arr);

    // Data blobs sized to frequently trigger OOL descriptors.
    uint32_t blob_sz = 1024u + arc4random_uniform(128u * 1024u);
    uint8_t *blob = (uint8_t *)malloc(blob_sz);
    if (blob) {
        fill_random_bytes(blob, blob_sz);
        xpc_object_t data = xpc_data_create(blob, blob_sz);
        xpc_dictionary_set_value(root, "blob", data);
        xpc_release(data);
        free(blob);
    }

    // Occasionally include an fd to generate port descriptors.
    if ((seq % 8u) == 0) {
        int fds[2] = {-1, -1};
        if (pipe(fds) == 0) {
            (void)write(fds[1], "xniff", 5);
            close(fds[1]);
            xpc_dictionary_set_fd(root, "fd", fds[0]);
            close(fds[0]);
        }
    }

    return root;
}

typedef struct {
    atomic_bool *running;
    peer_set_t *peers;
    uint32_t self_id;
    uint32_t min_sleep_ms;
    uint32_t max_sleep_ms;
    atomic_uint_fast64_t *seq;
} sender_ctx_t;

static void *sender_thread(void *arg) {
    sender_ctx_t *ctx = (sender_ctx_t *)arg;
    while (atomic_load_explicit(ctx->running, memory_order_relaxed)) {
        uint32_t peer_id = 0;
        xpc_connection_t conn = peers_pick_random_conn(ctx->peers, ctx->self_id, &peer_id);
        if (!conn) {
            usleep(10 * 1000);
            continue;
        }

        uint64_t seq = atomic_fetch_add_explicit(ctx->seq, 1, memory_order_relaxed);
        xpc_object_t msg = make_complex_payload(ctx->self_id, peer_id, seq);

        uint32_t mode = arc4random_uniform(3);
        if (mode == 0) {
            xpc_connection_send_message(conn, msg);
        } else if (mode == 1) {
            xpc_connection_send_message_with_reply(conn, msg, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^(xpc_object_t reply) {
                (void)reply;
            });
        } else {
            xpc_object_t reply = xpc_connection_send_message_with_reply_sync(conn, msg);
            if (reply) xpc_release(reply);
        }

        xpc_release(msg);
        xpc_release(conn);

        uint32_t ms = ctx->min_sleep_ms;
        if (ctx->max_sleep_ms > ms) ms += arc4random_uniform(ctx->max_sleep_ms - ms + 1);
        usleep(ms * 1000u);
    }
    return NULL;
}

static void install_peer_handlers(peer_set_t *peers, xpc_connection_t c) {
    // Replies are driven by the receiver; respond when a reply port is present.
    xpc_connection_set_event_handler(c, ^(xpc_object_t event) {
        xpc_type_t t = xpc_get_type(event);
        if (t == XPC_TYPE_DICTIONARY) {
            xpc_object_t reply = xpc_dictionary_create_reply(event);
            if (reply) {
                xpc_dictionary_set_string(reply, "ok", "1");
                xpc_connection_send_message(c, reply);
                xpc_release(reply);
            }
        } else if (t == XPC_TYPE_ERROR) {
            // Drop on disconnect.
        }
    });
    xpc_connection_activate(c);

    pid_t pid = xpc_connection_get_pid(c);
    if (pid > 0) peers_set_conn(peers, pid, c);
}

static int run_worker(const char *service, uint32_t self_id, uint32_t workers, uint32_t threads, uint32_t duration_s, uint32_t min_ms, uint32_t max_ms) {
    (void)workers;
    dispatch_queue_t q = dispatch_queue_create("xniff-xpc-stress.worker", DISPATCH_QUEUE_SERIAL);
    __block peer_set_t peers;
    peers_init(&peers);

    // Listener to accept inbound peer connections.
    xpc_connection_t listener = xpc_connection_create(NULL, q);
    xpc_connection_set_event_handler(listener, ^(xpc_object_t peer) {
        xpc_type_t t = xpc_get_type(peer);
        if (t != XPC_TYPE_CONNECTION) return;
        xpc_connection_t pc = (xpc_connection_t)peer;
        install_peer_handlers(&peers, pc);
    });
    xpc_connection_activate(listener);

    // Rendezvous connection (Mach service) used only to exchange endpoints.
    xpc_connection_t rv = xpc_connection_create_mach_service(service, q, 0);
    xpc_connection_set_event_handler(rv, ^(xpc_object_t event) {
        xpc_type_t t = xpc_get_type(event);
        if (t == XPC_TYPE_DICTIONARY) {
            const char *type = xpc_dictionary_get_string(event, "type");
            if (type && strcmp(type, "peer") == 0) {
                pid_t pid = (pid_t)xpc_dictionary_get_int64(event, "pid");
                uint32_t id = (uint32_t)xpc_dictionary_get_uint64(event, "id");
                (void)peers_upsert_meta(&peers, pid, id);

                // Deterministic rule to avoid double-connect: lower id initiates.
                if (self_id < id) {
                    xpc_connection_t pc = xpc_dictionary_create_connection(event, "listener");
                    if (pc) install_peer_handlers(&peers, pc);
                }
            }
        }
    });
    xpc_connection_activate(rv);

    // Register our anonymous listener with the rendezvous server.
    xpc_object_t reg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(reg, "type", "register");
    xpc_dictionary_set_int64(reg, "pid", (int64_t)getpid());
    xpc_dictionary_set_uint64(reg, "id", self_id);
    xpc_dictionary_set_connection(reg, "listener", listener);
    xpc_connection_send_message(rv, reg);
    xpc_release(reg);

    // Start senders.
    atomic_bool running = true;
    atomic_uint_fast64_t seq = 1;
    sender_ctx_t ctx = {
        .running = &running,
        .peers = &peers,
        .self_id = self_id,
        .min_sleep_ms = min_ms,
        .max_sleep_ms = max_ms,
        .seq = &seq,
    };

    pthread_t *ths = (pthread_t *)calloc(threads, sizeof(*ths));
    if (!ths) return 1;
    for (uint32_t i = 0; i < threads; i++) {
        (void)pthread_create(&ths[i], NULL, sender_thread, &ctx);
    }

    sleep(duration_s);
    atomic_store_explicit(&running, false, memory_order_relaxed);
    for (uint32_t i = 0; i < threads; i++) pthread_join(ths[i], NULL);
    free(ths);

    xpc_release(rv);
    xpc_release(listener);
    peers_destroy(&peers);
    return 0;
}

typedef struct {
    xpc_connection_t peer;
    pid_t pid;
    uint32_t id;
    xpc_object_t listener_ep;
} reg_t;

typedef struct {
    pthread_mutex_t mu;
    reg_t *regs;
    size_t count;
    size_t cap;
} reg_set_t;

static void regs_init(reg_set_t *rs) {
    memset(rs, 0, sizeof(*rs));
    pthread_mutex_init(&rs->mu, NULL);
}

static void regs_free(reg_set_t *rs) {
    if (!rs) return;
    pthread_mutex_lock(&rs->mu);
    for (size_t i = 0; i < rs->count; i++) {
        if (rs->regs[i].peer) xpc_release(rs->regs[i].peer);
        if (rs->regs[i].listener_ep) xpc_release(rs->regs[i].listener_ep);
    }
    free(rs->regs);
    rs->regs = NULL;
    rs->count = rs->cap = 0;
    pthread_mutex_unlock(&rs->mu);
    pthread_mutex_destroy(&rs->mu);
}

static void send_peer_announcement(xpc_connection_t to_peer, const reg_t *p) {
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(msg, "type", "peer");
    xpc_dictionary_set_int64(msg, "pid", (int64_t)p->pid);
    xpc_dictionary_set_uint64(msg, "id", p->id);
    xpc_dictionary_set_value(msg, "listener", p->listener_ep);
    xpc_connection_send_message(to_peer, msg);
    xpc_release(msg);
}

static void handle_register(reg_set_t *rs, xpc_connection_t peer, xpc_object_t event) {
    pid_t pid = (pid_t)xpc_dictionary_get_int64(event, "pid");
    uint32_t id = (uint32_t)xpc_dictionary_get_uint64(event, "id");
    xpc_object_t ep = xpc_dictionary_get_value(event, "listener");
    if (!ep) return;

    reg_t newr = {0};
    newr.peer = peer;
    newr.pid = pid;
    newr.id = id;
    newr.listener_ep = ep;
    xpc_retain(newr.peer);
    xpc_retain(newr.listener_ep);

    pthread_mutex_lock(&rs->mu);
    // Send existing peers to the new worker.
    for (size_t i = 0; i < rs->count; i++) {
        send_peer_announcement(peer, &rs->regs[i]);
    }

    // Broadcast new worker to existing peers.
    for (size_t i = 0; i < rs->count; i++) {
        send_peer_announcement(rs->regs[i].peer, &newr);
    }

    // Store.
    if (rs->count == rs->cap) {
        size_t nc = rs->cap ? rs->cap * 2 : 8;
        reg_t *nr = (reg_t *)realloc(rs->regs, nc * sizeof(*nr));
        if (nr) {
            rs->regs = nr;
            rs->cap = nc;
        }
    }
    if (rs->count < rs->cap) {
        rs->regs[rs->count++] = newr;
        // newr ownership transferred to array.
    } else {
        xpc_release(newr.peer);
        xpc_release(newr.listener_ep);
    }
    pthread_mutex_unlock(&rs->mu);
}

static int run_server(const char *service) {
    dispatch_queue_t q = dispatch_queue_create("xniff-xpc-stress.server", DISPATCH_QUEUE_SERIAL);
    __block reg_set_t regs;
    regs_init(&regs);

    xpc_connection_t listener = xpc_connection_create_mach_service(service, q, XPC_CONNECTION_MACH_SERVICE_LISTENER);
    xpc_connection_set_event_handler(listener, ^(xpc_object_t peer) {
        if (xpc_get_type(peer) != XPC_TYPE_CONNECTION) return;
        xpc_connection_t pc = (xpc_connection_t)peer;
        xpc_connection_set_event_handler(pc, ^(xpc_object_t event) {
            xpc_type_t t = xpc_get_type(event);
            if (t == XPC_TYPE_DICTIONARY) {
                const char *type = xpc_dictionary_get_string(event, "type");
                if (type && strcmp(type, "register") == 0) {
                    handle_register(&regs, pc, event);
                }
            } else if (t == XPC_TYPE_ERROR) {
                // ignore
            }
        });
        xpc_connection_activate(pc);
    });
    xpc_connection_activate(listener);

    dispatch_main();
    regs_free(&regs);
    return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "usage:\n"
            "  %s --server <mach-service-name>\n"
            "  %s --worker <mach-service-name> --id <n> [--workers N] [--threads T] [--duration S] [--min-ms A] [--max-ms B]\n"
            "  %s --run [--workers N] [--threads T] [--duration S] [--min-ms A] [--max-ms B]\n",
            argv0, argv0, argv0);
}

static char *realpath_dup(const char *path) {
    if (!path) return NULL;
    char tmp[PATH_MAX];
    if (!realpath(path, tmp)) return NULL;
    return strdup(tmp);
}

static int write_launchd_plist(const char *plist_path, const char *label, const char *service, const char *bin_path) {
    FILE *fp = fopen(plist_path, "w");
    if (!fp) return -1;

    fprintf(fp,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\">\n"
            "<dict>\n"
            "  <key>Label</key><string>%s</string>\n"
            "  <key>ProgramArguments</key>\n"
            "  <array>\n"
            "    <string>%s</string>\n"
            "    <string>--server</string>\n"
            "    <string>%s</string>\n"
            "  </array>\n"
            "  <key>MachServices</key>\n"
            "  <dict>\n"
            "    <key>%s</key><true/>\n"
            "  </dict>\n"
            "  <key>RunAtLoad</key><true/>\n"
            "  <key>KeepAlive</key><true/>\n"
            "  <key>StandardOutPath</key><string>/tmp/xniff-xpc-stress-server.out</string>\n"
            "  <key>StandardErrorPath</key><string>/tmp/xniff-xpc-stress-server.err</string>\n"
            "</dict>\n"
            "</plist>\n",
            label, bin_path, service, service);

    fclose(fp);
    return 0;
}

static int run_launchctl(const char *cmd, const char *a0, const char *a1, const char *a2) {
    pid_t pid = 0;
    const char *argvv[] = {"/bin/launchctl", cmd, a0, a1, a2, NULL};
    int rc = posix_spawn(&pid, argvv[0], NULL, NULL, (char *const *)argvv, environ);
    if (rc != 0) return -1;
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) return -1;
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return -1;
    return 0;
}

static int spawn_worker(const char *bin_path, const char *service, uint32_t id, uint32_t workers, uint32_t threads, uint32_t duration_s, uint32_t min_ms, uint32_t max_ms, pid_t *out_pid) {
    char id_s[32], workers_s[32], threads_s[32], dur_s[32], min_s[32], max_s[32];
    snprintf(id_s, sizeof(id_s), "%u", id);
    snprintf(workers_s, sizeof(workers_s), "%u", workers);
    snprintf(threads_s, sizeof(threads_s), "%u", threads);
    snprintf(dur_s, sizeof(dur_s), "%u", duration_s);
    snprintf(min_s, sizeof(min_s), "%u", min_ms);
    snprintf(max_s, sizeof(max_s), "%u", max_ms);

    const char *argvv[] = {
        bin_path,
        "--worker", service,
        "--id", id_s,
        "--workers", workers_s,
        "--threads", threads_s,
        "--duration", dur_s,
        "--min-ms", min_s,
        "--max-ms", max_s,
        NULL,
    };
    pid_t pid = 0;
    int rc = posix_spawn(&pid, argvv[0], NULL, NULL, (char *const *)argvv, environ);
    if (rc != 0) return -1;
    if (out_pid) *out_pid = pid;
    return 0;
}

static int run_orchestrator(const char *argv0, uint32_t workers, uint32_t threads, uint32_t duration_s, uint32_t min_ms, uint32_t max_ms) {
    char *bin_path = realpath_dup(argv0);
    if (!bin_path) {
        fprintf(stderr, "realpath(%s) failed: %s\n", argv0, strerror(errno));
        return 1;
    }

    uint32_t r = arc4random();
    char label[256];
    char service[256];
    snprintf(label, sizeof(label), "com.bluefalconhd.xniff.xpcstress.%d.%u", (int)getpid(), r);
    snprintf(service, sizeof(service), "com.bluefalconhd.xniff.xpcstress.service.%d.%u", (int)getpid(), r);

    char plist_path[PATH_MAX];
    snprintf(plist_path, sizeof(plist_path), "/tmp/%s.plist", label);
    if (write_launchd_plist(plist_path, label, service, bin_path) != 0) {
        fprintf(stderr, "failed to write plist %s\n", plist_path);
        free(bin_path);
        return 1;
    }

    uid_t uid = getuid();
    char domain[64];
    snprintf(domain, sizeof(domain), "gui/%u", (unsigned)uid);

    if (run_launchctl("bootstrap", domain, plist_path, NULL) != 0) {
        fprintf(stderr, "launchctl bootstrap failed\n");
        unlink(plist_path);
        free(bin_path);
        return 1;
    }

    pid_t *pids = (pid_t *)calloc(workers, sizeof(*pids));
    if (!pids) {
        (void)run_launchctl("bootout", domain, plist_path, NULL);
        unlink(plist_path);
        free(bin_path);
        return 1;
    }

    for (uint32_t i = 0; i < workers; i++) {
        if (spawn_worker(bin_path, service, i + 1, workers, threads, duration_s, min_ms, max_ms, &pids[i]) != 0) {
            fprintf(stderr, "failed to spawn worker %u\n", i);
        }
    }

    sleep(duration_s + 1);

    for (uint32_t i = 0; i < workers; i++) {
        if (pids[i] > 0) kill(pids[i], SIGTERM);
    }
    for (uint32_t i = 0; i < workers; i++) {
        if (pids[i] > 0) (void)waitpid(pids[i], NULL, 0);
    }

    free(pids);
    (void)run_launchctl("bootout", domain, plist_path, NULL);
    unlink(plist_path);
    free(bin_path);
    return 0;
}

static bool arg_eq(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }

static const char *arg_value(int argc, char **argv, int *i) {
    if (!argv || !i) return NULL;
    if (*i + 1 >= argc) return NULL;
    (*i)++;
    return argv[*i];
}

int main(int argc, char **argv) {
    const char *mode = NULL;
    const char *service = NULL;
    uint32_t id = 1;
    uint32_t workers = 6;
    uint32_t threads = 4;
    uint32_t duration_s = 10;
    uint32_t min_ms = 10;
    uint32_t max_ms = 250;

    for (int i = 1; i < argc; i++) {
        if (arg_eq(argv[i], "--server")) {
            mode = "server";
            service = arg_value(argc, argv, &i);
        } else if (arg_eq(argv[i], "--worker")) {
            mode = "worker";
            service = arg_value(argc, argv, &i);
        } else if (arg_eq(argv[i], "--run")) {
            mode = "run";
        } else if (arg_eq(argv[i], "--id")) {
            const char *v = arg_value(argc, argv, &i);
            if (v) id = (uint32_t)strtoul(v, NULL, 0);
        } else if (arg_eq(argv[i], "--workers")) {
            const char *v = arg_value(argc, argv, &i);
            if (v) workers = (uint32_t)strtoul(v, NULL, 0);
        } else if (arg_eq(argv[i], "--threads")) {
            const char *v = arg_value(argc, argv, &i);
            if (v) threads = (uint32_t)strtoul(v, NULL, 0);
        } else if (arg_eq(argv[i], "--duration")) {
            const char *v = arg_value(argc, argv, &i);
            if (v) duration_s = (uint32_t)strtoul(v, NULL, 0);
        } else if (arg_eq(argv[i], "--min-ms")) {
            const char *v = arg_value(argc, argv, &i);
            if (v) min_ms = (uint32_t)strtoul(v, NULL, 0);
        } else if (arg_eq(argv[i], "--max-ms")) {
            const char *v = arg_value(argc, argv, &i);
            if (v) max_ms = (uint32_t)strtoul(v, NULL, 0);
        } else if (arg_eq(argv[i], "--help") || arg_eq(argv[i], "-h")) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (!mode) {
        usage(argv[0]);
        return 2;
    }

    if (arg_eq(mode, "server")) {
        if (!service) { usage(argv[0]); return 2; }
        return run_server(service);
    }
    if (arg_eq(mode, "worker")) {
        if (!service) { usage(argv[0]); return 2; }
        if (threads == 0) threads = 1;
        if (duration_s == 0) duration_s = 1;
        return run_worker(service, id, workers, threads, duration_s, min_ms, max_ms);
    }
    if (arg_eq(mode, "run")) {
        if (workers == 0) workers = 1;
        if (threads == 0) threads = 1;
        if (duration_s == 0) duration_s = 1;
        return run_orchestrator(argv[0], workers, threads, duration_s, min_ms, max_ms);
    }

    return 2;
}
