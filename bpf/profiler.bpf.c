#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <stdbool.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_DATA_SIZE 256

enum direction {
    DIR_SEND = 0,
    DIR_RECV = 1,
};

struct conn_info {
    __u16 family;
    __u16 sport;
    __u16 dport;
    __u8 saddr[16];
    __u8 daddr[16];
};

struct event {
    __u64 ts;
    __u32 pid;
    __u32 tid;
    __u32 data_len;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 direction;
    char comm[16];
    __u8 saddr[16];
    __u8 daddr[16];
    __u8 data[MAX_DATA_SIZE];
};

struct recv_args {
    int fd;
    void *buf;
    size_t len;
};

struct accept_args {
    int fd;
    struct sockaddr *addr;
    int *addrlen;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct recv_args);
    __uint(max_entries, 10240);
} recv_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct accept_args);
    __uint(max_entries, 1024);
} accept_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct conn_info);
    __uint(max_entries, 16384);
} conn_map SEC(".maps");

static __always_inline __u64 make_key(__u32 pid, __u32 fd) {
    return ((__u64)pid << 32) | fd;
}

static __always_inline void copy_bytes(__u8 *dst, const __u8 *src, __u32 len) {
#pragma clang loop unroll(full)
    for (int i = 0; i < 16; i++) {
        if (i < len) {
            dst[i] = src[i];
        } else {
            dst[i] = 0;
        }
    }
}

static __always_inline int read_sockaddr(struct sockaddr *addr, struct conn_info *info, bool is_remote) {
    if (!addr || !info) {
        return -1;
    }

    __u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), &addr->sa_family) != 0) {
        return -1;
    }

    info->family = family;

    if (family == AF_INET) {
        struct sockaddr_in saddr = {};
        if (bpf_probe_read_user(&saddr, sizeof(saddr), addr) != 0) {
            return -1;
        }

        if (is_remote) {
            info->dport = saddr.sin_port;
            copy_bytes(info->daddr, (const __u8 *)&saddr.sin_addr.s_addr, 4);
        } else {
            info->sport = saddr.sin_port;
            copy_bytes(info->saddr, (const __u8 *)&saddr.sin_addr.s_addr, 4);
        }
    } else if (family == AF_INET6) {
        struct sockaddr_in6 saddr6 = {};
        if (bpf_probe_read_user(&saddr6, sizeof(saddr6), addr) != 0) {
            return -1;
        }

        if (is_remote) {
            info->dport = saddr6.sin6_port;
            copy_bytes(info->daddr, (const __u8 *)&saddr6.sin6_addr.in6_u.u6_addr8[0], 16);
        } else {
            info->sport = saddr6.sin6_port;
            copy_bytes(info->saddr, (const __u8 *)&saddr6.sin6_addr.in6_u.u6_addr8[0], 16);
        }
    } else {
        return -1;
    }

    return 0;
}

static __always_inline void maybe_update_conn_from_addr(__u64 key, struct sockaddr *addr, bool is_remote) {
    struct conn_info info = {};
    int res = read_sockaddr(addr, &info, is_remote);
    if (res == 0) {
        struct conn_info *existing = bpf_map_lookup_elem(&conn_map, &key);
        if (existing) {
            if (info.family != 0) {
                existing->family = info.family;
            }
            if (is_remote) {
                existing->dport = info.dport;
                copy_bytes(existing->daddr, info.daddr, 16);
            } else {
                existing->sport = info.sport;
                copy_bytes(existing->saddr, info.saddr, 16);
            }
            bpf_map_update_elem(&conn_map, &key, existing, BPF_ANY);
        } else {
            bpf_map_update_elem(&conn_map, &key, &info, BPF_ANY);
        }
    }
}

static __always_inline struct conn_info *lookup_conn(__u32 pid, int fd) {
    __u64 key = make_key(pid, fd);
    return bpf_map_lookup_elem(&conn_map, &key);
}

static __always_inline void fill_event_conn(struct event *e, struct conn_info *info) {
    if (!e || !info) {
        return;
    }
    e->family = info->family;
    e->sport = info->sport;
    e->dport = info->dport;
    copy_bytes(e->saddr, info->saddr, 16);
    copy_bytes(e->daddr, info->daddr, 16);
}

SEC("kprobe/__x64_sys_bind")
int sys_bind(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int fd = (int)PT_REGS_PARM1(ctx);
    struct sockaddr *umyaddr = (struct sockaddr *)PT_REGS_PARM2(ctx);

    struct conn_info info = {};
    if (read_sockaddr(umyaddr, &info, false) == 0) {
        __u64 key = make_key(pid, fd);
        bpf_map_update_elem(&conn_map, &key, &info, BPF_ANY);
    }
    return 0;
}

SEC("kprobe/__x64_sys_connect")
int sys_connect(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int fd = (int)PT_REGS_PARM1(ctx);
    struct sockaddr *uservaddr = (struct sockaddr *)PT_REGS_PARM2(ctx);

    __u64 key = make_key(pid, fd);
    maybe_update_conn_from_addr(key, uservaddr, true);
    return 0;
}

SEC("kprobe/__x64_sys_accept4")
int sys_accept4_enter(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = (int)PT_REGS_PARM1(ctx);
    struct sockaddr *upeer_sockaddr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    int *upeer_addrlen = (int *)PT_REGS_PARM3(ctx);

    struct accept_args args = {};
    args.fd = fd;
    args.addr = upeer_sockaddr;
    args.addrlen = upeer_addrlen;
    bpf_map_update_elem(&accept_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/__x64_sys_accept4")
int sys_accept4_exit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __s64 ret = PT_REGS_RC(ctx);
    struct accept_args *args = bpf_map_lookup_elem(&accept_args_map, &pid_tgid);
    if (!args) {
        return 0;
    }
    bpf_map_delete_elem(&accept_args_map, &pid_tgid);

    if (ret < 0) {
        return 0;
    }

    __u32 pid = pid_tgid >> 32;
    __u64 listen_key = make_key(pid, args->fd);
    __u64 new_key = make_key(pid, (__u32)ret);

    struct conn_info info = {};
    struct conn_info *listen_info = bpf_map_lookup_elem(&conn_map, &listen_key);
    if (listen_info) {
        info.family = listen_info->family;
        info.sport = listen_info->sport;
        copy_bytes(info.saddr, listen_info->saddr, 16);
    }

    if (args->addr) {
        read_sockaddr(args->addr, &info, true);
    }

    bpf_map_update_elem(&conn_map, &new_key, &info, BPF_ANY);
    return 0;
}

SEC("kprobe/__x64_sys_sendto")
int sys_sendto(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    int fd = (int)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t len = (size_t)PT_REGS_PARM3(ctx);
    struct sockaddr *dest_addr = (struct sockaddr *)PT_REGS_PARM5(ctx);

    __u64 key = make_key(pid, fd);
    if (dest_addr) {
        maybe_update_conn_from_addr(key, dest_addr, true);
    }

    struct conn_info *info = lookup_conn(pid, fd);
    if (!info) {
        return 0;
    }

    __u32 copy_len = len > MAX_DATA_SIZE ? MAX_DATA_SIZE : (__u32)len;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    e->ts = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = tid;
    e->direction = DIR_SEND;
    e->data_len = copy_len;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    fill_event_conn(e, info);
    bpf_probe_read_user(&e->data, copy_len, buf);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_recvfrom")
int sys_recvfrom_enter(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = (int)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t len = (size_t)PT_REGS_PARM3(ctx);
    struct sockaddr *src_addr = (struct sockaddr *)PT_REGS_PARM5(ctx);

    __u32 pid = pid_tgid >> 32;
    __u64 key = make_key(pid, fd);
    if (src_addr) {
        maybe_update_conn_from_addr(key, src_addr, true);
    }

    struct recv_args args = {
        .fd = fd,
        .buf = buf,
        .len = len,
    };
    bpf_map_update_elem(&recv_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/__x64_sys_recvfrom")
int sys_recvfrom_exit(struct pt_regs *ctx) {
    __s64 ret = PT_REGS_RC(ctx);
    if (ret <= 0) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    struct recv_args *args = bpf_map_lookup_elem(&recv_args_map, &pid_tgid);
    if (!args) {
        return 0;
    }
    bpf_map_delete_elem(&recv_args_map, &pid_tgid);

    struct conn_info *info = lookup_conn(pid, args->fd);
    if (!info) {
        return 0;
    }

    __u32 copy_len = ret > MAX_DATA_SIZE ? MAX_DATA_SIZE : (__u32)ret;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    e->ts = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = tid;
    e->direction = DIR_RECV;
    e->data_len = copy_len;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    fill_event_conn(e, info);
    bpf_probe_read_user(&e->data, copy_len, args->buf);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
