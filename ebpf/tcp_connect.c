#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>

BPF_RINGBUF_OUTPUT(events, 1 << 18);

struct tcp_event_t {
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u64 ts_ns;
    char comm[16];
};

static inline u16 my_ntohs(u16 x) { return ((x >> 8) | (x << 8)) & 0xFFFF; }

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    struct tcp_event_t evt = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.saddr = sk->__sk_common.skc_rcv_saddr;
    evt.daddr = sk->__sk_common.skc_daddr;
    evt.sport = sk->__sk_common.skc_num;
    evt.dport = my_ntohs(sk->__sk_common.skc_dport);
    events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}
