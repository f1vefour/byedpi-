#include "vpn.h"
#ifdef __linux__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "params.h"
#include "proxy.h"
#include "extend.h"
#include "error.h"
#include "tun.h"

/* ---- tunables ---------------------------------------------------- */
#define VPN_HASH_SIZE   1024   /* power of 2 */
#define TCP_IN_PEND_CAP 65536  /* per-flow inbound (tun->relay) backpressure cap */
#define TCP_OUT_CAP_MAX (1 << 20) /* sanity cap on unacked-data buffer growth */
#define UDP_IDLE_MS     (120 * 1000)
#define RTO_INIT_MS     500
#define RTO_MAX_MS      8000

static int g_tun_fd = -1;
static int g_mss = 1460;

/* =====================  checksums  ================================ */

static uint32_t csum_add(uint32_t sum, const void *data, size_t len)
{
    const uint8_t *p = data;
    while (len > 1) {
        sum += (p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len) {
        sum += p[0] << 8;
    }
    return sum;
}

/* inet_ntoa() returns a pointer to a single static buffer, so using it
   twice in one printf() call (undefined argument evaluation order)
   silently makes both conversions show the same address. This takes
   an explicit caller-owned buffer instead. */
static const char *ip_str(uint32_t addr_net, char *buf, size_t buflen)
{
    struct in_addr a = { .s_addr = addr_net };
    if (!inet_ntop(AF_INET, &a, buf, buflen)) {
        snprintf(buf, buflen, "?");
    }
    return buf;
}

static uint16_t csum_fold(uint32_t sum)
{
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static uint16_t ip_checksum(const struct iphdr *ih)
{
    return htons(csum_fold(csum_add(0, ih, sizeof(*ih))));
}

static uint16_t l4_checksum(uint32_t saddr, uint32_t daddr,
        uint8_t proto, const void *l4, size_t l4len)
{
    struct {
        uint32_t s, d;
        uint8_t zero, proto;
        uint16_t len;
    } __attribute__((packed)) ph = {
        saddr, daddr, 0, proto, htons((uint16_t)l4len)
    };
    uint32_t sum = csum_add(0, &ph, sizeof(ph));
    sum = csum_add(sum, l4, l4len);
    return htons(csum_fold(sum));
}

/* =====================  TCP flow table  ============================ */

enum tstate { TS_SYN_RCVD, TS_ESTABLISHED };

struct vpn_flow {
    uint32_t saddr, daddr;  /* network order; saddr = OS side, daddr = real remote */
    uint16_t sport, dport;  /* network order */

    enum tstate state;
    bool seen_data;         /* used to pick RST vs FIN on abrupt relay close */
    bool fin_from_os;       /* OS half-closed its send side; we shutdown(SHUT_WR) once */

    uint32_t isn;           /* host order, our chosen initial seq (the SYN itself) */
    uint32_t rcv_nxt;       /* host order, next seq expected from OS */
    uint32_t snd_una;       /* host order, oldest unacked *data* byte (isn+1 based) */
    uint32_t snd_nxt;       /* host order, next seq we will use */
    uint32_t snd_wnd;       /* bytes, OS's last advertised window */

    char *out_buf;
    size_t out_len;         /* bytes buffered from snd_una onward, unacked */
    size_t out_sent;        /* of out_len, how many already put on the wire */
    size_t out_cap;

    char *in_pend;
    size_t in_pend_len;
    size_t in_pend_off;

    int rto_ms;

    struct eval *client;    /* sv[0], bridged into connect_hook/on_tunnel */
    struct eval *relay;     /* sv[1], cb = on_vpn_relay */

    struct vpn_flow *next;
};

static struct vpn_flow *tcp_table[VPN_HASH_SIZE];

/* forward decls: these are registered as evcb_t before their definitions below */
int on_vpn_relay_cb(struct poolhd *pool, struct eval *val, int et);
int on_vpn_udp_read_cb(struct poolhd *pool, struct eval *val, int et);

struct udp_flow {
    uint32_t saddr, daddr;
    uint16_t sport, dport;
    struct eval *sock;
    struct udp_flow *next;
};

static struct udp_flow *udp_table[VPN_HASH_SIZE];

static unsigned flow_hash(uint32_t a, uint32_t b, uint16_t c, uint16_t d)
{
    uint32_t h = a * 2654435761u ^ b * 2246822519u ^ ((uint32_t)c << 16 | d);
    return (h ^ (h >> 15)) & (VPN_HASH_SIZE - 1);
}

static struct vpn_flow *tcp_find(uint32_t sa, uint32_t da, uint16_t sp, uint16_t dp)
{
    struct vpn_flow *f = tcp_table[flow_hash(sa, da, sp, dp)];
    for (; f; f = f->next) {
        if (f->saddr == sa && f->daddr == da && f->sport == sp && f->dport == dp) {
            return f;
        }
    }
    return 0;
}

static void tcp_insert(struct vpn_flow *f)
{
    unsigned h = flow_hash(f->saddr, f->daddr, f->sport, f->dport);
    f->next = tcp_table[h];
    tcp_table[h] = f;
}

static void tcp_remove(struct vpn_flow *f)
{
    unsigned h = flow_hash(f->saddr, f->daddr, f->sport, f->dport);
    struct vpn_flow **pp = &tcp_table[h];
    for (; *pp; pp = &(*pp)->next) {
        if (*pp == f) {
            *pp = f->next;
            break;
        }
    }
}

static struct udp_flow *udp_find(uint32_t sa, uint32_t da, uint16_t sp, uint16_t dp)
{
    struct udp_flow *f = udp_table[flow_hash(sa, da, sp, dp)];
    for (; f; f = f->next) {
        if (f->saddr == sa && f->daddr == da && f->sport == sp && f->dport == dp) {
            return f;
        }
    }
    return 0;
}

static void udp_insert(struct udp_flow *f)
{
    unsigned h = flow_hash(f->saddr, f->daddr, f->sport, f->dport);
    f->next = udp_table[h];
    udp_table[h] = f;
}

static void udp_remove(struct udp_flow *f)
{
    unsigned h = flow_hash(f->saddr, f->daddr, f->sport, f->dport);
    struct udp_flow **pp = &udp_table[h];
    for (; *pp; pp = &(*pp)->next) {
        if (*pp == f) {
            *pp = f->next;
            break;
        }
    }
}

/* =====================  outgoing packet builders  ================== */

/* Sends one TCP segment FROM flow->daddr:dport TO flow->saddr:sport
   (i.e. us, pretending to be the remote host, talking to the OS). */
static int send_tcp(struct vpn_flow *f, uint8_t flags,
        uint32_t seq, uint32_t ack, const char *payload, size_t paylen)
{
    static uint16_t ip_id = 0;
    char buf[sizeof(struct iphdr) + sizeof(struct tcphdr) + 1500];
    if (paylen > sizeof(buf) - sizeof(struct iphdr) - sizeof(struct tcphdr)) {
        paylen = sizeof(buf) - sizeof(struct iphdr) - sizeof(struct tcphdr);
    }
    struct iphdr *ih = (struct iphdr *)buf;
    struct tcphdr *th = (struct tcphdr *)(buf + sizeof(*ih));
    size_t tcp_len = sizeof(*th) + paylen;

    memset(ih, 0, sizeof(*ih));
    ih->ihl = 5;
    ih->version = 4;
    ih->tot_len = htons((uint16_t)(sizeof(*ih) + tcp_len));
    ih->id = htons(ip_id++);
    ih->frag_off = htons(0x4000); /* DF */
    ih->ttl = 64;
    ih->protocol = IPPROTO_TCP;
    ih->saddr = f->daddr;
    ih->daddr = f->saddr;
    ih->check = 0;
    ih->check = ip_checksum(ih);

    memset(th, 0, sizeof(*th));
    th->source = f->dport;
    th->dest = f->sport;
    th->seq = htonl(seq);
    th->ack_seq = htonl(ack);
    th->doff = 5;
    th->fin = !!(flags & 0x01);
    th->syn = !!(flags & 0x02);
    th->rst = !!(flags & 0x04);
    th->psh = !!(flags & 0x08);
    th->ack = !!(flags & 0x10);
    th->window = htons(65535);
    if (paylen) {
        memcpy((char *)th + sizeof(*th), payload, paylen);
    }
    th->check = l4_checksum(ih->saddr, ih->daddr, IPPROTO_TCP, th, tcp_len);

    ssize_t n = write(g_tun_fd, buf, sizeof(*ih) + tcp_len);
    if (n < 0) {
        uniperror("write tun (tcp)");
        return -1;
    }
    return 0;
}

/* Params match vpn_flow's own convention: os_addr/os_port identify the
   OS side, remote_addr/remote_port the real destination we impersonate
   when replying -- i.e. pass them exactly like ih->saddr/th->source
   (OS) and ih->daddr/th->dest (remote) from the packet that provoked
   this RST. */
static void send_rst(uint32_t os_addr, uint32_t remote_addr,
        uint16_t os_port, uint16_t remote_port,
        uint32_t seq, uint32_t ack, bool have_ack)
{
    struct vpn_flow tmp = {
        .saddr = os_addr, .daddr = remote_addr,
        .sport = os_port, .dport = remote_port
    };
    send_tcp(&tmp, have_ack ? (0x04 | 0x10) : 0x04, seq, ack, 0, 0);
}

/* =====================  flow teardown  ============================= */

/* Two teardown variants, because loop_event() auto-deletes whichever
   eval a callback returns -1 for, and we must never del_event() an
   eval from inside its own still-running callback (double free).

   We never explicitly del_event() f->client ourselves in either variant:
   closing our end of the socketpair (f->relay/sv[1]) delivers EOF/EPIPE
   to f->client (sv[0]), which byedpi's existing on_tunnel/on_fin error
   handling already turns into a normal teardown of f->client *and* the
   real destination socket paired to it. Relying on that avoids ever
   touching a pointer that byedpi's own generic code might already have
   torn down on its side (e.g. the real connect() failing on its own). */

/* Call from anywhere EXCEPT f->relay's own callback. */
static void tcp_flow_free(struct poolhd *pool, struct vpn_flow *f)
{
    tcp_remove(f);
    if (f->relay) {
        f->relay->vpn = 0;
        del_event(pool, f->relay);
    }
    free(f->out_buf);
    free(f->in_pend);
    free(f);
}

/* Call from inside on_vpn_relay_cb(pool, f->relay, ...) itself; caller
   must `return -1` right after so loop_event() deletes f->relay. */
static void tcp_flow_free_self(struct poolhd *pool, struct vpn_flow *f)
{
    (void)pool;
    tcp_remove(f);
    if (f->relay) {
        f->relay->vpn = 0;
    }
    free(f->out_buf);
    free(f->in_pend);
    free(f);
}

/* =====================  inbound TCP from tun  ======================= */

static void tcp_new_conn(struct poolhd *pool, const struct iphdr *ih, const struct tcphdr *th)
{
    union sockaddr_u dst = { 0 };
    dst.in.sin_family = AF_INET;
    dst.in.sin_addr.s_addr = ih->daddr;
    dst.in.sin_port = th->dest;

    LOG(LOG_S, "vpn: new tcp flow %s:%d -> %s:%d\n",
        ip_str(ih->saddr, (char[16]){0}, 16), ntohs(th->source),
        ip_str(ih->daddr, (char[16]){0}, 16), ntohs(th->dest));

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) < 0) {
        uniperror("socketpair");
        send_rst(ih->saddr, ih->daddr, th->source, th->dest,
            0, ntohl(th->seq) + 1, true);
        return;
    }
    int bufsz = 262144;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
    setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));

    struct vpn_flow *f = calloc(1, sizeof(*f));
    if (!f) {
        close(sv[0]); close(sv[1]);
        return;
    }
    f->saddr = ih->saddr; f->daddr = ih->daddr;
    f->sport = th->source; f->dport = th->dest;
    f->state = TS_SYN_RCVD;
    f->rcv_nxt = ntohl(th->seq) + 1;
    f->isn = (uint32_t)random();
    f->snd_una = f->snd_nxt = f->isn + 1; /* data sequence space starts right after our SYN */
    f->snd_wnd = ntohs(th->window);
    if (!f->snd_wnd) f->snd_wnd = 65535;
    f->rto_ms = RTO_INIT_MS;

    struct eval *val_client = add_event(pool, &on_ignore, sv[0], POLLIN);
    if (!val_client) {
        close(sv[0]); close(sv[1]);
        free(f);
        send_rst(ih->saddr, ih->daddr, th->source, th->dest, 0, ntohl(th->seq) + 1, true);
        return;
    }
    if (connect_hook(pool, val_client, &dst, &on_connect) < 0) {
        LOG(LOG_S, "vpn: connect_hook failed (desync group lookup?), sending RST\n");
        del_event(pool, val_client);
        close(sv[1]);
        free(f);
        send_rst(ih->saddr, ih->daddr, th->source, th->dest, 0, ntohl(th->seq) + 1, true);
        return;
    }
    struct eval *val_relay = add_event(pool, &on_vpn_relay_cb, sv[1], POLLIN);
    if (!val_relay) {
        /* val_client (and its pair, the real outbound socket) will get
           torn down naturally: closing sv[1] here delivers EOF to sv[0],
           which byedpi's existing relay error handling already turns
           into a normal close once it's next polled. */
        close(sv[1]);
        free(f);
        send_rst(ih->saddr, ih->daddr, th->source, th->dest, 0, ntohl(th->seq) + 1, true);
        return;
    }
    val_relay->vpn = f;
    f->client = val_client;
    f->relay = val_relay;

    tcp_insert(f);

    /* Optimistic SYN-ACK: we accept the local TCP handshake immediately;
       if the real destination turns out unreachable we'll RST/FIN once
       that becomes apparent (see on_vpn_relay_cb). */
    send_tcp(f, 0x02 | 0x10, f->isn, f->rcv_nxt, 0, 0);
}

static void tcp_try_flush_in_pend(struct vpn_flow *f)
{
    if (!f->in_pend_len) return;
    ssize_t n = write(f->relay->fd,
        f->in_pend + f->in_pend_off, f->in_pend_len - f->in_pend_off);
    if (n < 0) {
        if (errno != EAGAIN) {
            /* relay already dead; on_vpn_relay_cb will notice on next poll */
        }
        return;
    }
    f->in_pend_off += (size_t)n;
    if (f->in_pend_off >= f->in_pend_len) {
        f->in_pend_len = f->in_pend_off = 0;
    }
}

static void tcp_out_append(struct vpn_flow *f, const char *data, size_t len)
{
    if (f->out_len + len > f->out_cap) {
        size_t ncap = f->out_cap ? f->out_cap * 2 : 4096;
        while (ncap < f->out_len + len) ncap *= 2;
        if (ncap > TCP_OUT_CAP_MAX) ncap = TCP_OUT_CAP_MAX;
        char *nb = realloc(f->out_buf, ncap);
        if (!nb) return; /* drop; sender (real remote via desync) will need to retransmit at TCP layer above us -- acceptable rare-OOM case */
        f->out_buf = nb;
        f->out_cap = ncap;
    }
    if (f->out_len + len > f->out_cap) {
        len = f->out_cap - f->out_len; /* clamp on cap saturation */
    }
    memcpy(f->out_buf + f->out_len, data, len);
    f->out_len += len;
}

static void tcp_out_pump(struct poolhd *pool, struct vpn_flow *f)
{
    size_t avail_window = f->snd_wnd > f->out_sent ? f->snd_wnd - f->out_sent : 0;
    size_t can_send = f->out_len - f->out_sent;
    if (can_send > avail_window) can_send = avail_window;

    size_t off = 0;
    while (off < can_send) {
        size_t chunk = can_send - off;
        if (chunk > (size_t)g_mss) chunk = g_mss;
        send_tcp(f, 0x18 /* PSH|ACK */,
            f->snd_una + f->out_sent + off, f->rcv_nxt,
            f->out_buf + f->out_sent + off, chunk);
        off += chunk;
    }
    if (off) {
        f->out_sent += off;
        f->snd_nxt = f->snd_una + f->out_sent;
        set_timer(pool, f->relay, f->rto_ms);
    }
}

/* =====================  event callbacks  ============================ */

int on_vpn_relay_cb(struct poolhd *pool, struct eval *val, int et)
{
    struct vpn_flow *f = val->vpn;
    if (!f) {
        return -1;
    }
    if (et == POLLTIMEOUT) {
        if (f->out_sent > 0) {
            /* RTO: resend everything currently in flight, back off */
            f->out_sent = 0;
            tcp_out_pump(pool, f);
            f->rto_ms *= 2;
            if (f->rto_ms > RTO_MAX_MS) f->rto_ms = RTO_MAX_MS;
        }
        return 0;
    }
    if (et & (POLLIN | POLLHUP | POLLRDHUP | POLLERR)) {
        char buf[16384];
        ssize_t n = read(val->fd, buf, sizeof(buf));
        if (n > 0) {
            tcp_out_append(f, buf, (size_t)n);
            tcp_out_pump(pool, f);
        } else if (n == 0 || (n < 0 && errno != EAGAIN)) {
            /* relay peer (sv[0], the desync/relay side) is done: fire
               our FIN (or RST if nothing was ever exchanged) and drop
               the flow now rather than waiting for the OS's final ACK
               -- any stray follow-up packet just hits the "no matching
               flow" path below and gets RST'd, which is the correct
               response for a connection we no longer track. */
            if (f->seen_data || f->out_len) {
                send_tcp(f, 0x01 | 0x10 /* FIN|ACK */,
                    f->snd_una + f->out_sent, f->rcv_nxt, 0, 0);
            } else {
                send_rst(f->saddr, f->daddr, f->sport, f->dport,
                    f->snd_nxt, f->rcv_nxt, true);
            }
            tcp_flow_free_self(pool, f);
            return -1;
        }
    }
    if (et & POLLOUT) {
        tcp_try_flush_in_pend(f);
    }
    return 0;
}

static void handle_tcp_in(struct poolhd *pool, const struct iphdr *ih,
        const struct tcphdr *th, const char *payload, size_t paylen)
{
    uint32_t sa = ih->saddr, da = ih->daddr;
    uint16_t sp = th->source, dp = th->dest;

    struct vpn_flow *f = tcp_find(sa, da, sp, dp);

    if (th->rst) {
        if (f) tcp_flow_free(pool, f);
        return;
    }
    if (th->syn && !th->ack) {
        if (!f) {
            tcp_new_conn(pool, ih, th);
        } else {
            /* retransmitted SYN for a flow we already accepted; re-ack it */
            send_tcp(f, 0x02 | 0x10, f->isn, f->rcv_nxt, 0, 0);
        }
        return;
    }
    if (!f) {
        /* Segment for a connection we have no record of (e.g. after our
           side already tore it down) -- tell the OS it's gone. */
        if (th->ack) {
            send_rst(sa, da, sp, dp, ntohl(th->ack_seq), 0, false);
        }
        return;
    }

    uint32_t seq = ntohl(th->seq);
    f->snd_wnd = ntohs(th->window);

    if (th->ack) {
        uint32_t ack = ntohl(th->ack_seq);
        uint32_t acked = ack - f->snd_una; /* wraps correctly if ack < una is bogus/old */
        if (acked > 0 && acked <= f->out_sent) {
            memmove(f->out_buf, f->out_buf + acked, f->out_len - acked);
            f->out_len -= acked;
            f->out_sent -= acked;
            f->snd_una = ack;
            f->rto_ms = RTO_INIT_MS;
            if (f->out_sent > 0) {
                set_timer(pool, f->relay, f->rto_ms);
            } else {
                remove_timer(pool, f->relay);
            }
        }
        if (f->state == TS_SYN_RCVD) {
            f->state = TS_ESTABLISHED;
        }
    }

    if (paylen > 0 && seq == f->rcv_nxt) {
        f->seen_data = true;
        if (f->in_pend_len == 0) {
            ssize_t n = write(f->relay->fd, payload, paylen);
            if (n < 0 && errno == EAGAIN) {
                n = 0;
            } else if (n < 0) {
                n = (ssize_t)paylen; /* relay dead; drop silently, let it get cleaned up on next poll */
            }
            if ((size_t)n < paylen) {
                size_t rem = paylen - (size_t)n;
                if (rem > TCP_IN_PEND_CAP) rem = TCP_IN_PEND_CAP;
                char *nb = realloc(f->in_pend, rem);
                if (nb) {
                    f->in_pend = nb;
                    memcpy(f->in_pend, payload + n, rem);
                    f->in_pend_len = rem;
                    f->in_pend_off = 0;
                    mod_etype(pool, f->relay, POLLIN | POLLOUT);
                }
            }
            f->rcv_nxt += paylen;
            send_tcp(f, 0x10, f->snd_una + f->out_sent, f->rcv_nxt, 0, 0);
        }
        /* else: still backed up, drop this segment; OS will retransmit */
    } else if (paylen > 0) {
        /* out-of-order/duplicate: re-ack what we actually have */
        send_tcp(f, 0x10, f->snd_una + f->out_sent, f->rcv_nxt, 0, 0);
    }

    if (th->fin && !f->fin_from_os) {
        uint32_t fin_seq = seq + paylen;
        if (fin_seq == f->rcv_nxt) {
            f->rcv_nxt += 1;
            f->fin_from_os = true;
            send_tcp(f, 0x10, f->snd_una + f->out_sent, f->rcv_nxt, 0, 0);
            /* Half-close: tell the relay/desync side the OS is done
               sending. It may still have more response data in flight;
               the flow gets freed once *that* side hits EOF too, in
               on_vpn_relay_cb. */
            shutdown(f->relay->fd, SHUT_WR);
        }
    }
}

/* =====================  inbound UDP from tun  ======================= */

int on_vpn_udp_read_cb(struct poolhd *pool, struct eval *val, int et)
{
    struct udp_flow *uf = val->vpn;
    LOG(LOG_L, "vpn: on_vpn_udp_read_cb fired, fd=%d et=%d uf=%p\n", val->fd, et, (void*)uf);
    if (!uf) return -1;
    if (et == POLLTIMEOUT) {
        udp_remove(uf);
        val->vpn = 0;
        del_event(pool, val);
        free(uf);
        return 0;
    }
    char buf[2048];
    ssize_t n = recv(val->fd, buf, sizeof(buf), 0);
    if (n <= 0) {
        if (n < 0) LOG(LOG_S, "vpn: udp recv from real dest failed: %s\n", strerror(errno));
        return 0;
    }
    LOG(LOG_S, "vpn: udp reply %zd bytes from real dest, relaying to tun\n", n);
    set_timer(pool, val, UDP_IDLE_MS);

    size_t total = sizeof(struct iphdr) + sizeof(struct udphdr) + (size_t)n;
    if (total > sizeof(struct iphdr) + sizeof(struct udphdr) + 1500) {
        return 0; /* oversized reply, no fragmentation support -- drop */
    }
    char pkt[sizeof(struct iphdr) + sizeof(struct udphdr) + 1500 + 40];
    struct iphdr *ih = (struct iphdr *)pkt;
    struct udphdr *uh = (struct udphdr *)(pkt + sizeof(*ih));

    memset(ih, 0, sizeof(*ih));
    ih->ihl = 5; ih->version = 4;
    ih->tot_len = htons((uint16_t)(sizeof(*ih) + sizeof(*uh) + n));
    ih->frag_off = htons(0x4000);
    ih->ttl = 64;
    ih->protocol = IPPROTO_UDP;
    ih->saddr = uf->daddr;
    ih->daddr = uf->saddr;
    ih->check = 0;
    ih->check = ip_checksum(ih);

    uh->source = uf->dport;
    uh->dest = uf->sport;
    uh->len = htons((uint16_t)(sizeof(*uh) + n));
    uh->check = 0;
    memcpy(pkt + sizeof(*ih) + sizeof(*uh), buf, (size_t)n);
    uh->check = l4_checksum(ih->saddr, ih->daddr, IPPROTO_UDP, uh, sizeof(*uh) + (size_t)n);
    if (!uh->check) uh->check = 0xffff;

    ssize_t wn = write(g_tun_fd, pkt, sizeof(*ih) + sizeof(*uh) + (size_t)n);
    if (wn < 0) {
        uniperror("write tun (udp)");
    }
    return 0;
}

static void handle_udp_in(struct poolhd *pool, const struct iphdr *ih,
        const struct udphdr *uh, const char *payload, size_t paylen)
{
    struct udp_flow *uf = udp_find(ih->saddr, ih->daddr, uh->source, uh->dest);
    if (!uf) {
        LOG(LOG_S, "vpn: new udp flow %s:%d -> %s:%d\n",
            ip_str(ih->saddr, (char[16]){0}, 16), ntohs(uh->source),
            ip_str(ih->daddr, (char[16]){0}, 16), ntohs(uh->dest));
        int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (fd < 0) {
            uniperror("socket udp");
            return;
        }
        LOG(LOG_S, "vpn: udp socket() -> fd=%d\n", fd);
        if (tun_uplink_ifname[0]) {
            if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                    tun_uplink_ifname, strlen(tun_uplink_ifname) + 1) < 0) {
                uniperror("setsockopt SO_BINDTODEVICE (udp)");
            } else {
                LOG(LOG_S, "vpn: udp SO_BINDTODEVICE(%s) ok\n", tun_uplink_ifname);
            }
        }
        union sockaddr_u dst = { 0 };
        dst.in.sin_family = AF_INET;
        dst.in.sin_addr.s_addr = ih->daddr;
        dst.in.sin_port = uh->dest;
        if (connect(fd, &dst.sa, sizeof(dst.in)) < 0
                && errno != EINPROGRESS) {
            uniperror("connect udp");
            close(fd);
            return;
        }
        LOG(LOG_S, "vpn: udp connect() ok\n");
        struct eval *val = add_event(pool, &on_vpn_udp_read_cb, fd, POLLIN);
        if (!val) {
            LOG(LOG_S, "vpn: udp add_event failed\n");
            close(fd);
            return;
        }
        LOG(LOG_S, "vpn: udp add_event ok, val->fd=%d\n", val->fd);
        uf = calloc(1, sizeof(*uf));
        if (!uf) {
            del_event(pool, val);
            return;
        }
        uf->saddr = ih->saddr; uf->daddr = ih->daddr;
        uf->sport = uh->source; uf->dport = uh->dest;
        uf->sock = val;
        val->vpn = uf;
        udp_insert(uf);
        set_timer(pool, val, UDP_IDLE_MS);
    }
    ssize_t sn = send(uf->sock->fd, payload, paylen, 0);
    LOG(LOG_S, "vpn: udp send(fd=%d, %zu bytes) -> %zd %s\n",
        uf->sock->fd, paylen, sn, sn < 0 ? strerror(errno) : "");
    remove_timer(pool, uf->sock);
    set_timer(pool, uf->sock, UDP_IDLE_MS);
}

/* =====================  IPv6 support  =============================
   Mirrors everything above almost exactly -- same TCP state machine,
   same hash-table approach, same socketpair-into-connect_hook bridge
   -- just addressed with struct in6_addr and built on struct ip6_hdr
   instead of struct iphdr. Kept as fully separate types/functions
   rather than genericizing the v4 ones: the address size differs
   enough (4 vs 16 bytes) that unifying them would mean touching every
   v4 call site for no real benefit, and it keeps each path simple to
   read and verify on its own. IPv6 has no header checksum at all (one
   less thing to get wrong than v4), but its TCP/UDP pseudo-header for
   the L4 checksum uses 128-bit addresses and a 32-bit length field,
   so that part still needs its own version. Extension headers between
   the main IPv6 header and TCP/UDP aren't chased -- ih->ip6_nxt has to
   name the L4 protocol directly, which covers ordinary traffic but
   not e.g. IPv6 fragmentation. */

static uint32_t csum_add6(uint32_t sum, const struct in6_addr *a)
{
    return csum_add(sum, a->s6_addr, 16);
}

static uint16_t l4_checksum6(const struct in6_addr *saddr, const struct in6_addr *daddr,
        uint8_t proto, const void *l4, size_t l4len)
{
    uint32_t sum = csum_add6(0, saddr);
    sum = csum_add6(sum, daddr);
    uint32_t len_be = htonl((uint32_t)l4len);
    sum = csum_add(sum, &len_be, 4);
    uint8_t nexthdr[4] = { 0, 0, 0, proto };
    sum = csum_add(sum, nexthdr, 4);
    sum = csum_add(sum, l4, l4len);
    return htons(csum_fold(sum));
}

static const char *ip_str6(const struct in6_addr *addr, char *buf, size_t buflen)
{
    if (!inet_ntop(AF_INET6, addr, buf, buflen)) {
        snprintf(buf, buflen, "?");
    }
    return buf;
}

struct vpn_flow6 {
    struct in6_addr saddr, daddr;
    uint16_t sport, dport;

    enum tstate state;
    bool seen_data;
    bool fin_from_os;

    uint32_t isn;
    uint32_t rcv_nxt;
    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t snd_wnd;

    char *out_buf;
    size_t out_len;
    size_t out_sent;
    size_t out_cap;

    char *in_pend;
    size_t in_pend_len;
    size_t in_pend_off;

    int rto_ms;

    struct eval *client;
    struct eval *relay;

    struct vpn_flow6 *next;
};

static struct vpn_flow6 *tcp_table6[VPN_HASH_SIZE];

int on_vpn_relay_cb6(struct poolhd *pool, struct eval *val, int et);
int on_vpn_udp_read_cb6(struct poolhd *pool, struct eval *val, int et);

struct udp_flow6 {
    struct in6_addr saddr, daddr;
    uint16_t sport, dport;
    struct eval *sock;
    struct udp_flow6 *next;
};

static struct udp_flow6 *udp_table6[VPN_HASH_SIZE];

static unsigned flow_hash6(const struct in6_addr *a, const struct in6_addr *b,
        uint16_t c, uint16_t d)
{
    uint32_t aw[4], bw[4];
    memcpy(aw, a->s6_addr, 16);
    memcpy(bw, b->s6_addr, 16);
    uint32_t h = 0;
    for (int i = 0; i < 4; i++) {
        h = h * 2654435761u ^ aw[i];
        h = h * 2246822519u ^ bw[i];
    }
    h ^= ((uint32_t)c << 16 | d);
    return (h ^ (h >> 15)) & (VPN_HASH_SIZE - 1);
}

static struct vpn_flow6 *tcp_find6(const struct in6_addr *sa, const struct in6_addr *da,
        uint16_t sp, uint16_t dp)
{
    struct vpn_flow6 *f = tcp_table6[flow_hash6(sa, da, sp, dp)];
    for (; f; f = f->next) {
        if (!memcmp(&f->saddr, sa, sizeof(*sa)) && !memcmp(&f->daddr, da, sizeof(*da))
                && f->sport == sp && f->dport == dp) {
            return f;
        }
    }
    return 0;
}

static void tcp_insert6(struct vpn_flow6 *f)
{
    unsigned h = flow_hash6(&f->saddr, &f->daddr, f->sport, f->dport);
    f->next = tcp_table6[h];
    tcp_table6[h] = f;
}

static void tcp_remove6(struct vpn_flow6 *f)
{
    unsigned h = flow_hash6(&f->saddr, &f->daddr, f->sport, f->dport);
    struct vpn_flow6 **pp = &tcp_table6[h];
    for (; *pp; pp = &(*pp)->next) {
        if (*pp == f) {
            *pp = f->next;
            break;
        }
    }
}

static struct udp_flow6 *udp_find6(const struct in6_addr *sa, const struct in6_addr *da,
        uint16_t sp, uint16_t dp)
{
    struct udp_flow6 *f = udp_table6[flow_hash6(sa, da, sp, dp)];
    for (; f; f = f->next) {
        if (!memcmp(&f->saddr, sa, sizeof(*sa)) && !memcmp(&f->daddr, da, sizeof(*da))
                && f->sport == sp && f->dport == dp) {
            return f;
        }
    }
    return 0;
}

static void udp_insert6(struct udp_flow6 *f)
{
    unsigned h = flow_hash6(&f->saddr, &f->daddr, f->sport, f->dport);
    f->next = udp_table6[h];
    udp_table6[h] = f;
}

static void udp_remove6(struct udp_flow6 *f)
{
    unsigned h = flow_hash6(&f->saddr, &f->daddr, f->sport, f->dport);
    struct udp_flow6 **pp = &udp_table6[h];
    for (; *pp; pp = &(*pp)->next) {
        if (*pp == f) {
            *pp = f->next;
            break;
        }
    }
}

static int send_tcp6(struct vpn_flow6 *f, uint8_t flags,
        uint32_t seq, uint32_t ack, const char *payload, size_t paylen)
{
    char buf[sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + 1500];
    if (paylen > sizeof(buf) - sizeof(struct ip6_hdr) - sizeof(struct tcphdr)) {
        paylen = sizeof(buf) - sizeof(struct ip6_hdr) - sizeof(struct tcphdr);
    }
    struct ip6_hdr *ih = (struct ip6_hdr *)buf;
    struct tcphdr *th = (struct tcphdr *)(buf + sizeof(*ih));
    size_t tcp_len = sizeof(*th) + paylen;

    memset(ih, 0, sizeof(*ih));
    ih->ip6_vfc = 0x60; /* version 6, traffic class 0 */
    ih->ip6_plen = htons((uint16_t)tcp_len);
    ih->ip6_nxt = IPPROTO_TCP;
    ih->ip6_hlim = 64;
    ih->ip6_src = f->daddr;
    ih->ip6_dst = f->saddr;

    memset(th, 0, sizeof(*th));
    th->source = f->dport;
    th->dest = f->sport;
    th->seq = htonl(seq);
    th->ack_seq = htonl(ack);
    th->doff = 5;
    th->fin = !!(flags & 0x01);
    th->syn = !!(flags & 0x02);
    th->rst = !!(flags & 0x04);
    th->psh = !!(flags & 0x08);
    th->ack = !!(flags & 0x10);
    th->window = htons(65535);
    if (paylen) {
        memcpy((char *)th + sizeof(*th), payload, paylen);
    }
    th->check = l4_checksum6(&ih->ip6_src, &ih->ip6_dst, IPPROTO_TCP, th, tcp_len);

    ssize_t n = write(g_tun_fd, buf, sizeof(*ih) + tcp_len);
    if (n < 0) {
        uniperror("write tun (tcp6)");
        return -1;
    }
    return 0;
}

static void send_rst6(const struct in6_addr *os_addr, const struct in6_addr *remote_addr,
        uint16_t os_port, uint16_t remote_port,
        uint32_t seq, uint32_t ack, bool have_ack)
{
    struct vpn_flow6 tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.saddr = *os_addr;
    tmp.daddr = *remote_addr;
    tmp.sport = os_port;
    tmp.dport = remote_port;
    send_tcp6(&tmp, have_ack ? (0x04 | 0x10) : 0x04, seq, ack, 0, 0);
}

/* Same two-variant split as tcp_flow_free()/tcp_flow_free_self() above,
   for the same reason (never del_event() an eval from inside its own
   still-running callback). */
static void tcp_flow_free6(struct poolhd *pool, struct vpn_flow6 *f)
{
    tcp_remove6(f);
    if (f->relay) {
        f->relay->vpn = 0;
        del_event(pool, f->relay);
    }
    free(f->out_buf);
    free(f->in_pend);
    free(f);
}

static void tcp_flow_free_self6(struct poolhd *pool, struct vpn_flow6 *f)
{
    (void)pool;
    tcp_remove6(f);
    if (f->relay) {
        f->relay->vpn = 0;
    }
    free(f->out_buf);
    free(f->in_pend);
    free(f);
}

static void tcp_new_conn6(struct poolhd *pool, const struct ip6_hdr *ih, const struct tcphdr *th)
{
    union sockaddr_u dst = { 0 };
    dst.in6.sin6_family = AF_INET6;
    dst.in6.sin6_addr = ih->ip6_dst;
    dst.in6.sin6_port = th->dest;

    LOG(LOG_S, "vpn: new tcp6 flow %s:%d -> %s:%d\n",
        ip_str6(&ih->ip6_src, (char[46]){0}, 46), ntohs(th->source),
        ip_str6(&ih->ip6_dst, (char[46]){0}, 46), ntohs(th->dest));

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) < 0) {
        uniperror("socketpair");
        send_rst6(&ih->ip6_src, &ih->ip6_dst, th->source, th->dest,
            0, ntohl(th->seq) + 1, true);
        return;
    }
    int bufsz = 262144;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
    setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));

    struct vpn_flow6 *f = calloc(1, sizeof(*f));
    if (!f) {
        close(sv[0]); close(sv[1]);
        return;
    }
    f->saddr = ih->ip6_src; f->daddr = ih->ip6_dst;
    f->sport = th->source; f->dport = th->dest;
    f->state = TS_SYN_RCVD;
    f->rcv_nxt = ntohl(th->seq) + 1;
    f->isn = (uint32_t)random();
    f->snd_una = f->snd_nxt = f->isn + 1;
    f->snd_wnd = ntohs(th->window);
    if (!f->snd_wnd) f->snd_wnd = 65535;
    f->rto_ms = RTO_INIT_MS;

    struct eval *val_client = add_event(pool, &on_ignore, sv[0], POLLIN);
    if (!val_client) {
        close(sv[0]); close(sv[1]);
        free(f);
        send_rst6(&ih->ip6_src, &ih->ip6_dst, th->source, th->dest, 0, ntohl(th->seq) + 1, true);
        return;
    }
    if (connect_hook(pool, val_client, &dst, &on_connect) < 0) {
        LOG(LOG_S, "vpn: connect_hook (v6) failed (desync group lookup?), sending RST\n");
        del_event(pool, val_client);
        close(sv[1]);
        free(f);
        send_rst6(&ih->ip6_src, &ih->ip6_dst, th->source, th->dest, 0, ntohl(th->seq) + 1, true);
        return;
    }
    struct eval *val_relay = add_event(pool, &on_vpn_relay_cb6, sv[1], POLLIN);
    if (!val_relay) {
        close(sv[1]);
        free(f);
        send_rst6(&ih->ip6_src, &ih->ip6_dst, th->source, th->dest, 0, ntohl(th->seq) + 1, true);
        return;
    }
    val_relay->vpn = f;
    f->client = val_client;
    f->relay = val_relay;

    tcp_insert6(f);
    send_tcp6(f, 0x02 | 0x10, f->isn, f->rcv_nxt, 0, 0);
}

static void tcp_try_flush_in_pend6(struct vpn_flow6 *f)
{
    if (!f->in_pend_len) return;
    ssize_t n = write(f->relay->fd,
        f->in_pend + f->in_pend_off, f->in_pend_len - f->in_pend_off);
    if (n < 0) {
        return;
    }
    f->in_pend_off += (size_t)n;
    if (f->in_pend_off >= f->in_pend_len) {
        f->in_pend_len = f->in_pend_off = 0;
    }
}

static void tcp_out_append6(struct vpn_flow6 *f, const char *data, size_t len)
{
    if (f->out_len + len > f->out_cap) {
        size_t ncap = f->out_cap ? f->out_cap * 2 : 4096;
        while (ncap < f->out_len + len) ncap *= 2;
        if (ncap > TCP_OUT_CAP_MAX) ncap = TCP_OUT_CAP_MAX;
        char *nb = realloc(f->out_buf, ncap);
        if (!nb) return;
        f->out_buf = nb;
        f->out_cap = ncap;
    }
    if (f->out_len + len > f->out_cap) {
        len = f->out_cap - f->out_len;
    }
    memcpy(f->out_buf + f->out_len, data, len);
    f->out_len += len;
}

static void tcp_out_pump6(struct poolhd *pool, struct vpn_flow6 *f)
{
    size_t avail_window = f->snd_wnd > f->out_sent ? f->snd_wnd - f->out_sent : 0;
    size_t can_send = f->out_len - f->out_sent;
    if (can_send > avail_window) can_send = avail_window;

    size_t off = 0;
    while (off < can_send) {
        size_t chunk = can_send - off;
        if (chunk > (size_t)g_mss) chunk = g_mss;
        send_tcp6(f, 0x18 /* PSH|ACK */,
            f->snd_una + f->out_sent + off, f->rcv_nxt,
            f->out_buf + f->out_sent + off, chunk);
        off += chunk;
    }
    if (off) {
        f->out_sent += off;
        f->snd_nxt = f->snd_una + f->out_sent;
        set_timer(pool, f->relay, f->rto_ms);
    }
}

int on_vpn_relay_cb6(struct poolhd *pool, struct eval *val, int et)
{
    struct vpn_flow6 *f = val->vpn;
    if (!f) {
        return -1;
    }
    if (et == POLLTIMEOUT) {
        if (f->out_sent > 0) {
            f->out_sent = 0;
            tcp_out_pump6(pool, f);
            f->rto_ms *= 2;
            if (f->rto_ms > RTO_MAX_MS) f->rto_ms = RTO_MAX_MS;
        }
        return 0;
    }
    if (et & (POLLIN | POLLHUP | POLLRDHUP | POLLERR)) {
        char buf[16384];
        ssize_t n = read(val->fd, buf, sizeof(buf));
        if (n > 0) {
            tcp_out_append6(f, buf, (size_t)n);
            tcp_out_pump6(pool, f);
        } else if (n == 0 || (n < 0 && errno != EAGAIN)) {
            if (f->seen_data || f->out_len) {
                send_tcp6(f, 0x01 | 0x10,
                    f->snd_una + f->out_sent, f->rcv_nxt, 0, 0);
            } else {
                send_rst6(&f->saddr, &f->daddr, f->sport, f->dport,
                    f->snd_nxt, f->rcv_nxt, true);
            }
            tcp_flow_free_self6(pool, f);
            return -1;
        }
    }
    if (et & POLLOUT) {
        tcp_try_flush_in_pend6(f);
    }
    return 0;
}

static void handle_tcp_in6(struct poolhd *pool, const struct ip6_hdr *ih,
        const struct tcphdr *th, const char *payload, size_t paylen)
{
    const struct in6_addr *sa = &ih->ip6_src, *da = &ih->ip6_dst;
    uint16_t sp = th->source, dp = th->dest;

    struct vpn_flow6 *f = tcp_find6(sa, da, sp, dp);

    if (th->rst) {
        if (f) tcp_flow_free6(pool, f);
        return;
    }
    if (th->syn && !th->ack) {
        if (!f) {
            tcp_new_conn6(pool, ih, th);
        } else {
            send_tcp6(f, 0x02 | 0x10, f->isn, f->rcv_nxt, 0, 0);
        }
        return;
    }
    if (!f) {
        if (th->ack) {
            send_rst6(sa, da, sp, dp, ntohl(th->ack_seq), 0, false);
        }
        return;
    }

    uint32_t seq = ntohl(th->seq);
    f->snd_wnd = ntohs(th->window);

    if (th->ack) {
        uint32_t ack = ntohl(th->ack_seq);
        uint32_t acked = ack - f->snd_una;
        if (acked > 0 && acked <= f->out_sent) {
            memmove(f->out_buf, f->out_buf + acked, f->out_len - acked);
            f->out_len -= acked;
            f->out_sent -= acked;
            f->snd_una = ack;
            f->rto_ms = RTO_INIT_MS;
            if (f->out_sent > 0) {
                set_timer(pool, f->relay, f->rto_ms);
            } else {
                remove_timer(pool, f->relay);
            }
        }
        if (f->state == TS_SYN_RCVD) {
            f->state = TS_ESTABLISHED;
        }
    }

    if (paylen > 0 && seq == f->rcv_nxt) {
        f->seen_data = true;
        if (f->in_pend_len == 0) {
            ssize_t n = write(f->relay->fd, payload, paylen);
            if (n < 0 && errno == EAGAIN) {
                n = 0;
            } else if (n < 0) {
                n = (ssize_t)paylen;
            }
            if ((size_t)n < paylen) {
                size_t rem = paylen - (size_t)n;
                if (rem > TCP_IN_PEND_CAP) rem = TCP_IN_PEND_CAP;
                char *nb = realloc(f->in_pend, rem);
                if (nb) {
                    f->in_pend = nb;
                    memcpy(f->in_pend, payload + n, rem);
                    f->in_pend_len = rem;
                    f->in_pend_off = 0;
                    mod_etype(pool, f->relay, POLLIN | POLLOUT);
                }
            }
            f->rcv_nxt += paylen;
            send_tcp6(f, 0x10, f->snd_una + f->out_sent, f->rcv_nxt, 0, 0);
        }
    } else if (paylen > 0) {
        send_tcp6(f, 0x10, f->snd_una + f->out_sent, f->rcv_nxt, 0, 0);
    }

    if (th->fin && !f->fin_from_os) {
        uint32_t fin_seq = seq + paylen;
        if (fin_seq == f->rcv_nxt) {
            f->rcv_nxt += 1;
            f->fin_from_os = true;
            send_tcp6(f, 0x10, f->snd_una + f->out_sent, f->rcv_nxt, 0, 0);
            shutdown(f->relay->fd, SHUT_WR);
        }
    }
}

int on_vpn_udp_read_cb6(struct poolhd *pool, struct eval *val, int et)
{
    struct udp_flow6 *uf = val->vpn;
    if (!uf) return -1;
    if (et == POLLTIMEOUT) {
        udp_remove6(uf);
        val->vpn = 0;
        del_event(pool, val);
        free(uf);
        return 0;
    }
    char buf[2048];
    ssize_t n = recv(val->fd, buf, sizeof(buf), 0);
    if (n <= 0) {
        return 0;
    }
    set_timer(pool, val, UDP_IDLE_MS);

    size_t total = sizeof(struct ip6_hdr) + sizeof(struct udphdr) + (size_t)n;
    if (total > sizeof(struct ip6_hdr) + sizeof(struct udphdr) + 1500) {
        return 0; /* oversized reply, no fragmentation support -- drop */
    }
    char pkt[sizeof(struct ip6_hdr) + sizeof(struct udphdr) + 1500 + 40];
    struct ip6_hdr *ih = (struct ip6_hdr *)pkt;
    struct udphdr *uh = (struct udphdr *)(pkt + sizeof(*ih));

    memset(ih, 0, sizeof(*ih));
    ih->ip6_vfc = 0x60;
    ih->ip6_plen = htons((uint16_t)(sizeof(*uh) + n));
    ih->ip6_nxt = IPPROTO_UDP;
    ih->ip6_hlim = 64;
    ih->ip6_src = uf->daddr;
    ih->ip6_dst = uf->saddr;

    uh->source = uf->dport;
    uh->dest = uf->sport;
    uh->len = htons((uint16_t)(sizeof(*uh) + n));
    uh->check = 0;
    memcpy(pkt + sizeof(*ih) + sizeof(*uh), buf, (size_t)n);
    uh->check = l4_checksum6(&ih->ip6_src, &ih->ip6_dst, IPPROTO_UDP, uh, sizeof(*uh) + (size_t)n);
    /* unlike v4, an IPv6 UDP checksum of exactly 0 is not permitted
       (RFC 2460 8.1) and must be forced to the all-ones value */
    if (!uh->check) uh->check = 0xffff;

    ssize_t wn = write(g_tun_fd, pkt, sizeof(*ih) + sizeof(*uh) + (size_t)n);
    if (wn < 0) {
        uniperror("write tun (udp6)");
    }
    return 0;
}

static void handle_udp_in6(struct poolhd *pool, const struct ip6_hdr *ih,
        const struct udphdr *uh, const char *payload, size_t paylen)
{
    struct udp_flow6 *uf = udp_find6(&ih->ip6_src, &ih->ip6_dst, uh->source, uh->dest);
    if (!uf) {
        LOG(LOG_S, "vpn: new udp6 flow %s:%d -> %s:%d\n",
            ip_str6(&ih->ip6_src, (char[46]){0}, 46), ntohs(uh->source),
            ip_str6(&ih->ip6_dst, (char[46]){0}, 46), ntohs(uh->dest));
        int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (fd < 0) {
            uniperror("socket udp6");
            return;
        }
        if (tun_uplink_ifname6[0]) {
            if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                    tun_uplink_ifname6, strlen(tun_uplink_ifname6) + 1) < 0) {
                uniperror("setsockopt SO_BINDTODEVICE (udp6)");
            }
        }
        union sockaddr_u dst = { 0 };
        dst.in6.sin6_family = AF_INET6;
        dst.in6.sin6_addr = ih->ip6_dst;
        dst.in6.sin6_port = uh->dest;
        if (connect(fd, &dst.sa, sizeof(dst.in6)) < 0 && errno != EINPROGRESS) {
            uniperror("connect udp6");
            close(fd);
            return;
        }
        struct eval *val = add_event(pool, &on_vpn_udp_read_cb6, fd, POLLIN);
        if (!val) {
            close(fd);
            return;
        }
        uf = calloc(1, sizeof(*uf));
        if (!uf) {
            del_event(pool, val);
            return;
        }
        uf->saddr = ih->ip6_src; uf->daddr = ih->ip6_dst;
        uf->sport = uh->source; uf->dport = uh->dest;
        uf->sock = val;
        val->vpn = uf;
        udp_insert6(uf);
        set_timer(pool, val, UDP_IDLE_MS);
    }
    send(uf->sock->fd, payload, paylen, 0);
    remove_timer(pool, uf->sock);
    set_timer(pool, uf->sock, UDP_IDLE_MS);
}

/* =====================  tun fd reader  ============================== */

int on_tun_read_cb(struct poolhd *pool, struct eval *val, int et)
{
    char buf[65536];
    for (;;) {
        ssize_t n = read(val->fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EAGAIN) break;
            uniperror("read tun");
            break;
        }
        if ((size_t)n < 1) continue;
        uint8_t ipver = (uint8_t)buf[0] >> 4;

        if (ipver == 4) {
            if ((size_t)n < sizeof(struct iphdr)) continue;
            struct iphdr *ih = (struct iphdr *)buf;
            size_t iphlen = ih->ihl * 4u;
            if (iphlen < sizeof(struct iphdr) || (size_t)n < iphlen) continue;
            size_t l4len = ntohs(ih->tot_len) - iphlen;
            if (iphlen + l4len > (size_t)n) continue;

            if (ih->protocol == IPPROTO_TCP && l4len >= sizeof(struct tcphdr)) {
                struct tcphdr *th = (struct tcphdr *)(buf + iphlen);
                size_t thlen = th->doff * 4u;
                if (thlen < sizeof(struct tcphdr) || thlen > l4len) continue;
                LOG(LOG_L, "vpn: tun tcp packet %s:%d -> %s:%d flags=%c%c%c%c%c len=%zu\n",
                    ip_str(ih->saddr, (char[16]){0}, 16), ntohs(th->source),
                    ip_str(ih->daddr, (char[16]){0}, 16), ntohs(th->dest),
                    th->syn?'S':'-', th->ack?'A':'-', th->fin?'F':'-',
                    th->rst?'R':'-', th->psh?'P':'-', l4len - thlen);
                handle_tcp_in(pool, ih, th, buf + iphlen + thlen, l4len - thlen);
            } else if (ih->protocol == IPPROTO_UDP && l4len >= sizeof(struct udphdr)) {
                struct udphdr *uh = (struct udphdr *)(buf + iphlen);
                LOG(LOG_L, "vpn: tun udp packet %s:%d -> %s:%d len=%zu\n",
                    ip_str(ih->saddr, (char[16]){0}, 16), ntohs(uh->source),
                    ip_str(ih->daddr, (char[16]){0}, 16), ntohs(uh->dest),
                    l4len - sizeof(*uh));
                handle_udp_in(pool, ih, uh, buf + iphlen + sizeof(*uh), l4len - sizeof(*uh));
            }
            /* other protocols (ICMP, etc.) are silently ignored in v1 */

        } else if (ipver == 6) {
            if ((size_t)n < sizeof(struct ip6_hdr)) continue;
            struct ip6_hdr *ih = (struct ip6_hdr *)buf;
            size_t l4len = ntohs(ih->ip6_plen); /* does NOT include the 40-byte main header */
            if (sizeof(*ih) + l4len > (size_t)n) continue;
            /* extension headers between here and TCP/UDP aren't chased --
               ordinary traffic has ip6_nxt name the L4 protocol directly */

            if (ih->ip6_nxt == IPPROTO_TCP && l4len >= sizeof(struct tcphdr)) {
                struct tcphdr *th = (struct tcphdr *)(buf + sizeof(*ih));
                size_t thlen = th->doff * 4u;
                if (thlen < sizeof(struct tcphdr) || thlen > l4len) continue;
                LOG(LOG_L, "vpn: tun tcp6 packet %s:%d -> %s:%d flags=%c%c%c%c%c len=%zu\n",
                    ip_str6(&ih->ip6_src, (char[46]){0}, 46), ntohs(th->source),
                    ip_str6(&ih->ip6_dst, (char[46]){0}, 46), ntohs(th->dest),
                    th->syn?'S':'-', th->ack?'A':'-', th->fin?'F':'-',
                    th->rst?'R':'-', th->psh?'P':'-', l4len - thlen);
                handle_tcp_in6(pool, ih, th, buf + sizeof(*ih) + thlen, l4len - thlen);
            } else if (ih->ip6_nxt == IPPROTO_UDP && l4len >= sizeof(struct udphdr)) {
                struct udphdr *uh = (struct udphdr *)(buf + sizeof(*ih));
                LOG(LOG_L, "vpn: tun udp6 packet %s:%d -> %s:%d len=%zu\n",
                    ip_str6(&ih->ip6_src, (char[46]){0}, 46), ntohs(uh->source),
                    ip_str6(&ih->ip6_dst, (char[46]){0}, 46), ntohs(uh->dest),
                    l4len - sizeof(*uh));
                handle_udp_in6(pool, ih, uh, buf + sizeof(*ih) + sizeof(*uh), l4len - sizeof(*uh));
            }
        }
    }
    return 0;
}

/* =====================  init  ======================================= */

int vpn_init(struct poolhd *pool, int tun_fd)
{
    g_tun_fd = tun_fd;
    g_mss = (params.tun_mtu ? params.tun_mtu : 1500) - 40;
    srandom((unsigned)(time(0) ^ getpid()));
    if (!add_event(pool, &on_tun_read_cb, tun_fd, POLLIN)) {
        return -1;
    }
    return 0;
}

#else
typedef int byedpi_avoid_empty_tu_warning; /* this file is Linux-only */
#endif
