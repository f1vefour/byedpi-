#include "tun.h"
#ifdef __linux__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <endian.h>

#include <time.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <arpa/inet.h>

#include "params.h"
#include "error.h"

char tun_uplink_ifname[16] = { 0 };
char tun_uplink_ifname6[16] = { 0 };

/* Saved so tun_stop() can put things back exactly as they were. */
static bool orig_route_saved = false;
static bool orig_route_present = false;
static char orig_ifname[16] = { 0 };
static int orig_ifindex = 0;
static uint32_t orig_gw = 0; /* network byte order, 0 = no gateway (onlink) */
static int tun_ifindex = 0;

/* Same, for the IPv6 side. shadow6_installed tracks it separately
   from orig_route_saved since v6 is optional -- a v4-only host (or a
   sandbox/container with IPv6 disabled outright) just skips all of
   this rather than treating it as an error. */
static bool shadow6_installed = false;
static char orig_ifname6[16] = { 0 };


static int nl_add_attr(struct nlmsghdr *nh, size_t maxlen,
        int type, const void *data, size_t alen)
{
    struct rtattr *rta;
    size_t len = RTA_LENGTH(alen);
    if (NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
        return -1;
    }
    rta = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), data, alen);
    nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(len);
    return 0;
}


static int tun_alloc(char *dev /* IFNAMSIZ buffer, in/out */)
{
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        uniperror("open /dev/net/tun");
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (*dev) {
        snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    }
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        uniperror("ioctl TUNSETIFF");
        close(fd);
        return -1;
    }
    /* Without this, the second (and every later) read() in the tun
       drain loop blocks until a new packet arrives -- since that loop
       runs inside a single-threaded epoll callback, one blocking read
       here stalls the entire event loop, including every other flow's
       socket, until the next tun packet happens to show up. Cost me a
       while to track down: everything else -- routing, the relay
       socket, the reply actually arriving on the wire -- was fine. */
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        uniperror("fcntl O_NONBLOCK (tun)");
        close(fd);
        return -1;
    }
    snprintf(dev, IFNAMSIZ, "%s", ifr.ifr_name);
    return fd;
}


static int if_configure(const char *dev, uint32_t addr_h, uint32_t mask_h, int mtu)
{
    struct ifreq ifr;
    struct sockaddr_in *sin;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        uniperror("socket AF_INET");
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);

    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(addr_h);
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        uniperror("ioctl SIOCSIFADDR");
        close(sock);
        return -1;
    }
    sin->sin_addr.s_addr = htonl(mask_h);
    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        uniperror("ioctl SIOCSIFNETMASK");
        close(sock);
        return -1;
    }
    if (mtu > 0) {
        ifr.ifr_mtu = mtu;
        if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
            uniperror("ioctl SIOCSIFMTU");
            close(sock);
            return -1;
        }
    }
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        uniperror("ioctl SIOCGIFFLAGS");
        close(sock);
        return -1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        uniperror("ioctl SIOCSIFFLAGS");
        close(sock);
        return -1;
    }
    close(sock);
    return 0;
}


/* Some systems set net.ipv6.conf.default.disable_ipv6=1, which means
   every newly created interface (our tun device included) starts
   with IPv6 disabled on it specifically, regardless of the routes we
   install. Best-effort clear it for just this interface; if the file
   doesn't exist at all, IPv6 probably isn't compiled into the kernel
   here and the netlink calls below will fail on their own anyway. */
static void ensure_ipv6_not_disabled(const char *dev)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/disable_ipv6", dev);
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return;
    }
    if (write(fd, "0", 1) < 0) {
        /* best effort -- if this fails the netlink calls below will
           fail informatively instead of silently doing nothing */
    }
    close(fd);
}


/* Adds an IPv6 address to an already-up interface via RTM_NEWADDR.
   There's no ioctl equivalent of SIOCSIFADDR for IPv6 on modern
   Linux (the old one was removed years ago) -- netlink is the only
   way, which is no hardship since tun_start() already speaks it for
   routes. IFA_LOCAL and IFA_ADDRESS are set to the same value; the
   kernel only really needs IFA_ADDRESS for a non-point-to-point
   interface like this one, but setting both matches what ip-addr(8)
   itself sends and costs nothing. */
static int if_add_addr6(int ifindex, const struct in6_addr *addr, uint8_t prefixlen)
{
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        uniperror("socket NETLINK_ROUTE (addr6)");
        return -1;
    }
    struct {
        struct nlmsghdr nh;
        struct ifaddrmsg ifa;
        char attrbuf[64];
    } req;
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nh.nlmsg_type = RTM_NEWADDR;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    req.nh.nlmsg_seq = (uint32_t)time(0);
    req.ifa.ifa_family = AF_INET6;
    req.ifa.ifa_prefixlen = prefixlen;
    req.ifa.ifa_scope = 0; /* global */
    req.ifa.ifa_index = ifindex;

    if (nl_add_attr(&req.nh, sizeof(req), IFA_LOCAL, addr, sizeof(*addr)) < 0
            || nl_add_attr(&req.nh, sizeof(req), IFA_ADDRESS, addr, sizeof(*addr)) < 0) {
        LOG(LOG_E, "tun: addr6 netlink attr buffer too small\n");
        close(sock);
        return -1;
    }
    if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
        uniperror("send netlink (addr6)");
        close(sock);
        return -1;
    }
    char buf[4096];
    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    close(sock);
    if (n < 0) {
        uniperror("recv netlink (addr6)");
        return -1;
    }
    struct nlmsghdr *rnh = (struct nlmsghdr *)buf;
    if (rnh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(rnh);
        if (err->error != 0) {
            LOG(LOG_E, "netlink addr6 error: %s\n", strerror(-err->error));
            return -1;
        }
    }
    return 0;
}


/* /proc/net/route stores Destination/Gateway/Mask as the raw s_addr
   value (network byte order) printed with %X, so on a little-endian
   host strtoul() + assigning straight into s_addr reproduces the
   original address with no swap; on a big-endian host it needs one.
   Picks the default route (Destination 0) with the lowest metric. */
static bool find_default_route(char *ifname_out, uint32_t *gw_out)
{
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) {
        uniperror("fopen /proc/net/route");
        return false;
    }
    char line[256];
    bool found = false;
    unsigned long best_metric = ULONG_MAX;
    /* skip header */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return false;
    }
    while (fgets(line, sizeof(line), f)) {
        char iface[64];
        unsigned long dest, gw, flags, refcnt, use, metric, mask;
        if (sscanf(line, "%63s %lx %lx %lx %lu %lu %lu %lx",
                &iface[0], &dest, &gw, &flags, &refcnt, &use, &metric, &mask) != 8) {
            continue;
        }
        if (dest != 0 || mask != 0) {
            continue; /* not a default route */
        }
        if (!(flags & 0x1)) {
            continue; /* RTF_UP not set */
        }
        if (metric < best_metric) {
            best_metric = metric;
            found = true;
            snprintf(ifname_out, 16, "%s", iface);
            uint32_t raw = (uint32_t)gw;
            #if __BYTE_ORDER == __BIG_ENDIAN
            raw = __builtin_bswap32(raw);
            #endif
            *gw_out = raw; /* already network byte order */
        }
    }
    fclose(f);
    return found;
}


/* Same idea for IPv6: /proc/net/ipv6_route lines look like
     <dest 32 hex><plen 2 hex> <src 32 hex><plen 2 hex> <nexthop 32 hex>
     <metric 8 hex> <refcnt 8 hex> <use 8 hex> <flags 8 hex> <ifname>
   with every address printed as 32 raw hex chars (no colons). A
   missing file just means IPv6 is disabled here -- not an error,
   the caller treats it as "skip v6 capture". */
static bool find_default_route6(char *ifname_out, struct in6_addr *gw_out)
{
    FILE *f = fopen("/proc/net/ipv6_route", "r");
    if (!f) {
        return false;
    }
    char line[256];
    bool found = false;
    unsigned long best_metric = ULONG_MAX;
    while (fgets(line, sizeof(line), f)) {
        char dest[33], destplen[3], src[33], srcplen[3], nexthop[33], iface[64];
        unsigned long metric, refcnt, use, flags;
        if (sscanf(line, "%32s %2s %32s %2s %32s %lx %lx %lx %lx %63s",
                dest, destplen, src, srcplen, nexthop,
                &metric, &refcnt, &use, &flags, iface) != 10) {
            continue;
        }
        if (strcmp(dest, "00000000000000000000000000000000") != 0
                || strcmp(destplen, "00") != 0) {
            continue; /* not a default route */
        }
        if (!(flags & 0x1)) {
            continue; /* RTF_UP not set */
        }
        if (metric < best_metric) {
            best_metric = metric;
            found = true;
            snprintf(ifname_out, 16, "%s", iface);
            for (int i = 0; i < 16; i++) {
                char byte_hex[3] = { nexthop[i * 2], nexthop[i * 2 + 1], 0 };
                gw_out->s6_addr[i] = (uint8_t)strtoul(byte_hex, NULL, 16);
            }
        }
    }
    fclose(f);
    return found;
}


struct nl_req {
    struct nlmsghdr nh;
    struct rtmsg rt;
    char attrbuf[64];
};

/* Adds/deletes one IPv4 route in the main table. dst_len==0 means the
   default route; gw_net==0 means an onlink route (no gateway, just an
   oif) -- what we use for the tun side. */
static int rtnl_route(int cmd, unsigned flags,
        int oif, uint32_t gw_net, uint32_t dst_net, uint8_t dst_len)
{
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        uniperror("socket NETLINK_ROUTE");
        return -1;
    }
    struct nl_req req;
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nh.nlmsg_type = cmd;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
    req.nh.nlmsg_seq = (uint32_t)time(0);
    req.rt.rtm_family = AF_INET;
    req.rt.rtm_table = RT_TABLE_MAIN;
    req.rt.rtm_protocol = RTPROT_STATIC;
    req.rt.rtm_scope = gw_net ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
    req.rt.rtm_type = RTN_UNICAST;
    req.rt.rtm_dst_len = dst_len;

    if (dst_len) {
        nl_add_attr(&req.nh, sizeof(req), RTA_DST, &dst_net, sizeof(dst_net));
    }
    nl_add_attr(&req.nh, sizeof(req), RTA_OIF, &oif, sizeof(oif));
    if (gw_net) {
        nl_add_attr(&req.nh, sizeof(req), RTA_GATEWAY, &gw_net, sizeof(gw_net));
    }
    if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
        uniperror("send netlink");
        close(sock);
        return -1;
    }
    char buf[4096];
    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    close(sock);
    if (n < 0) {
        uniperror("recv netlink");
        return -1;
    }
    struct nlmsghdr *rnh = (struct nlmsghdr *)buf;
    if (rnh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(rnh);
        if (err->error != 0) {
            /* ESRCH on a delete just means the route is already gone --
               expected when the tun fd (and so the interface, and every
               route pinned to it) was already closed/torn down before
               we got here, e.g. by destroy_pool(). Anything else is a
               real problem worth logging. */
            if (!(cmd == RTM_DELROUTE && -err->error == ESRCH)) {
                LOG(LOG_E, "netlink route error: %s\n", strerror(-err->error));
            }
            return -1;
        }
    }
    return 0;
}

/* We deliberately do NOT touch/replace the original 0.0.0.0/0 route.
   Instead we add two more-specific routes -- 0.0.0.0/1 and 128.0.0.0/1
   via the tun device -- which together cover the whole IPv4 space and
   win over the original /0 by longest-prefix-match for everything on
   the system. The original default route is left completely intact,
   which is what lets ciadpi's own SO_BINDTODEVICE(uplink) outbound
   sockets (see remote_sock() in proxy.c) still find a route out the
   real interface: a socket bound to a device only ever considers
   routes via that device, and if we'd replaced/removed the uplink's
   only default route there'd be nothing left for it to use, so every
   real connection ciadpi makes would fail with ENETUNREACH. */
static int install_shadow_routes(int oif)
{
    if (rtnl_route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE,
            oif, 0, htonl(0x00000000u), 1) < 0) {
        return -1;
    }
    if (rtnl_route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE,
            oif, 0, htonl(0x80000000u), 1) < 0) {
        rtnl_route(RTM_DELROUTE, 0, oif, 0, htonl(0x00000000u), 1);
        return -1;
    }
    return 0;
}

static void remove_shadow_routes(int oif)
{
    rtnl_route(RTM_DELROUTE, 0, oif, 0, htonl(0x00000000u), 1);
    rtnl_route(RTM_DELROUTE, 0, oif, 0, htonl(0x80000000u), 1);
}


/* IPv6 counterpart of rtnl_route(). Kept as a separate function
   rather than folding family into rtnl_route() itself -- the address
   size differs (4 vs 16 bytes) enough that genericizing it would mean
   changing every existing v4 call site too, for no benefit; a proven
   working function is worth more than avoiding some duplication. */
static int rtnl_route6(int cmd, unsigned flags, int oif,
        const struct in6_addr *gw, const struct in6_addr *dst, uint8_t dst_len)
{
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        uniperror("socket NETLINK_ROUTE (v6)");
        return -1;
    }
    struct {
        struct nlmsghdr nh;
        struct rtmsg rt;
        char attrbuf[128];
    } req;
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nh.nlmsg_type = cmd;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
    req.nh.nlmsg_seq = (uint32_t)time(0);
    req.rt.rtm_family = AF_INET6;
    req.rt.rtm_table = RT_TABLE_MAIN;
    req.rt.rtm_protocol = RTPROT_STATIC;
    req.rt.rtm_scope = gw ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
    req.rt.rtm_type = RTN_UNICAST;
    req.rt.rtm_dst_len = dst_len;

    if (dst_len && dst
            && nl_add_attr(&req.nh, sizeof(req), RTA_DST, dst, sizeof(*dst)) < 0) {
        LOG(LOG_E, "tun: v6 netlink attr buffer too small (dst)\n");
        close(sock);
        return -1;
    }
    if (nl_add_attr(&req.nh, sizeof(req), RTA_OIF, &oif, sizeof(oif)) < 0) {
        LOG(LOG_E, "tun: v6 netlink attr buffer too small (oif)\n");
        close(sock);
        return -1;
    }
    if (gw && nl_add_attr(&req.nh, sizeof(req), RTA_GATEWAY, gw, sizeof(*gw)) < 0) {
        LOG(LOG_E, "tun: v6 netlink attr buffer too small (gw)\n");
        close(sock);
        return -1;
    }
    if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
        uniperror("send netlink (v6)");
        close(sock);
        return -1;
    }
    char buf[4096];
    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    close(sock);
    if (n < 0) {
        uniperror("recv netlink (v6)");
        return -1;
    }
    struct nlmsghdr *rnh = (struct nlmsghdr *)buf;
    if (rnh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(rnh);
        if (err->error != 0) {
            /* Same ESRCH-on-delete story as the v4 path: benign once
               the tun fd (and so the routes pinned to it) is already
               gone by the time we get here. */
            if (!(cmd == RTM_DELROUTE && -err->error == ESRCH)) {
                LOG(LOG_E, "netlink v6 route error: %s\n", strerror(-err->error));
            }
            return -1;
        }
    }
    return 0;
}

/* Same ::/1 + 8000::/1 split as the v4 0.0.0.0/1 + 128.0.0.0/1 one --
   two routes that together cover the whole v6 address space and win
   over the real ::/0 by longest-prefix-match, without ever touching
   the real default route (same reasoning as the v4 version: ciadpi's
   own SO_BINDTODEVICE'd v6 connections need it left alone). */
static int install_shadow_routes6(int oif)
{
    struct in6_addr lower, upper;
    memset(&lower, 0, sizeof(lower));
    memset(&upper, 0, sizeof(upper));
    upper.s6_addr[0] = 0x80;

    if (rtnl_route6(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, oif, NULL, &lower, 1) < 0) {
        return -1;
    }
    if (rtnl_route6(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, oif, NULL, &upper, 1) < 0) {
        rtnl_route6(RTM_DELROUTE, 0, oif, NULL, &lower, 1);
        return -1;
    }
    return 0;
}

static void remove_shadow_routes6(int oif)
{
    struct in6_addr lower, upper;
    memset(&lower, 0, sizeof(lower));
    memset(&upper, 0, sizeof(upper));
    upper.s6_addr[0] = 0x80;
    rtnl_route6(RTM_DELROUTE, 0, oif, NULL, &lower, 1);
    rtnl_route6(RTM_DELROUTE, 0, oif, NULL, &upper, 1);
}


static void set_defaults_if_unset(void)
{
    if (!params.tun_ifname[0]) {
        strcpy(params.tun_ifname, "byedpi0");
    }
    if (!params.tun_addr) {
        inet_pton(AF_INET, "10.231.0.1", &params.tun_addr);
        params.tun_addr = ntohl(params.tun_addr);
    }
    if (!params.tun_mask) {
        params.tun_mask = 0xffffff00u; /* /24 */
    }
    if (!params.tun_mtu) {
        params.tun_mtu = 1500;
    }
    if (!params.tun_prefix6) {
        /* fd00::/8 is the reserved Unique Local Address range -- exactly
           what this is for, an address that's guaranteed never to collide
           with anything actually routed on the internet. */
        inet_pton(AF_INET6, "fd66:6564:7069::1", &params.tun_addr6);
        params.tun_prefix6 = 64;
    }
}


int tun_start(void)
{
    set_defaults_if_unset();

    char devname[16];
    snprintf(devname, sizeof(devname), "%s", params.tun_ifname);

    int fd = tun_alloc(devname);
    if (fd < 0) {
        return -1;
    }
    snprintf(params.tun_ifname, sizeof(params.tun_ifname), "%s", devname);

    if (if_configure(devname, params.tun_addr, params.tun_mask, params.tun_mtu) < 0) {
        close(fd);
        return -1;
    }
    tun_ifindex = if_nametoindex(devname);
    if (!tun_ifindex) {
        uniperror("if_nametoindex");
        close(fd);
        return -1;
    }

    orig_route_present = find_default_route(orig_ifname, &orig_gw);
    if (orig_route_present) {
        orig_ifindex = if_nametoindex(orig_ifname);
        snprintf(tun_uplink_ifname, sizeof(tun_uplink_ifname), "%s", orig_ifname);
        LOG(LOG_S, "tun: uplink is %s (gw %s); ciadpi's own connections"
                " will keep using it directly\n",
            orig_ifname, inet_ntoa(*(struct in_addr *)&orig_gw));
    } else {
        LOG(LOG_E, "tun: no existing default route found -- ciadpi's own"
                " outbound connections have no way out; aborting\n");
        close(fd);
        return -1;
    }
    orig_route_saved = true;

    if (install_shadow_routes(tun_ifindex) < 0) {
        LOG(LOG_E, "tun: failed to install routes via %s\n", devname);
        tun_stop(fd);
        return -1;
    }
    struct in_addr tun_ia = { .s_addr = htonl(params.tun_addr) };
    LOG(LOG_S, "tun: %s up, %s/%d, now carrying all system traffic"
            " except ciadpi's own (no ip/ifconfig/iptables invoked)\n",
        devname, inet_ntoa(tun_ia), __builtin_popcount(params.tun_mask));

    /* IPv6 is best-effort and additive on top of the v4 setup above:
       if there's no v6 default route (no connectivity, or IPv6
       disabled outright), that's not an error -- we just skip it and
       v4 capture stands on its own. */
    struct in6_addr gw6;
    char ifname6[16] = { 0 };
    if (find_default_route6(ifname6, &gw6)) {
        char gw6_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &gw6, gw6_str, sizeof(gw6_str));
        int ifindex6 = if_nametoindex(ifname6);
        ensure_ipv6_not_disabled(devname);
        if (!ifindex6) {
            LOG(LOG_E, "tun: if_nametoindex(%s) failed for the IPv6 uplink,"
                    " skipping IPv6 capture\n", ifname6);
        } else if (if_add_addr6(tun_ifindex, &params.tun_addr6, params.tun_prefix6) < 0) {
            LOG(LOG_E, "tun: failed to assign an IPv6 address to %s,"
                    " skipping IPv6 capture\n", devname);
        } else if (install_shadow_routes6(tun_ifindex) < 0) {
            LOG(LOG_E, "tun: failed to install IPv6 routes via %s,"
                    " skipping IPv6 capture\n", devname);
        } else {
            snprintf(orig_ifname6, sizeof(orig_ifname6), "%s", ifname6);
            snprintf(tun_uplink_ifname6, sizeof(tun_uplink_ifname6), "%s", ifname6);
            shadow6_installed = true;
            char tun6_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &params.tun_addr6, tun6_str, sizeof(tun6_str));
            LOG(LOG_S, "tun: IPv6 uplink is %s (gw %s); also carrying v6"
                    " traffic now, %s/%d on %s\n",
                ifname6, gw6_str, tun6_str, params.tun_prefix6, devname);
        }
    } else {
        LOG(LOG_S, "tun: no IPv6 default route found -- v6 traffic will"
                " take its normal path, untouched by ciadpi\n");
    }

    return fd;
}


void tun_stop(int fd)
{
    if (orig_route_saved && tun_ifindex) {
        remove_shadow_routes(tun_ifindex);
        LOG(LOG_S, "tun: routes removed, %s's original default route was"
                " never touched\n", orig_ifname[0] ? orig_ifname : "the uplink");
    }
    if (shadow6_installed && tun_ifindex) {
        remove_shadow_routes6(tun_ifindex);
        LOG(LOG_S, "tun: IPv6 routes removed, %s's original default route"
                " was never touched\n", orig_ifname6[0] ? orig_ifname6 : "the uplink");
    }
    orig_route_saved = false;
    orig_route_present = false;
    shadow6_installed = false;
    tun_ifindex = 0;
    tun_uplink_ifname[0] = 0;
    tun_uplink_ifname6[0] = 0;
    orig_ifname6[0] = 0;

    if (fd >= 0) {
        close(fd); /* non-persistent tun device is destroyed here */
    }
}

#else
typedef int byedpi_avoid_empty_tu_warning; /* this file is Linux-only */
#endif
