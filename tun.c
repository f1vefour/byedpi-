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
#include <arpa/inet.h>

#include "params.h"
#include "error.h"

char tun_uplink_ifname[16] = { 0 };

/* Saved so tun_stop() can put things back exactly as they were. */
static bool orig_route_saved = false;
static bool orig_route_present = false;
static char orig_ifname[16] = { 0 };
static int orig_ifindex = 0;
static uint32_t orig_gw = 0; /* network byte order, 0 = no gateway (onlink) */
static int tun_ifindex = 0;


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


struct nl_req {
    struct nlmsghdr nh;
    struct rtmsg rt;
    char attrbuf[64];
};

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
    return fd;
}


void tun_stop(int fd)
{
    if (orig_route_saved && tun_ifindex) {
        remove_shadow_routes(tun_ifindex);
        LOG(LOG_S, "tun: routes removed, %s's original default route was"
                " never touched\n", orig_ifname[0] ? orig_ifname : "the uplink");
    }
    orig_route_saved = false;
    orig_route_present = false;
    tun_ifindex = 0;
    tun_uplink_ifname[0] = 0;

    if (fd >= 0) {
        close(fd); /* non-persistent tun device is destroyed here */
    }
}

#else
typedef int byedpi_avoid_empty_tu_warning; /* this file is Linux-only */
#endif
