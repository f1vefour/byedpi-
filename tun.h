#ifndef TUN_H
#define TUN_H
#ifdef __linux__

#include <stdint.h>
#include <stdbool.h>

/* Name of the physical interface that had the default route before we
   touched anything. Set by tun_start(), consumed by proxy.c's
   remote_sock() to SO_BINDTODEVICE our own outbound sockets so they
   can't loop back through the tunnel they just created. Empty string
   means "don't bind" (tun mode inactive, or no default route existed
   to begin with). */
extern char tun_uplink_ifname[16];

/* Same, for IPv6 -- may be empty even when tun_uplink_ifname isn't:
   IPv6 capture is best-effort and simply skipped if the host had no
   IPv6 default route at startup, which isn't an error. remote_sock()
   picks between the two based on the destination's address family. */
extern char tun_uplink_ifname6[16];

/* Opens /dev/net/tun, creates params.tun_ifname, assigns
   params.tun_addr/tun_mask, brings it up, and shadows the system
   default route with it for every destination (via two /1 routes,
   which win over the real 0.0.0.0/0 by longest-prefix-match) while
   leaving the original default route completely untouched -- that's
   what lets ciadpi's own outbound connections still reach the real
   internet directly (see tun_uplink_ifname below). Does the same for
   IPv6 if the host has a v6 default route at startup. Returns the tun
   fd, or -1 on error (nothing is left half-configured on error; it
   cleans up after itself). */
int tun_start(void);

/* Reverses everything tun_start() did: removes the shadow routes (v4
   and, if installed, v6) and closes the fd (which destroys the
   non-persistent tun device). The original default route(s) were
   never modified, so there's nothing to restore for them. Safe to
   call even if tun_start() partially failed or was never called.
   Idempotent. */
void tun_stop(int fd);

#endif
#endif
