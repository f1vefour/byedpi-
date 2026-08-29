#ifndef VPN_H
#define VPN_H
#ifdef __linux__

#include "conev.h"

/* Registers the tun fd in the event loop and starts tracking flows.
   Call once, after tun_start() and after init_pool(). */
int vpn_init(struct poolhd *pool, int tun_fd);

#endif
#endif
