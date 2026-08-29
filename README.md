Implementation of some DPI bypass methods.
The program is a local SOCKS proxy server.

Usage example:
```
ciadpi --disorder 1 --auto=torst --tlsrec 1+s
ciadpi --fake -1 --ttl 8
```

------
### Argument descriptions
```
-i, --ip <ip>
    Listening IP, default 0.0.0.0

-p, --port <num>
    Listening port, default 1080

-D, --daemon
    Run in daemon mode
    Only supported on Linux and BSD systems

-w, --pidfile <filename>
    Location of the PID file

-E, --transparent
    Run in transparent proxy mode; SOCKS will not work
    
-G, --tun
    Systemwide VPN mode via a native TUN device (Linux only)
    Captures all system traffic except ciadpi's own outbound
    connections (see details below)
    The TUN device, its IP address, and routes are configured
    directly via ioctl/rtnetlink, without calling ip/ifconfig/iptables
    On exit (including via Ctrl+C) the routes are restored
    automatically
    Requires root privileges
    
-c, --max-conn <count>
    Maximum number of client connections, default 512

-I,  --conn-ip <ip>
    Address that outgoing connections will be bound to, default ::
    If an IPv4 address is given, IPv6 requests will be rejected

-b, --buf-size <size>
    Maximum amount of data received/sent per recv/send call
    Given in bytes, default 16384

-g, --def-ttl <num>
    TTL value for all outgoing connections
    Can help bypass detection of a non-standard/reduced TTL

-N, --no-domain
    Drop requests where the address is given as a domain
    Since resolving is done synchronously, it can slow down or even freeze the program

-U, --no-udp
    Don't proxy UDP
    
-F, --tfo
    Enables TCP Fast Open
    If the server supports it, the first packet is sent immediately along with the SYN
    Only supported on Linux (4.11+)
    
-A, --auto <t,r,s,n>
    Automatic mode
    If an event resembling blocking or breakage occurs,
    the bypass parameters following this option will be applied
    Possible events:
        torst   : Timeout expired, or the server reset the connection after the first request
        redirect: HTTP redirect whose Location domain doesn't match the outgoing one
        ssl_err : No ServerHello was received in response to the ClientHello, or the SH contains an invalid session_id
        none    : The previous group was skipped, e.g. due to a domain or protocol restriction
    
-L, --auto-mode <0-3>
    0: cache the IP only if reconnecting is possible
    1: also cache the IP if:
        torst - timeout/connection reset happened during the exchange (i.e. after the first data from the server)
        ssl_err - only one round of exchange occurred (request-response/request-response-request)
    2: sort groups by trigger count, ascending
    3: 1 and 2 together
    
-u, --cache-ttl <sec>
    Lifetime of a cache entry, default 100800 (28 hours)
    
-y, --cache-dump <file|->
    Dump the cache to a file or stdout. Format: <ip> <port> <group index> <time> <host>
    
-T, --timeout <sec>
    Timeout for the first response from the server, in seconds
    On Linux this is converted to milliseconds, so a fractional value can be given
    
-K, --proto <t,h,u,i>
    Protocol whitelist: tls,http,udp,ipv4
    
-H, --hosts <file|:string>
    Restrict the scope of parameters to a list of domains
    Domains must be separated by a newline or space
    
-j, --ipset <file|:str>
    Restrict by specific IPs/subnets
    
-V, --pf <port[-portr]>
    Restrict by ports
    
-R, --round <num[-numr]>
    Which request(s) to apply obfuscation to
    Default is 1, i.e. the first request
    
-s, --split <pos_t>
    Split the request at the given position
    The position has the form offset[:repeats:skip][+flag1[flag2]]
    Flags:
        +s: add the SNI offset
        +h: add the Host offset
        +n: zero offset
    Additional flags:
        +e: end; +m: middle
    Examples: 
        0+sm - split the request in the middle of the SNI
        1:3:5 - split at positions 1, 6, and 11
    The key can be given multiple times to split the request at several positions
    If offset is negative and has no flags, the packet size is added to it
    
-d, --disorder <pos_t>
    Similar to --split, but the parts are sent in reverse order
    
-o, --oob <pos_t>
    Similar to --split, but a part is sent as OOB data
    
-q, --disoob <pos_t>
    Similar to --disorder, but a part is sent as OOB data
    
-f, --fake <pos_t>
    Similar to --disorder, but a fake part is sent before the first chunk
    The number of bytes sent from the fake equals the size of the split part
    ! May be unstable on Windows
 
-t, --ttl <num>
    TTL for the fake packet, default 8
    You need to pick a value such that the packet doesn't reach the server but is still processed by the DPI

-S, --md5sig
    Set the TCP MD5 Signature option on the fake packet
    Most servers (mainly on Linux) drop packets with this option
    Only supported on Linux, may be disabled in some kernel builds (< 3.9, Android)

-O, --fake-offset <pos_t>
    Shift the start of the fake data
    Offsets with flags are calculated relative to the original request
       
-l, --fake-data <file|:str>
    Specify your own fake packets
    The string may contain escape characters (\n,\0,\0x10)

-e, --oob-data <char>
    Byte sent outside the main stream, default 'a'
    Can be given as ASCII or an escape character
    
-n, --fake-sni <str>
    Dynamically changes the SNI in the fake packet
    If the fake is larger than the request, it's shrunk (Padding/ECH sizes are changed or some extensions are removed)
    "?" is replaced with a random Latin letter, "#" with a digit, "*" with a letter or digit
    Can be given multiple times; a random SNI from the given ones is chosen for each request
    
-Q, --fake-tls-mod <flag>
    rand - fill the SessionID, Random, and KeyExchange fields with random data
    orig - use the original ClientHello as the fake
    msize=n - maximum fake size; a negative number shrinks the original size by -n bytes
    
-M, --mod-http <h[,d,r]>
    Various manipulations of the HTTP packet, can be combined
    hcsmix:
        "Host: name" -> "hOsT: name"
    dcsmix:
        "Host: name" -> "Host: NaMe"
    rmspace:
        "Host: name" -> "Host:name\t"

-r, --tlsrec <pos_t>
    Split the ClientHello into separate records at the given offset
    Can be given multiple times  

-m, --tlsminor <ver>
    Changes the third byte of the TLS record to the given value
    
-a, --udp-fake <count>
    Number of fake UDP packets

-Y, --drop-sack
    Ignore SACK, forcing the kernel to resend packets that were already delivered
    Only supported on Linux
```

------
### More details
`--split`

Splits the request into parts. Example with a 30-byte request:
- Parameters: `--split 3 --split 7`
- Send order: 1-3, 3-7, 7-30  

Positions should be given in increasing order.  

------
`--disorder`

The part covered by disorder is sent with TTL=1, meaning it's effectively never delivered anywhere.
The OS only finds out after sending the next part, when the server reports the loss via SACK.
The system then has to resend the previous packet, breaking the normal order.
- Parameters: `--disorder 7`
- Send order: 7-30, 1-7  

The above applies to Linux only.
On Windows, retransmission starts from the position where the loss began (the maximum ACK received from the server):
- Parameters: `--disorder 7`
- Send order: 7-30, 1-30

So it's a good idea to also use `split`:  
- Parameters: `--split 7 --disorder 23`
- Send order: 1-7, 23-30, 7-30

In practice it's optimal to use:  
* Linux: `--disorder 1`
* Windows: `--split 1+s --disorder 3+s`

------
`--fake`

- Parameters: `--fake 7`
- Send order: 1-7 fake, 7-30 original, 1-7 original

The data in the first part of the request is replaced with fake data.  
This part needs to pass through the DPI but not reach the server.
Since the part doesn't arrive, the OS will resend it, changing the order the same way `disorder` does.
The `ttl` and `md5sig` options exist to keep the fake from reaching the server.  

TTL needs to be tuned so the packet passes through all DPI but doesn't reach the server.  
On Linux there's md5sig. It sets the TCP MD5 Signature option, which keeps many servers from accepting the packet.
Unfortunately, md5sig doesn't work in every build.  

On Windows there's another way to keep the server from processing the fake.
This is combining `fake` with `disorder`:
- Parameters: `--disorder 1 --fake 7`
- Send order: 2-7 fake, 7-30 original, 1-30 original  

Even if the fake packet does reach the server, it will be overwritten by the full retransmission.  

In practice it's optimal to use:  
* Linux: `--fake -1 --md5sig`
* Windows: `--disorder 1 --fake -1`

------
`--oob`

TCP can send data outside the main stream using the URG flag, but only 1 byte per packet.  
All the data in such a packet is delivered to the application except the last byte, which is the out-of-band one:
- Parameters: `--oob 3`
- Sent: 1-4 with the URG flag (1-3 request data + byte 4, which will be truncated), 3-30

It's a good idea to place this byte within the SNI: `--oob 3+s` 

------
`--disoob`

Similar to `--disorder`, but the part is sent with an OOB byte:
- Parameters: `--disoob 3`
- Sent: 3-30, 1-4 with the URG flag (1-3 request data + byte 4, which will be truncated)

Used together with `--fake` or `--disorder`, you can get a packet where the OOB byte sits right at the split point:
- Parameters: `--disoob 3 --disorder 7`
- Sent: 3-30, 1-8 with the URG flag (1-3 + the byte that will be truncated + 4-8)

------
`--tlsrec`

A single TLS record can be split into several by slightly reworking the header.  
A new header is inserted at the split point, increasing the request size by 5 bytes.  

This header can be placed in the middle of the SNI, preventing the DPI from reading it correctly: 
`--tlsrec 3+s`

Although `tlsrec` and `oob` confuse the DPI, they can also confuse various middleboxes that don't support a full TCP/TLS stack.  
Because of this, they should be used together with `--auto`:  
`--auto=torst --timeout 3 --tlsrec 3+s`  
In this example, `tlsrec` is only applied if the connection was reset or a timeout expired, i.e. when blocking most likely occurred.  
Conversely, you can disable tlsrec if the server resets the connection or drops the packet:  
`--tlsrec 3+s --auto=torst --timeout 3`  

------
`-Y, --drop-sack`

Forces the kernel to ignore packets with the TCP SACK extension.
This extension lets the receiver acknowledge individual data segments.
If the first part of a request is lost but the second reaches the server, the server can use this extension to notify the client. The client, knowing the second part arrived, then only resends the first.  
Why ignore this extension? The second segment might be a fake. If it reaches the server but the client doesn't find out, it will try to resend it. But that segment will already contain the original data, overwriting the fake and thereby preventing the protocol from breaking.  
Since fast acknowledgment won't work, this breaks `disorder`, and also adds a delay before retransmission (around 200ms).

------
`--tun`

Brings up a TUN device (default `byedpi0`, 10.231.0.1/24) and captures system traffic, acting like an ordinary VPN client but without external dependencies like iproute2 or iptables -- the device is created and routes are configured directly via syscalls.

Instead of replacing the main default route, two more specific routes are added -- `0.0.0.0/1` and `128.0.0.0/1` via the TUN device -- which together cover the entire address range without touching the original default route. This matters: ciadpi's own outbound connections are bound (`SO_BINDTODEVICE`) to the original uplink, and if the main route had been replaced they'd have nowhere to go.

Each captured TCP connection is wrapped in a socketpair() and goes through the existing desync/relay code unchanged -- meaning all the other parameters (`--split`, `--disorder`, `--fake`, etc.) work exactly the same in this mode as they do normally.

Limitations:
- IPv4 only
- no TCP SACK or out-of-order handling (the server has to resend after the OS's own timeout)
- on a half-closed connection, if the OS sends a FIN but the relay side never closes, the flow's state can leak (UDP has idle-timeout garbage collection; TCP doesn't yet)
- assumes a single uplink -- whichever interface held the default route at startup
- not tested under heavy load or with a large number of simultaneous connections

------
`--auto`, `--hosts`

The `auto` parameter splits options into groups.
For each request they are walked through left to right.
First the trigger given in `auto` is checked, then `pf`, `ipset`, `proto`, and `hosts`.

You can specify several option groups, separating them with this parameter.  
Parameters that come after `--timeout` in the help text can be moved into a separate group.  

#### Examples:
```
--fake -1 --ttl 10 --auto=ssl_err --fake -1 --ttl 5
```
Use `fake` with ttl=10 by default; on error, use `fake` with ttl=5

```
--hosts list.txt --disorder 3 --auto=none
```
Apply obfuscation only to domains from list.txt

```
--hosts list.txt --auto=none --disorder 3
```
Don't apply obfuscation to domains from list.txt

```
--auto=torst --hosts list.txt --disorder 3
```
Do nothing by default; use disorder if blocking occurred and the domain is in list.txt.

```
--proto=http,tls --disorder 3 --auto=none
```
Obfuscate only HTTP and TLS

```
--proto=http --fake -1 --fake-data=':GET /...' --auto=none --fake -1
```
Override the fake packet for HTTP

------
### Building
You'll need: 
`make`, `gcc/clang` for Linux, `mingw` for Windows  

* Linux: `make`
* Windows: `make windows CC=x86_64-w64-mingw32-gcc`

------
### Docker image

The Docker image is published on [DockerHub](https://hub.docker.com/r/hufrea/byedpi).
An example container configuration can be found in [dist/docker](dist/docker).

------
### Further reading on DPI, sources of ideas  
* https://github.com/bol-van/zapret/blob/master/docs/readme.md  
* https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf  
* https://habr.com/ru/post/335436  
