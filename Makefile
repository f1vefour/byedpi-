TARGET = ciadpi

# _GNU_SOURCE (not just _DEFAULT_SOURCE) matters specifically for musl
# libc: musl only exposes the Linux-style struct tcphdr/udphdr field
# names (.source, .syn, .ack, .check, etc. -- what vpn.c uses
# throughout) when _GNU_SOURCE is defined; under _DEFAULT_SOURCE alone
# it falls back to BSD-style th_sport/th_flags names instead, which
# doesn't compile against this code at all. glibc doesn't gate those
# fields behind either macro, so this changes nothing there -- it's
# specifically what makes `make CC=<musl-target>-gcc` work for OpenWrt
# and other musl-based targets.
CPPFLAGS = -D_DEFAULT_SOURCE -D_GNU_SOURCE
CFLAGS += -I. -std=c99 -O2 -Wall -Wno-unused -Wextra -Wno-unused-parameter -pedantic
WIN_LDFLAGS = -lws2_32 -lmswsock

HEADERS = conev.h desync.h error.h extend.h kavl.h mpool.h packets.h params.h proxy.h tun.h vpn.h win_service.h
SRC = packets.c main.c conev.c proxy.c desync.c mpool.c extend.c tun.c vpn.c
WIN_SRC = win_service.c

OBJ = $(SRC:.c=.o)
WIN_OBJ = $(WIN_SRC:.c=.o)

PREFIX := /usr/local
INSTALL_DIR := $(DESTDIR)$(PREFIX)/bin/

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $(TARGET) $(OBJ) $(LDFLAGS)

windows: $(OBJ) $(WIN_OBJ)
	$(CC) -o $(TARGET).exe $(OBJ) $(WIN_OBJ) $(WIN_LDFLAGS)

$(OBJ): $(HEADERS)
.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

clean:
	rm -f $(TARGET) $(TARGET).exe $(OBJ) $(WIN_OBJ)

install: $(TARGET)
	mkdir -p $(INSTALL_DIR)
	install -m 755 $(TARGET) $(INSTALL_DIR)
