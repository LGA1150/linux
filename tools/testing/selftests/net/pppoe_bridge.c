// SPDX-License-Identifier: GPL-2.0-only
/*
 * Bridge two locally configured PPPoE channels without PPP negotiation.
 * Build: cc -O2 -Wall -Wextra -o pppoe_bridge pppoe_bridge.c
 * See pppoe_bridge.rst for the GRO -> PPP channel bridge -> NIC TSO test.
 */
#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_pppox.h>
#include <linux/ppp-ioctl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

struct endpoint {
	const char *ifname;
	const char *peer_text;
	uint8_t peer[ETH_ALEN];
	uint8_t local[ETH_ALEN];
	uint16_t sid;
	int mtu;
	int session_fd;
	int channel_fd;
	int channel;
};

static void usage(const char *prog)
{
	printf("Usage: %s IFACE_A PEER_MAC_A SESSION_A IFACE_B PEER_MAC_B SESSION_B\n"
	       "Create two PPPoE channels and join them with PPPIOCBRIDGECHAN.\n"
	       "Both Ethernet interfaces must be up. Session IDs are 1..65534\n"
	       "in decimal or 0xhex. Peer MACs are the remote MAC on each link.\n"
	       "Incoming frames must use the local destination MAC, the specified\n"
	       "peer source MAC, and that link's session ID.\n"
	       "Requires CAP_NET_ADMIN and access to /dev/ppp. No pppN is created.\n"
	       "Keep running while testing; SIGINT/SIGTERM/SIGHUP remove the bridge\n"
	       "and both sessions. No discovery, negotiation, or peer reply is needed.\n",
	       prog);
}

static uint16_t parse_session(const char *text)
{
	unsigned long sid;
	char *end;

	errno = 0;
	sid = strtoul(text, &end, 0);
	if (text[0] < '0' || text[0] > '9' || errno || *end || !sid || sid >= 65535)
		error(1, 0, "invalid session ID: %s (range 1..65534)", text);
	return sid;
}

static void parse_mac(const char *text, uint8_t *mac)
{
	unsigned int bytes[ETH_ALEN], i, nonzero = 0;

	if (strlen(text) != 17)
		error(1, 0, "invalid Ethernet address: %s", text);
	for (i = 0; i < 17; i++) {
		if (i % 3 == 2 ? text[i] != ':' :
		    !isxdigit((unsigned char)text[i]))
			error(1, 0, "invalid Ethernet address: %s", text);
	}
	if (sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x", &bytes[0], &bytes[1],
		   &bytes[2], &bytes[3], &bytes[4], &bytes[5]) != ETH_ALEN)
		error(1, 0, "invalid Ethernet address: %s", text);
	for (i = 0; i < ETH_ALEN; i++) {
		mac[i] = bytes[i];
		nonzero |= bytes[i];
	}
	if (!nonzero || (mac[0] & 1))
		error(1, 0, "peer must be a nonzero unicast MAC address: %s", text);
}

static void checked_ioctl(int fd, unsigned long request, void *arg,
			  const char *name, const struct endpoint *ep)
{
	if (ioctl(fd, request, arg) < 0)
		error(1, errno, "%s on %s (peer %s, session 0x%04x)",
		      name, ep->ifname, ep->peer_text, ep->sid);
}

static void check_interface(int fd, struct endpoint *ep)
{
	struct ifreq ifr = {};

	strcpy(ifr.ifr_name, ep->ifname);
	checked_ioctl(fd, SIOCGIFFLAGS, &ifr, "SIOCGIFFLAGS", ep);
	if (!(ifr.ifr_flags & IFF_UP))
		error(1, 0, "%s is down; bring it up with ip link set dev %s up",
		      ep->ifname, ep->ifname);
	checked_ioctl(fd, SIOCGIFHWADDR, &ifr, "SIOCGIFHWADDR", ep);
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
		error(1, 0, "%s is not an Ethernet interface", ep->ifname);
	memcpy(ep->local, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	checked_ioctl(fd, SIOCGIFMTU, &ifr, "SIOCGIFMTU", ep);
	if (ifr.ifr_mtu < PPPOE_SES_HLEN + 68)
		error(1, 0, "%s MTU is too small for PPPoE/IP", ep->ifname);
	ep->mtu = ifr.ifr_mtu - PPPOE_SES_HLEN;
}

static void connect_channel(struct endpoint *ep)
{
	/* sockaddr_pppox is packed; provide aligned storage for connect(). */
	union {
		struct sockaddr sa;
		struct sockaddr_pppox pppox;
	} addr = {
		.pppox = {
			.sa_family = AF_PPPOX,
			.sa_protocol = PX_PROTO_OE,
		},
	};

	strcpy(addr.pppox.sa_addr.pppoe.dev, ep->ifname);
	memcpy(addr.pppox.sa_addr.pppoe.remote, ep->peer, ETH_ALEN);
	addr.pppox.sa_addr.pppoe.sid = htons(ep->sid);
	ep->session_fd = socket(AF_PPPOX, SOCK_STREAM | SOCK_CLOEXEC, PX_PROTO_OE);
	if (ep->session_fd < 0)
		error(1, errno, "socket(AF_PPPOX); load the pppoe kernel module");
	if (connect(ep->session_fd, &addr.sa, sizeof(addr.pppox)))
		error(1, errno, "connect on %s (peer %s, session 0x%04x)",
		      ep->ifname, ep->peer_text, ep->sid);
	checked_ioctl(ep->session_fd, PPPIOCGCHAN, &ep->channel, "PPPIOCGCHAN", ep);
	ep->channel_fd = open("/dev/ppp", O_RDWR | O_CLOEXEC);
	if (ep->channel_fd < 0)
		error(1, errno, "open(/dev/ppp); use CAP_NET_ADMIN and load ppp_generic");
	checked_ioctl(ep->channel_fd, PPPIOCATTCHAN, &ep->channel, "PPPIOCATTCHAN", ep);
}

int main(int argc, char **argv)
{
	struct endpoint ep[2] = {};
	sigset_t signals;
	int fd, sig, ret, i;

	if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
		usage(argv[0]);
		return 0;
	}
	if (argc != 7) {
		usage(argv[0]);
		return 1;
	}
	for (i = 0; i < 2; i++) {
		ep[i].ifname = argv[1 + i * 3];
		ep[i].peer_text = argv[2 + i * 3];
		if (!ep[i].ifname[0] || strlen(ep[i].ifname) >= IFNAMSIZ)
			error(1, 0, "invalid interface name: %s", ep[i].ifname);
		parse_mac(ep[i].peer_text, ep[i].peer);
		ep[i].sid = parse_session(argv[3 + i * 3]);
	}
	if (!strcmp(ep[0].ifname, ep[1].ifname) && ep[0].sid == ep[1].sid &&
	    !memcmp(ep[0].peer, ep[1].peer, ETH_ALEN))
		error(1, 0, "endpoints must be distinct PPPoE sessions");
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		error(1, errno, "socket for interface queries");
	for (i = 0; i < 2; i++)
		check_interface(fd, &ep[i]);
	close(fd);

	/* sigwait avoids a signal arriving between checking a flag and sleeping. */
	sigemptyset(&signals);
	sigaddset(&signals, SIGINT);
	sigaddset(&signals, SIGTERM);
	sigaddset(&signals, SIGHUP);
	if (sigprocmask(SIG_BLOCK, &signals, NULL))
		error(1, errno, "sigprocmask");
	for (i = 0; i < 2; i++)
		connect_channel(&ep[i]);
	checked_ioctl(ep[0].channel_fd, PPPIOCBRIDGECHAN, &ep[1].channel,
		      "PPPIOCBRIDGECHAN", &ep[0]);

	printf("Bridged PPP channels %d <-> %d\n", ep[0].channel, ep[1].channel);
	for (i = 0; i < 2; i++) {
		printf("%c: %s local=%02x:%02x:%02x:%02x:%02x:%02x ",
		       'A' + i, ep[i].ifname, ep[i].local[0], ep[i].local[1],
		       ep[i].local[2], ep[i].local[3], ep[i].local[4], ep[i].local[5]);
		printf("peer=%s session=0x%04x PPP_MTU=%d\n",
		       ep[i].peer_text, ep[i].sid, ep[i].mtu);
	}
	fputs("Kernel forwards both ways. No pppN or PPP negotiation. ", stdout);
	puts("Ctrl-C removes both sessions.");
	fflush(stdout);
	ret = sigwait(&signals, &sig);
	if (ret)
		error(1, ret, "sigwait");

	/* Unregistering the channels also tears down their bridge. This works
	 * if an interface went down and the kernel already disconnected it.
	 */
	for (i = 0; i < 2; i++)
		close(ep[i].session_fd);
	for (i = 0; i < 2; i++)
		close(ep[i].channel_fd);
	return 0;
}
