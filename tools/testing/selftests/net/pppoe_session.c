// SPDX-License-Identifier: GPL-2.0-only
/*
 * Create a PPP interface over a locally configured PPPoE session.
 * No PPPoE discovery, PPP negotiation, or responding peer is required.
 * Build: cc -O2 -Wall -Wextra -o pppoe_session pppoe_session.c
 */
#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
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

static void usage(const char *prog)
{
	printf("Usage: %s -i IFACE -d DEST_MAC [options]\n"
	       "  -i IFACE      Underlying Ethernet interface (must be up)\n"
	       "  -d DEST_MAC   Receiver's unicast Ethernet address\n"
	       "  -S SESSION    PPPoE session ID, decimal or 0xhex (default 1)\n"
	       "  -u UNIT       Create pppUNIT (default: first available unit)\n"
	       "  -m MTU        PPP MTU (default: Ethernet MTU minus 8)\n"
	       "  -h            Show this help\n"
	       "Needs CAP_NET_ADMIN and access to /dev/ppp.\n"
	       "Keeps the interface up until SIGINT, SIGTERM, or SIGHUP.\n"
	       "Assign IP addresses and routes separately with ip.\n", prog);
}

static int parse_int(const char *text, int min, int max)
{
	unsigned long value;
	char *end;

	errno = 0;
	value = strtoul(text, &end, 0);
	if (text[0] < '0' || text[0] > '9' || errno || *end ||
	    value < (unsigned long)min || value > (unsigned long)max)
		error(1, 0, "invalid number: %s (range %d..%d)", text, min, max);
	return value;
}

static void parse_mac(const char *text, uint8_t *mac)
{
	unsigned int bytes[ETH_ALEN];
	unsigned int i, nonzero = 0;

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
		error(1, 0, "destination must be a nonzero unicast MAC address");
}

static void checked_ioctl(int fd, unsigned long request, void *arg,
			  const char *name)
{
	if (ioctl(fd, request, arg) < 0)
		error(1, errno, "%s", name);
}

int main(int argc, char **argv)
{
	/* sockaddr_pppox is packed; the union gives connect() aligned storage. */
	union {
		struct sockaddr sa;
		struct sockaddr_pppox pppox;
	} addr = {
		.pppox = {
			.sa_family = AF_PPPOX,
			.sa_protocol = PX_PROTO_OE,
		},
	};
	const char *ifname = NULL, *dest = NULL;
	struct npioctl npi = { .mode = NPMODE_PASS };
	int unit = -1, mtu = 0, session = 1;
	int ctl_fd, session_fd, unit_fd, channel_fd;
	int channel, max_mtu, flags = 0, sig, ret, opt;
	struct ifreq ifr = {};
	sigset_t signals;

	while ((opt = getopt(argc, argv, "i:d:S:u:m:h")) != -1) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		case 'd':
			dest = optarg;
			break;
		case 'S':
			/* RFC 2516 reserves session IDs 0 and 0xffff. */
			session = parse_int(optarg, 1, 65534);
			break;
		case 'u':
			unit = parse_int(optarg, 0, INT_MAX);
			break;
		case 'm':
			/* The 16-bit PPPoE length includes the two-byte PPP protocol. */
			mtu = parse_int(optarg, 68, 65533);
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}
	if (!ifname || !dest || optind != argc) {
		usage(argv[0]);
		return 1;
	}
	if (!ifname[0] || strlen(ifname) >= IFNAMSIZ)
		error(1, 0, "invalid interface name: %s", ifname);
	parse_mac(dest, addr.pppox.sa_addr.pppoe.remote);
	strcpy(addr.pppox.sa_addr.pppoe.dev, ifname);
	addr.pppox.sa_addr.pppoe.sid = htons(session);

	ctl_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (ctl_fd < 0)
		error(1, errno, "socket(AF_INET)");
	strcpy(ifr.ifr_name, ifname);
	checked_ioctl(ctl_fd, SIOCGIFFLAGS, &ifr, "SIOCGIFFLAGS (Ethernet)");
	if (!(ifr.ifr_flags & IFF_UP))
		error(1, 0, "%s is down; bring it up with ip link set dev %s up",
		      ifname, ifname);
	checked_ioctl(ctl_fd, SIOCGIFHWADDR, &ifr, "SIOCGIFHWADDR");
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
		error(1, 0, "%s is not an Ethernet interface", ifname);
	checked_ioctl(ctl_fd, SIOCGIFMTU, &ifr, "SIOCGIFMTU (Ethernet)");
	max_mtu = ifr.ifr_mtu - PPPOE_SES_HLEN;
	if (max_mtu > 65533)
		max_mtu = 65533;
	if (max_mtu < 68 || mtu > max_mtu)
		error(1, 0, "PPP MTU must fit Ethernet MTU minus 8 (maximum %d)",
		      max_mtu);
	if (!mtu)
		mtu = max_mtu;

	/* Block termination signals before creating resources; sigwait has no race. */
	sigemptyset(&signals);
	sigaddset(&signals, SIGINT);
	sigaddset(&signals, SIGTERM);
	sigaddset(&signals, SIGHUP);
	if (sigprocmask(SIG_BLOCK, &signals, NULL))
		error(1, errno, "sigprocmask");

	/* connect() installs a local session; it sends no discovery or PPP packets. */
	session_fd = socket(AF_PPPOX, SOCK_STREAM | SOCK_CLOEXEC, PX_PROTO_OE);
	if (session_fd < 0)
		error(1, errno, "socket(AF_PPPOX); load the pppoe kernel module");
	if (connect(session_fd, &addr.sa, sizeof(addr.pppox)))
		error(1, errno, "connect(PPPoE session)");
	checked_ioctl(session_fd, PPPIOCGCHAN, &channel, "PPPIOCGCHAN");

	channel_fd = open("/dev/ppp", O_RDWR | O_CLOEXEC);
	if (channel_fd < 0)
		error(1, errno, "open(/dev/ppp); load ppp_generic and use CAP_NET_ADMIN");
	checked_ioctl(channel_fd, PPPIOCATTCHAN, &channel, "PPPIOCATTCHAN");

	unit_fd = open("/dev/ppp", O_RDWR | O_CLOEXEC);
	if (unit_fd < 0)
		error(1, errno, "open(/dev/ppp) for unit");
	checked_ioctl(unit_fd, PPPIOCNEWUNIT, &unit, "PPPIOCNEWUNIT");
	checked_ioctl(channel_fd, PPPIOCCONNECT, &unit, "PPPIOCCONNECT");
	/* No VJ compression, CCP, multilink, or demand-dial loopback. */
	checked_ioctl(unit_fd, PPPIOCSFLAGS, &flags, "PPPIOCSFLAGS");
	npi.protocol = PPP_IP;
	checked_ioctl(unit_fd, PPPIOCSNPMODE, &npi, "PPPIOCSNPMODE (IPv4)");
	npi.protocol = PPP_IPV6;
	checked_ioctl(unit_fd, PPPIOCSNPMODE, &npi, "PPPIOCSNPMODE (IPv6)");

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "ppp%d", unit);
	ifr.ifr_mtu = mtu;
	checked_ioctl(ctl_fd, SIOCSIFMTU, &ifr, "SIOCSIFMTU (PPP)");
	checked_ioctl(unit_fd, PPPIOCSMRU, &mtu, "PPPIOCSMRU");
	checked_ioctl(ctl_fd, SIOCGIFFLAGS, &ifr, "SIOCGIFFLAGS (PPP)");
	ifr.ifr_flags |= IFF_UP;
	checked_ioctl(ctl_fd, SIOCSIFFLAGS, &ifr, "SIOCSIFFLAGS (PPP)");
	close(ctl_fd);

	printf("Created %s: %s -> %s, session 0x%04x, MTU %d\n",
	       ifr.ifr_name, ifname, dest, session, mtu);
	printf("IPv4/IPv6 enabled without negotiation. Assign addresses/routes with ip.\n"
	       "Keep this process running; Ctrl-C removes the interface and session.\n");
	fflush(stdout);
	ret = sigwait(&signals, &sig);
	if (ret)
		error(1, ret, "sigwait");

	/* The unit owner closing its fd unregisters the interface and its routes. */
	close(unit_fd);
	close(channel_fd);
	close(session_fd);
	return 0;
}
