// SPDX-License-Identifier: GPL-2.0-only
/*
 * Send PPPoE / IPv4 or IPv6 / UDP, TCP, or ICMP with CHECKSUM_PARTIAL.
 * Standalone build: cc -O2 -Wall -Wextra -o pppoe_csum pppoe_csum.c
 * See pppoe_csum.rst for receiver capture and software-fallback tracing.
 */
#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/virtio_net.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

enum {
	PPPOE_HLEN = 6,
	PPP_HLEN = 2,
	IPV4_HLEN = 20,
	IPV6_HLEN = 40,
	UDP_HLEN = 8,
	TCP_HLEN = 20,
	ICMP_HLEN = 8,
	IP_OFF = ETH_HLEN + PPPOE_HLEN + PPP_HLEN,
	UDP_CSUM_OFF = 6,
	TCP_CSUM_OFF = 16,
	ICMP_CSUM_OFF = 2,
	/* Keep IPv4 UDP/ICMP frames at least ETH_ZLEN, with room for seq. */
	MIN_PAYLOAD = ETH_ZLEN - (IP_OFF + IPV4_HLEN + UDP_HLEN),
};

enum csum_mode { PARTIAL, SOFTWARE, BAD };

struct ip_config {
	int family;
	unsigned int hdr_len;
	uint8_t src[16];
	uint8_t dst[16];
};

struct l4_proto {
	const char *name;
	uint8_t number;
	unsigned int hdr_len;
	unsigned int csum_offset;
};

static const struct l4_proto udp_proto = {
	.name = "udp", .number = IPPROTO_UDP,
	.hdr_len = UDP_HLEN, .csum_offset = UDP_CSUM_OFF,
};

static const struct l4_proto tcp_proto = {
	.name = "tcp", .number = IPPROTO_TCP,
	.hdr_len = TCP_HLEN, .csum_offset = TCP_CSUM_OFF,
};

static const struct l4_proto icmp4_proto = {
	.name = "icmp", .number = IPPROTO_ICMP,
	.hdr_len = ICMP_HLEN, .csum_offset = ICMP_CSUM_OFF,
};

static const struct l4_proto icmp6_proto = {
	.name = "icmp", .number = IPPROTO_ICMPV6,
	.hdr_len = ICMP_HLEN, .csum_offset = ICMP_CSUM_OFF,
};

static void usage(const char *prog)
{
	printf("Usage: %s -i IFACE -d DEST_MAC [options]\n"
	       "  -4 / -6       IPv4 (default) or IPv6\n"
	       "  -p PROTOCOL   udp (default), tcp, or icmp (Echo Request)\n"
	       "  -s ADDRESS    Source IP (default 192.0.2.1 or 2001:db8::1)\n"
	       "  -t ADDRESS    Destination IP (default 192.0.2.2 or 2001:db8::2)\n"
	       "  -S SESSION    PPPoE session ID, decimal or 0xhex (default 1)\n"
	       "  -l BYTES      Payload length (default 64; minimum 10, or 0 for TCP)\n"
	       "  -c COUNT      Number of packets, 100 ms apart (default 5)\n"
	       "  -m MODE       partial (default), software, or bad\n"
	       "  -n            Dry run: print virtio header and frame; do not send\n"
	       "                Without -i, use a test source MAC and MTU 1500\n"
	       "  -h            Show this help\n"
	       "Use the physical Ethernet interface; transmission needs CAP_NET_RAW.\n",
	       prog);
}

static unsigned int parse_uint(const char *text, unsigned int min,
			       unsigned int max)
{
	unsigned long value;
	char *end;

	errno = 0;
	value = strtoul(text, &end, 0);
	if (text[0] < '0' || text[0] > '9' || errno || *end ||
	    value < min || value > max)
		error(1, 0, "invalid number: %s (range %u..%u)", text, min, max);
	return value;
}

static void parse_mac(const char *text, uint8_t *mac)
{
	unsigned int bytes[ETH_ALEN];
	int end = 0;
	unsigned int i;

	if (strlen(text) != 17)
		error(1, 0, "invalid Ethernet address: %s", text);
	for (i = 0; i < 17; i++) {
		if (i % 3 == 2 ? text[i] != ':' :
		    !isxdigit((unsigned char)text[i]))
			error(1, 0, "invalid Ethernet address: %s", text);
	}
	if (sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%n", &bytes[0], &bytes[1],
		   &bytes[2], &bytes[3], &bytes[4], &bytes[5], &end) != ETH_ALEN ||
	    text[end])
		error(1, 0, "invalid Ethernet address: %s", text);
	for (i = 0; i < ETH_ALEN; i++)
		mac[i] = bytes[i];
}

static void put_be16(uint8_t *p, uint16_t value)
{
	p[0] = value >> 8;
	p[1] = value;
}

static void put_be32(uint8_t *p, uint32_t value)
{
	put_be16(p, value >> 16);
	put_be16(p + 2, value);
}

/* Sum bytes in network order, without alignment or host-endian assumptions. */
static uint32_t sum_bytes(const uint8_t *p, size_t len)
{
	uint32_t sum = 0;

	while (len >= 2) {
		sum += ((uint32_t)p[0] << 8) | p[1];
		p += 2;
		len -= 2;
	}
	if (len)
		sum += (uint32_t)p[0] << 8;
	return sum;
}

static uint16_t fold_sum(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

static uint16_t transport_checksum(const uint8_t *l4, size_t len,
				   const struct l4_proto *proto)
{
	uint16_t csum = ~fold_sum(sum_bytes(l4, len));

	/* UDP encodes a computed zero as all ones; TCP can use zero directly. */
	return !csum && proto->number == IPPROTO_UDP ? 0xffff : csum;
}

static uint16_t build_frame(uint8_t *frame, unsigned int payload,
			    uint16_t session, const struct ip_config *net,
			    uint32_t seq,
			    const struct l4_proto *proto, enum csum_mode mode,
			    uint16_t *seed)
{
	uint8_t *pppoe = frame + ETH_HLEN;
	uint8_t *ip = frame + IP_OFF;
	unsigned int l4_off = IP_OFF + net->hdr_len;
	unsigned int addr_len = net->family == AF_INET6 ? 16 : 4;
	uint8_t *l4 = frame + l4_off;
	size_t l4_len = proto->hdr_len + (size_t)payload;
	uint16_t expected, bad;
	unsigned int i;

	/* Ethernet addresses were populated by the caller. */
	put_be16(frame + 12, ETH_P_PPP_SES);
	memset(pppoe, 0, l4_off + proto->hdr_len - ETH_HLEN);
	pppoe[0] = 0x11; /* Version 1, type 1; code 0 = session data. */
	put_be16(pppoe + 2, session);
	put_be16(pppoe + 4, PPP_HLEN + net->hdr_len + l4_len);
	if (net->family == AF_INET6) {
		put_be16(pppoe + PPPOE_HLEN, 0x0057); /* Uncompressed PPP IPv6. */
		ip[0] = 0x60;
		put_be16(ip + 4, l4_len);
		ip[6] = proto->number; /* Next header; no extension headers. */
		ip[7] = 64;
		memcpy(ip + 8, net->src, addr_len);
		memcpy(ip + 24, net->dst, addr_len);
	} else {
		put_be16(pppoe + PPPOE_HLEN, 0x0021); /* Uncompressed PPP IPv4. */
		ip[0] = 0x45;
		put_be16(ip + 2, net->hdr_len + l4_len);
		put_be16(ip + 4, seq);
		put_be16(ip + 6, 0x4000); /* Don't fragment. */
		ip[8] = 64;
		ip[9] = proto->number;
		memcpy(ip + 12, net->src, addr_len);
		memcpy(ip + 16, net->dst, addr_len);
		/* The IPv4 header checksum is separate from CHECKSUM_PARTIAL. */
		put_be16(ip + 10, ~fold_sum(sum_bytes(ip, net->hdr_len)));
	}

	if (proto->number == IPPROTO_ICMP || proto->number == IPPROTO_ICMPV6) {
		l4[0] = net->family == AF_INET6 ? 128 : 8; /* Echo Request. */
		put_be16(l4 + 4, 0x1234); /* Identifier. */
		put_be16(l4 + 6, seq);
	} else {
		put_be16(l4, 12345);
		put_be16(l4 + 2, 54321);
		if (proto->number == IPPROTO_TCP) {
			put_be32(l4 + 4, seq);
			put_be32(l4 + 8, 1); /* Synthetic ACK; no connection required. */
			l4[12] = (TCP_HLEN / 4) << 4; /* Data offset; no options. */
			l4[13] = payload ? 0x18 : 0x10; /* PSH|ACK, or just ACK. */
			put_be16(l4 + 14, 65535); /* Window. */
		} else {
			put_be16(l4 + 4, l4_len);
		}
	}
	for (i = 0; i < payload; i++)
		l4[proto->hdr_len + i] = 0x5a + i * 37;
	if (payload >= sizeof(seq))
		put_be32(l4 + proto->hdr_len, seq);

	/* ICMPv4 has no pseudo-header. The other protocols use its folded,
	 * uncomplemented sum. IPv6 uses a 32-bit length whose upper word is
	 * zero here because PPPoE limits the frame size.
	 */
	*seed = 0;
	if (proto->number != IPPROTO_ICMP)
		*seed = fold_sum(sum_bytes(net->src, addr_len) +
				 sum_bytes(net->dst, addr_len) + proto->number + l4_len);
	put_be16(l4 + proto->csum_offset, *seed);
	expected = transport_checksum(l4, l4_len, proto);
	/* Treat the two one's-complement representations of zero as equivalent. */
	if (expected % 0xffff == *seed % 0xffff) {
		/* Ensure an unchanged seed is distinguishable from completion. */
		if (proto->number == IPPROTO_TCP)
			l4[15] ^= 1; /* Window also exists in a zero-payload segment. */
		else
			l4[l4_len - 1] ^= 1;
		expected = transport_checksum(l4, l4_len, proto);
	}
	if (mode == SOFTWARE) {
		put_be16(l4 + proto->csum_offset, expected);
	} else if (mode == BAD) {
		bad = expected ^ 1;
		/* Zero would disable IPv4 UDP checksumming instead of failing it. */
		put_be16(l4 + proto->csum_offset, bad ? bad : 2);
	}
	return expected;
}

static unsigned int interface_info(const char *name, uint8_t *src_mac,
				   bool dry_run)
{
	struct ifreq ifr = { 0 };
	unsigned int mtu;
	int fd;

	if (strlen(name) >= IFNAMSIZ)
		error(1, 0, "interface name is too long");
	strcpy(ifr.ifr_name, name);
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		error(1, errno, "socket for interface query");
	if (ioctl(fd, SIOCGIFHWADDR, &ifr))
		error(1, errno, "SIOCGIFHWADDR %s", name);
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
		error(1, 0, "%s is not an Ethernet interface", name);
	memcpy(src_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr))
		error(1, errno, "SIOCGIFFLAGS %s", name);
	if (!dry_run && !(ifr.ifr_flags & IFF_UP))
		error(1, 0, "%s is down", name);
	if (ioctl(fd, SIOCGIFMTU, &ifr))
		error(1, errno, "SIOCGIFMTU %s", name);
	if (ifr.ifr_mtu < ETH_ZLEN - ETH_HLEN)
		error(1, 0, "%s MTU is too small", name);
	mtu = ifr.ifr_mtu;
	close(fd);
	return mtu;
}

static void print_hex(const char *label, const void *data, size_t len)
{
	const uint8_t *p = data;
	size_t i;

	printf("%s=", label);
	for (i = 0; i < len; i++)
		printf("%02x", p[i]);
	putchar('\n');
}

int main(int argc, char **argv)
{
	struct sockaddr_ll addr = { .sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_PPP_SES), .sll_halen = ETH_ALEN };
	struct virtio_net_hdr vh = { 0 };
	struct ip_config net = { .family = AF_INET };
	const struct l4_proto *proto = &udp_proto;
	const char *ifname = NULL, *dest_mac = NULL, *mode_name = "partial";
	const char *src_text = NULL, *dst_text = NULL;
	unsigned int payload = 64, count = 5, mtu, i;
	unsigned int l4_off, data_off, min_payload, max_payload;
	uint16_t session = 1, seed, expected;
	enum csum_mode mode = PARTIAL;
	uint8_t src_mac[ETH_ALEN], *frame;
	bool dry_run = false;
	struct msghdr msg = { 0 };
	struct iovec iov[2];
	int fd = -1, opt, one = 1;
	size_t frame_len, total;
	ssize_t sent;

	static_assert(sizeof(vh) == 10, "unexpected legacy virtio header size");
	while ((opt = getopt(argc, argv, "46i:d:p:s:t:S:l:c:m:nh")) != -1) {
		switch (opt) {
		case '4':
			net.family = AF_INET;
			break;
		case '6':
			net.family = AF_INET6;
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'd':
			dest_mac = optarg;
			break;
		case 'p':
			if (!strcmp(optarg, "tcp"))
				proto = &tcp_proto;
			else if (!strcmp(optarg, "udp"))
				proto = &udp_proto;
			else if (!strcmp(optarg, "icmp"))
				proto = &icmp4_proto;
			else
				error(1, 0, "protocol must be udp, tcp, or icmp");
			break;
		case 's':
			src_text = optarg;
			break;
		case 't':
			dst_text = optarg;
			break;
		case 'S':
			session = parse_uint(optarg, 1, 65534);
			break;
		case 'l':
			payload = parse_uint(optarg, 0, UINT16_MAX);
			break;
		case 'c':
			count = parse_uint(optarg, 1, UINT_MAX);
			break;
		case 'm':
			mode_name = optarg;
			break;
		case 'n':
			dry_run = true;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}
	if ((!ifname && !dry_run) || !dest_mac || optind != argc) {
		usage(argv[0]);
		return 1;
	}
	if (!strcmp(mode_name, "software"))
		mode = SOFTWARE;
	else if (!strcmp(mode_name, "bad"))
		mode = BAD;
	else if (strcmp(mode_name, "partial"))
		error(1, 0, "mode must be partial, software, or bad");

	if (proto == &icmp4_proto && net.family == AF_INET6)
		proto = &icmp6_proto;
	if (!src_text)
		src_text = net.family == AF_INET6 ? "2001:db8::1" : "192.0.2.1";
	if (!dst_text)
		dst_text = net.family == AF_INET6 ? "2001:db8::2" : "192.0.2.2";
	if (inet_pton(net.family, src_text, net.src) != 1)
		error(1, 0, "invalid source address for selected IP version: %s", src_text);
	if (inet_pton(net.family, dst_text, net.dst) != 1)
		error(1, 0, "invalid destination address for selected IP version: %s", dst_text);
	net.hdr_len = net.family == AF_INET6 ? IPV6_HLEN : IPV4_HLEN;
	l4_off = IP_OFF + net.hdr_len;
	data_off = l4_off + proto->hdr_len;
	/* UDP/ICMP keep space for a sequence marker and avoid IPv4 frame padding. */
	min_payload = proto->number == IPPROTO_TCP ? 0 : MIN_PAYLOAD;
	max_payload = UINT16_MAX - PPP_HLEN - net.hdr_len - proto->hdr_len;
	if (payload < min_payload || payload > max_payload)
		error(1, 0, "%s payload length must be %u..%u",
		      proto->name, min_payload, max_payload);

	parse_mac(dest_mac, addr.sll_addr);
	if (ifname) {
		addr.sll_ifindex = if_nametoindex(ifname);
		if (!addr.sll_ifindex)
			error(1, errno, "if_nametoindex %s", ifname);
		mtu = interface_info(ifname, src_mac, dry_run);
	} else {
		const uint8_t test_mac[ETH_ALEN] = { 0x02, 0, 0, 0, 0, 1 };

		memcpy(src_mac, test_mac, ETH_ALEN);
		ifname = "offline";
		mtu = 1500;
	}
	frame_len = data_off + (size_t)payload;
	if (mtu < data_off - ETH_HLEN)
		error(1, 0, "MTU %u is too small for %s headers", mtu, proto->name);
	if (frame_len - ETH_HLEN > mtu)
		error(1, 0, "payload too large for MTU %u (maximum %u)",
		      mtu, mtu - (data_off - ETH_HLEN));
	frame = malloc(frame_len);
	if (!frame)
		error(1, errno, "malloc");
	memcpy(frame, addr.sll_addr, ETH_ALEN);
	memcpy(frame + ETH_ALEN, src_mac, ETH_ALEN);

	/* PACKET_VNET_HDR uses the legacy, native-endian virtio header.
	 * Offsets start at the Ethernet header, excluding this 10-byte prefix.
	 * The prefix is consumed by AF_PACKET and is never sent on the wire.
	 */
	vh.hdr_len = data_off;
	vh.gso_type = VIRTIO_NET_HDR_GSO_NONE;
	if (mode == PARTIAL) {
		vh.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
		vh.csum_start = l4_off;
		vh.csum_offset = proto->csum_offset;
	}
	iov[0] = (struct iovec) { .iov_base = &vh, .iov_len = sizeof(vh) };
	iov[1] = (struct iovec) { .iov_base = frame, .iov_len = frame_len };
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	total = sizeof(vh) + frame_len;
	if (!dry_run) {
		/* Protocol zero avoids subscribing this sending socket to RX traffic. */
		fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
		if (fd < 0)
			error(1, errno, "AF_PACKET socket (requires CAP_NET_RAW)");
		if (setsockopt(fd, SOL_PACKET, PACKET_VNET_HDR, &one, sizeof(one)))
			error(1, errno, "PACKET_VNET_HDR");
	}
	printf("%s: mode=%s session=0x%04x frame_len=%zu IPv%u/%s%s%s\n",
	       ifname, mode_name, session, frame_len,
	       net.family == AF_INET6 ? 6 : 4, proto->name,
	       proto->csum_offset == ICMP_CSUM_OFF ?
		" echo-request id=0x1234" : " ports=12345->54321",
	       dry_run ? " (dry run)" : "");
	if (mode == PARTIAL)
		printf("CHECKSUM_PARTIAL requested: csum_start=%u csum_offset=%u; no GSO\n",
		       l4_off, proto->csum_offset);
	for (i = 0; i < count; i++) {
		expected = build_frame(frame, payload, session, &net, i,
				       proto, mode, &seed);
		if (dry_run) {
			print_hex("vnet", &vh, sizeof(vh));
			print_hex("frame", frame, frame_len);
		} else {
			do {
				sent = sendmsg(fd, &msg, 0);
			} while (sent < 0 && errno == EINTR);
			if (sent < 0)
				error(1, errno, "sendmsg");
			if ((size_t)sent != total)
				error(1, 0, "short send: %zd of %zu bytes", sent, total);
		}
		printf("seq=%u seed=0x%04x expected_%s=0x%04x\n",
		       i, seed, proto->name, expected);
		fflush(stdout);
		if (!dry_run && i + 1 < count) {
			struct timespec delay = { .tv_nsec = 100000000 };

			while (nanosleep(&delay, &delay)) {
				if (errno != EINTR)
					error(1, errno, "nanosleep");
			}
		}
	}
	if (fd >= 0)
		close(fd);
	free(frame);
	return 0;
}
