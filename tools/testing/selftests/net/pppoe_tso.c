// SPDX-License-Identifier: GPL-2.0-only
/*
 * Request TCP segmentation of PPPoE frames with PACKET_VNET_HDR.
 * Build: cc -O2 -Wall -Wextra -o pppoe_tso pppoe_tso.c
 * See pppoe_tso.rst: successful transmission does not establish hardware TSO.
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
	TCP_HLEN = 20,
	TCP_CSUM_OFF = 16,
	/* Avoid kernel minimum-GSO-size clamping and short Ethernet frames. */
	MIN_MSS = 64,
};

struct config {
	int family;
	bool plain_ip;
	unsigned int ip_off, ip_hlen, tcp_off, hdr_len;
	uint16_t session;
	uint8_t src_mac[ETH_ALEN], dst_mac[ETH_ALEN];
	uint8_t src[16], dst[16];
};

static void usage(const char *prog)
{
	printf("Usage: %s -i IFACE -d DEST_MAC [options]\n"
	       "  -4 / -6       IPv4 (default) or IPv6\n"
	       "  -e ENCAP      pppoe (default), or ip for a plain Ethernet/IP control\n"
	       "  -m MODE       gso (default), or software for userspace segmentation\n"
	       "  -g MSS        TCP data bytes per segment (default min(1200, MTU limit))\n"
	       "  -l BYTES      Total TCP payload (default 2*MSS+137; must exceed MSS)\n"
	       "  -c COUNT      Number of large packets, 100 ms apart (default 1)\n"
	       "  -S SESSION    PPPoE session ID, decimal or 0xhex (default 1)\n"
	       "  -s ADDRESS    Source IP (default 192.0.2.1 or 2001:db8::1)\n"
	       "  -t ADDRESS    Destination IP (default 192.0.2.2 or 2001:db8::2)\n"
	       "  -n            Dry run: print virtio headers and frames; do not send\n"
	       "                Omit -i for an offline test MAC and MTU 1500\n"
	       "  -h            Show this help\n"
	       "Use the physical Ethernet NIC. Sending requires CAP_NET_RAW.\n"
	       "GSO requests can be segmented in software, rejected, or dropped.\n",
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
		error(1, 0, "destination must be a nonzero unicast MAC address");
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

static uint16_t build_frame(uint8_t *frame, const struct config *cfg,
			    uint32_t seq, uint16_t id, unsigned int offset,
			    unsigned int len, bool last, bool partial)
{
	uint8_t *ip = frame + cfg->ip_off, *tcp = frame + cfg->tcp_off;
	unsigned int addr_len = cfg->family == AF_INET6 ? 16 : 4;
	unsigned int tcp_len = TCP_HLEN + len, i;
	uint16_t ip_type = cfg->family == AF_INET6 ? ETH_P_IPV6 : ETH_P_IP;
	uint16_t csum;

	memset(frame, 0, cfg->hdr_len);
	memcpy(frame, cfg->dst_mac, ETH_ALEN);
	memcpy(frame + ETH_ALEN, cfg->src_mac, ETH_ALEN);
	put_be16(frame + 12, cfg->plain_ip ? ip_type : ETH_P_PPP_SES);
	if (!cfg->plain_ip) {
		uint8_t *pppoe = frame + ETH_HLEN;

		pppoe[0] = 0x11; /* Version 1, type 1, session data (code 0). */
		put_be16(pppoe + 2, cfg->session);
		/* The aggregate carries its actual length, not a guessed segment length. */
		put_be16(pppoe + 4, PPP_HLEN + cfg->ip_hlen + tcp_len);
		put_be16(pppoe + PPPOE_HLEN, cfg->family == AF_INET6 ? 0x57 : 0x21);
	}
	if (cfg->family == AF_INET6) {
		ip[0] = 0x60;
		put_be16(ip + 4, tcp_len);
		ip[6] = IPPROTO_TCP;
		ip[7] = 64;
		memcpy(ip + 8, cfg->src, addr_len);
		memcpy(ip + 24, cfg->dst, addr_len);
	} else {
		ip[0] = 0x45;
		put_be16(ip + 2, cfg->ip_hlen + tcp_len);
		put_be16(ip + 4, id);
		put_be16(ip + 6, 0x4000); /* DF: segmentation, not IP fragmentation. */
		ip[8] = 64;
		ip[9] = IPPROTO_TCP;
		memcpy(ip + 12, cfg->src, addr_len);
		memcpy(ip + 16, cfg->dst, addr_len);
		put_be16(ip + 10, ~fold_sum(sum_bytes(ip, cfg->ip_hlen)));
	}
	put_be16(tcp, 12345);
	put_be16(tcp + 2, 54321);
	put_be32(tcp + 4, seq + offset);
	put_be32(tcp + 8, 1); /* Synthetic ACK; no TCP connection required. */
	tcp[12] = (TCP_HLEN / 4) << 4;
	tcp[13] = last ? 0x18 : 0x10; /* PSH only on the last segment. */
	put_be16(tcp + 14, 65535);
	for (i = 0; i < len; i++)
		tcp[TCP_HLEN + i] = (seq + offset + i) * 37 + 0x5a;

	/* Linux's GSO input uses the full TCP length in the pseudo-header seed.
	 * The driver/segmenter adjusts it for each output segment.
	 */
	csum = fold_sum(sum_bytes(cfg->src, addr_len) +
			sum_bytes(cfg->dst, addr_len) + IPPROTO_TCP + tcp_len);
	put_be16(tcp + TCP_CSUM_OFF, csum);
	if (!partial) {
		csum = ~fold_sum(sum_bytes(tcp, tcp_len));
		put_be16(tcp + TCP_CSUM_OFF, csum);
	}
	return csum;
}

static unsigned int interface_info(const char *name, uint8_t *mac, bool dry_run)
{
	struct ifreq ifr = {};
	unsigned int mtu;
	int fd;

	if (!name[0] || strlen(name) >= IFNAMSIZ)
		error(1, 0, "invalid interface name: %s", name);
	strcpy(ifr.ifr_name, name);
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		error(1, errno, "socket for interface query");
	if (ioctl(fd, SIOCGIFHWADDR, &ifr))
		error(1, errno, "SIOCGIFHWADDR %s", name);
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
		error(1, 0, "%s is not an Ethernet interface", name);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr))
		error(1, errno, "SIOCGIFFLAGS %s", name);
	if (!dry_run && !(ifr.ifr_flags & IFF_UP))
		error(1, 0, "%s is down", name);
	if (ioctl(fd, SIOCGIFMTU, &ifr))
		error(1, errno, "SIOCGIFMTU %s", name);
	if (ifr.ifr_mtu < 0)
		error(1, 0, "invalid MTU on %s", name);
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

static void submit(int fd, struct sockaddr_ll *addr, struct virtio_net_hdr *vh,
		   uint8_t *frame, size_t len, bool dry_run)
{
	struct iovec iov[] = {
		{ .iov_base = vh, .iov_len = sizeof(*vh) },
		{ .iov_base = frame, .iov_len = len },
	};
	struct msghdr msg = {
		.msg_name = addr, .msg_namelen = sizeof(*addr),
		.msg_iov = iov, .msg_iovlen = 2,
	};
	ssize_t sent;

	if (dry_run) {
		print_hex("vnet", vh, sizeof(*vh));
		print_hex("frame", frame, len);
		return;
	}
	do {
		sent = sendmsg(fd, &msg, 0);
	} while (sent < 0 && errno == EINTR);
	if (sent < 0)
		error(1, errno, "sendmsg (request rejected or transmission failed)");
	if ((size_t)sent != sizeof(*vh) + len)
		error(1, 0, "short send: %zd of %zu bytes", sent, sizeof(*vh) + len);
}

int main(int argc, char **argv)
{
	struct config cfg = { .family = AF_INET, .session = 1 };
	struct sockaddr_ll addr = { .sll_family = AF_PACKET, .sll_halen = ETH_ALEN };
	struct virtio_net_hdr vh = {};
	const char *ifname = NULL, *dest_mac = NULL, *src_text = NULL, *dst_text = NULL;
	bool dry_run = false, software = false;
	unsigned int payload = 0, mss = 0, count = 1, mtu, max_mss, max_payload;
	unsigned int burst, segment, offset, len, segments;
	int fd = -1, opt, one = 1;
	uint8_t *frame;
	uint16_t csum;
	uint32_t seq;

	static_assert(sizeof(vh) == 10, "unexpected legacy virtio header size");
	while ((opt = getopt(argc, argv, "46i:d:e:m:g:l:c:S:s:t:nh")) != -1) {
		switch (opt) {
		case '4':
			cfg.family = AF_INET;
			break;
		case '6':
			cfg.family = AF_INET6;
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'd':
			dest_mac = optarg;
			break;
		case 's':
			src_text = optarg;
			break;
		case 't':
			dst_text = optarg;
			break;
		case 'n':
			dry_run = true;
			break;
		case 'e':
			if (strcmp(optarg, "ip") && strcmp(optarg, "pppoe"))
				error(1, 0, "encapsulation must be pppoe or ip");
			cfg.plain_ip = !strcmp(optarg, "ip");
			break;
		case 'm':
			if (strcmp(optarg, "gso") && strcmp(optarg, "software"))
				error(1, 0, "mode must be gso or software");
			software = !strcmp(optarg, "software");
			break;
		case 'g':
			mss = parse_uint(optarg, MIN_MSS, UINT16_MAX - 1);
			break;
		case 'l':
			payload = parse_uint(optarg, 1, UINT16_MAX);
			break;
		case 'c':
			count = parse_uint(optarg, 1, UINT_MAX);
			break;
		case 'S':
			cfg.session = parse_uint(optarg, 1, 65534);
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
	parse_mac(dest_mac, cfg.dst_mac);
	if (!src_text)
		src_text = cfg.family == AF_INET6 ? "2001:db8::1" : "192.0.2.1";
	if (!dst_text)
		dst_text = cfg.family == AF_INET6 ? "2001:db8::2" : "192.0.2.2";
	if (inet_pton(cfg.family, src_text, cfg.src) != 1 ||
	    inet_pton(cfg.family, dst_text, cfg.dst) != 1)
		error(1, 0, "invalid source/destination address for selected IP version");
	cfg.ip_off = ETH_HLEN + (cfg.plain_ip ? 0 : PPPOE_HLEN + PPP_HLEN);
	cfg.ip_hlen = cfg.family == AF_INET6 ? 40 : 20;
	cfg.tcp_off = cfg.ip_off + cfg.ip_hlen;
	cfg.hdr_len = cfg.tcp_off + TCP_HLEN;
	if (ifname) {
		mtu = interface_info(ifname, cfg.src_mac, dry_run);
		addr.sll_ifindex = if_nametoindex(ifname);
		if (!addr.sll_ifindex)
			error(1, errno, "if_nametoindex %s", ifname);
	} else {
		cfg.src_mac[0] = 2;
		cfg.src_mac[5] = 1;
		mtu = 1500;
		ifname = "offline";
	}
	if (mtu < cfg.hdr_len - ETH_HLEN + MIN_MSS)
		error(1, 0, "MTU %u is too small", mtu);
	max_mss = mtu - (cfg.hdr_len - ETH_HLEN);
	if (!mss)
		mss = max_mss < 1200 ? max_mss : 1200;
	if (mss > max_mss)
		error(1, 0, "MSS exceeds MTU %u (maximum %u)", mtu, max_mss);
	if (!payload)
		payload = 2 * mss + 137;
	/* Keep the whole frame below the legacy 64 KiB GSO device limit and
	 * all IP/PPPoE length fields representable, without BIG TCP or jumbograms.
	 */
	max_payload = UINT16_MAX - cfg.hdr_len;
	if (payload <= mss || payload > max_payload)
		error(1, 0, "payload must exceed MSS %u and be at most %u", mss, max_payload);
	segments = (payload + mss - 1) / mss;
	frame = malloc(cfg.hdr_len + payload);
	if (!frame)
		error(1, errno, "malloc");
	addr.sll_protocol = htons(cfg.plain_ip ?
				 (cfg.family == AF_INET6 ? ETH_P_IPV6 : ETH_P_IP) : ETH_P_PPP_SES);
	memcpy(addr.sll_addr, cfg.dst_mac, ETH_ALEN);
	/* Legacy PACKET_VNET_HDR fields are native-endian. All offsets exclude
	 * the 10-byte prefix and include Ethernet and (if present) PPPoE/PPP.
	 */
	vh.hdr_len = cfg.hdr_len;
	if (!software) {
		vh.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
		vh.gso_type = cfg.family == AF_INET6 ?
			VIRTIO_NET_HDR_GSO_TCPV6 : VIRTIO_NET_HDR_GSO_TCPV4;
		vh.gso_size = mss;
		vh.csum_start = cfg.tcp_off;
		vh.csum_offset = TCP_CSUM_OFF;
	}
	if (!dry_run) {
		fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
		if (fd < 0)
			error(1, errno, "AF_PACKET socket (requires CAP_NET_RAW)");
		if (setsockopt(fd, SOL_PACKET, PACKET_VNET_HDR, &one, sizeof(one)))
			error(1, errno, "PACKET_VNET_HDR");
	}
	printf("%s: encap=%s IPv%u mode=%s MSS=%u payload=%u expected_segments=%u%s\n",
	       ifname, cfg.plain_ip ? "ip" : "pppoe", cfg.family == AF_INET6 ? 6 : 4,
	       software ? "software" : "gso", mss, payload, segments, dry_run ? " (dry run)" : "");
	if (!software)
		printf("GSO request: type=%u hdr_len=%u gso_size=%u csum_start=%u csum_offset=%u\n",
		       vh.gso_type, cfg.hdr_len, mss, cfg.tcp_off, TCP_CSUM_OFF);
	for (burst = 0; burst < count; burst++) {
		seq = 1 + (uint32_t)burst * payload;
		for (offset = 0, segment = 0; offset < payload; offset += len, segment++) {
			len = payload - offset < mss ? payload - offset : mss;
			csum = build_frame(frame, &cfg, seq, burst * segments + segment + 1,
					   offset, len, offset + len == payload, false);
			printf("expected burst=%u segment=%u seq=%u payload=%u frame_len=%u",
			       burst, segment, seq + offset, len, cfg.hdr_len + len);
			if (!cfg.plain_ip)
				printf(" pppoe_len=%u", PPP_HLEN + cfg.ip_hlen + TCP_HLEN + len);
			printf(" ip_len=%u tcp_checksum=0x%04x\n",
			       cfg.ip_hlen + TCP_HLEN + len, csum);
			if (software)
				submit(fd, &addr, &vh, frame, cfg.hdr_len + len, dry_run);
		}
		if (!software) {
			csum = build_frame(frame, &cfg, seq, burst * segments + 1,
					   0, payload, true, true);
			printf("input burst=%u seq=%u frame_len=%u tcp_seed=0x%04x",
			       burst, seq, cfg.hdr_len + payload, csum);
			if (!cfg.plain_ip)
				printf(" pppoe_len=%u",
				       PPP_HLEN + cfg.ip_hlen + TCP_HLEN + payload);
			putchar('\n');
			submit(fd, &addr, &vh, frame, cfg.hdr_len + payload, dry_run);
		}
		printf("burst=%u %s; capture and trace to determine the result\n",
		       burst, dry_run ? "encoded" : "submitted");
		fflush(stdout);
		if (!dry_run && burst + 1 < count) {
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
