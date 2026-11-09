// SPDX-License-Identifier: GPL-2.0
/* Exercise PPPoE session lookup while the per-net hash table changes size. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_pppox.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../kselftest_harness.h"

#define SESSION_COUNT 2048

static const unsigned char remote[ETH_ALEN] = { 0x02, 0, 0, 0, 0, 0x10 };
static const char * const devices[] = { "pppoe0", "pppoe1" };

FIXTURE(pppoe_hash) {
	int sockets[SESSION_COUNT];
	int count;
	int tx;
};

static void create_devices(struct __test_metadata *_metadata)
{
	ASSERT_EQ(0, system("ip link add pppoe0 type veth peer name pppoe1"));
	ASSERT_EQ(0, system("ip link set pppoe0 address 02:00:00:00:00:01 up"));
	ASSERT_EQ(0, system("ip link set pppoe1 address 02:00:00:00:00:02 up"));
}

static int connect_session(int fd, unsigned int device, unsigned int sid,
			   const unsigned char *mac)
{
	struct sockaddr_pppox addr = {
		.sa_family = AF_PPPOX,
		.sa_protocol = PX_PROTO_OE,
		.sa_addr.pppoe.sid = htons(sid),
	};

	strcpy(addr.sa_addr.pppoe.dev, devices[device]);
	memcpy(addr.sa_addr.pppoe.remote, mac, ETH_ALEN);
	return connect(fd, (struct sockaddr *)&addr, sizeof(addr));
}

static int new_session(struct __test_metadata *_metadata,
		       FIXTURE_DATA(pppoe_hash) *self, unsigned int device,
		       unsigned int sid, const unsigned char *mac)
{
	struct timeval timeout = { .tv_sec = 2 };
	int fd;

	ASSERT_LT(self->count, SESSION_COUNT);
	fd = socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_OE);
	ASSERT_GE(fd, 0);
	self->sockets[self->count++] = fd;
	ASSERT_EQ(0, setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
			       &timeout, sizeof(timeout)));
	ASSERT_EQ(0, connect_session(fd, device, sid, mac));
	return fd;
}

static void check_packet(struct __test_metadata *_metadata,
			FIXTURE_DATA(pppoe_hash) *self, int fd,
			unsigned int device, unsigned int sid,
			const unsigned char *mac)
{
	unsigned char payload[] = { 0, 0x21, sid >> 8, sid, 0xaa, 0x55 };
	unsigned char frame[ETH_HLEN + sizeof(struct pppoe_hdr) + sizeof(payload)];
	struct pppoe_hdr *ph = (struct pppoe_hdr *)(frame + ETH_HLEN);
	struct ethhdr *eth = (struct ethhdr *)frame;
	struct sockaddr_ll addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_PPP_SES),
		.sll_ifindex = if_nametoindex(devices[!device]),
	};
	unsigned char received[sizeof(payload) + 1];

	memset(frame, 0, sizeof(frame));
	eth->h_dest[0] = 0x02;
	eth->h_dest[ETH_ALEN - 1] = device + 1;
	memcpy(eth->h_source, mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_PPP_SES);
	ph->ver = 1;
	ph->type = 1;
	ph->sid = htons(sid);
	ph->length = htons(sizeof(payload));
	memcpy(frame + ETH_HLEN + sizeof(*ph), payload, sizeof(payload));

	ASSERT_EQ((ssize_t)sizeof(frame),
		  sendto(self->tx, frame, sizeof(frame), 0,
			 (struct sockaddr *)&addr, sizeof(addr)));
	ASSERT_EQ((ssize_t)sizeof(payload), recv(fd, received, sizeof(received), 0));
	ASSERT_EQ(0, memcmp(received, payload, sizeof(payload)));
}

static void check_proc_count(struct __test_metadata *_metadata, int expected)
{
	char *line = NULL;
	size_t size = 0;
	int count = 0;
	FILE *file;

	file = fopen("/proc/net/pppoe", "r");
	ASSERT_NE(NULL, file);
	ASSERT_GT(getline(&line, &size, file), 0);
	ASSERT_STREQ("Id       Address              Device\n", line);
	while (getline(&line, &size, file) > 0)
		count++;
	ASSERT_EQ(0, ferror(file));
	EXPECT_EQ(expected, count);
	free(line);
	fclose(file);
}

FIXTURE_SETUP(pppoe_hash)
{
	struct rlimit limit;
	int fd;

	self->tx = -1;
	if (unshare(CLONE_NEWNET))
		SKIP(return, "Need permission to create a network namespace");
	fd = socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_OE);
	if (fd < 0 && (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT))
		SKIP(return, "PPPoE sockets are not available");
	ASSERT_GE(fd, 0);
	close(fd);
	if (system("ip link show lo >/dev/null 2>&1"))
		SKIP(return, "Need the ip command");
	ASSERT_EQ(0, getrlimit(RLIMIT_NOFILE, &limit));
	if (limit.rlim_max < SESSION_COUNT + 64)
		SKIP(return, "Need a higher open-file limit");
	limit.rlim_cur = SESSION_COUNT + 64;
	ASSERT_EQ(0, setrlimit(RLIMIT_NOFILE, &limit));

	create_devices(_metadata);
	self->tx = socket(AF_PACKET, SOCK_RAW, 0);
	ASSERT_GE(self->tx, 0);
}

FIXTURE_TEARDOWN(pppoe_hash)
{
	int i;

	for (i = 0; i < self->count; i++)
		if (self->sockets[i] >= 0)
			close(self->sockets[i]);
	if (self->tx >= 0)
		close(self->tx);
}

TEST_F(pppoe_hash, grow_shrink)
{
	int round, i;

	for (round = 0; round < 2; round++) {
		self->count = 0;
		for (i = 0; i < SESSION_COUNT; i++) {
			int fd = new_session(_metadata, self, 0, i + 1, remote);

			check_packet(_metadata, self, fd, 0, i + 1, remote);
		}
		check_proc_count(_metadata, SESSION_COUNT);

		/* Keep the oldest session alive through successive shrinks. */
		for (i = SESSION_COUNT - 1; i > 0; i--) {
			check_packet(_metadata, self, self->sockets[i], 0,
				     i + 1, remote);
			close(self->sockets[i]);
			self->sockets[i] = -1;
			if (!(i % 64)) {
				check_packet(_metadata, self, self->sockets[0],
					     0, 1, remote);
				check_proc_count(_metadata, i);
			}
		}
		check_packet(_metadata, self, self->sockets[0], 0, 1, remote);
		close(self->sockets[0]);
		self->sockets[0] = -1;
		check_proc_count(_metadata, 0);
	}
}

TEST_F(pppoe_hash, session_key)
{
	unsigned char other[ETH_ALEN];
	int first, second, third, duplicate;

	memcpy(other, remote, sizeof(other));
	other[ETH_ALEN - 1]++;
	first = new_session(_metadata, self, 0, 1, remote);
	second = new_session(_metadata, self, 1, 1, remote);
	third = new_session(_metadata, self, 0, 1, other);
	duplicate = socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_OE);
	ASSERT_GE(duplicate, 0);
	EXPECT_EQ(-1, connect_session(duplicate, 0, 1, remote));
	EXPECT_EQ(EALREADY, errno);
	close(duplicate);
	check_proc_count(_metadata, 3);
	check_packet(_metadata, self, first, 0, 1, remote);
	check_packet(_metadata, self, second, 1, 1, remote);
	check_packet(_metadata, self, third, 0, 1, other);

	ASSERT_EQ(0, connect_session(first, 0, 0, remote));
	check_proc_count(_metadata, 2);
	ASSERT_EQ(0, connect_session(first, 0, 1, remote));
	check_packet(_metadata, self, first, 0, 1, remote);
	check_proc_count(_metadata, 3);
}

TEST_F(pppoe_hash, device_down)
{
	unsigned char payload[] = { 0, 0x21, 0, 0 };
	int i;

	for (i = 0; i < SESSION_COUNT; i++)
		new_session(_metadata, self, 0, i + 1, remote);
	ASSERT_EQ(0, system("ip link set pppoe0 down"));
	for (i = 0; i < SESSION_COUNT; i++) {
		EXPECT_EQ(-1, send(self->sockets[i], payload, sizeof(payload), 0));
		EXPECT_EQ(ENOTCONN, errno);
	}
	ASSERT_EQ(0, system("ip link set pppoe0 up"));
	ASSERT_EQ(0, connect_session(self->sockets[0], 0, 1, remote));
	check_packet(_metadata, self, self->sockets[0], 0, 1, remote);
}

TEST_F(pppoe_hash, network_namespace)
{
	int original, first, second;

	original = open("/proc/self/ns/net", O_RDONLY);
	ASSERT_GE(original, 0);
	first = new_session(_metadata, self, 0, 1, remote);
	ASSERT_EQ(0, unshare(CLONE_NEWNET));
	create_devices(_metadata);
	second = new_session(_metadata, self, 0, 1, remote);
	check_proc_count(_metadata, 1);
	close(self->tx);
	self->tx = socket(AF_PACKET, SOCK_RAW, 0);
	ASSERT_GE(self->tx, 0);
	check_packet(_metadata, self, second, 0, 1, remote);
	ASSERT_EQ(0, setns(original, CLONE_NEWNET));
	close(original);
	check_proc_count(_metadata, 1);
	close(self->tx);
	self->tx = socket(AF_PACKET, SOCK_RAW, 0);
	ASSERT_GE(self->tx, 0);
	check_packet(_metadata, self, first, 0, 1, remote);
}

TEST_HARNESS_MAIN
