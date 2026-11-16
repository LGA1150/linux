// SPDX-License-Identifier: GPL-2.0-only
/*
 * Standalone kTLS RX/TX benchmark (AES-GCM-128, TLS 1.2 or 1.3).
 *
 * Build: gcc -O2 -Wall -Wextra -pthread -o tls_rx_bench tls_rx_bench.c
 * Run:   ./tls_rx_bench -v 1.3 -s 16384 -n 4096 -b 64 -r 5
 *        ./tls_rx_bench -m splice -v 1.3 -s 16384 -n 4096 -b 64 -r 5
 *        ./tls_rx_bench -d tx -m send -v 1.3 -n 4096 -b 64 -r 5
 *        ./tls_rx_bench -d tx -m splice -v 1.2 -n 4096 -b 64 -r 5
 *        ./tls_rx_bench -j 4 -m splice -v 1.2 -n 4096
 *
 * Generate ciphertext with kTLS TX before timing. A separate thread feeds
 * these records over plain loopback TCP to kTLS RX. Every trial uses a fresh
 * connection and resets the record sequence; encryption, setup, allocation,
 * warmups and plaintext verification are outside the measured interval.
 * Fixed keys are for this local benchmark only; there is no TLS handshake.
 * In splice mode, receive into a pipe and drain it to /dev/null with splice.
 * First verify the plaintext in an untimed recv trial; subsequent splice
 * trials check the byte count and EOF, since discarded data cannot be checked.
 *
 * TX sends prepared plaintext to kTLS while a raw TCP sink captures ciphertext
 * in memory. Timing ends only after the sink has captured every byte,
 * including pending crypto work. Decrypt and verify that capture after timing.
 * Full-size TX records use MSG_MORE/SPLICE_F_MORE across calls to keep crypto
 * busy; smaller records are flushed individually. -b bounds full-size records
 * per TX request. TX splice includes writing plaintext into the source pipe.
 *
 * -j creates independent TLS worker threads and connections, each with a raw
 * peer thread. Split the total -n records as evenly as possible between them.
 * Start timing after every connection is ready, and stop after all workers
 * finish. Verification starts only after this common interval, including for
 * faster TX workers. Report aggregate throughput, call counts and thread CPU
 * times; pipe_bytes is the smallest per-worker pipe capacity. -p applies to
 * each RX connection. -R/-T pin every thread of that role to the specified CPU;
 * without them threads can use any CPU in the original affinity mask.
 * Multiple connections can keep an async engine busy even when the kernel
 * waits for each record on an individual socket.
 *
 * Compare the same command on kernels with/without pipelining, using the
 * same configured crypto backend (e.g. pcrypt). This program does not change
 * global crypto priorities. -b controls the maximum I/O request size,
 * NOT the kernel's pipeline depth. Splice is also limited by pipe capacity.
 * Use a sufficiently large transfer and several repetitions.
 *
 * rx_cpu_s/tx_cpu_s exclude async crypto workers. system_busy_s includes them,
 * the peer and ALL other work on the machine, at /proc/stat tick resolution;
 * use an otherwise idle machine. -1 means that /proc/stat is unavailable.
 * Peer CPU time includes its setup/teardown and, for RX, untimed prefill.
 * system_busy_s is sampled once per trial, not summed across workers.
 * Throughput also includes TCP and copying costs. QEMU TCG is useful for
 * correctness, not hardware speedups.
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define MAX_RECORD_SIZE 16384
#define FEED_CHUNK (256 * 1024)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

enum io_mode {
	IO_DEFAULT,
	IO_RECV,
	IO_SEND,
	IO_SPLICE,
};

struct options {
	enum io_mode mode;
	bool tx;
	unsigned int version;
	size_t size, records, read_records, prefill;
	unsigned int runs, warmups;
	unsigned int threads;
	int rx_cpu, tx_cpu;
};

struct result {
	double seconds, io_cpu, peer_cpu, system_busy;
	size_t calls, pipe_calls, prefill;
	int pipe_bytes;
};

struct trial {
	pthread_barrier_t ready, start, finish, verify;
};

struct worker {
	struct options opt;
	struct trial *trial;
	struct result result;
	unsigned char *cipher, *plain;
	size_t wire_size;
	pthread_t thread;
};

struct peer {
	const struct options *opt;
	const unsigned char *src;
	unsigned char *dst;
	size_t wire_len, prefill;
	int fd, ready, go, done;
	double cpu;
};

static cpu_set_t initial_affinity;

static void fail(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	fprintf(stderr, "tls_rx_bench: ");
	vfprintf(stderr, fmt, args);
	fputc('\n', stderr);
	va_end(args);
	exit(EXIT_FAILURE);
}

static void sys_fail(const char *what)
{
	fail("%s: %s", what, strerror(errno));
}

static void *alloc(size_t len)
{
	void *buf = malloc(len);

	if (!buf)
		sys_fail("malloc");
	return buf;
}

static void thread_check(int err, const char *what)
{
	if (err)
		fail("%s: %s", what, strerror(err));
}

static void barrier_wait(pthread_barrier_t *barrier)
{
	int err = pthread_barrier_wait(barrier);

	if (err != PTHREAD_BARRIER_SERIAL_THREAD)
		thread_check(err, "pthread_barrier_wait");
}

static double clock_seconds(clockid_t clock)
{
	struct timespec ts;

	if (clock_gettime(clock, &ts))
		sys_fail("clock_gettime");
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static double start_io(struct trial *trial)
{
	if (trial) {
		barrier_wait(&trial->ready);
		barrier_wait(&trial->start);
	}
	return clock_seconds(CLOCK_THREAD_CPUTIME_ID);
}

static void finish_io(struct trial *trial, struct result *result, double cpu)
{
	result->io_cpu = clock_seconds(CLOCK_THREAD_CPUTIME_ID) - cpu;
	if (trial) {
		barrier_wait(&trial->finish);
		/* No worker may start verification while another is timed. */
		barrier_wait(&trial->verify);
	}
}

static double system_busy(void)
{
	unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
	FILE *fp = fopen("/proc/stat", "r");
	long ticks = sysconf(_SC_CLK_TCK);
	int fields;

	if (!fp)
		return -1;
	fields = fscanf(fp, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
			&user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal);
	fclose(fp);
	if (fields != 8 || ticks <= 0)
		return -1;
	return (double)(user + nice + system + irq + softirq) / ticks;
}

static void pin_cpu(int cpu)
{
	cpu_set_t set;

	if (cpu < 0)
		return;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set))
		sys_fail("sched_setaffinity");
}

static void pin_peer(int cpu)
{
	/* The measured endpoint's affinity must not also pin its peer thread. */
	if (sched_setaffinity(0, sizeof(initial_affinity), &initial_affinity))
		sys_fail("restore peer affinity");
	pin_cpu(cpu);
}

static void set_int(int fd, int level, int opt, int val)
{
	if (setsockopt(fd, level, opt, &val, sizeof(val)))
		sys_fail("setsockopt");
}

static int get_int(int fd, int level, int opt)
{
	socklen_t len = sizeof(int);
	int val;

	if (getsockopt(fd, level, opt, &val, &len))
		sys_fail("getsockopt");
	return val;
}

static void tcp_pair(int pair[2])
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct timeval timeout = { .tv_sec = 120 };
	socklen_t len = sizeof(addr);
	int listener, i;

	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0)
		sys_fail("socket listener");
	set_int(listener, SOL_SOCKET, SO_RCVBUF, 1024 * 1024);
	if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) ||
	    getsockname(listener, (struct sockaddr *)&addr, &len) ||
	    listen(listener, 1))
		sys_fail("listen on loopback");
	pair[0] = socket(AF_INET, SOCK_STREAM, 0);
	if (pair[0] < 0)
		sys_fail("socket sender");
	if (connect(pair[0], (struct sockaddr *)&addr, sizeof(addr)))
		sys_fail("connect loopback");
	pair[1] = accept(listener, NULL, NULL);
	if (pair[1] < 0)
		sys_fail("accept");
	close(listener);
	for (i = 0; i < 2; i++) {
		set_int(pair[i], IPPROTO_TCP, TCP_NODELAY, 1);
		set_int(pair[i], SOL_SOCKET, SO_SNDBUF, 1024 * 1024);
		if (setsockopt(pair[i], SOL_SOCKET, SO_RCVTIMEO,
			       &timeout, sizeof(timeout)) ||
		    setsockopt(pair[i], SOL_SOCKET, SO_SNDTIMEO,
			       &timeout, sizeof(timeout)))
			sys_fail("set socket timeout");
	}
}

static void enable_tls(int fd, int direction, unsigned int version)
{
	struct tls12_crypto_info_aes_gcm_128 info = { 0 };

	info.info.version = version;
	info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	if (setsockopt(fd, IPPROTO_TCP, TCP_ULP, "tls", sizeof("tls")))
		sys_fail("TCP_ULP tls (requires CONFIG_TLS / tls module)");
	if (setsockopt(fd, SOL_TLS, direction, &info, sizeof(info)))
		sys_fail(direction == TLS_TX ? "TLS_TX AES-GCM-128" : "TLS_RX AES-GCM-128");
}

static void send_all(int fd, const unsigned char *buf, size_t len)
{
	while (len) {
		size_t chunk = len < FEED_CHUNK ? len : FEED_CHUNK;
		ssize_t ret = send(fd, buf, chunk, MSG_NOSIGNAL);

		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			sys_fail("send ciphertext");
		if (!ret)
			fail("send made no progress");
		buf += ret;
		len -= ret;
	}
}

static void expect_eof(int fd)
{
	unsigned char byte;
	ssize_t ret;

	do {
		ret = recv(fd, &byte, 1, 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0)
		sys_fail("recv EOF");
	if (ret)
		fail("unexpected trailing data");
}

static void pattern(unsigned char *buf, size_t len, uint64_t seq)
{
	size_t i;

	for (i = 0; i < len; i++)
		buf[i] = (i * 13 + 17) & 0xff;
	for (i = 0; i < len && i < sizeof(seq); i++)
		buf[i] = seq >> (i * 8);
}

static void capture_cipher(int fd, unsigned char *cipher, size_t wire_len)
{
	size_t offset = 0;

	while (offset < wire_len) {
		size_t len = wire_len - offset;
		ssize_t ret;

		if (len > FEED_CHUNK)
			len = FEED_CHUNK;
		ret = recv(fd, cipher + offset, len, 0);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			sys_fail("capture ciphertext");
		if (!ret)
			fail("EOF after %zu of %zu ciphertext bytes", offset, wire_len);
		offset += ret;
	}
}

static void check_framing(const struct options *opt, const unsigned char *cipher,
			  size_t wire_size)
{
	size_t i;

	for (i = 0; i < opt->records; i++) {
		const unsigned char *hdr = cipher + i * wire_size;
		size_t len = ((unsigned int)hdr[3] << 8) | hdr[4];

		if (hdr[0] != 23 || hdr[1] != 3 || hdr[2] != 3 || len + 5 != wire_size)
			fail("unexpected TLS framing at record %zu", i);
	}
}

static void *prepare_sender(void *arg)
{
	const struct peer *peer = arg;
	const struct options *opt = peer->opt;
	unsigned char plain[MAX_RECORD_SIZE];
	size_t i;

	pin_peer(opt->tx_cpu);
	for (i = 0; i < opt->records; i++) {
		ssize_t ret;

		pattern(plain, opt->size, i);
		do {
			ret = send(peer->fd, plain, opt->size, MSG_NOSIGNAL);
		} while (ret < 0 && errno == EINTR);
		if (ret < 0)
			sys_fail("send plaintext for preparation");
		if ((size_t)ret != opt->size)
			fail("short preparation send would change record boundaries");
	}
	close(peer->fd);
	return NULL;
}

static void prepare(const struct options *opt, unsigned char *cipher, size_t wire_size)
{
	struct peer peer = { .opt = opt };
	pthread_t thread;
	int pair[2];

	tcp_pair(pair);
	enable_tls(pair[0], TLS_TX, opt->version);
	peer.fd = pair[0];
	thread_check(pthread_create(&thread, NULL, prepare_sender, &peer),
		     "create preparation sender");
	capture_cipher(pair[1], cipher, opt->records * wire_size);
	expect_eof(pair[1]);
	close(pair[1]);
	thread_check(pthread_join(thread, NULL), "join preparation sender");
	check_framing(opt, cipher, wire_size);
}

static void signal_peer(int fd, bool send_signal)
{
	char byte = 0;
	ssize_t ret;

	do {
		ret = send_signal ? write(fd, &byte, 1) : read(fd, &byte, 1);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0)
		sys_fail("synchronize peer");
	if (ret != 1)
		fail("peer synchronization pipe closed");
}

static void *run_peer(void *arg)
{
	struct peer *peer = arg;
	double cpu = clock_seconds(CLOCK_THREAD_CPUTIME_ID);

	pin_peer(peer->opt->tx ? peer->opt->rx_cpu : peer->opt->tx_cpu);
	if (!peer->opt->tx)
		send_all(peer->fd, peer->src, peer->prefill);
	signal_peer(peer->ready, true);
	close(peer->ready);
	if (peer->opt->tx) {
		capture_cipher(peer->fd, peer->dst, peer->wire_len);
		signal_peer(peer->done, true);
		close(peer->done);
		expect_eof(peer->fd);
	} else {
		signal_peer(peer->go, false);
		close(peer->go);
		send_all(peer->fd, peer->src + peer->prefill,
			 peer->wire_len - peer->prefill);
	}
	close(peer->fd);
	peer->cpu = clock_seconds(CLOCK_THREAD_CPUTIME_ID) - cpu;
	return NULL;
}

static void drain_pipe(int fd, int nullfd, size_t len, struct result *result)
{
	while (len) {
		ssize_t ret = splice(fd, NULL, nullfd, NULL, len, 0);

		result->pipe_calls++;
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			sys_fail("splice pipe to /dev/null");
		if (!ret)
			fail("splice pipe to /dev/null made no progress");
		len -= ret;
	}
}

static struct result run_rx(const struct options *opt, const unsigned char *cipher,
			    unsigned char *plain, size_t wire_size, struct trial *trial)
{
	size_t plain_len = opt->records * opt->size;
	size_t wire_len = opt->records * wire_size;
	size_t read_size = opt->read_records * opt->size;
	struct result result = { 0 };
	struct peer peer = { .opt = opt, .src = cipher, .wire_len = wire_len };
	unsigned char expected[MAX_RECORD_SIZE];
	size_t budget, limit, offset = 0, i;
	int pair[2], ready[2], go[2];
	int data_pipe[2] = { -1, -1 };
	pthread_t thread;
	int nullfd = -1;
	double cpu;

	tcp_pair(pair);
	enable_tls(pair[1], TLS_RX, opt->version);
	/* Bound the prefill, leaving room for TCP skb overhead. */
	budget = get_int(pair[0], SOL_SOCKET, SO_SNDBUF) / 4;
	limit = get_int(pair[1], SOL_SOCKET, SO_RCVBUF) / 4;
	if (budget > limit)
		budget = limit;
	result.prefill = budget / wire_size;
	if (result.prefill > opt->prefill)
		result.prefill = opt->prefill;
	if (result.prefill > opt->records)
		result.prefill = opt->records;
	if (pipe(ready) || pipe(go))
		sys_fail("pipe");
	peer.fd = pair[0];
	peer.prefill = result.prefill * wire_size;
	peer.ready = ready[1];
	peer.go = go[0];
	thread_check(pthread_create(&thread, NULL, run_peer, &peer), "create RX feeder");
	if (opt->mode == IO_SPLICE) {
		if (pipe(data_pipe))
			sys_fail("splice pipe");
		nullfd = open("/dev/null", O_WRONLY | O_CLOEXEC);
		if (nullfd < 0)
			sys_fail("open /dev/null");
		result.pipe_bytes = fcntl(data_pipe[0], F_GETPIPE_SZ);
		if (result.pipe_bytes < 0)
			sys_fail("F_GETPIPE_SZ");
	} else {
		/* Fault in the output pages outside the measured interval. */
		memset(plain, 0, plain_len);
	}
	signal_peer(ready[0], false);
	close(ready[0]);
	cpu = start_io(trial);
	signal_peer(go[1], true);
	close(go[1]);
	while (offset < plain_len) {
		size_t len = plain_len - offset;
		ssize_t ret;

		if (len > read_size)
			len = read_size;
		if (opt->mode == IO_SPLICE)
			ret = splice(pair[1], NULL, data_pipe[1], NULL, len, 0);
		else
			ret = recv(pair[1], plain + offset, len, MSG_WAITALL);
		result.calls++;
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			sys_fail(opt->mode == IO_SPLICE ? "splice TLS to pipe" : "TLS receive");
		if (!ret)
			fail("EOF after %zu of %zu plaintext bytes", offset, plain_len);
		if (opt->mode == IO_SPLICE)
			drain_pipe(data_pipe[0], nullfd, ret, &result);
		offset += ret;
	}
	finish_io(trial, &result, cpu);
	expect_eof(pair[1]);
	close(pair[1]);
	thread_check(pthread_join(thread, NULL), "join RX feeder");
	result.peer_cpu = peer.cpu;
	if (opt->mode == IO_SPLICE) {
		close(data_pipe[0]);
		close(data_pipe[1]);
		close(nullfd);
		return result;
	}
	for (i = 0; i < opt->records; i++) {
		pattern(expected, opt->size, i);
		if (memcmp(plain + i * opt->size, expected, opt->size))
			fail("plaintext mismatch at record %zu", i);
	}
	return result;
}

static void splice_tx(int fd, int data_pipe[2], const unsigned char *plain,
		      size_t len, bool full_records, struct result *result)
{
	size_t offset = 0;

	while (offset < len) {
		size_t chunk = len - offset, queued;
		ssize_t ret;

		if (chunk > (size_t)result->pipe_bytes)
			chunk = result->pipe_bytes;
		ret = write(data_pipe[1], plain + offset, chunk);
		result->pipe_calls++;
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			sys_fail("fill TX splice pipe");
		if (!ret)
			fail("TX pipe write made no progress");
		queued = ret;
		while (queued) {
			unsigned int flags = full_records || offset + queued < len ?
					     SPLICE_F_MORE : 0;

			ret = splice(data_pipe[0], NULL, fd, NULL, queued, flags);
			result->calls++;
			if (ret < 0 && errno == EINTR)
				continue;
			if (ret < 0)
				sys_fail("splice pipe to TLS");
			if (!ret)
				fail("TX splice made no progress");
			if (!flags && (size_t)ret != queued)
				fail("short final TX splice would change record boundaries");
			offset += ret;
			queued -= ret;
		}
	}
}

static struct result run_tx(const struct options *opt, unsigned char *cipher,
			    unsigned char *plain, size_t wire_size, struct trial *trial)
{
	size_t plain_len = opt->records * opt->size;
	size_t wire_len = opt->records * wire_size;
	bool full_records = opt->size == MAX_RECORD_SIZE;
	size_t batch = opt->size * (full_records ? opt->read_records : 1);
	struct options verify = *opt;
	struct result result = { 0 };
	struct peer peer = { .opt = opt, .dst = cipher, .wire_len = wire_len };
	int data_pipe[2] = { -1, -1 };
	int pair[2], ready[2], done[2];
	size_t offset = 0;
	pthread_t thread;
	double cpu;

	tcp_pair(pair);
	enable_tls(pair[0], TLS_TX, opt->version);
	/* Fault in the sink's capture buffer before timing. */
	memset(cipher, 0, wire_len);
	if (pipe(ready) || pipe(done))
		sys_fail("TX synchronization pipe");
	peer.fd = pair[1];
	peer.ready = ready[1];
	peer.done = done[1];
	thread_check(pthread_create(&thread, NULL, run_peer, &peer), "create TX sink");
	if (opt->mode == IO_SPLICE) {
		if (pipe(data_pipe))
			sys_fail("TX splice pipe");
		result.pipe_bytes = fcntl(data_pipe[0], F_GETPIPE_SZ);
		if (result.pipe_bytes < 0)
			sys_fail("F_GETPIPE_SZ");
	}
	signal_peer(ready[0], false);
	close(ready[0]);
	cpu = start_io(trial);
	while (offset < plain_len) {
		size_t len = plain_len - offset;
		ssize_t ret;

		if (len > batch)
			len = batch;
		if (opt->mode == IO_SPLICE) {
			splice_tx(pair[0], data_pipe, plain + offset, len,
				  full_records, &result);
			offset += len;
			continue;
		}
		ret = send(pair[0], plain + offset, len,
			   MSG_NOSIGNAL | (full_records ? MSG_MORE : 0));
		result.calls++;
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			sys_fail("TLS transmit");
		if (!ret)
			fail("TLS transmit made no progress");
		if (!full_records && (size_t)ret != len)
			fail("short TX send would change record boundaries");
		offset += ret;
	}
	/* A successful send may leave async encryption pending. The sink's
	 * acknowledgment proves that all ciphertext has reached TCP. Wait
	 * before shutdown too, so a FIN cannot overtake pending encryption.
	 */
	signal_peer(done[0], false);
	finish_io(trial, &result, cpu);
	close(done[0]);
	if (shutdown(pair[0], SHUT_WR))
		sys_fail("shutdown TLS transmit");
	close(pair[0]);
	if (data_pipe[0] >= 0) {
		close(data_pipe[0]);
		close(data_pipe[1]);
	}
	thread_check(pthread_join(thread, NULL), "join TX sink");
	result.peer_cpu = peer.cpu;
	check_framing(opt, cipher, wire_size);
	/* RX crypto and plaintext checking are entirely outside TX timing. */
	verify.tx = false;
	verify.mode = IO_RECV;
	verify.prefill = 0;
	verify.tx_cpu = opt->rx_cpu;
	run_rx(&verify, cipher, plain, wire_size, NULL);
	return result;
}

static void *run_worker(void *arg)
{
	struct worker *worker = arg;
	const struct options *opt = &worker->opt;

	pin_cpu(opt->tx ? opt->tx_cpu : opt->rx_cpu);
	worker->result = opt->tx ?
		run_tx(opt, worker->cipher, worker->plain, worker->wire_size, worker->trial) :
		run_rx(opt, worker->cipher, worker->plain, worker->wire_size, worker->trial);
	return NULL;
}

static struct result run_trial(const struct options *opt, struct worker *workers)
{
	struct result total = { 0 };
	struct trial trial;
	pthread_barrier_t *barriers[] = {
		&trial.ready, &trial.start, &trial.finish, &trial.verify,
	};
	double start, busy, busy_end;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(barriers); i++)
		thread_check(pthread_barrier_init(barriers[i], NULL, opt->threads + 1),
			     "pthread_barrier_init");
	for (i = 0; i < opt->threads; i++) {
		workers[i].trial = &trial;
		thread_check(pthread_create(&workers[i].thread, NULL, run_worker, &workers[i]),
			     "create TLS worker");
	}
	/* Every socket, peer and buffer is ready before the common interval. */
	barrier_wait(&trial.ready);
	busy = system_busy();
	start = clock_seconds(CLOCK_MONOTONIC);
	barrier_wait(&trial.start);
	barrier_wait(&trial.finish);
	total.seconds = clock_seconds(CLOCK_MONOTONIC) - start;
	busy_end = system_busy();
	total.system_busy = busy < 0 || busy_end < 0 ? -1 : busy_end - busy;
	barrier_wait(&trial.verify);
	for (i = 0; i < opt->threads; i++) {
		const struct result *part = &workers[i].result;

		thread_check(pthread_join(workers[i].thread, NULL), "join TLS worker");
		total.calls += part->calls;
		total.pipe_calls += part->pipe_calls;
		total.io_cpu += part->io_cpu;
		total.peer_cpu += part->peer_cpu;
		total.prefill += part->prefill;
		if (part->pipe_bytes && (!total.pipe_bytes || part->pipe_bytes < total.pipe_bytes))
			total.pipe_bytes = part->pipe_bytes;
	}
	for (i = 0; i < ARRAY_SIZE(barriers); i++)
		thread_check(pthread_barrier_destroy(barriers[i]), "pthread_barrier_destroy");
	return total;
}

static struct worker *prepare_workers(const struct options *opt, size_t wire_size)
{
	struct worker *workers = alloc(opt->threads * sizeof(*workers));
	unsigned int i;

	for (i = 0; i < opt->threads; i++) {
		struct options *part = &workers[i].opt;
		size_t record;

		*part = *opt;
		part->records = opt->records / opt->threads + (i < opt->records % opt->threads);
		workers[i].wire_size = wire_size;
		workers[i].cipher = alloc(part->records * wire_size);
		workers[i].plain = alloc(part->records * opt->size);
		if (opt->tx) {
			for (record = 0; record < part->records; record++)
				pattern(workers[i].plain + record * opt->size, opt->size, record);
		} else {
			prepare(part, workers[i].cipher, wire_size);
		}
		if (!opt->tx && opt->mode == IO_SPLICE) {
			struct options verify = *part;

			verify.mode = IO_RECV;
			run_rx(&verify, workers[i].cipher, workers[i].plain, wire_size, NULL);
			free(workers[i].plain);
			workers[i].plain = NULL;
		}
	}
	return workers;
}

static size_t parse_number(const char *arg, size_t min, size_t max)
{
	unsigned long long n;
	char *end;

	errno = 0;
	n = strtoull(arg, &end, 10);
	if (arg[0] < '0' || arg[0] > '9' || *end || errno || n < min || n > max)
		fail("invalid number '%s' (expected %zu..%zu)", arg, min, max);
	return n;
}

static void usage(const char *prog)
{
	printf("Usage: %s [options]\n"
	       "  -d rx|tx    measured direction (default rx)\n"
	       "  -m MODE     recv/send (default for rx/tx) or splice\n"
	       "  -v 1.2|1.3  TLS version (default 1.3), AES-GCM-128\n"
	       "  -s BYTES    plaintext bytes per record, 1..16384 (16384)\n"
	       "  -n RECORDS  total records per trial (4096, i.e. 64 MiB by default)\n"
	       "  -j THREADS  parallel TLS connections/worker threads, 1..1024 (1)\n"
	       "  -b RECORDS  max records per I/O request (64; not pipeline depth)\n"
	       "  -p RECORDS  RX prefill per connection (8, capped by socket buffers)\n"
	       "  -r RUNS     measured trials (5)\n"
	       "  -w WARMUPS  untimed warmup trials (1)\n"
	       "  -R CPU      pin receiver/raw TX sink (default: unpinned)\n"
	       "  -T CPU      pin transmitter/raw RX feeder (default: unpinned)\n"
	       "  -h          show help\n\n"
	       "One C file; libc, pthreads (-pthread) and Linux UAPI headers only.\n"
	       "No root required if kTLS and AES-GCM are available.\n"
	       "Backend selection is external.\n"
	       "-n is divided evenly across -j workers and must be at least -j.\n"
	       "Each worker has its own TLS socket and a raw peer thread. All workers\n"
	       "share a timed interval; verification waits for the slowest worker.\n"
	       "CSV rates and counters are totals; pipe_bytes is the minimum capacity.\n"
	       "-R/-T apply to every thread of that role; omit them to allow spreading\n"
	       "across the original CPU affinity mask.\n"
	       "Output: CSV trials and a summary. RX recv verifies plaintext after\n"
	       "each trial. RX splice goes through a pipe to /dev/null, with an\n"
	       "untimed recv preflight and length/EOF checks in subsequent trials.\n"
	       "TX waits for a raw sink to capture all ciphertext, then decrypts\n"
	       "and verifies it outside timing. Full-size TX records use MORE flags\n"
	       "to pipeline across calls; smaller records are flushed individually\n"
	       "and use one record per request. TX splice includes source pipe writes.\n"
	       "Short writes which would change small-record framing fail the trial.\n"
	       "CPU times sum thread CPU use, excluding async crypto workers.\n"
	       "system_busy_s is sampled once for the entire trial and covers the\n"
	       "whole machine (use an idle host). Buffers hold plaintext plus\n"
	       "ciphertext in resident memory, plus per-thread/socket overhead.\n", prog);
}

static int compare_double(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
	struct options opt = {
		.version = TLS_1_3_VERSION, .size = MAX_RECORD_SIZE,
		.records = 4096, .read_records = 64, .prefill = 8,
		.runs = 5, .warmups = 1, .threads = 1, .rx_cpu = -1, .tx_cpu = -1,
	};
	double total_seconds = 0, *rates, median;
	struct worker *workers;
	const char *mode, *validation;
	size_t wire_size, plain_len;
	bool prefill_set = false;
	struct utsname uts;
	unsigned int i;
	int c;

	while ((c = getopt(argc, argv, "d:m:v:s:n:j:b:p:r:w:R:T:h")) != -1) {
		switch (c) {
		case 'd':
			if (!strcmp(optarg, "rx"))
				opt.tx = false;
			else if (!strcmp(optarg, "tx"))
				opt.tx = true;
			else
				fail("direction must be rx or tx");
			break;
		case 'm':
			if (!strcmp(optarg, "recv"))
				opt.mode = IO_RECV;
			else if (!strcmp(optarg, "send"))
				opt.mode = IO_SEND;
			else if (!strcmp(optarg, "splice"))
				opt.mode = IO_SPLICE;
			else
				fail("mode must be recv, send or splice");
			break;
		case 'v':
			if (!strcmp(optarg, "1.2"))
				opt.version = TLS_1_2_VERSION;
			else if (!strcmp(optarg, "1.3"))
				opt.version = TLS_1_3_VERSION;
			else
				fail("TLS version must be 1.2 or 1.3");
			break;
		case 's':
			opt.size = parse_number(optarg, 1, MAX_RECORD_SIZE);
			break;
		case 'n':
			opt.records = parse_number(optarg, 1, SIZE_MAX);
			break;
		case 'j':
			opt.threads = parse_number(optarg, 1, 1024);
			break;
		case 'b':
			opt.read_records = parse_number(optarg, 1, 65536);
			break;
		case 'p':
			opt.prefill = parse_number(optarg, 0, SIZE_MAX);
			prefill_set = true;
			break;
		case 'r':
			opt.runs = parse_number(optarg, 1, 10000);
			break;
		case 'w':
			opt.warmups = parse_number(optarg, 0, 10000);
			break;
		case 'R':
			opt.rx_cpu = parse_number(optarg, 0, CPU_SETSIZE - 1);
			break;
		case 'T':
			opt.tx_cpu = parse_number(optarg, 0, CPU_SETSIZE - 1);
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}
	if (optind != argc)
		fail("unexpected argument: %s", argv[optind]);
	if (opt.mode == IO_DEFAULT)
		opt.mode = opt.tx ? IO_SEND : IO_RECV;
	if ((opt.tx && opt.mode == IO_RECV) || (!opt.tx && opt.mode == IO_SEND))
		fail("TX supports send/splice; RX supports recv/splice");
	if (opt.tx && prefill_set)
		fail("-p is only supported for RX");
	if (opt.records < opt.threads)
		fail("-n must provide at least one record for each of the -j workers");
	mode = opt.mode == IO_SPLICE ? "splice" : opt.tx ? "send" : "recv";
	validation = !opt.tx && opt.mode == IO_SPLICE ? "length" : "plaintext";
	/* TLS header + tag + explicit nonce (1.2) or inner content type (1.3). */
	wire_size = opt.size + 5 + 16 + (opt.version == TLS_1_2_VERSION ? 8 : 1);
	if (opt.records > SIZE_MAX / wire_size)
		fail("record count overflows the ciphertext buffer size");
	plain_len = opt.size * opt.records;
	signal(SIGPIPE, SIG_IGN);
	if (sched_getaffinity(0, sizeof(initial_affinity), &initial_affinity))
		sys_fail("sched_getaffinity");
	if (uname(&uts))
		sys_fail("uname");
	printf("# kernel=%s machine=%s tls=%s cipher=AES-GCM-128 direction=%s mode=%s\n",
	       uts.release, uts.machine, opt.version == TLS_1_2_VERSION ? "1.2" : "1.3",
	       opt.tx ? "tx" : "rx", mode);
	printf("# record_bytes=%zu records=%zu plaintext_bytes=%zu %s=%zu",
	       opt.size, opt.records, plain_len, opt.tx ? "tx_batch_records" : "read_records",
	       opt.tx && opt.size < MAX_RECORD_SIZE ? 1 : opt.read_records);
	printf(" runs=%u warmups=%u rx_cpu=%d tx_cpu=%d threads=%u records_per_thread=%zu..%zu\n",
	       opt.runs, opt.warmups, opt.rx_cpu, opt.tx_cpu, opt.threads,
	       opt.records / opt.threads,
	       opt.records / opt.threads + !!(opt.records % opt.threads));
	if (opt.tx)
		printf("# Preparing plaintext; capture and verify ciphertext on each TX trial.\n");
	else
		printf("# Preparing ciphertext; this is outside the measurements.\n");
	workers = prepare_workers(&opt, wire_size);
	if (!opt.tx && opt.mode == IO_SPLICE)
		printf("# plaintext preflight verified with untimed recv\n");
	rates = alloc(opt.runs * sizeof(*rates));
	for (i = 0; i < opt.warmups; i++) {
		run_trial(&opt, workers);
		printf("# warmup=%u verified=%s\n", i + 1, validation);
	}
	printf("run,mode,seconds,gbps,mib_per_s,records_per_s,%s,",
	       opt.tx ? "tx_calls,fill_calls,tx_cpu_s,sink_cpu_s" :
			"rx_calls,drain_calls,rx_cpu_s,feeder_cpu_s");
	printf("system_busy_s,prefill_records,pipe_bytes\n");
	for (i = 0; i < opt.runs; i++) {
		struct result r = run_trial(&opt, workers);

		rates[i] = (double)plain_len * 8 / r.seconds / 1e9;
		total_seconds += r.seconds;
		printf("%u,%s,%.6f,%.6f,%.3f,%.0f,%zu,%zu,%.6f,%.6f,%.6f,%zu,%d\n",
		       i + 1, mode, r.seconds, rates[i], plain_len / r.seconds / 1048576,
		       opt.records / r.seconds, r.calls, r.pipe_calls, r.io_cpu,
		       r.peer_cpu, r.system_busy, r.prefill, r.pipe_bytes);
	}
	qsort(rates, opt.runs, sizeof(*rates), compare_double);
	median = (rates[(opt.runs - 1) / 2] + rates[opt.runs / 2]) / 2;
	printf("# gbps min=%.6f median=%.6f max=%.6f aggregate=%.6f verified=%s\n",
	       rates[0], median, rates[opt.runs - 1],
	       (double)plain_len * opt.runs * 8 / total_seconds / 1e9, validation);
	free(rates);
	for (i = 0; i < opt.threads; i++) {
		free(workers[i].plain);
		free(workers[i].cipher);
	}
	free(workers);
	return 0;
}
