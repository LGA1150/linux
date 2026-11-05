// SPDX-License-Identifier: GPL-2.0-only
/*
 * Submit prepared PPPoE TCP GSO skbs directly to an Ethernet driver.
 * No PPPoE GSO kernel patches or private driver headers are required.
 * See README.rst for the deliberately nonstandard skb header layout.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/etherdevice.h>
/* mac_pton() moved out of kernel.h in newer kernels. */
#if __has_include("linux/hex.h")
#include <linux/hex.h>
#endif
#include <linux/if_pppox.h>
#include <linux/inet.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/ppp_defs.h>
#include <linux/rtnetlink.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/net_namespace.h>
#include <net/tcp.h>

static char *ifname;
module_param(ifname, charp, 0444);
MODULE_PARM_DESC(ifname, "Physical Ethernet interface in the initial netns");

static char *dst_mac;
module_param(dst_mac, charp, 0444);
MODULE_PARM_DESC(dst_mac, "Receiver unicast Ethernet address (required)");

static bool ipv6;
module_param(ipv6, bool, 0444);
MODULE_PARM_DESC(ipv6, "Use IPv6 instead of IPv4");

static char *src_ip;
module_param(src_ip, charp, 0444);
MODULE_PARM_DESC(src_ip, "Source IP (default 192.0.2.1 or 2001:db8::1)");

static char *dst_ip;
module_param(dst_ip, charp, 0444);
MODULE_PARM_DESC(dst_ip, "Destination IP (default 192.0.2.2 or 2001:db8::2)");

static unsigned int mss = 1200;
module_param(mss, uint, 0444);
MODULE_PARM_DESC(mss, "TCP data bytes per segment (minimum 64)");

static unsigned int payload_len = 2537;
module_param(payload_len, uint, 0444);
MODULE_PARM_DESC(payload_len, "TCP data bytes per burst (default 2537)");

static unsigned int count = 1;
module_param(count, uint, 0444);
MODULE_PARM_DESC(count, "Bursts, 100 ms apart (1..100)");

static unsigned int session = 0x1234;
module_param(session, uint, 0444);
MODULE_PARM_DESC(session, "PPPoE session ID (1..65534)");

static bool software;
module_param(software, bool, 0444);
MODULE_PARM_DESC(software, "Control: build wire packets and checksums in software");

static bool plain_ip;
module_param(plain_ip, bool, 0444);
MODULE_PARM_DESC(plain_ip, "Control: omit PPPoE/PPP, use ordinary Ethernet/IP");

static bool prefill = true;
module_param(prefill, bool, 0444);
MODULE_PARM_DESC(prefill, "Prefill per-segment PPPoE length; false is a negative control");

static unsigned int submitted_skbs;
module_param(submitted_skbs, uint, 0444);
MODULE_PARM_DESC(submitted_skbs, "Skbs accepted by the driver, not confirmed on wire");

static unsigned int submitted_gso;
module_param(submitted_gso, uint, 0444);
MODULE_PARM_DESC(submitted_gso, "GSO skbs accepted by the driver");

struct probe_config {
	u8 dmac[ETH_ALEN];
	__be32 saddr4, daddr4;
	struct in6_addr saddr6, daddr6;
	unsigned int ip_off, ip_hlen, hdr_len;
};

static int parse_config(struct probe_config *cfg)
{
	const char *src = src_ip ?: (ipv6 ? "2001:db8::1" : "192.0.2.1");
	const char *dst = dst_ip ?: (ipv6 ? "2001:db8::2" : "192.0.2.2");
	const char *end;

	if (!ifname || !*ifname || strlen(ifname) >= IFNAMSIZ ||
	    !dst_mac || strlen(dst_mac) != 17 ||
	    !mac_pton(dst_mac, cfg->dmac) || !is_valid_ether_addr(cfg->dmac)) {
		pr_err("ifname and a unicast dst_mac are required\n");
		return -EINVAL;
	}
	if (ipv6) {
		if (!in6_pton(src, -1, cfg->saddr6.s6_addr, -1, &end) || *end ||
		    !in6_pton(dst, -1, cfg->daddr6.s6_addr, -1, &end) || *end)
			return -EINVAL;
	} else {
		if (!in4_pton(src, -1, (u8 *)&cfg->saddr4, -1, &end) || *end ||
		    !in4_pton(dst, -1, (u8 *)&cfg->daddr4, -1, &end) || *end)
			return -EINVAL;
	}

	cfg->ip_off = ETH_HLEN + (plain_ip ? 0 : PPPOE_SES_HLEN);
	cfg->ip_hlen = ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr);
	cfg->hdr_len = cfg->ip_off + cfg->ip_hlen + sizeof(struct tcphdr);
	if (!count || count > 100 || !session || session >= U16_MAX ||
	    mss < 64 || mss > U16_MAX || !payload_len ||
	    payload_len > U16_MAX - cfg->hdr_len ||
	    (!software && payload_len / mss < 2)) {
		pr_err("invalid sizes/count/session; hardware mode needs at least two full MSS segments\n");
		return -EINVAL;
	}
	return 0;
}

static struct sk_buff *build_packet(struct net_device *dev,
				    const struct probe_config *cfg,
				    unsigned int len, u32 seq, u16 id,
				    bool last)
{
	bool gso = !software && len > mss;
	unsigned int wire_len = gso ? mss : len;
	unsigned int tcp_len = sizeof(struct tcphdr) + len;
	unsigned int ip_data_len = plain_ip ? len : wire_len;
	struct sk_buff *skb;
	struct ethhdr *eth;
	struct tcphdr *tcp;
	__sum16 sum;
	u8 *data;
	unsigned int i;

	skb = alloc_skb(NET_SKB_PAD + NET_IP_ALIGN + cfg->hdr_len + len,
			GFP_KERNEL);
	if (!skb)
		return NULL;
	skb_reserve(skb, NET_SKB_PAD + NET_IP_ALIGN);
	skb_put_zero(skb, cfg->hdr_len);
	data = skb_put(skb, len);
	for (i = 0; i < len; i++)
		data[i] = (seq + i) * 37 + 0x5a;

	skb->dev = dev;
	skb->protocol = htons(plain_ip ? (ipv6 ? ETH_P_IPV6 : ETH_P_IP) :
					ETH_P_PPP_SES);
	skb->ip_summed = software ? CHECKSUM_NONE : CHECKSUM_PARTIAL;
	skb_reset_mac_header(skb);
	/* Deliberately point at IP, not PPPoE: only the driver sees this skb. */
	skb_set_network_header(skb, cfg->ip_off);
	skb_set_transport_header(skb, cfg->ip_off + cfg->ip_hlen);
	skb_reset_mac_len(skb);
	skb_set_queue_mapping(skb, 0);
	skb->csum_start = skb_headroom(skb) + skb_transport_offset(skb);
	skb->csum_offset = offsetof(struct tcphdr, check);
	if (gso) {
		skb_shinfo(skb)->gso_type = ipv6 ? SKB_GSO_TCPV6 : SKB_GSO_TCPV4;
		skb_shinfo(skb)->gso_size = mss;
		skb_shinfo(skb)->gso_segs = len / mss;
	}

	eth = eth_hdr(skb);
	ether_addr_copy(eth->h_dest, cfg->dmac);
	ether_addr_copy(eth->h_source, dev->dev_addr);
	eth->h_proto = skb->protocol;
	if (!plain_ip) {
		struct pppoe_hdr *ph = (void *)(skb->data + ETH_HLEN);
		__be16 *ppp = (__be16 *)(ph + 1);

		ph->ver = 1;
		ph->type = 1;
		ph->sid = htons(session);
		ph->length = htons(2 + cfg->ip_hlen + sizeof(*tcp) +
				   (prefill ? wire_len : len));
		*ppp = htons(ipv6 ? PPP_IPV6 : PPP_IP);
	}

	tcp = tcp_hdr(skb);
	tcp->source = htons(12345);
	tcp->dest = htons(54321);
	tcp->seq = htonl(seq);
	tcp->ack_seq = htonl(1);
	tcp->doff = sizeof(*tcp) / 4;
	tcp->ack = 1;
	tcp->psh = last;
	tcp->window = htons(65535);

	if (ipv6) {
		struct ipv6hdr *ip6 = ipv6_hdr(skb);

		ip6->version = 6;
		ip6->payload_len = htons(sizeof(*tcp) + ip_data_len);
		ip6->nexthdr = IPPROTO_TCP;
		ip6->hop_limit = 64;
		ip6->saddr = cfg->saddr6;
		ip6->daddr = cfg->daddr6;
		sum = csum_ipv6_magic(&ip6->saddr, &ip6->daddr, tcp_len,
				      IPPROTO_TCP, software ?
				      csum_partial(tcp, tcp_len, 0) : 0);
	} else {
		struct iphdr *ip = ip_hdr(skb);

		ip->version = 4;
		ip->ihl = sizeof(*ip) / 4;
		ip->tot_len = htons(sizeof(*ip) + sizeof(*tcp) + ip_data_len);
		ip->id = htons(id);
		ip->frag_off = htons(IP_DF);
		ip->ttl = 64;
		ip->protocol = IPPROTO_TCP;
		ip->saddr = cfg->saddr4;
		ip->daddr = cfg->daddr4;
		ip_send_check(ip);
		sum = csum_tcpudp_magic(ip->saddr, ip->daddr, tcp_len,
					IPPROTO_TCP, software ?
					csum_partial(tcp, tcp_len, 0) : 0);
	}
	/* igc_tso() subtracts the entire batch's TCP length from this seed. */
	tcp->check = software ? sum : ~sum;
	return skb;
}

static int check_packet(struct net_device *dev, struct sk_buff *skb)
{
	netdev_features_t features = dev->features;

	/* Do not call netif_skb_features(): it may classify PPPoE for GSO. */
	if (dev->netdev_ops->ndo_features_check)
		features &= dev->netdev_ops->ndo_features_check(skb, dev, features);
	if (skb->ip_summed == CHECKSUM_PARTIAL && !(features & NETIF_F_HW_CSUM)) {
		pr_err("%s: TX hardware checksum offload is unavailable\n", dev->name);
		return -EOPNOTSUPP;
	}
	if (skb_is_gso(skb) &&
	    (!skb_gso_ok(skb, features) ||
	     skb->len >= min(dev->gso_max_size, dev->tso_max_size) ||
	     skb_shinfo(skb)->gso_segs > min(dev->gso_max_segs, dev->tso_max_segs))) {
		pr_err("%s: requested TSO is disabled or exceeds device limits\n", dev->name);
		return -EOPNOTSUPP;
	}
	return 0;
}

/* The caller holds RTNL. This consumes skb on every return path. */
static int transmit_packet(struct net_device *dev, struct sk_buff *skb)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, 0);
	bool gso = skb_is_gso(skb);
	netdev_tx_t status;
	unsigned int retry;
	int err = -EBUSY;

	pr_info("%s: submit len=%u ip=%u tcp=%d gso_size=%u gso_segs=%u seq=%u\n",
		dev->name, skb->len, skb_network_offset(skb),
		skb_checksum_start_offset(skb), skb_shinfo(skb)->gso_size,
		skb_shinfo(skb)->gso_segs, ntohl(tcp_hdr(skb)->seq));
	for (retry = 0; retry < 100; retry++) {
		status = NETDEV_TX_BUSY;
		local_bh_disable();
		HARD_TX_LOCK(dev, txq, smp_processor_id());
		if (!netif_device_present(dev) || !netif_running(dev) ||
		    !netif_carrier_ok(dev))
			err = -ENETDOWN;
		else if (!netif_xmit_frozen_or_stopped(txq))
			status = netdev_start_xmit(skb, dev, txq, false);
		HARD_TX_UNLOCK(dev, txq);
		local_bh_enable();

		if (dev_xmit_complete(status)) {
			if (status != NETDEV_TX_OK)
				return -EIO;
			submitted_skbs++;
			submitted_gso += gso;
			return 0;
		}
		if (err == -ENETDOWN)
			break;
		usleep_range(1000, 2000);
	}
	kfree_skb(skb);
	return err;
}

static int send_burst(struct net_device *dev, const struct probe_config *cfg,
		      unsigned int burst)
{
	struct sk_buff_head packets;
	unsigned int offset = 0;
	u16 id = 1 + burst * DIV_ROUND_UP(payload_len, mss);
	u32 seq = 1 + burst * payload_len;
	struct sk_buff *skb;
	int err = 0;

	__skb_queue_head_init(&packets);
	rtnl_lock();
	if (dev->reg_state != NETREG_REGISTERED || !netif_device_present(dev) ||
	    !netif_running(dev) || !netif_carrier_ok(dev)) {
		pr_err("%s: interface must be registered, up, and have carrier\n", dev->name);
		err = -ENETDOWN;
		goto out;
	}
	if (dev->type != ARPHRD_ETHER || dev->addr_len != ETH_ALEN ||
	    dev->rtnl_link_ops || !dev->netdev_ops->ndo_start_xmit ||
	    !dev->real_num_tx_queues || !is_valid_ether_addr(dev->dev_addr)) {
		pr_err("%s: use a physical Ethernet interface\n", dev->name);
		err = -EINVAL;
		goto out;
	}
	if (cfg->hdr_len - ETH_HLEN + mss > dev->mtu) {
		pr_err("%s: MSS plus headers exceeds MTU %u\n", dev->name, dev->mtu);
		err = -EMSGSIZE;
		goto out;
	}
	/* Allocate and validate the whole burst before sending any of it. */
	while (offset < payload_len) {
		unsigned int len = min(mss, payload_len - offset);

		if (!software && !offset)
			len = payload_len / mss * mss;
		skb = build_packet(dev, cfg, len, seq + offset, id,
				   offset + len == payload_len);
		if (!skb) {
			err = -ENOMEM;
			goto out;
		}
		__skb_queue_tail(&packets, skb);
		err = check_packet(dev, skb);
		if (err)
			goto out;
		offset += len;
		id += DIV_ROUND_UP(len, mss);
	}
	while ((skb = __skb_dequeue(&packets))) {
		err = transmit_packet(dev, skb);
		if (err)
			break;
	}
out:
	rtnl_unlock();
	__skb_queue_purge(&packets);
	return err;
}

static int __init pppoe_tso_hw_init(void)
{
	struct probe_config cfg;
	struct net_device *dev;
	unsigned int burst;
	int err;

	err = parse_config(&cfg);
	if (err)
		return err;
	dev = dev_get_by_name(&init_net, ifname);
	if (!dev)
		return -ENODEV;

	pr_info("%s: IPv%u %s %s, MSS=%u payload=%u bursts=%u prefill=%u\n",
		dev->name, ipv6 ? 6 : 4, plain_ip ? "IP" : "PPPoE",
		software ? "software control" : "direct TSO probe",
		mss, payload_len, count, prefill);
	for (burst = 0; burst < count; burst++) {
		err = send_burst(dev, &cfg, burst);
		if (err)
			break;
		if (burst + 1 < count)
			msleep(100);
	}
	pr_info("driver accepted %u skbs (%u GSO); expected %u wire packets if successful; status=%d\n",
		submitted_skbs, submitted_gso, count * DIV_ROUND_UP(payload_len, mss), err);
	dev_put(dev);
	return err;
}

static void __exit pppoe_tso_hw_exit(void)
{
}

module_init(pppoe_tso_hw_init);
module_exit(pppoe_tso_hw_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Direct-driver PPPoE TCP segmentation hardware probe");
