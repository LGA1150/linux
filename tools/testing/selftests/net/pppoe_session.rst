.. SPDX-License-Identifier: GPL-2.0-only

PPP interface without a negotiating peer
========================================

``pppoe_session`` creates a real ``pppN`` network interface attached to a
kernel PPPoE channel. It configures the session locally using an Ethernet
interface, destination MAC, and session ID. It does not send discovery,
LCP, authentication, IPCP, or IPv6CP messages, and needs no response from
the receiving machine. The receiver only needs to capture Ethernet frames.

This exercises the PPP interface's transmit path, including its advertised
``NETIF_F_HW_CSUM`` feature, before PPPoE encapsulation and transmission on
the underlying NIC. The separate ``pppoe_csum`` utility constructs Ethernet
frames directly and bypasses this PPP interface.

Build and create the interface
------------------------------

On Arch Linux, install the build and test tools::

    sudo pacman -S --needed gcc linux-api-headers iproute2 ethtool iputils python

Install ``tcpdump`` on the receiver. No ``pppd`` or PPPoE server is needed.
The running kernel must include the PPP checksum change to test it, along
with ``CONFIG_PPP``, ``CONFIG_PPPOE``, and IPv6 support for IPv6 tests.

Build with the system userspace headers::

    cc -O2 -Wall -Wextra -o pppoe_session pppoe_session.c

Load the driver if it is modular, bring up the physical NIC, and start the
utility. Replace the interface and MAC with the sender's igc interface and
the receiving NIC's MAC::

    sudo modprobe pppoe
    sudo ip link set dev enp1s0 up
    sudo ./pppoe_session -i enp1s0 -d 02:00:00:00:00:02 -S 0x1234 -u 0

``-u 0`` requests ``ppp0`` and fails if that unit is already in use. Omit
``-u`` to allocate an available unit and use the printed interface name in
the commands below. ``-S`` defaults to 1; valid session IDs are 1..65534.
``-m`` overrides the default MTU of Ethernet MTU minus eight bytes (1492
for Ethernet MTU 1500). IPv6 requires an MTU of at least 1280.

The utility requires ``CAP_NET_ADMIN`` and access to ``/dev/ppp``; running
it with ``sudo`` supplies both on a normal host. Keep it running while
testing. Ctrl-C, SIGTERM, or SIGHUP closes the descriptors and removes the
PPP interface, its addresses and routes, and the local PPPoE session.

Configure IPv4 and IPv6
----------------------

In another terminal on the sender, assign test addresses and routes::

    sudo ip addr add 192.0.2.1 peer 192.0.2.2/32 dev ppp0
    sudo ip -6 addr add 2001:db8::1/128 dev ppp0 nodad
    sudo ip -6 route add 2001:db8::2/128 dev ppp0
    ip route get 192.0.2.2
    ip -6 route get 2001:db8::2
    ethtool -k ppp0
    ethtool -k enp1s0

Both routes should select ``ppp0``. With the checksum patch, ``ppp0`` should
show ``tx-checksum-ip-generic: on``. Enable TX checksum offload on the
underlying NIC if needed, recording its previous state::

    sudo ethtool -K enp1s0 tx on

The PPP interface is point-to-point: ARP and IPv6 neighbor discovery are
not needed to reach these destinations. Their IP addresses do not need to
exist on the receiver. PPP negotiation and all compression remain disabled.

Send traffic and capture
------------------------

On the receiver, capture its physical interface::

    sudo tcpdump -i enp2s0 -nn -e -vvv -s 0 'ether proto 0x8864'

Do not use ``tcpdump -K``, which disables checksum verification. Check the
wire capture for the session ID, inner addresses, and checksum results.

On the sender, these commands produce ICMPv4 and ICMPv6 Echo Requests::

    ping -4 -I ppp0 -c 3 -W 1 192.0.2.2
    ping -6 -I ppp0 -c 3 -W 1 2001:db8::2

Generate UDP datagrams and TCP SYNs for both IP versions with Python::

    python3 - <<'PY'
    import socket

    for family, src, dst in (
        (socket.AF_INET, "192.0.2.1", "192.0.2.2"),
        (socket.AF_INET6, "2001:db8::1", "2001:db8::2"),
    ):
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.bind((src, 0))
            for size in (64, 65, 1400):
                s.sendto(bytes(size), (dst, 54321))
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.bind((src, 0))
            s.settimeout(1)
            try:
                s.connect((dst, 54321))
            except TimeoutError:
                pass  # SYN was sent; no peer is expected to answer.
    PY

Ping and TCP connection attempts time out because no peer responds. TCP
SYNs suffice to check TCP checksum completion; sending ordinary TCP stream
data would require a handshake. Successful UDP sends indicate only local
acceptance; the receiver capture determines what reached the wire.

Check the checksum path
-----------------------

Ordinary sockets let the IP stack decide whether to request checksum
offload. In particular, ordinary ICMPv4 ping computes its checksum in
software; a correct ping checksum alone does not test ``CHECKSUM_PARTIAL``.
For the actual offload test, trace ``net:net_dev_start_xmit`` for both
``ppp0`` and ``enp1s0`` and confirm ``ip_summed=3`` (``CHECKSUM_PARTIAL``)
on the packets of interest. With bpftrace installed, kernel BTF and kprobes
available, run the following before sending traffic, replacing the
interface names::

    sudo bpftrace -e '
    tracepoint:net:net_dev_start_xmit
    /str(args->name) == "ppp0" ||
     (str(args->name) == "enp1s0" && args->protocol == 0x8864)/
    {
        printf("%s skb=%p ip_summed=%u gso=%u\n",
               str(args->name), args->skbaddr, args->ip_summed, args->gso_size);
    }
    kprobe:skb_checksum_help
    {
        $skb = (struct sk_buff *)arg0;
        if ($skb->dev != 0 &&
            (str($skb->dev->name) == "ppp0" ||
             str($skb->dev->name) == "enp1s0")) {
            printf("software checksum dev=%s skb=%p\n",
                   str($skb->dev->name), arg0);
        }
    }'

A completed checksum at the receiver, a partial checksum at NIC driver
entry, and no software checksum completion for that packet provide
evidence of hardware completion. A valid wire checksum alone cannot tell
whether hardware or software completed it. Tracing must cover the entire
send without losing events.

As a control, repeat UDP and TCP sends with the PPP feature disabled::

    sudo ethtool -K ppp0 tx off

Then restore it and disable TX checksum offload only on the underlying NIC
to exercise completion after PPPoE encapsulation::

    sudo ethtool -K ppp0 tx on
    sudo ethtool -K enp1s0 tx off

All three configurations should produce valid receiver-side checksums.
Tracing distinguishes offload from software fallback. Restore the NIC's
original feature state when finished. On the checked-out igc driver,
ICMP checksum requests fall back to software inside the driver.
