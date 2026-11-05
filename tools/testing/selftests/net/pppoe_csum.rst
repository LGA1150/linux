.. SPDX-License-Identifier: GPL-2.0-only

PPPoE TX checksum probe
======================

``pppoe_csum`` sends Ethernet / PPPoE session / PPP / IPv4 or IPv6 /
UDP, TCP, or ICMP Echo Request frames on a specified Ethernet interface.
Its default mode uses ``AF_PACKET``, ``SOCK_RAW`` and ``PACKET_VNET_HDR``
to request real ``CHECKSUM_PARTIAL`` skbs. Merely sending a raw packet
with an unfinished checksum would not set this metadata.

Build and send
--------------

Build with the system's Linux userspace headers; no module or kernel build
is required::

    cc -O2 -Wall -Wextra -o pppoe_csum pppoe_csum.c

Use two machines connected over Ethernet. The transmitter's interface must
be the physical igc interface, such as ``enp1s0``. Replace the destination
MAC below with the receiving interface's MAC. No PPPoE discovery, PPP
negotiation, IP address assignment, TCP handshake, listener, or reply is
needed for a receiver-side packet capture. The program supplies a test
session ID and documentation IP addresses. It does not establish a PPPoE
session or TCP connection.

On the receiver, start tcpdump (replace ``enp2s0``)::

    sudo tcpdump -i enp2s0 -nn -e -vvv -s 0 'ether proto 0x8864'

Do not pass tcpdump's ``-K`` option: that disables checksum verification.
Capture on the physical receiving interface so the PPPoE session need not
exist in its PPP stack. The packets should decode as PPPoE session data,
IP, and the selected transport protocol. Look for ``[udp sum ok]``,
``cksum ... (correct)``, or an incorrect-checksum diagnostic as applicable.
The exact wording, including whether valid ICMP checksums are printed,
depends on tcpdump's protocol decoder and version; use the controls below.

On the sender, inspect the driver and enabled features::

    ethtool -i enp1s0
    ethtool -k enp1s0

Confirm ``driver: igc`` and ``tx-checksum-ip-generic: on``. If necessary,
enable TX checksum offload with ``sudo ethtool -K enp1s0 tx on``. Record
the original state if you change it. Select an IP version and protocol::

    sudo ./pppoe_csum -i enp1s0 -d 02:00:00:00:00:02 -4 -p udp
    sudo ./pppoe_csum -i enp1s0 -d 02:00:00:00:00:02 -4 -p tcp
    sudo ./pppoe_csum -i enp1s0 -d 02:00:00:00:00:02 -4 -p icmp
    sudo ./pppoe_csum -i enp1s0 -d 02:00:00:00:00:02 -6 -p udp
    sudo ./pppoe_csum -i enp1s0 -d 02:00:00:00:00:02 -6 -p tcp
    sudo ./pppoe_csum -i enp1s0 -d 02:00:00:00:00:02 -6 -p icmp

The defaults are IPv4, UDP, ``-m partial``, five packets and 64 payload
bytes. IPv4 defaults to 192.0.2.1 -> 192.0.2.2; IPv6 defaults to
2001:db8::1 -> 2001:db8::2. ``-p icmp`` selects ICMPv4 Echo Request
(type 8) or ICMPv6 Echo Request (type 128), according to the IP version.
Both have code 0 and echo identifier 0x1234.

TCP and UDP use ports 12345 -> 54321. TCP uses a 20-byte header without
options, flags PSH|ACK (ACK alone with zero payload), and acknowledgment
number 1. These are synthetic segments for checksum testing; no established
TCP connection is needed. Each segment's TCP sequence number is the packet
index, not a progression of bytes in an established stream.

The sender prints the submitted checksum seed and expected completed
checksum for every packet. The packet index is also in the first four
payload bytes when the payload is at least four bytes long. Its low 16 bits
are the IPv4 ID and ICMP echo sequence; TCP carries the full index in its
sequence number. Successful sendmsg only means the kernel accepted the
frame; use the receiving capture to determine the wire result.

To change session ID, inner addresses, payload length, or packet count::

    sudo ./pppoe_csum -i enp1s0 -d 02:00:00:00:00:02 -6 -p tcp \
        -S 0x1234 -s 2001:db8::1 -t 2001:db8::2 -l 65 -c 10

Packets are spaced 100 ms apart. Try even and odd payload lengths and the
MTU boundary. With Ethernet MTU 1500, the limits and offsets are:

===========  ==========  ===========  =======  ===========
Packet       csum_start  csum_offset  hdr_len  Max payload
===========  ==========  ===========  =======  ===========
IPv4/UDP     42          6            50       1464
IPv4/TCP     42          16           62       1452
IPv4/ICMP    42          2            50       1464
IPv6/UDP     62          6            70       1444
IPv6/TCP     62          16           82       1432
IPv6/ICMP    62          2            70       1444
===========  ==========  ===========  =======  ===========

The minimum UDP/ICMP payload is 10 bytes for either IP version. This keeps
space for the packet index and avoids Ethernet minimum-frame padding even
with IPv4. TCP permits zero payload; even its IPv4 frame is already 62
bytes. The sender does not append an Ethernet FCS; the NIC supplies it.
There are no VLAN tags, IP fragments, IPv4 options, IPv6 extension headers,
TCP options, or GSO in this test.

Controls
--------

For any IP/protocol combination, repeat with the same arguments and
``-m software`` or ``-m bad``, for example::

    sudo ./pppoe_csum -i enp1s0 -d 02:00:00:00:00:02 -6 -p icmp -m software
    sudo ./pppoe_csum -i enp1s0 -d 02:00:00:00:00:02 -6 -p icmp -m bad

``software`` fills in the correct transport checksum in userspace and does
not request checksum offload. ``bad`` supplies an intentionally incorrect,
nonzero checksum and also does not request offload. These establish that
your capture can distinguish valid and invalid checksums. A zero UDP
checksum would disable IPv4 UDP checksumming and is therefore unsuitable
for its bad-checksum control.

You can additionally repeat ``partial`` with TX checksum offload disabled
to exercise the kernel's software fallback; restore the previous feature
state afterwards. An unprivileged dry run prints the virtio header and
Ethernet frame bytes without transmitting::

    ./pppoe_csum -i enp1s0 -d 02:00:00:00:00:02 -6 -p tcp -n -c 1

Omit ``-i`` with ``-n`` for a completely offline run using source MAC
``02:00:00:00:00:01`` and MTU 1500. No sockets are opened in that case.

Why this is CHECKSUM_PARTIAL
---------------------------

Each sendmsg contains two iovecs: a legacy 10-byte ``struct virtio_net_hdr``
and the Ethernet frame. AF_PACKET consumes the virtio header; it is not
part of the transmitted frame. Partial mode sets::

    flags       = VIRTIO_NET_HDR_F_NEEDS_CSUM
    gso_type    = VIRTIO_NET_HDR_GSO_NONE
    gso_size    = 0

``csum_start``, ``csum_offset`` and ``hdr_len`` are set according to the
table above. These virtio fields use native byte order for the AF_PACKET
legacy interface. Ethernet, PPPoE, IP, and transport fields use network byte
order. The checksum start counts from the Ethernet header and the checksum
offset counts from that start; neither includes the virtio prefix.

The uncompressed PPP protocol is 0x0021 for IPv4 and 0x0057 for IPv6.
The checksum starts at Ethernet 14 + PPPoE 6 + PPP 2 + IP header 20 or 40.
In the kernel, ``virtio_net_hdr_to_skb()`` calls ``skb_partial_csum_set()``
to set ``skb->ip_summed = CHECKSUM_PARTIAL``, ``skb->csum_start`` (relative
to skb head), ``skb->csum_offset`` and the transport header position.

TCP, UDP, and ICMPv6 initially contain the folded, uncomplemented sum of
the appropriate IP pseudo-header in their checksum field. IPv6's
pseudo-header uses the 128-bit addresses, 32-bit upper-layer length,
and Next Header value (TCP 6, UDP 17, ICMPv6 58). ICMPv4 has no
pseudo-header: its checksum field starts at zero. Completion sums from the
transport header to the end of the frame, including the seed, and writes
the complemented result at ``csum_start + csum_offset``. The IPv4 header
checksum is already complete in software; IPv6 has no IP header checksum.

UDP's computed zero is encoded as 0xffff. TCP and ICMP can carry a computed
zero directly; a completion path that writes 0xffff instead also produces
a valid one's-complement checksum in that case. A rare seed that already
matches the completed checksum is avoided by changing a payload byte, or
the TCP window, so the seed alone cannot masquerade as completion.

Distinguish hardware from software fallback
------------------------------------------

``NETIF_F_HW_CSUM`` advertises generic one's-complement checksum support
across protocol layers through the CHECKSUM_PARTIAL interface. It does
not guarantee that every request is executed in silicon: per-packet
feature checks and the driver can fall back to software. A valid checksum
on the receiving machine alone cannot distinguish these cases. Conversely,
an unfinished checksum in a local outgoing capture is normal for offload
and does not establish what was sent on the wire.

For stronger evidence, on a sender with bpftrace, kernel BTF and kprobes
available, run this in a separate terminal, replacing both interface names
in the script::

    sudo bpftrace -e '
    tracepoint:net:net_dev_start_xmit
    /str(args->name) == "enp1s0" && args->protocol == 0x8864/
    {
        printf("driver entry skb=%p ip_summed=%u network=%d transport=%d gso=%u\n",
               args->skbaddr, args->ip_summed, args->network_offset,
               args->transport_offset, args->gso_size);
    }
    kprobe:skb_checksum_help
    {
        $skb = (struct sk_buff *)arg0;
        if ($skb->dev != 0 && str($skb->dev->name) == "enp1s0") {
            printf("software checksum skb=%p\n", arg0);
        }
    }'

For the partial test, expect ``ip_summed=3`` (CHECKSUM_PARTIAL) at driver
entry, ``network=14``, ``transport=42`` for IPv4 or ``62`` for IPv6, and
``gso=0``. The network header points to PPPoE, as in the kernel's PPPoE
transmit path. A prior generic software fallback instead produces
``ip_summed=0`` at driver entry. A driver-internal fallback happens after
this tracepoint, so also watch for ``skb_checksum_help`` on the same skb
address. Ignore unrelated traffic; tracing must be active for the entire
send and must not lose events.

In the checked-out igc source, ``igc_tx_csum()`` accepts UDP checksum offset
6 and TCP checksum offset 16, setting the TCP descriptor flag for the
latter. It uses ``skb_checksum_start_offset()`` and
``skb_network_offset()`` to describe the checksum start. ICMP's offset 2
hits its default case, which calls ``skb_checksum_help()``. Thus ICMPv4 and
ICMPv6 are expected to enter the driver as CHECKSUM_PARTIAL but be completed
in software by this driver version; a correct ICMP wire checksum does not
demonstrate ICMP checksum execution by the NIC.

The ``igc_features_check()`` header-length checks can also cause fallback
in the core. Inspect the actual running driver's implementation if it
differs. Together, driver-entry metadata, absence of the relevant software
fallback, and a valid receiver-side checksum provide evidence of hardware
completion for a tested packet. This test does not establish support for
other encapsulations, IP/TCP options, IPv6 extension headers, or segmentation
offload.
