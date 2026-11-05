.. SPDX-License-Identifier: GPL-2.0-only

PPPoE TCP segmentation probe
===========================

``pppoe_tso`` submits an oversized Ethernet / PPPoE / PPP / IPv4 or IPv6 /
TCP packet using ``AF_PACKET``, ``SOCK_RAW`` and ``PACKET_VNET_HDR``. It sets
``CHECKSUM_PARTIAL`` and requests TCP GSO with a specified MSS. It is a
separate program from the checksum-only probe and sends directly through
the specified Ethernet interface; no ``pppN`` interface, PPPoE peer, TCP
handshake, or listener is required.

This is a probe, not a test that assumes hardware success. Without software
preparation, hardware PPPoE segmentation would have to update the PPPoE
length for every segment.
Partial GSO can instead separate the short tail and prefill the length
for each full-sized segment, leaving IP/TCP updates to hardware. A
successful ``sendmsg()`` means local submission only. Software segmentation,
rejection, a drop, or malformed output are distinct possible outcomes; a
valid receiver capture alone does not establish hardware TSO.

Build and send
--------------

Build with system Linux userspace headers::

    cc -O2 -Wall -Wextra -o pppoe_tso pppoe_tso.c

On Arch Linux, the build dependencies are ``gcc`` and ``linux-api-headers``.
Use ``ethtool`` on both hosts and ``tcpdump`` on the receiver. ``bpftrace``
is optional for observing the sender's software/hardware boundary.

On the sender, inspect the physical NIC's features::

    ethtool -i enp1s0
    ethtool -k enp1s0
    sudo ip link set dev enp1s0 up

To test the partial-GSO changes on ``codex/ppp-tx-checksum-offload``, enable
TX checksum, scatter-gather, and TCP segmentation on igc if disabled;
record their original states first::

    sudo ethtool -K enp1s0 tx on sg on tso on
    sudo ethtool -K enp1s0 tx-gso-partial on tx-pppoe-segmentation on

On the receiver, disable receive coalescing so the capture shows individual
segments. Disable the supported features below and record their previous
states; a device may report a feature as fixed or unsupported::

    ethtool -k enp2s0
    sudo ethtool -K enp2s0 gro off lro off
    sudo ethtool -K enp2s0 rx-gro-hw off
    sudo tcpdump -i enp2s0 -nn -e -vvv -S -s 0 -XX 'ether proto 0x8864'

``-S`` prints absolute TCP sequence numbers; ``-XX`` exposes the raw PPPoE
header even if its length is malformed. Do not use ``tcpdump -K``. For
later inspection, capture with ``-w pppoe-tso.pcap`` instead. No IP addresses
need to be configured on either host for these raw frames.

Replace the destination MAC with the receiving interface's MAC::

    sudo ./pppoe_tso -i enp1s0 -d 02:00:00:00:00:02 -4 -S 0x1234
    sudo ./pppoe_tso -i enp1s0 -d 02:00:00:00:00:02 -6 -S 0x1234

Defaults are one large packet, MSS 1200, and 2537 payload bytes. This
requests three segments carrying 1200, 1200, and 137 data bytes. The input
PPPoE length is the full aggregate length: 2579 for IPv4 or 2599 for IPv6.
It is deliberately not prefilled with the expected length of a full-sized
segment. The shorter tail detects implementations that merely copy a
constant length.

The program prints the expected lengths, TCP sequence numbers, and completed
TCP checksums before submitting the aggregate. With the defaults:

======  =======================  =======================  =======================
Packet  TCP sequence numbers     PPPoE length fields      Ethernet frame lengths
======  =======================  =======================  =======================
IPv4    1, 1201, 2401            1242, 1242, 179          1262, 1262, 199
IPv6    1, 1201, 2401            1262, 1262, 199          1282, 1282, 219
======  =======================  =======================  =======================

Frame lengths exclude Ethernet FCS and padding. The PPPoE length is a
network-order 16-bit value at Ethernet offset 18; it counts the two-byte
PPP protocol plus the IP packet, excluding Ethernet and the six-byte PPPoE
header. For small custom tails, ignore Ethernet padding beyond the IP and
PPPoE lengths. TCP ACK is set on every segment and PSH only on the last.
TCP uses ports 12345 -> 54321, acknowledgment number 1, and a deterministic
payload whose byte at stream sequence number N is ``(N * 37 + 0x5a) & 255``.

Change MSS, total payload, addresses, and packet count with::

    sudo ./pppoe_tso -i enp1s0 -d 02:00:00:00:00:02 -6 \
        -g 1000 -l 4097 -c 3 -s 2001:db8::10 -t 2001:db8::20

Each burst advances its initial TCP sequence by the total payload length.
Bursts are 100 ms apart. With Ethernet MTU 1500, the maximum MSS is 1452
for PPPoE/IPv4 and 1432 for PPPoE/IPv6. The MSS must be at least 64, and the
total payload must exceed it so the kernel really receives a GSO request.
Aggregate frame size is capped at 65535 bytes, below the legacy 64 KiB GSO
device limit; no IPv6 jumbograms, BIG TCP, VLANs, TCP options, IP options,
or IPv6 extension headers are used.

Controls and dry run
--------------------

``-m software`` constructs the individual segments in userspace, including
correct PPPoE/IP lengths and complete TCP checksums. Its virtio headers
request neither GSO nor checksum offload. Use this to validate the receiver
setup and the expected bytes::

    sudo ./pppoe_tso -i enp1s0 -d 02:00:00:00:00:02 -6 -m software

``-e ip`` omits PPPoE/PPP and submits ordinary Ethernet/IP/TCP GSO. It is
a control for normal IPv4/IPv6 TSO on the same NIC. Capture with a filter
such as ``tcp dst port 54321`` for this control::

    sudo ./pppoe_tso -i enp1s0 -d 02:00:00:00:00:02 -4 -e ip
    sudo ./pppoe_tso -i enp1s0 -d 02:00:00:00:00:02 -6 -e ip

You can also repeat GSO mode with ``tso off`` on the sender to request
kernel software segmentation. This works only if the running kernel has
the relevant software segmenter available. On kernels with PPPoE GSO,
``sudo modprobe pppoe`` loads it when modular; AF_PACKET transmission alone
does not load the PPPoE module. Older kernels without a PPPoE GSO handler
may drop the packet before NIC driver entry.

An unprivileged, offline dry run emits each submitted virtio header and
frame as hex; no sockets are opened when ``-i`` is omitted::

    ./pppoe_tso -d 02:00:00:00:00:02 -6 -n
    ./pppoe_tso -d 02:00:00:00:00:02 -6 -m software -n

Restore any changed sender and receiver offload settings when finished.

What is submitted
-----------------

GSO mode uses the legacy ten-byte virtio header with native-endian 16-bit
fields, followed by the complete Ethernet frame. AF_PACKET consumes this
prefix; it is never transmitted. The fields are:

================  ===========================  ===========================
Field             PPPoE/IPv4                   PPPoE/IPv6
================  ===========================  ===========================
``flags``         1 (NEEDS_CSUM)               1 (NEEDS_CSUM)
``gso_type``      1 (TCPV4)                    4 (TCPV6)
``gso_size``      Requested TCP MSS            Requested TCP MSS
``hdr_len``       62                           82
``csum_start``    42                           62
``csum_offset``   16                           16
================  ===========================  ===========================

For ``-e ip``, subtract eight from ``hdr_len`` and ``csum_start``. Offsets
start at Ethernet, excluding the virtio prefix. TCP's checksum field is
seeded with the folded, uncomplemented IP pseudo-header sum, including the
full aggregate TCP length. The kernel/driver adjusts that seed during
segmentation; userspace does not pre-subtract the length. The aggregate
IPv4 total length and header checksum, or IPv6 payload length, are valid
for the whole aggregate before segmentation.

Distinguish software GSO from hardware TSO
------------------------------------------

With the kernel changes on ``codex/ppp-tx-checksum-offload``, PPPoE packets
require ``NETIF_F_GSO_PPPOE`` in addition to ordinary TCP TSO. igc advertises
this capability through partial GSO. See ``pppoe_tests.rst`` for the branch
link and the separate hardware-only probe for an unmodified kernel.
The core invokes software preparation for both raw ``PACKET_VNET_HDR``
requests and trusted GRO aggregates. The PPPoE segmenter separates a
short final segment and sets the retained batch's PPPoE length to that
of one full-sized wire packet. igc then uses the IP header following
PPPoE/PPP to build its context descriptor.

With default arguments, expect a GSO batch carrying 2400 TCP payload bytes
with ``gso_size=1200`` and ``gso_segs=2``, followed by a non-GSO packet
carrying 137 bytes. The batch's PPPoE length is 1242 for IPv4 or 1262 for
IPv6, even though its skb contains two segments. A receiver should see the
three packets listed above. Try ``-l 12000`` for an exact MSS multiple and
``-l 12137`` for ten full-sized segments plus a short tail.

The retained batch's ``gso_type`` includes ``SKB_GSO_PARTIAL`` (0x1000)
and ``SKB_GSO_PPPOE`` (0x100000), plus TCPv4 (0x1) or TCPv6 (0x10).
Do not confuse ``SKB_GSO_PARTIAL`` with ``CHECKSUM_PARTIAL``.

Repeat with either ``tx-pppoe-segmentation off``, ``tx-gso-partial off``,
or ``tso off`` to exercise full software segmentation. Re-enable both
partial-GSO and PPPoE offloads for the next hardware test. Without the
kernel patches the PPPoE feature is absent, and ``NETIF_F_GSO_SOFTWARE`` alone
does not clear ``NETIF_F_GSO_PARTIAL``: entering the old PPPoE segmenter
was not sufficient to guarantee complete software segmentation.

For plain IP, GSO validation can retain the large packet for hardware TSO.
Merely observing entry to ``__skb_gso_segment()`` is therefore insufficient
to conclude that software performed the split. Inspect the skbs at NIC
driver entry. With bpftrace and the kernel's network tracepoints available,
replace the sender interface name and run::

    sudo bpftrace -e '
    tracepoint:net:net_dev_start_xmit
    /str(args->name) == "enp1s0"/
    {
        printf("skb=%p proto=0x%x len=%u partial=%u net=%d tcp=%d gso_size=%u segs=%u type=0x%x\n",
               args->skbaddr, args->protocol, args->len, args->ip_summed,
               args->network_offset, args->transport_offset,
               args->gso_size, args->gso_segs, args->gso_type);
    }'

``partial=3`` means ``CHECKSUM_PARTIAL``. Multiple MTU-sized packets with
``gso_size=0`` mean segmentation was completed before the driver, even if
TCP checksums are still delegated to hardware. One large packet with
``gso_size=MSS`` and the expected ``gso_segs`` means the driver received a
segmentation request. Driver-entry metadata plus a receiver capture are
needed to assess actual output; neither a successful send nor a local
outgoing tcpdump capture establishes hardware completion.

The legacy virtio header supplies a checksum-start offset but no separate
inner-IP offset. The PPPoE GSO handler establishes the header positions,
and igc explicitly skips PPPoE/PPP when programming TSO. The utility uses
the real PPPoE EtherType and does not bypass kernel validation.

Forward GRO packets through a bridge
-----------------------------------

Ordinary TCP GRO can produce ``CHECKSUM_PARTIAL`` GSO packets without
``SKB_GSO_DODGY``. An Ethernet bridge preserves those packets. A PPP channel
bridge also preserves them when the destination channel sets
``xmit_offload``, as PPPoE does. Neither bridge automatically makes an
untrusted userspace GSO request trusted: feed ordinary, completed segments
into GRO to exercise this path.

The PPPoE capability requirement now sends these trusted aggregates through
partial-GSO preparation before igc driver entry. On kernels without this
requirement, supported TCP GSO flags alone could bypass the PPPoE handler
on either bridge path. With this change, compare receiver output and
sender metadata for the same bridge setup with PPPoE offload on and off.

Partial GSO also requires a buffer layout the NIC can transmit. GRO from
AF_PACKET traffic over veth can produce a ``frag_list``; igc cannot send
that layout directly, so the core falls back to full software segmentation.
The veth recipe below therefore also tests this fallback. To exercise
partial GSO through either bridge, use a physical ingress interface whose
GRO packets use page fragments instead, and send ``-m software`` traffic
from another host into that interface. Keep ``rx-gro-list`` disabled.

IPv4 GRO packets with a fixed IP ID require ``tx-tcp-mangleid-segmentation``
on the egress device to permit hardware ID changes when DF is set. Without
that optional feature, these packets can also fall back to software.

The following topology uses a local veth pair to supply GRO input, so only
the test host and capture host are needed::

    pppoe_tso -m software -> tso-src --veth--> tso-in (GRO)
                                                   |
                                                br-tso
                                                   |
                                              enp1s0 (igc) --> receiver

Use an otherwise unused test NIC for ``enp1s0``. Create the bridge on the
test host, with the PPPoE GRO handler loaded::

    sudo modprobe pppoe
    sudo ip link add tso-src type veth peer name tso-in
    sudo ip link add br-tso type bridge stp_state 0 forward_delay 0
    sudo ip link set tso-in master br-tso
    sudo ip link set enp1s0 master br-tso
    sudo ip link set tso-src up
    sudo ip link set tso-in up
    sudo ip link set enp1s0 up
    sudo ip link set br-tso up

Disable TSO on the source veth: in this kernel veth normally skips peer GRO
when the sending device advertises TSO. Enable ordinary GRO on the ingress
veth and disable GRO's fraglist variant, which would add a GSO type that
igc does not support::

    sudo ethtool -K tso-src tso off
    sudo ethtool -K tso-in gro on rx-gro-list off
    sudo ethtool -K enp1s0 tx on sg on tso on
    sudo ethtool -K enp1s0 tx-gso-partial on tx-pppoe-segmentation on

To help packets from separate send calls coalesce across NAPI polls, set
these parameters on the newly created ingress veth::

    echo 10000000 | sudo tee /sys/class/net/tso-in/gro_flush_timeout
    echo 2 | sudo tee /sys/class/net/tso-in/napi_defer_hard_irqs

Keep GRO/LRO disabled on the final capture NIC, as above. Start the
driver-entry trace on the test host, then generate completed PPPoE
segments addressed to the final receiver's MAC::

    sudo ./pppoe_tso -i tso-src -d 02:00:00:00:00:02 -4 \
        -m software -g 1200 -l 12137 -c 10 -S 0x1234
    sudo ./pppoe_tso -i tso-src -d 02:00:00:00:00:02 -6 \
        -m software -g 1200 -l 12137 -c 10 -S 0x1234

Look for large skbs at ``enp1s0`` driver entry with ``ip_summed=3`` and
``gso_size=1200``. GRO batching is timing dependent, so do not assume every
burst becomes exactly one skb. The tracepoint's ``gso_type`` uses
``SKB_GSO_*`` flags, not virtio values: basic TCPv4 is 0x1, TCPv6 is 0x10,
and the ``SKB_GSO_DODGY`` bit is 0x2. This bit should be absent on the GRO
aggregates. A final receiver capture determines how igc handled them.

Repeat with ``sudo ethtool -K enp1s0 tso off`` to force segmentation on
egress, or with ``sudo ethtool -K tso-in gro off`` to prevent aggregation
on ingress. Either control should leave only individual segments at NIC
driver entry. Restore the enabled state between controls.

Both Ethernet and PPPoE-to-PPPoE channel bridging were checked in a VM with
veth egress: ordinary IPv4/IPv6 GRO aggregates retained GSO through both
bridges with egress TSO enabled, and were split with it disabled. This
verifies the software path; it does not establish igc hardware behavior.
For a PPP channel bridge, the same principle applies after connecting the
channels with ``PPPIOCBRIDGECHAN``; no PPP unit or IP negotiation is needed.
The ``pppoe_bridge`` utility creates these sessions and channels. See
``pppoe_bridge.rst`` for a complete hardware recipe with the ingress and
egress MAC addresses and session IDs specified separately.

Remove the local test topology afterwards::

    sudo ip link set enp1s0 nomaster
    sudo ip link delete br-tso
    sudo ip link delete tso-src

Restore the NIC offload settings to their original values.
