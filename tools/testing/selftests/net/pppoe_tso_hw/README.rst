.. SPDX-License-Identifier: GPL-2.0-only

PPPoE TSO hardware capability probe
==================================

``pppoe_tso_hw`` is a standalone external kernel module for testing whether
an existing Intel ``igc`` driver and NIC can segment TCP over PPPoE when
software has already prepared the headers. It supports IPv4 and IPv6.
Build it against the running kernel's installed headers; neither a full
kernel build nor the proposed PPPoE GSO patches are required.

Each module load sends a bounded number of bursts. No PPP interface, PPPoE
peer, IP address configuration, TCP connection, or receiver listener is
needed. Inspect the frames with tcpdump on a separate receiving host.

Build on Arch Linux
-------------------

Install the tools and the headers matching your running kernel::

    sudo pacman -S --needed base-devel linux-headers ethtool tcpdump

Use ``linux-lts-headers``, ``linux-zen-headers``, or your kernel's matching
package instead when appropriate. After an Arch kernel upgrade, reboot
into that kernel before building against its headers. The directory
``/lib/modules/$(uname -r)/build`` must refer to the running kernel.

Only this directory's ``Makefile`` and ``pppoe_tso_hw.c`` are needed::

    cd tools/testing/selftests/net/pppoe_tso_hw
    make

An alternate prepared kernel build directory can be selected with
``make KDIR=/path/to/kernel/build``. The resulting module is
``pppoe_tso_hw.ko``. There is no installation step; load it by path.

Receiver
--------

Start the capture before loading the module on the sender. Record the
receiver's offload settings and disable supported receive aggregation
features so the capture shows individual wire frames::

    ethtool -k enp2s0
    sudo ethtool -K enp2s0 gro off lro off
    sudo ethtool -K enp2s0 rx-gro-hw off
    sudo tcpdump -i enp2s0 -nn -e -vvv -S -s 0 -XX 'ether proto 0x8864'

Do not use tcpdump's ``-K`` option: it disables checksum verification.
``-XX`` includes the Ethernet and PPPoE bytes, which is useful for the
deliberately incorrect length control. Use ``-w capture.pcap`` to save
the frames for later inspection.

Sender
------

Select the physical Ethernet interface driven by igc. Virtual interfaces
such as bridges, VLAN interfaces, and veth devices are rejected. Record
the original offload settings before changing them::

    ethtool -i enp1s0
    ethtool -k enp1s0
    sudo ip link set dev enp1s0 up
    sudo ethtool -K enp1s0 tx on sg on tso on

The link must have carrier. Replace the example destination MAC below
with the receiving NIC's address::

    sudo insmod ./pppoe_tso_hw.ko ifname=enp1s0 dst_mac=02:00:00:00:00:02
    sudo dmesg | tail -n 15
    sudo rmmod pppoe_tso_hw

Repeat for IPv6::

    sudo insmod ./pppoe_tso_hw.ko ifname=enp1s0 dst_mac=02:00:00:00:00:02 ipv6=1
    sudo rmmod pppoe_tso_hw

The module does not enable offloads or alter the interface configuration.
It checks the requested TSO/checksum features and device size limits, then
calls the driver's transmit operation under the TX queue lock. There is
no software GSO or checksum fallback in hardware mode. A driver accepting
an skb does not establish that it transmitted valid frames; the receiver
capture determines the hardware result.

With the defaults, the log should show one GSO skb with
``gso_size=1200 gso_segs=2``, followed by a non-GSO tail. The module exposes
``submitted_skbs`` and ``submitted_gso`` under
``/sys/module/pppoe_tso_hw/parameters/`` while loaded. Expect 2 and 1 for
one default burst. These count driver acceptance, not wire delivery.
The module sends only during insertion; unload and reload to run again.
If insertion fails after a transmit error, some preceding packets may
already have been accepted; consult the final status and counters in dmesg.

Expected default output
-----------------------

The default MSS is 1200 and TCP payload is 2537 bytes. The module groups
2400 bytes into one TSO skb and sends the remaining 137 bytes separately.
It fills the batch's PPPoE length for a single full-sized segment.

======  ====================  ===================  ======================
Packet  TCP sequence numbers  PPPoE lengths        Ethernet frame lengths
======  ====================  ===================  ======================
IPv4    1, 1201, 2401         1242, 1242, 179      1262, 1262, 199
IPv6    1, 1201, 2401         1262, 1262, 199      1282, 1282, 219
======  ====================  ===================  ======================

All three TCP checksums should verify. IPv4 header checksums should also
verify. Frame lengths exclude Ethernet padding and FCS. The PPPoE length
is the big-endian 16-bit field at Ethernet offset 18; it includes the PPP
protocol and IP packet, excluding Ethernet and the six-byte PPPoE header.

TCP uses ports 12345 -> 54321, acknowledgment number 1, ACK on every
segment, and PSH only on the last segment of each burst. IPv4 uses DF and
sequential IDs starting at 1. The payload byte at stream sequence number
N is ``(N * 37 + 0x5a) & 255``. Subsequent bursts advance the initial TCP
sequence by ``payload_len`` and IPv4 ID by the number of wire packets.

Controls
--------

Unload the module between runs. To check the link, receiver, and expected
packet contents, generate individual packets with complete checksums in
software::

    sudo insmod ./pppoe_tso_hw.ko ifname=enp1s0 dst_mac=02:00:00:00:00:02 software=1
    sudo rmmod pppoe_tso_hw

Add ``ipv6=1`` for the IPv6 control. This mode submits three non-GSO skbs
with the defaults and does not require checksum or TSO offload.

To test ordinary Ethernet/IP TSO on the same NIC, omit PPPoE::

    sudo insmod ./pppoe_tso_hw.ko ifname=enp1s0 dst_mac=02:00:00:00:00:02 plain_ip=1
    sudo rmmod pppoe_tso_hw

Capture this control with ``tcp dst port 54321`` instead of the PPPoE
filter. ``ipv6=1`` and ``software=1`` can also be used with ``plain_ip=1``.

To confirm whether hardware copies the PPPoE length unchanged, deliberately
put the aggregate batch length in that field::

    sudo insmod ./pppoe_tso_hw.ko ifname=enp1s0 dst_mac=02:00:00:00:00:02 prefill=0
    sudo rmmod pppoe_tso_hw

If hardware simply copies that field, the first two default IPv4 segments
will contain PPPoE length 2442 instead of 1242; for IPv6, 2462 instead of
1262. The tail remains correct. This control deliberately sends malformed
PPPoE lengths; check raw bytes if tcpdump cannot decode the frame normally.
``prefill`` affects only PPPoE; in software mode each skb is already one
wire packet, so the length is correct with either value.

Other parameters
----------------

``mss=1200 payload_len=12000`` tests an exact MSS multiple with no tail.
``mss=1200 payload_len=12137`` tests ten full-sized segments plus a tail.
``count=10`` repeats the burst ten times, 100 ms apart (maximum 100).

Hardware mode requires at least two full MSS segments in each burst. MSS
must be at least 64 and fit the interface MTU including the PPPoE, IP and
TCP headers. With MTU 1500 the maximum PPPoE MSS is 1452 for IPv4 or 1432
for IPv6. The total aggregate frame is limited to 65535 bytes and must also
fit the driver's GSO/TSO limits. Hardware mode fails when the requested
offloads are disabled, instead of falling back to software.

``src_ip=`` and ``dst_ip=`` override 192.0.2.1/192.0.2.2 or
2001:db8::1/2001:db8::2. ``session=0x1234`` selects the PPPoE session ID;
values 1..65534 are accepted. The source MAC comes from the interface.
``ifname`` is resolved in the initial network namespace.

What this tests
---------------

This isolates the NIC's descriptor-based segmentation and checksum
behavior. The skb's network header points to IP at Ethernet offset 22 for
PPPoE, or 14 for plain IP. Its transport header and checksum start identify
TCP. The GSO batch contains an exact MSS multiple, a normal TCPv4/TCPv6
GSO type, and CHECKSUM_PARTIAL with the pseudo-header seed for the entire
batch. The driver removes that TCP length from the seed and programs its
normal TSO context. The separate tail also requests hardware checksum
completion in hardware mode.

There is no SKB_GSO_PPPOE, SKB_GSO_PARTIAL, SKB_GSO_DODGY, or encapsulation
flag. PPPoE IP lengths are prepared for one wire segment; the plain-IP
control uses ordinary aggregate IP lengths. No VLANs, TCP/IP options,
IPv6 extension headers, IP tunnels, or PPP compression are generated.

The altered network-header position is deliberately private to this
probe. The skbs go directly to the driver, bypassing qdiscs, TC egress,
the normal feature-validation/GSO path, and outgoing packet taps. Sender
tcpdump and the usual net_dev_start_xmit tracepoint therefore do not see
these submissions; use the module's metadata logs and receiver capture.
Do not use this skb layout as the normal PPPoE networking API.

Success demonstrates the hardware mechanism. It does not validate the
proposed generic PPPoE GSO support, bridge forwarding, or normal kernel
fallback behavior. The module is intended for igc; other physical drivers
may interpret the supplied headers differently.

Restore any changed NIC offload settings after testing.
