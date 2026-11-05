.. SPDX-License-Identifier: GPL-2.0-only

PPPoE channel bridge for offload testing
=======================================

``pppoe_bridge`` creates two local PPPoE sessions, attaches their channels
through ``/dev/ppp``, and joins them with ``PPPIOCBRIDGECHAN``. Forwarding
runs in the kernel in both directions. No PPPoE discovery, authentication,
PPP negotiation, ``pppN`` interface, IP address, or response from a peer is
required. The utility keeps the descriptors open until stopped.

Build and arguments
-------------------

Build with the system userspace headers. On Arch Linux the build packages
are ``gcc`` and ``linux-api-headers``; the examples also use ``iproute2``
and ``ethtool``, with ``tcpdump`` on the receiver::

    cc -O2 -Wall -Wextra -o pppoe_bridge pppoe_bridge.c
    cc -O2 -Wall -Wextra -o pppoe_tso pppoe_tso.c

The arguments describe the two endpoints symmetrically::

    sudo ./pppoe_bridge IFACE_A PEER_MAC_A SESSION_A IFACE_B PEER_MAC_B SESSION_B

Both interfaces must already be up. Session IDs accept decimal or ``0xhex``
and must be in 1..65534. Each peer MAC is the remote MAC on that link:
received frames must carry that source MAC, the local destination MAC, and
the matching session ID. The utility prints both local MACs and channel
numbers. It requires ``CAP_NET_ADMIN`` and access to ``/dev/ppp``.

On A-to-B forwarding, the kernel removes A's PPPoE header and adds B's
PPPoE/Ethernet headers. The output uses B's local source MAC, peer
destination MAC, and session ID. The inner PPP/IP/TCP packet is preserved.
The reverse direction uses A's headers. This is a PPP channel bridge;
neither endpoint is enslaved to a Linux Ethernet bridge.

GRO to PPP channel bridge to igc
-------------------------------

Use a local veth pair to provide PPPoE GRO input, and an otherwise unused
igc interface connected to the capture host::

    pppoe_tso -m software -> pcp-src --veth--> pcp-in (GRO, session 0x1234)
                                                     |
                                               PPPIOCBRIDGECHAN
                                                     |
                                      enp1s0 (igc, session 0x5678) --> receiver

This setup is separate from the Ethernet bridge recipe in
``pppoe_tso.rst``. Use interfaces that are not members of that bridge.
Substitute your igc NIC for ``enp1s0`` and your receiver's actual MAC for
``02:00:00:00:00:04``. The two veth MACs below are assigned explicitly so
the PPPoE session lookup is reproducible::

    sudo modprobe pppoe
    sudo ip link add pcp-src type veth peer name pcp-in
    sudo ip link set pcp-src address 02:00:00:00:00:01 up
    sudo ip link set pcp-in address 02:00:00:00:00:02 up
    sudo ip link set enp1s0 up

Record the NIC's offload settings before changing them. Disable TSO on
the source veth to make veth use the peer's GRO path, enable ordinary TCP
GRO on ``pcp-in``, and enable TX offloads on igc::

    ethtool -k enp1s0
    sudo ethtool -K pcp-src tso off
    sudo ethtool -K pcp-in gro on rx-gro-list off
    sudo ethtool -K enp1s0 tx on sg on tso on
    sudo ethtool -K enp1s0 tx-gso-partial on tx-pppoe-segmentation on
    echo 10000000 | sudo tee /sys/class/net/pcp-in/gro_flush_timeout
    echo 2 | sudo tee /sys/class/net/pcp-in/napi_defer_hard_irqs

Start the channel bridge and leave it running::

    sudo ./pppoe_bridge \
        pcp-in  02:00:00:00:00:01 0x1234 \
        enp1s0  02:00:00:00:00:04 0x5678

The first peer MAC is the source veth's MAC, not ``pcp-in``'s local MAC.
The second peer MAC is the final receiver's MAC. The program creates fresh
channels for these tuples; an already active session causes an error.

On the receiver, disable supported receive coalescing features and capture
on the physical port, recording the prior feature states for restoration::

    ethtool -k enp2s0
    sudo ethtool -K enp2s0 gro off lro off
    sudo ethtool -K enp2s0 rx-gro-hw off
    sudo tcpdump -i enp2s0 -nn -e -vvv -S -s 0 -XX 'ether proto 0x8864'

Start the ``net:net_dev_start_xmit`` trace from ``pppoe_tso.rst`` on the
test host. In another terminal, generate completed IPv4 or IPv6 TCP
segments. Their destination is ``pcp-in``'s local MAC, with A's session ID::

    sudo ./pppoe_tso -i pcp-src -d 02:00:00:00:00:02 -4 \
        -m software -g 1200 -l 12137 -c 10 -S 0x1234
    sudo ./pppoe_tso -i pcp-src -d 02:00:00:00:00:02 -6 \
        -m software -g 1200 -l 12137 -c 10 -S 0x1234

GRO can combine these into trusted GSO packets. PPPoE's ``xmit_offload``
channel flag lets the PPP channel bridge pass them to the egress channel.
The kernel changes on ``codex/ppp-tx-checksum-offload`` require PPPoE
partial-GSO preparation before igc driver entry. With a suitable buffer
layout, look for a full-sized batch with
``SKB_GSO_PARTIAL`` (0x1000), ``SKB_GSO_PPPOE`` (0x100000), and the TCP GSO
flag, followed by a separate short tail. The batch's PPPoE length must
already describe one wire segment. igc skips the PPPoE/PPP prefix when
locating IP for its TSO descriptor.

The veth recipe can produce GRO packets with a ``frag_list``, which igc
cannot transmit directly. Those packets correctly fall back to full
software segmentation. To test bridge partial GSO on hardware, substitute
a physical ingress interface whose GRO uses page fragments for ``pcp-in``,
and send completed segments from a separate host. Use that host's source
MAC for the first peer argument and the physical ingress MAC as the
sender's destination. The session IDs and bridge setup are otherwise the
same. See ``pppoe_tso.rst`` for fixed IPv4 ID and buffer-layout controls.

The outgoing session ID is ``0x5678``. Check PPPoE/IP lengths, TCP sequence
numbers and checksums on the receiver, and compare them with driver-entry
metadata on the sender. Real hardware validation is still required.

Controls and cleanup
--------------------

Repeat with ``sudo ethtool -K enp1s0 tso off`` to force kernel segmentation
before NIC entry. Restore TSO, then repeat with
``sudo ethtool -K pcp-in gro off`` to prevent aggregation on ingress.
Both controls should produce individual segments at NIC driver entry.
The incoming MSS must fit both links after subtracting PPPoE/IP/TCP
headers: for Ethernet MTU 1500, at most 1452 for IPv4 or 1432 for IPv6.
The bridge utility does not negotiate or adjust the MSS or link MTUs.

Stop ``pppoe_bridge`` with Ctrl-C, SIGTERM, or SIGHUP. Closing its sockets
unregisters the channels and removes their bridge and sessions, including
on a partial setup failure. Existing Ethernet interfaces and their
settings remain in place. If a link goes down, the kernel disconnects its
PPPoE session; bring the link back up and restart the utility.

Remove the local veth pair after stopping the utility::

    sudo ip link delete pcp-src

Restore the NIC offload settings changed for the experiment.
