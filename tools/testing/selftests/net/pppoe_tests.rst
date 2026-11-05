.. SPDX-License-Identifier: GPL-2.0-only

PPPoE checksum and segmentation test tools
=========================================

The ``codex/pppoe-test-artifacts`` branch collects the test tools and
hardware instructions. The kernel changes under test are on the separate
`codex/ppp-tx-checksum-offload branch
<https://github.com/LGA1150/linux/tree/codex/ppp-tx-checksum-offload>`_.

Choose a test
-------------

* `pppoe_csum <pppoe_csum.rst>`_: send IPv4/IPv6 UDP, TCP, and ICMP
  CHECKSUM_PARTIAL packets using AF_PACKET and PACKET_VNET_HDR. Includes
  complete software checksums, incorrect checksums, and offline controls.
  Runs on an unmodified kernel.

* `pppoe_session <pppoe_session.rst>`_: create a PPP interface attached to
  a locally configured PPPoE session without a negotiating peer. Interface
  creation works on an unmodified kernel; testing the new PPP transmit
  checksum behavior requires the checksum patch.

* `pppoe_bridge <pppoe_bridge.rst>`_: connect two PPPoE channels using a
  PPP channel bridge. The guide describes GRO forwarding tests and the
  partial-GSO behavior expected with the kernel patches.

* `pppoe_tso <pppoe_tso.rst>`_: submit IPv4/IPv6 TCP GSO packets through
  PACKET_VNET_HDR, with software segmentation and plain-IP controls.
  Exercises the normal kernel transmit path. The guide includes Ethernet
  bridge tests and distinguishes software fallback from hardware TSO.
  Expected PPPoE partial-GSO results require the kernel patches.

* `pppoe_tso_hw <pppoe_tso_hw/README.rst>`_: standalone external module
  that submits already-prepared IPv4/IPv6 PPPoE TCP GSO packets directly
  to the existing driver. Builds against the installed kernel headers;
  no custom kernel or PPPoE GSO patches are required. Use this to test
  only the NIC's segmentation and checksum mechanism.

Build the userspace tools
-------------------------

From this directory, using the system's Linux userspace headers::

    cc -O2 -Wall -Wextra -o pppoe_csum pppoe_csum.c
    cc -O2 -Wall -Wextra -o pppoe_session pppoe_session.c
    cc -O2 -Wall -Wextra -o pppoe_bridge pppoe_bridge.c
    cc -O2 -Wall -Wextra -o pppoe_tso pppoe_tso.c

On Arch Linux the compiler and header packages are ``gcc`` and
``linux-api-headers``. The guides list the networking tools needed for
each test. The userspace programs are also registered as generated helper
files in the networking selftest Makefile; they are not run automatically.

The hardware-only module has its own Makefile. Follow its README to select
the headers matching the running kernel and build only that module.

Each guide documents interface setup, controls, expected output, and
receiver-side tcpdump commands. A successful local submission does not
establish that the NIC produced valid packets; use the receiver capture
and the sender metadata described by the selected test.
