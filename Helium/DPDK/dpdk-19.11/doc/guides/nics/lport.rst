..  Copyright(c) 2018 Marvell International Ltd.
    Copyright(c) 2018 Semihalf.
    All rights reserved.

    This program is provided "as is" without any warranty of any kind,
    and is distributed under the applicable Marvell proprietary limited
    use license agreement.

.. _lport_poll_mode_driver:

L-Port Poll Mode Driver
=======================

The L-Port PMD (`librte_pmd_lport`) provides a logical poll mode driver
that is meant to be used as an abstract layer on top of underlying
physical driver.

It is meant to be used in situation when user traffic has some tagging
mechanism and you'd like to handle traffic for different tag values to
be directed and handled by different logical ports.  Let's explain that
via example of VLAN based traffic (there are also DSA-port and DSA-vid
based tagging supported). So suppose you have traffic that is VLAN
tagged and you'd like to handle all traffic with VLAN id = 100 in one
way and that with VLAN id = 200 in another.  What you can do is to
create simple textual configuration file `lport.cfg`:

.. code-block:: console

	[l-domain]
	classify = vlan
	p-port = net_mvneta,iface=eth0
	# l-ports  rule
	lport:vlan100 = 100
	lport:vlan200 = 200

and create application that would open ports named ``vlan100`` and ``vlan200``
and handle their traffic separately (e.g. divide the traffic into two
"low" and "high" priority policies).

What will happen behind the scene is that l-port PMD will strip the VLAN
tag and pass the packets without them to the user and upon sending
packets to given port it will insert VLAN tag (with appropriate id).

This l-port driver is a logical one so what it does under the hood is
that it is using the actual physical driver as its "transport
mechanism".  So in this configuration example you see "l-domain"
and "p-port".  Each physical port that is used creates a "logical
domain" in which several logical ports can exist.  The "p-port"
configuration line gives the arguments that will be used for attaching
to the physical port and the "classify" parameter is used to switch
between following tagging schemes:

- ``vlan``    : 802.1Q based tagging (using VLAN id)
- ``dsa``     : DSA based tagging (using the src/tgt port ID)
- ``dsa-vid`` : DSA based tagging (using VID inside the DSA tag)

The "lport:xxx" syntax is used to create logical port (you can name the
logical port after colon but it is optional) and the value of the
parameter is the tag value that given port will be using.  What it
actually stands for depends on the chosen classification scheme
described above.

Logical port PMD provides basic functionality listed below and for the
speed capabilities and link status it actually act as a proxy to the
underlying physical port.

.. Note::

   This driver is disabled by default. It must be enabled manually by
   setting relevant configuration option manually.  Please refer to
   `Config File Options`_ section for further details.


Features
--------

Features of the L-Port PMD are:

- Start/stop
- tx/rx queue setup
- tx/rx burst
- Speed capabilities
- Port statistics
- Promiscuous mode
- Allmulticast mode
- Unicast MAC filter
- MTU update


Limitations
-----------

- Currently only one RX queue is used even though the underlying
  physical port might support more.

Prerequisites
-------------

- DPDK environment

  Follow the DPDK :ref:`Getting Started Guide for Linux <linux_gsg>` to setup
  DPDK environment.


Config File Options
-------------------

The following options can be modified in the DPDK ``config/common_base`` file.

- ``CONFIG_RTE_LIBRTE_PMD_LPORT`` (default: ``n``)

    Toggle compilation of the `librte_pmd_lport` driver.



Usage Example
-------------

L-port PMD does not have any particular requirements as it relies on
underlying physical driver to do the transmission/reception.  So just
describe your desired configuration in a file (by default named
`lport.cfg`) and pass it to the vdev as:

.. code-block:: console

   ./testpmd --vdev=net_lport,iface=wan,iface=lan -c 3 -- -i

where ``wan`` and ``lan`` are the names of lports defined in `lport.cfg` file.

If you need to have different configurations you can keep them in
separate files and pass the name of the file via `cfg` option as:

.. code-block:: console

   ./testpmd --vdev=net_lport,cfg=lport-vlan.cfg,iface=v1,iface=v2 -c 3 -- -i

where ``v1`` and ``v2`` are names of lports defined in `lport-vlan.cfg` file.
