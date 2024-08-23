..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(C) 2023 Marvell International Ltd.

Graph Sample Application to receive UDP frames
==============================================

The L3 Forwarding Graph application is a simple example of receiving UDP frames
using the DPDK Graph framework. The application registers a user node with
specified destination port in Graph framework to receive UPD frames.

Overview
--------

The application demonstrates the use of the graph framework and graph nodes
``ethdev_rx``, ``pkt_cls``, ``ip4_lookup``/``ip6_lookup``,
``ip4_local``/``udp4_input``, ``app_node`` and ``pkt_drop`` in DPDK to
implement packet forwarding.


The application demonstrates the use of the hash, LPM libraries in DPDK
to implement packet reception using poll or event mode PMDs for packet I/O.
The initialization is very similar to those of the :doc:`l3_forward`.
There is also additional initialization of graph for graph object creation
and configuration per lcore along with registraion of user node and
UDP destinaiton port to receive packets

Packet reception logic starts from Rx, followed by LPM lookup,
hash lookup  and finally send filtered packets to user node .These nodes are
interconnected in graph framework. Application main loop needs to walk over
graph using ``rte_graph_walk()`` with graph objects created one per worker lcore.


To receive UDP filtered frames application registers user specific node using API
``rte_node_udp4_add_usr_node()``. This api returns a specific node id for registered
node. This node is added to hash table along with user specified destination port
uing the API ``rte_node_udp4_dst_port_add()``.Hash table is updated with node id and
destination port for ``udp4_input`` lookup.

The lookup method is as per implementation of ``ip4_lookup``/``ip6_lookup`` graph node.
The ID of the output interface for the input packet is the next hop returned by
the LPM lookup. The set of LPM rules used by the application is statically
configured and provided to ``ip4_lookup``/``ip6_lookup`` graph node using node control API
``rte_node_ip4_route_add()``/``rte_node_ip6_route_add``.

After LPM lookup next hop could be ``ip4_local``/``ip_rewrite`` based on mask provided
and next hop provided to the API ``rte_node_ip4_route_add()``. Once packet is passed to
``ip4_local`` node , packet is filtered based on packet proto i.e UDP proto , next hop
is updated to ``udp4_input`` node. Hash lookup is performed with registered destination
port, on success packets are passed to user node else dropped.


In the sample application, UDP4 reception is supported.

Compiling the Application
-------------------------

To compile the sample application see :doc:`compiling`.

The application is located in the ``udp4-recv`` sub-directory.

Running the Application
-----------------------

The application has a number of command line options similar to l3fwd::

    ./upd4-recv [EAL options] -- -p PORTMASK
                                   [-P]
                                   --config(port,queue,lcore)[,(port,queue,lcore)]
                                   --dest-port=X
                                   --ip-addr=X:X:X:X
                                   [--eth-dest=X,MM:MM:MM:MM:MM:MM]
                                   [--max-pkt-len PKTLEN]
                                   [--no-numa]
                                   [--per-port-pool]
                                   [--pcap-enable]
                                   [--pcap-num-cap]
                                   [--pcap-file-name]

Where,

* ``-p PORTMASK:`` Hexadecimal bitmask of ports to configure

* ``-P:`` Optional, sets all ports to promiscuous mode so that packets are accepted regardless of the packet's Ethernet MAC destination address.
  Without this option, only packets with the Ethernet MAC destination address set to the Ethernet address of the port are accepted.

* ``--config (port,queue,lcore)[,(port,queue,lcore)]:`` Determines which queues from which ports are mapped to which cores.

* ``--dest-port=X:`` Filter UDP packets for this destination port

* ``--ip-addr=X.X.X.X`` Filter packets  for  ipv4 address

* ``--eth-dest=X,MM:MM:MM:MM:MM:MM:`` Optional, ethernet destination for port X.

* ``--max-pkt-len:`` Optional, maximum packet length in decimal (64-9600).

* ``--no-numa:`` Optional, disables numa awareness.

* ``--per-port-pool:`` Optional, set to use independent buffer pools per port. Without this option, single buffer pool is used for all ports.

* ``--pcap-enable:`` Optional, Enables packet capture in pcap format on each node with mbuf and node metadata.

* ``--pcap-num-cap:`` Optional, Number of packets to be captured per core.

* ``--pcap-file-name:`` Optional, Pcap filename to capture packets in.

For example, consider a dual processor socket platform with 8 physical cores, where cores 0-7 and 16-23 appear on socket 0,
while cores 8-15 and 24-31 appear on socket 1.

To enable L3 forwarding between two ports, assuming that both ports are in the same socket, using two cores, cores 1 and 2,
(which are in the same socket too), use the following command:

.. code-block:: console

    ./<build_dir>/examples/dpdk-l3fwd-graph -l 1,2 -n 4 -- -p 0x3 --config="(0,0,1),(1,0,2)" --dest-port=8844 --ip-addr=192.168.10.2

In this command:

*   The -l option enables cores 1, 2

*   The -p option enables ports 0 and 1

*   The --config option enables one queue on each port and maps each (port,queue) pair to a specific core.

*   The --dest-port option enbled to receive packets with this destination port

*   The --ip-addr option enbled to receive packets with this ipaddress
    The following table shows the mapping in this example:

+----------+-----------+-----------+-------------------------------------+
| **Port** | **Queue** | **lcore** | **Description**                     |
|          |           |           |                                     |
+----------+-----------+-----------+-------------------------------------+
| 0        | 0         | 1         | Map queue 0 from port 0 to lcore 1. |
|          |           |           |                                     |
+----------+-----------+-----------+-------------------------------------+
| 1        | 0         | 2         | Map queue 0 from port 1 to lcore 2. |
|          |           |           |                                     |
+----------+-----------+-----------+-------------------------------------+

To enable pcap trace on each graph, use following command:

.. code-block:: console

    ./<build_dir>/examples/dpdk-l3fwd-graph -l 1,2 -n 4 -- -p 0x3 --config="(0,0,1),(1,0,2)" --dest-port=8844 --ip-addr=192.168.10.2 --pcap-enable --pcap-num-cap=<number of packets> --pcap-file-name "</path/to/file>"

In this command:

*   The --pcap-enable option enables pcap trace on graph nodes.

*   The --pcap-num-cap option enables user to configure number packets to be captured per graph. Default 1024 packets per graph are captured.

*   The --pcap-file-name option enables user to give filename in which packets are to be captured.

Refer to the *DPDK Getting Started Guide* for general information on running applications and
the Environment Abstraction Layer (EAL) options.

.. _udp4_recv_graph_explanation:

Explanation
-----------

The following sections provide some explanation of the sample application code.

Graph Node Pre-Init Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After device configuration and device Rx, queue setup is complete,
a minimal config of port id, num_rx_queues, num_tx_queues, mempools etc will
be passed to *ethdev_** node ctrl API ``rte_node_eth_config()``. This will be
lead to the clone of ``ethdev_rx`` and ``ethdev_tx`` nodes as ``ethdev_rx-X-Y`` and
``ethdev_tx-X`` where X, Y represent port id and queue id associated with them.
In case of ``ethdev_tx-X`` nodes, tx queue id assigned per instance of the node
is same as graph id.

These cloned nodes along with existing static nodes such as ``ip4_lookup``/``ip6_lookup``
and ``ip4_local``, ``udp4_input`` and user_node will be used in graph creation to associate node's to lcore
specific graph object.

.. literalinclude:: ../../../examples/udp4-recv/main.c
    :language: c
    :start-after: Initialize all ports. 8<
    :end-before: >8 End of graph creation.
    :dedent: 1

Graph Initialization
~~~~~~~~~~~~~~~~~~~~

Now a graph needs to be created with a specific set of nodes for every lcore.
A graph object returned after graph creation is a per lcore object and
cannot be shared between lcores. Since ``ethdev_rx-X-Y`` node is created per
(port, rx_queue_id), so they should be associated with a graph based on
the application argument ``--config`` specifying rx queue mapping to lcore.
Along with ``ethdev_rx-X-Y`` ``ip4_lookup``, ``ip4_local`` and ``udp4_input``
nodes are used in graph creation, user node registered as one of edges
to ``udp4_input`` node using API ``rte_node_udp4_add_usr_node()``.

.. note::

    The Graph creation will fail if the passed set of shell node pattern's
    are not sufficient to meet their inter-dependency or even one node is not
    found with a given regex node pattern.

.. literalinclude:: ../../../examples/udp4-recv/main.c
    :language: c
    :start-after: Graph initialization. 8<
    :end-before: >8 End of graph initialization.
    :dedent: 1

Forwarding data(Route, Next-Hop) addition
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once graph objects are created, node specific info like routes and udp destination
lookup will be provided run-time using ``rte_node_ip4_route_add()`` and
``rte_node_udp4_dst_port_add()``
API.

.. literalinclude:: ../../../examples/l3fwd-graph/main.c
    :language: c
    :start-after: Add routes and rewrite data to graph infra. 8<
    :end-before: >8 End of adding routes and rewrite data to graph infa.
    :dedent: 1

Packet Forwarding using Graph Walk
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Now that all the device configurations are done, graph creations are done and
nodes are updated to receive UDP frams, worker lcores will be launched with graph
main loop. Graph main loop is very simple in the sense that it needs to
continuously call a non-blocking API ``rte_graph_walk()`` with it's lcore
specific graph object that was already created.

.. note::

    rte_graph_walk() will walk over all the sources nodes i.e ``ethdev_rx-X-Y``
    associated with a given graph and Rx the available packets and enqueue them
    to the following node ``pkt_cls`` which based on the packet type will enqueue
    them to ``ip4_lookup``/``ip6_lookup`` which then will enqueue them to
    ``ip4_local`` node if LPM lookup succeeds.
    ``ip4_local`` node then will check for UDP protocol in UDP header
    as per next-hop and then enqueue  packet to udp4_input for UDP packets
    Packet are processed and enqueued to user node if hash lookup succeeds

.. literalinclude:: ../../../examples/udp4-recv/main.c
    :language: c
    :start-after: Main processing loop. 8<
    :end-before: >8 End of main processing loop.
