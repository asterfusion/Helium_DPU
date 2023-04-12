..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(C) 2019 Marvell International Ltd.


OCTEONTX2 End Point Performance Sample Application
==================================================

The end point performance sample application is a sample app that demonstrates
the usage of the end point rawdev API using the software PMD. It shows how an
application can configure rawdev queues and assign a set of worker cores for
each VF to perform the processing required.

The application has a range of command line arguments allowing it to be
configured for various number of rawdev VF. This is useful for performance
testing as well as quickly testing a particular rawdev VF configuration.

Compiling the Application
-------------------------

To compile the sample application see :doc:`compiling`.

The application is located in the ``examples`` sub-directory.

Running the Application
-----------------------

The application has a lot of command line options. This allows specification of
the end point rawdev PMD to use, and a number of attributes of the processing
options.

An example end-point rawdev performance running with the software rawdev PMD
using these settings is shown below:
 * ``-w BDF``: Rawdev VF to test
 * ``-n 0``: process infinite packets (run forever)
 * ``-m 2``: Running on transceiver mode
 * ``-l 1024``: Transmitting packets size is 1024
 * ``-b 32``: Receiving packets in burst-mode with 32

.. code-block:: console

    ./build//otx2_ep_perf -w 02:01.0 -- -w 02:01.0 -n 0 -m 2 -l 1024 -b 32

The application has some sanity checking built-in, so if provided number of
white-listings VFs are more than available cores, the application will print
an error message:

.. code-block:: console

  Available cores are <num-cores> only
  But number of white listing rawdevs are <num-VFs>

Observing the Application
-------------------------

At runtime the end-point rawdev performance application prints out runtime
statistics like mpps, gbps in average and received and transmitted mpps, gbps
in last one second instance. The following sections show sample output for each
of the output types.

Runtime
~~~~~~~

At runtime, the statistics of the rawdevs are printed, average mpps, gbps and
last one second instance mpps, gbps.

.. code-block:: console

  # avg: xx.xxxx mpps, xx.xxxx gbps; time: xxxx seconds
  #   rx: xx.xxxx mpps, xx.xxxx gbps
  #   tx: xx.xxxx mpps, xx.xxxx gbps
  # rxtx: xx.xxxx mpps, xx.xxxx gbps

