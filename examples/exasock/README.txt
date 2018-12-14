Exasock example programs
========================

This directory contains examples of sockets programs which work with the
Exasock socket acceleration library.

ate-connect.c
-------------

This program demonstrates the use of ExaNIC Accelerated TCP Engine (ATE) for
exasock accelerated TCP connections. It creates a socket, enables Accelerated
TCP Engine for the socket and connects to a TCP server. Once the connection is
established, ATE is ready to send TCP segments directly from HW whenever
triggered. This program will keep on receiving any data sent from the server on
the connection and printing the data as it arrives.

Example usage:

  exasock ./ate-connect 192.168.1.10 11111

Note that exasock is required to enable and control ExaNIC Accelerated TCP
Engine, so this program will fail if run without exasock.

multicast-echo.c
----------------

This program receives multicast UDP packets and echos the packets on a
different unicast UDP socket.


Example usage:

  ./multicast-echo 224.1.2.3:192.168.1.11:14159 192.168.2.10:26535

This will receive packets on the interface with address 192.168.1.11
which are addressed to multicast group 224.1.2.3 and UDP port 14159.

Each received packet will be sent out again on unicast UDP to address
192.168.2.10 port 26535.


To run using Exasock socket acceleration:

  exasock ./multicast-echo 224.1.2.3:192.168.1.11:14159 192.168.2.10:26535

192.168.1.11 must be the address of an ExaNIC interface and the route to
192.168.2.10 must go out via an ExaNIC interface.

tcp-raw-send.c
--------------

This program demonstrates the use of the Exasock extensions API. It retrieves a
raw TCP header from an accelerated socket, construct a TCP segment manually and
sends it via the raw API (libexanic).

Example usage:

  exasock ./tcp-raw-send 192.168.1.11 11111

This will listen for TCP connections on the interface with address 192.168.1.11
and port 11111. After a connection is accepted, any received packets will be
echoed by manually constructing the next TCP segment and transmitting it via
the raw ethernet frame API (libexanic).

The extensions API is useful for performing TCP transmission from outside of
standard sockets, for example, from the ExaNIC FPGA or by preloading the
transmit buffers on the card.

Note that if run without Exasock this example will fail, as the Exasock
extensions API function stubs will not have been replaced with the versions
that are preloaded via the Exasock wrapper.

udp-timestamp.c:
----------------

This program demonstrates the use of hardware timestamps for received packets
on a UDP socket using the SO_TIMESTAMPING API.  It can be used with or without
exasock.

Example usage:
  exasock ./udp-timestamp enp1s0 8000
  recvmsg returned 6
  timestamp 1501811797.753824888
