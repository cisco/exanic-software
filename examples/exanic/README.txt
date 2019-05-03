ExaNIC example programs
========================

This directory contains examples of programs which work with the
libexanic interface.

exanic-rx-frame.c
-----------------
Basic example of how to send a frame using the libexanic API.

exanic-tx-frame.c
-----------------
Basic example of how to receive a frame using the libexanic API.

exanic-rx-chunk-inplace.c
-------------------------
This is a demonstration of the exanic_receive_chunk_inplace() function. This
demo tests the ability of the host to receive chunks/frames and reports the
speed at which they are received.

exanic-tx-preload.c
-------------------
This is an example showing how to arbitrarily divide up the ExaNIC TX buffer,
then load a number of frames into each slot and choose one to send later. The
idea is to remove the overhead of transferring the packet to the card from the
critical path.

exanic-benchmarker.c
---------------------
This is an example of a benchmarking application written primarily for use with
the ExaNIC HPT*. This tool is designed to allow you to quickly start working
with the ExaNIC HPT as well as a starting point for writing your own
benchmarking software. It operates in two modes, cable length estimation mode
and system measurement mode.

In cable length estimation mode, it can be used to estimate cable lengths where
the  propagation speeds are known. In system measurement mode, it can be used to
estimate the delay measured from TX to RX through some device, where both cable
lengths and propagation delays are known.

The application can also report raw measured values which can be used for
calibration and high precision benchmarking.

Examples and usage details can be found here:
https://exablaze.com/docs/exanic/user-guide/x10-hpt/x10-hpt/

*Although nothing prevents the application from being used with other devices
such as the X10/X40.

exanic-benchmarker-stac-t0.c
----------------------------
This application works with the stac_t0 FDK example. It performs the
STAC_T0 latency test as defined by the Securities Technology Analysis Center (STAC).
It generates UDP datagrams containing random indexes and expects
echoed indexes to come back in TCP segments from the stack under test,
in this case an ExaNIC.

Hardware timestamps are taken to calculate the latency in the stack.
