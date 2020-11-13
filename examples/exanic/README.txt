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


exanic-hpt-fiber-len.c
----------------------
This is an example application to show the power of picosecond timestamps which 
are available using ExaNIC HPT. It demonstrates how to measure fiber/DAC cable 
lengths to within a few centimeters (inches) accuracy. 


exanic-measure.c
---------------------
This is an example of a measurement application written primarily for use with 
ExaNIC HPT (though it can be used with other devices such as the ExaNIC 
X10/X25/X40/X100).

The application is intended to be used to benchmark external devices with high 
precision. To use the application:
1. First measure a device of zero latency (e.g. an optical coupler). This will 
   give a calibration estimate of the "offset" including cabling delays and 
   internal NIC delays. The "average" number reported is the result.
2. Then replace the optical coupler with the device that has an unknown latency 
   (using the same cables as in step 1) and apply the -O offset parameter, with 
   the measurement from step 1. Your result will now be high precision, 
   compensated for cabling delays and NIC internal delays.


exanic-benchmarker-stac-t0.c
----------------------------
This application works with the stac_t0 FDK example. It performs the
STAC_T0 latency test as defined by the Securities Technology Analysis Center (STAC).
It generates UDP datagrams containing random indexes and expects
echoed indexes to come back in TCP segments from the stack under test,
in this case an ExaNIC.

Hardware timestamps are taken to calculate the latency in the stack.
