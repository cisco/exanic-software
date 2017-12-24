ExaNIC Software
===============
This repository contains drivers, utilities and development libraries for Exablaze ultra-low-latency network cards (ExaNIC X2, ExaNIC X4, ExaNIC X10, ExaNIC X40, ExaNIC GM, and ExaNIC HPT). For full installation instructions and user guide please refer to the [ExaNIC User Guide](http://exablaze.com/docs/exanic/user-guide/).

What's an ExaNIC?
-----------------
The ExaNIC range from Exablaze features world-leading latency performance, precision timing, a simple and flexible programming interface, and true hardware extensibility through FPGA based reconfiguration.

Once the drivers are installed, ExaNICs present as normal network cards under Linux and many of the features are available through standard Linux APIs, however there are also additional tools and libraries that unlock the full performance and feature set.

An **exanic-config** utility provides an overview of device configuration and status at a glance.

An **exanic-capture** utility is provided for packet capture.  With appropriate configuration, ExaNICs can provide lossless line rate capture at 10G.  Accurate hardware timestamps are provided for each packet, to 6.2ns resolution for most ExaNICs and to 0.25ns resolution on the ExaNIC HPT (High Precision Timing) variant.

For low latency applications, Linux sockets applications can be accelerated with the **exasock** wrapper that hooks sockets calls and sends data directly to the card, bypassing the kernel.  No recompilation is necessary.  Alternatively, developers can access the card directly, including sending and receiving packets, through the **libexanic** API.  Exasock also provides an extensions API that allows a hybrid model, where sockets are used for the majority of TCP functions but bypassed on the critical path.

Hardware traffic filtering and steering features are available to reduce host application load.

Advanced users with specific network processing needs can also program the onboard FPGA to develop custom network functions in hardware.  (The Firmware Development Kit is licensed separately.)

Repository Contents
-------------------
- **modules** - ExaNIC and exasock drivers for Linux
- **libs** - libexanic and exasock libraries
- **util** - ExaNIC utilities including exanic-config, exanic-capture, exanic-clock-sync and exanic-fwupdate
- **scripts** - exasock wrapper script
- **perf_test** - tools for performing performance tests with ExaNICs as well as with devices from other vendors
- **examples** 
	- **exanic** - advanced usage with preloaded frames and a demonstration of a high resolution timing/measurement application
	- **exasock** - exasock related examples (multicast receive, timestamping, extensions API)
	- **filters** - filtering and traffic steering examples
	- **devkit** - software examples that are paired with the Firmware Development Kit (FDK)
- **debian** - Debian/Ubuntu packaging
- **exanic.spec** - Redhat/CentOS packaging

Installation
------------
To install from source please run ``make`` and ``sudo make install`` from the top level.

Pre-built packages for Ubuntu are available from our [apt](http://www.exablaze.com/downloads/apt/) repository, and pre-built packages for Redhat/CentOS are available from our [yum](http://www.exablaze.com/downloads/yum/) repository.  Packages for ArchLinux are available from [AUR](https://aur.archlinux.org/packages/exanic/).

Support
-------
Complete documentation is available from our [website](http://exablaze.com/docs/exanic/user-guide/).  For other questions and comments, you can contact us at supportATexablaze.com.

