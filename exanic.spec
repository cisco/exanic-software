Name:           exanic
Version:        2.2.2-git
Release:        1%{?dist}

Summary:        ExaNIC drivers and software
Group:          System Environment/Kernel
License:        GPLv2
URL:            http://exablaze.com/support
Source:         %{name}-%{version}.tar.gz
Buildroot:      %_tmppath/%{name}-%{version}-%{release}
Requires:       exanic-dkms = %{version}-%{release}, exanic-utils = %{version}-%{release}, exanic-devel = %{version}-%{release}
Prefix:         /usr
%description
Drivers and software for ExaNIC, a low latency network card from
Exablaze (www.exablaze.com).  The exanic package installs exanic-dkms,
exanic-utils and exanic-devel.

%package dkms
Summary:        ExaNIC network driver
Group:          System Environment/Kernel
%if 0%{?suse_version}
Requires:       dkms, kernel-source
%else
Requires:       dkms, kernel-devel
%endif
BuildArch:      noarch
%description dkms
This package contains the Linux network drivers for the ExaNIC.  This
package installs the source code and dkms control files; the kernel
modules are then automatically built by dkms.

%package utils
Summary:        ExaNIC utilities
Group:          Applications/System
BuildRequires:  pkgconfig, libnl3-devel
Requires:       libnl3
%description utils
This package contains userspace utilities for the ExaNIC, including
exanic-config, exanic-capture, exanic-clock-sync and exanic-fwupdate.
It also contains the ExaNIC Sockets wrapper (exasock) and its utilities
(exasock-stat).

%package devel
Summary:        ExaNIC development library
Group:          Development/Libraries
%description devel 
This package contains libexanic, a low-level access library for the
ExaNIC.  It can be used to write applications which transmit and receive
raw Ethernet packets with minimum possible latency.

%prep
%setup -q

%build
make bin

%install
test "%{buildroot}" != "/" && rm -rf %{buildroot}

make install-bin BINDIR=%{buildroot}%{_bindir} LIBDIR=%{buildroot}%{_libdir} INCDIR=%{buildroot}%{_includedir}

# Package up required files to build modules
mkdir -p %{buildroot}/usr/src/%{name}-%{version}-%{release}/libs/exanic %{buildroot}/usr/src/%{name}-%{version}-%{release}/libs/exasock/kernel \
         %{buildroot}/usr/src/%{name}-%{version}-%{release}/include
cp -r modules %{buildroot}/usr/src/%{name}-%{version}-%{release}/
cp libs/exanic/{ioctl.h,pcie_if.h,fifo_if.h,const.h} %{buildroot}/usr/src/%{name}-%{version}-%{release}/libs/exanic
cp libs/exasock/kernel/{api.h,structs.h,consts.h} %{buildroot}/usr/src/%{name}-%{version}-%{release}/libs/exasock/kernel
cp include/exanic_version.h %{buildroot}/usr/src/%{name}-%{version}-%{release}/include


# Create a dkms.conf
cat >%{buildroot}/usr/src/%{name}-%{version}-%{release}/dkms.conf <<EOF
PACKAGE_NAME="%{name}"
PACKAGE_VERSION="%{version}-%{release}"
CLEAN="make -C modules clean KDIR=\$kernel_source_dir"
MAKE[0]="make -C modules KDIR=\$kernel_source_dir"
DEST_MODULE_LOCATION[0]=/extra
DEST_MODULE_LOCATION[1]=/extra
BUILT_MODULE_NAME[0]="exanic"
BUILT_MODULE_LOCATION[0]="modules/exanic/"
BUILT_MODULE_NAME[1]="exasock"
BUILT_MODULE_LOCATION[1]="modules/exasock/"
AUTOINSTALL="yes"
EOF


%clean
test "%{buildroot}" != "/" && rm -rf %{buildroot}

%post dkms
dkms add -m %{name} -v %{version}-%{release} --rpm_safe_upgrade
dkms build -m %{name} -v %{version}-%{release} --rpm_safe_upgrade
dkms install -m %{name} -v %{version}-%{release} --rpm_safe_upgrade

%preun dkms
echo -e
echo -e "Uninstall of %{name} module (version %{version}) beginning:"
dkms remove -m %{name} -v %{version}-%{release} --all --rpm_safe_upgrade


%files
%defattr(-,root,root,-)
%doc LICENSE.txt changelog.txt docs/README.txt

%files dkms
%defattr(-,root,root,-)
/usr/src/%{name}-%{version}-%{release}/

%files utils
%defattr(-,root,root,-)
%{_bindir}/*
%{_libdir}/exasock/*
%{_libdir}/libexasock_ext.so.*

%files devel
%defattr(-,root,root,-)
%{_libdir}/libexanic.a
%{_libdir}/libexasock_ext.so
%{_includedir}/exanic
%{_includedir}/exasock

