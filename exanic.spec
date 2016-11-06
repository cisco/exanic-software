Name:           exanic
Version:        1.8.0
Release:        1%{?dist}

Summary:        ExaNIC drivers and software
Group:          System Environment/Kernel
License:        GPLv2
URL:            http://exablaze.com/support
Source:         %{name}-%{version}.tar.gz
Buildroot:      %_tmppath/%{name}-%{version}
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
%description utils
This package contains userspace utilities for the ExaNIC, including
exanic-config, exanic-capture, exanic-clock-sync and exanic-fwupdate.
It also contains the ExaNIC Sockets wrapper (exasock).

%package devel
Summary:        ExaNIC development library
Group:          Development/Libraries
%description devel 
This package contains libexanic, a low-level access library for the
ExaNIC.  It can be used to write applications which transmit and receive
raw Ethernet packets with minimum possible latency.

%package doc
Summary:        ExaNIC documentation
Group:          Documentation
BuildArch:      noarch
%description doc
This package contains documentation for the ExaNIC.

%prep
%setup -q

%build
make bin

%install
test "%{buildroot}" != "/" && rm -rf %{buildroot}

make install-bin BINDIR=%{buildroot}%{_bindir} LIBDIR=%{buildroot}%{_libdir} INCDIR=%{buildroot}%{_includedir}

# Package up required files to build modules
mkdir -p %{buildroot}/usr/src/%{name}-%{version}/libs/exanic %{buildroot}/usr/src/%{name}-%{version}/libs/exasock/kernel
cp -r modules %{buildroot}/usr/src/%{name}-%{version}/
cp libs/exanic/{ioctl.h,pcie_if.h,fifo_if.h,const.h} %{buildroot}/usr/src/%{name}-%{version}/libs/exanic
cp libs/exasock/kernel/{api.h,structs.h,consts.h} %{buildroot}/usr/src/%{name}-%{version}/libs/exasock/kernel

# Create a dkms.conf
cat >%{buildroot}/usr/src/%{name}-%{version}/dkms.conf <<EOF
PACKAGE_NAME="%{name}"
PACKAGE_VERSION="%{version}"
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
dkms add -m %{name} -v %{version} --rpm_safe_upgrade
dkms build -m %{name} -v %{version}
dkms install -m %{name} -v %{version}

%preun dkms
echo -e
echo -e "Uninstall of %{name} module (version %{version}) beginning:"
dkms remove -m %{name} -v %{version} --all --rpm_safe_upgrade


%files
%defattr(-,root,root,-)
%doc LICENSE.txt changelog.txt

%files dkms
%defattr(-,root,root,-)
/usr/src/%{name}-%{version}/

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

%files doc
%defattr(-,root,root,-)
%doc docs/*.pdf

