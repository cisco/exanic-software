%{!?kversion: %define kversion %(uname -r)}

# This is the name of the source package; the binary package is defined by the kmodtool
# invocation below and will be called kmod-exanic.
Name:           exanic-kmod
Version:        2.6.1
Release:        1%{?dist}

Summary:        ExaNIC pre-built driver modules
Group:          System Environment/Kernel
License:        GPLv2
URL:            http://exablaze.com/support
Source0:        exanic-%{version}.tar.gz
Source1:        kmodtool
Buildroot:      %_tmppath/exanic-%{version}-%{release}

Prefix:         /usr
BuildRequires:  redhat-rpm-config

ExclusiveArch:  x86_64

%description
This package encapsulates pre-built Linux network drivers for the ExaNIC.

# Disable the building of the debug package(s).
%define debug_package %{nil}

# Use kmodtool to generate the binary package definition.
%{expand:%(TMPFILE=$(mktemp);\
           echo "Provides: exanic-drivers = %{version}-%{release}" > ${TMPFILE};\
           echo "Conflicts: exanic-dkms" >> ${TMPFILE};\
           override_preamble=${TMPFILE} sh %{SOURCE1} rpmtemplate exanic %{kversion} "";\
           rm -f ${TMPFILE})}

%prep
%setup -q -n exanic-%{version}
echo "override exanic * weak-updates/exanic" > kmod-exanic.conf

%build
make modules KDIR=%{_usrsrc}/kernels/%{kversion}

%install
%{__install} -d %{buildroot}/lib/modules/%{kversion}/extra/
%{__install} -m 644 modules/exanic/exanic.ko %{buildroot}/lib/modules/%{kversion}/extra
%{__install} -m 644 modules/exasock/exasock.ko %{buildroot}/lib/modules/%{kversion}/extra
%{__install} -d %{buildroot}%{_sysconfdir}/depmod.d/
%{__install} -m 644 kmod-exanic.conf %{buildroot}%{_sysconfdir}/depmod.d/
%{__install} -d %{buildroot}%{_defaultdocdir}/kmod-exanic-%{version}/

%clean
test "%{buildroot}" != "/" && rm -rf %{buildroot}
