Name: libkae
Summary: Huawei Kunpeng Accelerator Engine
Version: 1.2.1
Release: 1
Source: %{name}-%{version}.tar.gz
Vendor: Huawei Corporation
License: Apache-2.0
ExclusiveOS: linux
Group: System Environment/Kernel
Provides: %{name} = %{version}
URL:https://support.huawei.com
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Requires: libwd >= %{version}
Autoreq: no
Autoprov: no
Prefix: /usr/local/lib/engines-1.1
Conflicts: %{name} < %{version}
BuildRequires: libwd >= %{version} openssl-devel

%description
This package contains the Huawei Kunpeng Accelerator Engine

%prep
%global debug_package %{nil}
%setup -c -n %{name}-%{version}

%build
cd kunpeng_engine
chmod +x configure
./configure
make

%install
mkdir -p ${RPM_BUILD_ROOT}/usr/local/lib/engines-1.1
install -p -m 0755 kunpeng_engine/libkae.so.%{version} ${RPM_BUILD_ROOT}/usr/local/lib/engines-1.1

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(755,root,root)
/usr/local/lib/engines-1.1/libkae.so.%{version}

%pre
if [ "$1" = "2" ] ; then  #2: update
    rm -rf $RPM_INSTALL_PREFIX/kae.so      > /dev/null 2>&1 || true
    rm -rf $RPM_INSTALL_PREFIX/kae.so.0    > /dev/null 2>&1 || true
fi

%post
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    ln -sf $RPM_INSTALL_PREFIX/libkae.so.%{version}    $RPM_INSTALL_PREFIX/kae.so
    ln -sf $RPM_INSTALL_PREFIX/libkae.so.%{version}    $RPM_INSTALL_PREFIX/kae.so.0
fi
/sbin/ldconfig

%preun
if [ "$1" = "0" ] ; then  #0: uninstall
    rm -rf $RPM_INSTALL_PREFIX/kae.so
    rm -rf $RPM_INSTALL_PREFIX/kae.so.0
    if [ -e /var/log/kae.log ] ; then
        rm -f /var/log/kae.log
    fi
fi

%postun
/sbin/ldconfig

%changelog


