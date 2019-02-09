%define name pius
%define version	2.2.7
%define release 1

Name: %{name}
Summary: A tool for signing and email all UIDs on a set of PGP keys.
Version: %{version}
Release: %{release}
Group: Utilities
License: GPLv2
URL: http://www.phildev.net/pius/
BuildRoot: %{_tmppath}/%{name}-buildroot
Requires: python
Source: %{name}-%{version}.tar.bz2

%description
 The PGP Individual UID Signer (PIUS) is a tool for individually
 signing all of the UIDs on a set of keys and encrypt-emailing each
 one to it's respective email address. This drastically reduces the time
 and errors involved in signing keys after a keysigning party.

%prep
rm -rf $RPM_BUILD_ROOT
%setup

%build
./setup.py build

%install
./setup.py install --prefix=$RPM_BUILD_ROOT/usr

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(755, root, bin, 755)
/usr/bin/%{name}
/usr/bin/%{name}-keyring-mgr
/usr/bin/%{name}-party-worksheet
/usr/bin/%{name}-report
/usr/lib/python*/site-packages/%{name}-%{version}-*egg-info
%attr(644, root, bin) /usr/lib/python*/site-packages/libpius/*
%doc README.md README-keyring-mgr.md README-report.md COPYING
