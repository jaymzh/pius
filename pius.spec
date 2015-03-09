# Sample spec file.
# $Id$

%define name pius
%define version	2.1.0
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

%description
 The PGP Individual UID Signer (PIUS) is a tool for individually
 signing all of the UIDs on a set of keys and encrypt-emailing each
 one to it's respective email address. This drastically reduces the time
 and errors involved in signing keys after a keysigning party.

%prep
rm -rf $RPM_BUILD_ROOT
%setup

%install
install PREFIX=$RPM_BUILD_ROOT/usr

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(755, root, bin, 755)
/usr/bin/%{name}
/usr/bin/%{name}-keyring-mgr
/usr/bin/%{name}-party-worksheet
%doc README README.keyring-mgr COPYING

