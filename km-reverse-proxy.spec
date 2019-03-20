Name:           km-reverse-proxy
Version:        0.1.0
Release:        1%{?dist}
Summary:        Reverse proxy service for http resources

#Group:
License:        ASL 2.0
URL:            https://github.com/cviecco/km-reverse-proxy/
Source0:        km-reverse-proxy-%{version}.tar.gz

#BuildRequires: golang
#Requires:
Requires(pre): /usr/sbin/useradd, /usr/bin/getent
Requires(postun): /usr/sbin/userdel

#no debug package as this is go
%define debug_package %{nil}

%description
A web broker for accesing AWS and potentially other clouds


%prep
%setup -n %{name}-%{version}


%build
make


%install
#%make_install
%{__install} -Dp -m0755 ~/go/bin/cloud-gate %{buildroot}%{_bindir}/cloud-gate
install -d %{buildroot}/usr/lib/systemd/system
install -p -m 0644 misc/startup/km-reverse-proxy.service %{buildroot}/usr/lib/systemd/system/cloud-gate.service

%pre
/usr/bin/getent passwd km-reverse-proxy || useradd -d /var/lib/km-reverse-proxy -s /bin/false -U -r  km-reverse-proxy

%post
mkdir -p /etc/km-reverse-proxy/
mkdir -p /var/lib/km-reverse-proxy
chown km-reverse-proxy /var/lib/km-reverse-proxy
systemctl daemon-reload

%postun
/usr/sbin/userdel km-reverse-proxy
systemctl daemon-reload

%files
#%doc
%{_bindir}/km-reverse-proxy
/usr/lib/systemd/system/km-reverse-proxy.service
%changelog


