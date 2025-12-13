Name:               kdyndns
Version:            1.0.0
Release:            0.1.beta.1%{?dist}
Summary:            A minimalistic DynDNS service written in Rust.

License:            %cargo_license
URL:                https://github.com/KaiKorla/KDynDNS
Source0:            %{url}/archive/refs/tags/v%{version}-beta.1.tar.gz

ExclusiveArch:      %{rust_arches}

BuildRequires:      rust-packaging
BuildRequires:      systemd-rpm-macros

%description
A minimalistic DynDNS service written in Rust.

%prep
%autosetup -n KDynDNS-%{version}-beta.1
%cargo_prep

%build
%cargo_build --release

%install
%cargo_install
install -d %{buildroot}%{_sysconfdir}/kdyndns
install -m0644 config/config.toml %{buildroot}%{_sysconfdir}/kdyndns/config.toml
install -Dm0644 packaging/kdyndns-sysusers.conf %{buildroot}%{_sysusersdir}/kdyndns.conf
install -Dm0644 packaging/kdyndns-tmpfiles.conf %{buildroot}%{_tmpfilesdir}/kdyndns.conf
install -Dm0644 packaging/kdyndns.service %{buildroot}%{_unitdir}/kdyndns.service

%files
%license LICENSE
%doc CHANGELOG.md
%doc README.md

%config(noreplace) %{_sysconfdir}/kdyndns/config.toml

%{_sysusersdir}/kdyndns.conf
%{_tmpfilesdir}/kdyndns.conf
%{_unitdir}/kdyndns.service

%{_bindir}/kdyndns

%pre
%sysusers_create %{_sysusersdir}/kdyndns.conf

%post
%tmpfiles_create %{_tmpfilesdir}/kdyndns.conf
%systemd_post kdyndns.service

%preun
%systemd_preun kdyndns.service

%postun
%systemd_postun_with_restart kdyndns.service

%check
%cargo_test
