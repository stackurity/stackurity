#!/bin/sh
# Runs the agent's dnf, yum and zypper code for real in throwaway containers:
# openSUSE Leap 15.5 (zypper), Amazon Linux 2 (yum), Rocky Linux 9 and
# Amazon Linux 2023 (dnf). Needs Docker and Go.
#
#   sh internal/agentfix/testdata/pkgmanagers.sh
#
# Real repository packages (several versions of each are published):
#   zypper: less 590-150400.3.3.1 -> 3.6.2 -> 3.9.1
#   yum:    tar 2:1.26-35.amzn2.0.2 -> 0.3 -> 0.4 (epoch 2)
#   dnf:    sudo 1.9.17p2-3.el9_8 -> el9_8.1 -> el9_8.3 (Rocky Linux 9)
#           tar 2:1.34-1.amzn2023.0.2 -> 0.3 -> 0.4 (Amazon Linux 2023)
# plus packages built here into a local "stkdemo" repository.
set -eu
cd "$(dirname "$0")/../../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
arch=$(docker version --format '{{.Server.Arch}}')

GOOS=linux GOARCH=$arch CGO_ENABLED=0 go test -c -tags pkgmanagers -o "$work/agentfix.test" ./internal/agentfix

# stk-demo (epoch 1): 1.0-1, 1.0-2, 1.0-3 (obsoletes stk-victim), 1.0-4 (another
# vendor); stk-victim; stk-needy (requires stk-demo = 1:1.0-2).
cat > "$work/build.sh" <<'EOF'
set -eu
yum -y -q install rpm-build createrepo >/dev/null
mk() {
	cat > /tmp/p.spec <<SPEC
Name: $1
Version: $2
Release: $3
Summary: Stackurity remediation test package
License: Apache-2.0
BuildArch: noarch
Vendor: ${5:-Stackurity Test}
$4
%description
Test package for the agent's package manager tests.
%files
SPEC
	rpmbuild -bb --quiet --define '_topdir /tmp/rpm' --define '_binary_payload w9.gzdio' /tmp/p.spec
}
mk stk-demo 1.0 1 'Epoch: 1'
mk stk-demo 1.0 2 'Epoch: 1'
mk stk-demo 1.0 3 "$(printf 'Epoch: 1\nObsoletes: stk-victim')"
mk stk-demo 1.0 4 'Epoch: 1' 'Someone Else'
mk stk-victim 1.0 1 ''
mk stk-needy 1.0 1 'Requires: stk-demo = 1:1.0-2'
mkdir -p /stk/repo && cp /tmp/rpm/RPMS/noarch/*.rpm /stk/repo/ && createrepo -q /stk/repo
EOF
docker run --rm -v "$work:/stk" amazonlinux:2 sh /stk/build.sh

docker run --rm -v "$work:/stk:ro" -e STK_PM=zypper -e STK_PKG=less \
	-e STK_OLD=590-150400.3.3.1 -e STK_MID=590-150400.3.6.2 -e STK_NEW=590-150400.3.9.1 \
	opensuse/leap:15.5 sh -c '
	set -e
	zypper -q -n ar --no-gpgcheck file:///stk/repo stkdemo
	zypper -q -n refresh >/dev/null
	zypper -q -n install --oldpackage less=590-150400.3.3.1 stk-demo=1:1.0-1 stk-victim >/dev/null
	/stk/agentfix.test -test.v -test.run TestRealPackageManager'

docker run --rm -v "$work:/stk:ro" -e STK_PM=yum -e STK_PKG=tar \
	-e STK_OLD=2:1.26-35.amzn2.0.2 -e STK_MID=2:1.26-35.amzn2.0.3 -e STK_NEW=2:1.26-35.amzn2.0.4 \
	amazonlinux:2 sh -c '
	set -e
	printf "[stkdemo]\nname=stkdemo\nbaseurl=file:///stk/repo\ngpgcheck=0\n" > /etc/yum.repos.d/stkdemo.repo
	yum -y -q install tar-1.26-35.amzn2.0.2 stk-demo-1.0-1 stk-victim >/dev/null
	/stk/agentfix.test -test.v -test.run TestRealPackageManager'

# dnf refuses to install stk-victim while a repository package obsoletes it,
# so the starting packages are installed with rpm.
dnf_setup='
	set -e
	printf "[stkdemo]\nname=stkdemo\nbaseurl=file:///stk/repo\ngpgcheck=0\n" > /etc/yum.repos.d/stkdemo.repo
	dnf -y -q install "$STK_PKG-${STK_OLD#*:}" >/dev/null
	rpm -i /stk/repo/stk-demo-1.0-1.noarch.rpm /stk/repo/stk-victim-1.0-1.noarch.rpm
	/stk/agentfix.test -test.v -test.run TestRealPackageManager'

docker run --rm -v "$work:/stk:ro" -e STK_PM=dnf -e STK_PKG=sudo \
	-e STK_OLD=1.9.17p2-3.el9_8 -e STK_MID=1.9.17p2-3.el9_8.1 -e STK_NEW=1.9.17p2-3.el9_8.3 \
	rockylinux:9 sh -c "$dnf_setup"

docker run --rm -v "$work:/stk:ro" -e STK_PM=dnf -e STK_PKG=tar \
	-e STK_OLD=2:1.34-1.amzn2023.0.2 -e STK_MID=2:1.34-1.amzn2023.0.3 -e STK_NEW=2:1.34-1.amzn2023.0.4 \
	amazonlinux:2023 sh -c "$dnf_setup"
