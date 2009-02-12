# Copyright 1999-2009 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

DESCRIPTION="secure mesh networking VPN"
HOMEPAGE="http://exa.czweb.org/"
SRC_URI="http://exa.czweb.org/releases/${P}.tar.bz2"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~x86 ~amd64"
IUSE=""

RDEPEND="dev-libs/openssl"
DEPEND="dev-util/scons $RDEPEND"

src_compile () {
	scons $MAKEOPTS || die "compilation failed"
}

src_install () {
	dobin "cloudvpn"
	dobin "extras/cloudctl"
	doman "extras/cloudvpn.1"
}

