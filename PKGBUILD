# Maintainer: pcarrier

pkgname=gauth
pkgver=1.0
pkgrel=1
pkgdesc="Local laptop/desktop Google Authenticator written in go"
arch=('x86_64' 'i686')
url="https://github.com/tuxmartin/gauth"
license=('MIT')
depends=('go')
makedepends=('mercurial')
options=('!strip' '!emptydirs')
_gourl=github.com/pcarrier/gauth

build() {
  GOPATH="$srcdir" go get -fix -v -x ${_gourl}/...
}

check() {
  GOPATH="$GOPATH:$srcdir" go test -v -x ${_gourl}/...
}

package() {
  mkdir -p "$pkgdir/usr/bin"
  install -p -m755 "$srcdir/bin/"* "$pkgdir/usr/bin"

  mkdir -p "$pkgdir/$GOPATH"
  cp -Rv --preserve=timestamps "$srcdir/"{src,pkg} "$pkgdir/$GOPATH"

  # Package license (if available)
  for f in LICENSE COPYING LICENSE.* COPYING.*; do
      if [ -e "$srcdir/src/$_gourl/$f" ]; then
            install -Dm644 "$srcdir/src/$_gourl/$f" \
                    "$pkgdir/usr/share/licenses/$pkgname/$f"
      fi
      done
}

# vim:set ts=2 sw=2 et:
