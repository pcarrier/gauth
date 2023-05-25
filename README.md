[![Go presubmit](https://github.com/pcarrier/gauth/actions/workflows/go-presubmit.yml/badge.svg)](https://github.com/pcarrier/gauth/actions)

gauth: replace Google Authenticator
===================================

Installation
------------

With a Go environment already set up, it should be as easy as `go install github.com/pcarrier/gauth@latest`.

*Eg,* with `GOPATH=$HOME/go` (its default), it will create a binary `$HOME/go/bin/gauth`.

Usage
-----

- In web interfaces, pretend you can't read QR codes, get a secret like `hret 3ij7 kaj4 2jzg` instead.
- Store one secret per line in `~/.config/gauth.csv`, in the format `name:secret`. For example:

        AWS:   ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
        Airbnb:abcd efgh ijkl mnop
        Google:a2b3c4d5e6f7ghij
        Github:234567qrstuvwxyz
        otpauth://totp/testOrg:testuser?secret=AAAQEAYEAUDAOCAJ======&issuer=testOrg&algorithm=SHA512&digits=8&period=30

- Restrict access to your user:

        $ chmod 600 ~/.config/gauth.csv

- Run `gauth`. The progress bar indicates how far the next change is.

        $ gauth
                   prev   curr   next
        AWS        315306 135387 483601
        Airbnb     563728 339206 904549
        Google     453564 477615 356846
        Github     911264 548790 784099
        [=======                      ]

- Run `gauth KEYNAME` to print a specific key with progress bar.

- Run `gauth KEYNAME -b` to print a bare current key.

        $ gauth Google -b
        477615

- `gauth` is convenient to use in `watch`.

        $ watch -n1 gauth

- Remember to keep your system clock synchronized and to **lock your computer when brewing your tea!**

- If you find yourself needing to interpret a QR code (e.g. exporting a code
  from an existing Google Authenticator setup, on a phone to which you do not
  have root access), then [gauthQR](https://github.com/jbert/gauthQR) may be useful.

Encryption
----------

`gauth` supports password-based encryption of `gauth.csv`. To encrypt, use:

        $ openssl enc -aes-128-cbc -md sha256 -in ~/gauth.csv -out ~/.config/gauth.csv
        enter aes-128-cbc encryption password:
        Verifying - enter aes-128-cbc encryption password:

`gauth` will then prompt you for that password on every run:

        $ gauth
        Encryption password:
                   prev   curr   next
        LastPass   915200 479333 408710

Note that this encryption mechanism is far from ideal from a pure security standpoint.
Please read [OpenSSL's notes on the subject](http://www.openssl.org/docs/crypto/EVP_BytesToKey.html#NOTES).

Compatibility
-------------

Tested with:

- Airbnb
- Apple
- AWS
- DreamHost
- Dropbox
- Evernote
- Facebook
- Gandi
- Github
- Google
- LastPass
- Linode
- Microsoft
- Okta (reported by Bryan Baldwin)
- WP.com
- bittrex.com
- poloniex.com

Please report further results to pc@rrier.ca.

Rooted Android?
---------------

If your Android phone is rooted, it's easy to "back up" your secrets from an `adb shell` into `gauth`.

    # sqlite3 /data/data/com.google.android.apps.authenticator2/databases/database \
              'select email,secret from accounts'

If your phone isn't rooted, you may have luck with the gauthQR tool mentioned
in the Usage section above.

Really, does this make sense?
-----------------------------

At least to me, it does. My laptop features encrypted storage, a stronger authentication mechanism,
and I take good care of its physical integrity.

My phone also runs arbitrary apps, is constantly connected to the Internet, gets forgotten on tables.

Thanks to the convenience of a command line utility, my usage of 2-factor authentication went from
3 to 10 services over a few days.

Clearly a win for security.
