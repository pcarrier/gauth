Google Authenticator
====================

Installation
------------

With a Go environment already set up, it should be as easy as `go get github.com/pcarrier/gauth`.

*Eg,* with `GOPATH=$HOME/go`, it will create a binary `$HOME/go/bin/gauth`.

Usage
-----

- In web interfaces, pretend you can't read QR codes, get a secret like `hret 3ij7 kaj4 2jzg` instead.
- Store one secrets per line in `~/.config/gauth.csv`, in the format `name:secret`, for example:

        AWS:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
        Airbnb:abcdefghijklmnop
        Google:a2b3c4d5e6f7g8h9
        Github:234567qrstuvwxyz

- Restrict access to your user:

        $ chmod 600 ~/.config/gauth.json

- Run `gauth`. The progress bar shows when the next change will happen.

        ~$ gauth
                   prev   curr   next
        AWS        315306 135387 483601
        Airbnb     563728 339206 904549
        Google     453564 477615 356846
        Github     911264 548790 784099
        [=======                      ]

- Remember to keep your system clock synchronized and to **lock your computer when brewing your tea**!

Rooted Android?
---------------

If your Android phone is rooted, it's easy to "back up" your secrets from an `adb shell` into `gauth`.

    # sqlite3 /data/data/com.google.android.apps.authenticator2/databases/database 'select email,secret from accounts'

Really, does this make sense?
-----------------------------

At least to me, it does. My laptop features encrypted storage, a stronger authentication mechanism,
and I take better care of preserving its physical integrity. My phone also runs arbitrary apps.

Thanks to the convenience of a command line utility, my usage of 2-factor authentication went from
3 services to 9 over a few days. Clearly a win for security.
