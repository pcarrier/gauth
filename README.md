[![Build Status](https://travis-ci.org/pcarrier/gauth.png?branch=master)](https://travis-ci.org/pcarrier/gauth)

gauth: replace Google Authenticator
===================================

What is this:
-------------
A fork with some mods, I wanted of `github.com/pcarrier/gauth` credits goes to him for the implementation, I'm lazy indeed.

added the following: 
- AES-GCM-256/PEM encrypted file by default.
- create the file with 0600 permissions.
- delete (unlink()) the plaintext file.
- display only the one you need based on the argument given.


Installation
------------

With a Go environment already set up, it should be as easy as `go get github.com/eau-u4f/gauth`.

*Eg,* with `GOPATH=$HOME/go`, it will create a binary `$HOME/go/bin/gauth`.

Usage
-----

- In web interfaces, pretend you can't read QR codes, get a secret like `hret 3ij7 kaj4 2jzg` instead.
- Store one secret per line in `~/.config/gauth.csv`, in the format `name:secret`. For example:

        AWS:   ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
        Airbnb:abcd efgh ijkl mnop
        Google:a2b3c4d5e6f7g8h9
        Github:234567qrstuvwxyz

- Encrypt it (it will prompt for your password):
	$ gauth -e

- It creates `~/.config/gauth.pem` (default perm 0600) and removes `~/.config/gauth.csv`.

- Run `gauth`, type your password. The progress bar indicates how far the next change is:

        $ gauth
        password: 
        account    | prev   curr   next  
        -------------------------------
        github     | 312783 436124 570822
        gmail      | 349274 437823 523780
        facebook   | 345426 830969 031337
        aws        | 738308 175551 926454
        -------------------------------
        [========================     ]


- `gauth` is NOT convenient to use in `watch` anymore.
- Remember to keep your system clock synchronized and to **lock your computer when brewing your tea!** (eau: that's right)

Encryption
----------

it's now by default and uses AES-GCM-256/PEM with additionnal datas (to protect PEM headers) instead of Salted CBC-128,
it is part of gauth.

`gauth -e` take the current ~/.config/gauth.csv and encrypts it to ~/.config/gauth.pem and remove the plaintext version.
`gauth -d` if you need to peek/poke in your token file, then `gauth -e` again.

gauth TOTP keyfile encryption uses:
- AEAD Authenticated Encryption Additionnal Data modes (protect the plaintext PEM headers)
- AES-GCM-256 authenticated encryption mode.
- 16K rounds PBKDF2 key derivation function.
- Crypto PRNG.

Compatibility
-------------

Tested and relied upon for:

- Evernote
- Facebook
- Github
- Google
- Microsoft

Please report further results to eau-code@unix4fun.net

Rooted Android?
---------------

If your Android phone is rooted, it's easy to "back up" your secrets from an `adb shell` into `gauth`.

    # sqlite3 /data/data/com.google.android.apps.authenticator2/databases/database \
              'select email,secret from accounts'

(eau-u4f: thanks for the tips!)

Really, does this make sense?
-----------------------------

At least to me, it does. My laptop features encrypted storage, a stronger authentication mechanism,
and I take good care of its physical integrity.

My phone also runs arbitrary apps, is constantly connected to the Internet, gets forgotten on tables.

Thanks to the convenience of a command line utility, my usage of 2-factor authentication went from
3 to 10 services over a few days.

Clearly a win for security.

(eau-u4f: agreed with pcarrier just made a couple of changes to match my needs and improve the encryption security (hopefully) :))
