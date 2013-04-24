Google Authenticator
====================

Usage
-----

- In web interfaces, pretend you can't read QR codes, get a secret like `hret 3ij7 kaj4 2jzg` instead.
- Get your token on https://gauth.herokuapp.com/hret3ij7kaj42jzg (I'll let you guess how to adapt it for your needs; if you leave the spaces, that's OK too).
- Enjoy sending me your secret everytime you run out of battery.

Rooted Android?
---------------

Back up your secrets!

    # sqlite3 /data/data/com.google.android.apps.authenticator2/databases/database 'select email,secret from accounts'
