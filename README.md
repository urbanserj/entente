Entente
=======

Entente is a LDAP server for authentication via PAM.

Usage
-----

```
# entente [options]
```

### Options

* -a --allow-anonymous

  Allow anonymous access.

* -b --basedn="dc=entente"

  Set base distinguished name.

* -s --service=entente

  Set PAM service name.

* -p port=389

  Set server port number.

* -i --bind=127.0.0.1

  Set bind address.

* -d --daemonize

  Run as a daemon.

* -w --workers=4

  Set number of workers (default: 4).

* -g --debug

  Enable debug mode.

* -h --help

  Print help information.

Dependencies
------------

* [libev](http://software.schmorp.de/pkg/libev.html)
* [libpam](http://www.kernel.org/pub/linux/libs/pam/)
