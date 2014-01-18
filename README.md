Entente
=======

Simplest ldap server with authentication via PAM.


Dependencies
------------

* [asn1c](https://github.com/vlm/asn1c)
* [libev](http://software.schmorp.de/pkg/libev.html)
* [libpam](http://www.kernel.org/pub/linux/libs/pam/)


Build
-----

    make
    make install

Or (for building debian package):

    make debian


Usage
-----

    # entente [options]

Or:

    # /etc/init.d/entente start
    # # config file: /etc/default/entente

### Options

* -a
  Allow anonymous access.

* -b basedn
  Set the basedn for the ldap server (default: "dc=entente").

* -l
  Bind to the loopback interface only.

* -p port
  Set local port number (default: 389).

* -d
  Run as a daemon.


Example usage with lighttpd
---------------------------

lighttpd.conf:

    server.modules += ( "mod_rewrite" )

    auth.backend = "ldap"
    auth.backend.ldap.hostname = "localhost"
    auth.backend.ldap.filter   = "(user=$)"

    auth.require = (
        "/tratata" => (
            "method"  => "basic",
            "realm"   => "entente",
            "require" => "user=kiki|user=ooki"
        ),
    )
