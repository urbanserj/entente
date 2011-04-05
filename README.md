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

* -a (or `ENTENTE_ANONYMOUS=true`) allow anonymous access

* -b (or `ENTENTE_BASEDN="dc=entente"`) setup basedn for ldap server

* -l (or `ENTENTE_LOOPBACK=true`) bind entente to loopback interface else bind to all interfaces

* -p (or `ENTENTE_PORT=389`) setup local port number

* -d for daemonizing process


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
