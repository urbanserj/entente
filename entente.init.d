#!/bin/sh
### BEGIN INIT INFO
# Provides:          entente
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Simplest ldap server with authentication via pam
### END INIT INFO

# Author: Sergey Urbanovich <sergey.urbanovich@gmail.com>

PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC="ldap server"
NAME=entente
DAEMON=/usr/sbin/$NAME
DAEMON_OPTS="-d -l"
SCRIPTNAME=/etc/init.d/$NAME
ENABLED=1

# Exit if the package is not installed.
[ -x "$DAEMON" ] || exit 0

# Read configuration variable file if it is present.
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Exit if the package is not enabled.
[ "$ENABLED" != "0" ] || exit 0

. /lib/lsb/init-functions

case "$1" in
    start)
        log_daemon_msg "Starting $DESC" $NAME
        if ! start-stop-daemon --start --oknodo --quiet \
            --exec $DAEMON -- $DAEMON_OPTS
        then
            log_end_msg 1
        else
            log_end_msg 0
        fi
        ;;
    stop)
        log_daemon_msg "Stopping $DESC" $NAME
        if start-stop-daemon --stop --retry 2 --oknodo --quiet \
            --exec $DAEMON
        then
            log_end_msg 0
        else
            log_end_msg 1
        fi
        ;;
    restart|force-reload)
        $0 stop
        $0 start
        ;;
    status)
       status_of_proc "$DAEMON" "$NAME" && exit 0 || exit $?
       ;;
    *)
		echo "Usage: $SCRIPTNAME {start|stop|status|restart|force-reload}" >&2
		exit 3
	;;
esac
