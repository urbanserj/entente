#include "ent_net.h"
#include "ent_config.h"
#include "ent_ldap.h"
#include <ev.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>

int listening()
{
#define LISTENQ 128
    struct sockaddr_in sockaddr = {.sin_family = AF_INET,
                                   .sin_addr = config.addr,
                                   .sin_port = htons(config.port)};

    int sock = socket(PF_INET, SOCK_STREAM, 0);
    int opt_value = 1;

    if (sock < 0 ||
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt_value,
                   sizeof(opt_value)) < 0 ||
        bind(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0 ||
        listen(sock, LISTENQ) < 0) {
        perror("Listening socket");
        exit(EXIT_FAILURE);
    }
    return sock;
}

static void io_read(struct ev_loop *loop, ev_io *watcher, int revents)
{
    if (EV_ERROR & revents) {
        perror("Invalid event");
        return;
    }

    switch (ent_read(loop, watcher)) {
    case ENT_CLOSE:
        ev_io_stop(loop, watcher);
        ent_free(loop, watcher);
        close(watcher->fd);
        free(watcher);
        break;
    case ENT_WAIT_READ:
        break;
    }
}

static void io_accept(struct ev_loop *loop, ev_io *watcher, int revents)
{
    if (EV_ERROR & revents) {
        perror("Invalid event");
        return;
    }

    int socket = accept(watcher->fd, NULL, NULL);
    if (socket < 0) {
        perror("Accept");
        return;
    }

    ev_io *client = calloc(1, sizeof(ev_io));
    if (!client) {
        perror("Calloc");
        exit(EXIT_FAILURE);
    }

    switch (ent_init(loop, client)) {
    case ENT_CLOSE:
        ent_free(loop, client);
        close(socket);
        free(client);
        break;
    case ENT_WAIT_READ:
        ev_io_init(client, io_read, socket, EV_READ);
        ev_io_start(loop, client);
        break;
    }
}

static void start_loop(int socket)
{
    struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO);
    ev_io accept;

    ev_io_init(&accept, io_accept, socket, EV_READ);
    ev_io_start(loop, &accept);

    ev_run(loop, 0);
}

void start_workers(int socket)
{
    if (config.workers == 1) {
        start_loop(socket);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < config.workers; i++) {
        switch (fork()) {
        case 0:
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            start_loop(socket);
            exit(EXIT_FAILURE);
        case -1:
            perror("Fork");
            exit(EXIT_FAILURE);
        }
    }
    if (wait(NULL) == -1) {
        perror("Wait");
    }
    exit(EXIT_FAILURE);
}
