#include "ent_config.h"
#include "ent_net.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

static void daemonize()
{
    if (!config.daemonize) {
        return;
    }
    if (daemon(0, 0) < 0) {
        perror("daemonize");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    get_options(argc, argv);

    int sock = listening();
    daemonize();
    start_workers(sock);

    return EXIT_SUCCESS;
}
