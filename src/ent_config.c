#include "ent_config.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct config config = {.anonymous = false,
                        .service = (uint8_t *)"entente",
                        .basedn = (uint8_t *)"dc=entente",
                        .daemonize = false,
                        .port = 389,
                        .workers = 4}; /* global config */

void print_usage(FILE *stream, char *name)
{
    fprintf(stream,
            "Usage: %s [OPTIONS]\n\n"
            "Options:\n"
            "    -a --allow-anonymous\tAllow anonymous access\n"
            "    -b --basedn=\"dc=entente\"\tSet base distinguished name\n"
            "    -s --service=entente\tSet PAM service name\n"
            "    -i --bind=127.0.0.1\t\tSet bind address\n"
            "    -p --port=389\t\tSet server port\n"
            "    -w --workers=4\t\tSet number of workers\n"
            "    -d --daemonize\t\tRun as a daemon\n"
            "    -g --debug\t\t\tEnable debug mode\n"
            "    -h --help\t\t\tPrint this help\n",
            name);
}

void get_options(int argc, char **argv)
{
    config.addr.s_addr = htonl(INADDR_LOOPBACK);
    while (true) {
        int port = 0;
        int workers = 0;
        static struct option long_options[] = {
            {"allow-anonymous", no_argument, 0, 'a'},
            {"basedn", required_argument, 0, 'b'},
            {"daemonize", no_argument, 0, 'd'},
            {"bind", required_argument, 0, 'i'},
            {"port", required_argument, 0, 'p'},
            {"service", required_argument, 0, 's'},
            {"workers", required_argument, 0, 'w'},
            {"debug", no_argument, 0, 'g'},
            {"help", no_argument, 0, 'h'}};
        int c = getopt_long(argc, argv, "ab:di:p:hs:w:g", long_options, NULL);
        switch (c) {
        case 'a':
            config.anonymous = true;
            break;
        case 'b':
            config.basedn = (uint8_t *)optarg;
            break;
        case 'd':
            config.daemonize = true;
            break;
        case 'i':
            if (inet_aton(optarg, &config.addr) == 0) {
                fprintf(stderr, "Invalid address: %s\n\n", optarg);
                print_usage(stderr, argv[0]);
                exit(EXIT_FAILURE);
            }
            break;
        case 'p':
            if (!sscanf(optarg, "%i", &port) || port < 1 || port >= 0xFFFF) {
                fprintf(stderr, "Invalid port: %s\n\n", optarg);
                print_usage(stderr, argv[0]);
                exit(EXIT_FAILURE);
            }
            config.port = port;
            break;
        case 's':
            config.service = (uint8_t *)optarg;
            break;
        case 'w':
            if (!sscanf(optarg, "%i", &workers) || workers < 1) {
                fprintf(stderr, "Invalid workers: %s\n\n", optarg);
                print_usage(stderr, argv[0]);
                exit(EXIT_FAILURE);
            }
            config.workers = workers;
            break;
        case 'h':
            print_usage(stdout, argv[0]);
            exit(EXIT_SUCCESS);
            break;
        case 'g':
            config.debug = true;
            break;
        case -1:
            return;
        default:
            print_usage(stderr, argv[0]);
            exit(EXIT_FAILURE);
            break;
        }
    }
}
