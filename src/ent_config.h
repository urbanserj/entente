#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

struct config
{
    bool daemonize;
    struct in_addr addr;
    uint16_t port;
    uint8_t *service;
    uint8_t *basedn;
    uint16_t workers;
    bool anonymous;
    bool debug;
};

extern struct config config;

void get_options(int argc, char **argv);
