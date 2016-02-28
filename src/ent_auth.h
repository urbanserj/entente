#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool ent_auth(const uint8_t *username, const uint8_t *password, uint8_t *status,
              size_t size);
