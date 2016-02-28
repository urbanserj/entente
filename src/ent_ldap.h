#pragma once

#include <ev.h>

enum ent_state { ENT_CLOSE, ENT_WAIT_READ };

enum ent_state ent_init(struct ev_loop *loop, ev_io *watcher);
enum ent_state ent_read(struct ev_loop *loop, ev_io *watcher);
void ent_free(struct ev_loop *loop, ev_io *watcher);
