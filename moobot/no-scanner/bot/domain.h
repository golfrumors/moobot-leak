#pragma once

struct resolv_entries {
    uint8_t addrs_len;
    uint32_t *addrs;
};

struct dnshdr {
    uint16_t id, opts, qdcount, ancount, nscount, arcount;
};

struct dns_question {
    uint16_t qtype, qclass;
};

struct dns_resource {
    uint16_t type, _class;
    uint32_t ttl;
    uint16_t data_len;
} __attribute__((packed));

void resolv_domain_to_hostname(char *, char *);
struct resolv_entries *resolv_lookup(char *);
void resolv_entries_free(struct resolv_entries *);
