/*
 * http://www.evc.net/dew/pages/sniffer/
 */

#ifndef __PARSEPACKET_FUNCTIONS_H__
#define __PARSEPACKET_FUNCTIONS_H__

#include "lwip/inet.h"

#define IPTOSBUFFERS    12
#define ETHER_ADDR_LEN  6
#define IP_ADDR_LEN     4

#define CAP_SNAPLEN     2000
#define CAP_TIMEOUT     1000
#define CAP_CNT         0

#define ETHERTYPE_IP    2048
#define ETHERTYPE_ARP   2054
#define ETHERTYPE_RARP  32821

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN   0
#endif

#ifndef BIG_ENDIAN
#define BIG_ENDIAN      1
#endif


/* Ethernet header */
struct sniff_ethernet {
    uint8_t ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    uint8_t ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    uint16_t ether_type;                 /* Ether type */
};

/* IP header */
struct sniff_ip {
    #if BYTE_ORDER == LITTLE_ENDIAN
    uint32_t ip_hl:4,                      /* header length */
    ip_v:4;                             /* version */
    #if BYTE_ORDER == BIG_ENDIAN
    uint32_t ip_v:4,                       /* version */
    ip_hl:4;                            /* header length */
    #endif
    #endif                              /* not _IP_VHL */

    uint8_t ip_tos;                      /* type of service */
    uint16_t ip_len;                     /* total length */
    uint16_t ip_id;                      /* identification */
    uint16_t ip_off;                     /* fragment offset field */
    #define IP_RF 0x8000                /* reserved fragment flag */
    #define IP_DF 0x4000                /* dont fragment flag */
    #define IP_MF 0x2000                /* more fragments flag */
    #define IP_OFFMASK 0x1fff           /* mask for fragmenting bits */
    uint8_t ip_ttl;                      /* time to live */
    uint8_t ip_p;                        /* protocol */
    uint16_t ip_sum;                     /* checksum */
    struct in_addr ip_src,ip_dst;       /* source and dest address */
};

/* TCP header */
struct sniff_tcp {
	uint16_t th_sport;                   /* source port */
	uint16_t th_dport;                   /* destination port */
	uint32_t th_seq;                       /* sequence number */
	uint32_t th_ack;                       /* acknowledgement number */
    #if BYTE_ORDER == LITTLE_ENDIAN
	uint32_t th_x2:4,                      /* (unused) */
    th_off:4;                           /* data offset */
    #endif
    #if BYTE_ORDER == BIG_ENDIAN
	uint32_t th_off:4,                     /* data offset */
    th_x2:4;                            /* (unused) */
    #endif
	uint8_t th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    uint16_t th_win;                     /* window */
    uint16_t th_sum;                     /* checksum */
    uint16_t th_urp;                     /* urgent pointer */
};

/* UDP header */
struct sniff_udp {
	uint16_t uh_sport;                   /* source port */
	uint16_t uh_dport;                   /* destination port */
	uint16_t uh_len;                     /* length */
	uint16_t uh_checksum;                /* checksum */
};

/* ICMP */
struct sniff_icmp {
	uint8_t icmp_type;                   /* type */
	uint8_t icmp_code;                   /* code */
    uint16_t icmp_checksum;              /* checksum */
    uint16_t icmp_id;                    /* identifier */
    uint16_t icmp_seq;                   /* sequence number */
};

/* ARP */
struct sniff_arp {
	uint16_t arp_ht;                     /* hardware type */
	uint16_t arp_pt;                     /* protocol type */
	uint8_t arp_hlen;                    /* hardware address length */
	uint8_t arp_plen;                    /* protocol address length */
    uint16_t arp_op;                     /* operation */
    uint8_t arp_sha[ETHER_ADDR_LEN];     /* sender hardware address */
    uint8_t arp_spa[IP_ADDR_LEN];        /* sender protocol address */
    //struct in_addr arp_spa;           /* bugged */
    uint8_t arp_tha[ETHER_ADDR_LEN];     /* target hardware address */
    uint8_t arp_tpa[IP_ADDR_LEN];        /* target protocol address */
    //struct in_addr arp_tpa;           /* bugged */
};

/* BOOTP */
struct sniff_bootp {
	uint8_t bootp_op;                    /* opcode */
	uint8_t bootp_ht;                    /* hardware address type */
	uint8_t bootp_hl;                    /* hardware address length  */
	uint8_t bootp_hops;                  /* hops */
    uint32_t bootp_xid;                    /* transaction id */
    uint16_t bootp_secs;                 /* seconds passed since client began the request process  */
    uint16_t bootp_flags;                /* flags */
    struct in_addr bootp_ciaddr;        /* client IP address */
    struct in_addr bootp_yiaddr;        /* 'your' (client) IP address - server's response to client */
    struct in_addr bootp_siaddr;        /* server ip address */
    struct in_addr bootp_giaddr;        /* relay agent IP address */
    uint8_t bootp_chaddr[16];            /* client hardware address */
    char bootp_sname[64];               /* optional server host name - null terminated string */
    char bootp_file[128];               /* boot file name */
};

#endif
