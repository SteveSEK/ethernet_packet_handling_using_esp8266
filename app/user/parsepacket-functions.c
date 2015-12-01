/*
 * http://www.evc.net/dew/pages/sniffer/
 */

#include "ets_sys.h"
#include "user_interface.h"
#include "driver/uart.h"

#include "netif/etharp.h"

#include "menu-functions.h"
#include "misc-functions.h"
#include "parsepacket-functions.h"

char *analyze_ether_type(uint16_t type)
{
	switch(type) {
	case ETHERTYPE_IP:
		return "(IPv4)   ";
		break;
	case ETHERTYPE_ARP:
		return "(ARP)    ";
		break;
	case ETHERTYPE_RARP:
		return "(RARP)   ";
		break;
	default:
		return "(Unknown)";
	}
}

char *analyze_ip_proto(uint8_t type)
{
	switch(type) {
	case 1:
		return " ICMP";
		break;
	case 2:
		return " IGMP";
		break;
	case 6:
		return "  TCP";
		break;
	case 17:
		return "  UDP";
		break;
	case 37:
		return "  RDP";
		break;
	case 41:
		return " IPv6";
		break;
	default:
		return "    ?";
	}
}

char *analyze_icmp_type(uint8_t type,uint8_t code)
{
	switch(type) {
	case 0:
		return "Echo Reply             ";
		break;
	case 3:
		switch(code) {
		case 0:
			return "Net unreachable        ";
			break;                               
		case 1:
			return "Host unreachable       ";
			break;
		case 2:
			return "Protocol unreachable   ";
			break;                               
		case 3:
			return "Port unreachable       ";
			break;                               
		case 4:
			return "Fragmentation needed   ";
			break;                               
		case 5:
			return "Source route failed    ";
			break;                               
		default:
			return "Destination unreachable";
		}
		break;
	case 4:
		return "Source quench          ";
		break;
	case 5:
		return "Redirect               ";
		break;
	case 8:
		return "Echo                   ";
		break;
	case 11:
		return "Time exceeded          ";
		break;
	case 12:
		return "Parameter problem      ";
		break;
	case 13:
		return "Timestamp              ";
		break;
	case 14:
		return "Timestamp reply        ";
		break;
	case 15:
		return "Information request    ";
		break;
	case 16:
		return "Information reply      ";
		break;
	default:
		return "?                      ";
	}
}

char *analyze_arp_op(uint16_t op)
{
	switch(op) {
	case 1:
		return "(ARP Request)     ";
		break;
	case 2:
		return "(ARP Response)    ";
		break;
	case 3:
		return "(RARP Request)    ";
		break;
	case 4:
		return "(RARP Response)   ";
		break;
	case 5:
		return "(Dyn RARP request)";
		break;
	case 6:
		return "(Dyn RARP reply)  ";
		break;
	case 7:
		return "(Dyn RARP error)  ";
		break;
	case 8:
		return "(InARP request)   ";
		break;
	case 9:
		return "(InARP reply)     ";
		break;
	default:
		return "(?)               ";
	}
}

char *analyze_bootp_op(uint8_t op)
{
	switch(op)
	{
	case 1:
		return "(Request)";
		break;
	case 2:
		return "(Reply)  ";
		break;
	default:
		return "(Unknown)";
	}
}

char *analyze_arp_ht(uint16_t ht)
{
	switch(ht) {
	/*
	case 1:
		return "(10Mb Ethernet)";
		break;
	*/
	default:
		return "               ";
	}
}

char *analyze_dhcp_mt(uint8_t mt)
{
	switch(mt) {
	case 1:
		return "(DHCP Discover)";
		break;
	case 2:
		return "(DHCP Offer)   ";
		break;
	case 3:
		return "(DHCP Request) ";
		break;
	case 4:
		return "(DHCP Decline) ";
		break;
	case 5:
		return "(DHCP Ack)     ";
		break;
	case 6:
		return "(DHCP Nack)    ";
		break;
	case 7:
		return "(DHCP Release) ";
		break;
	case 8:
		return "(DHCP Inform)  ";
		break;
	default:
		return "               ";
	}
}

char *iptos(uint32_t in)
{
	static char output[IPTOSBUFFERS][16];
	static short which;
	uint8_t *p;

	p = (uint8_t *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	os_sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

char *ipctos(uint8_t *ip)
{
	static char output[15];
	os_sprintf(output,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
	return output;
}

void xecho(char *s)
{
	//printf(s);
}

void print_payload(const uint8_t *payload,int len)
{
	uint32_t s=0,i,j;
	char alpha[20];
	char buffer[4];
	if(len<1) return;
	ets_uart_printf("+..............................................................+\r\n");
	ets_uart_printf("+ PAYLOAD                                                      +\r\n");
	ets_uart_printf("+..............................................................+\r\n");

	j=0;
	memset(alpha,0,20);
	for(i=0;i<len;i++)
	{
		os_sprintf(buffer,"%02x ", payload[i]);
		ets_uart_printf(buffer);
		if(payload[i]>=32 && payload[i]<127)
		{
			alpha[j]=payload[i];
		}
		else
		{
			alpha[j]='.';
		}
		j++;
		if(j>15)
		{
			j=0;
			ets_uart_printf(alpha);
			memset(alpha,0,20);
			ets_uart_printf("\r\n");
		}
	}
	if(j!=0)
	{
		for(i=16;i>j;i--)
		{
			ets_uart_printf("   ");
		}
		ets_uart_printf(alpha);
		ets_uart_printf("\r\n");
	}
}

void analyze_sniff_ether(const struct sniff_ethernet *ethernet, uint32_t packet_length)
{
	char buffer[80];

	os_sprintf(buffer,"| ETHERNET                                         %5d bytes |\r\n", packet_length);
	ets_uart_printf(buffer);
	ets_uart_printf("+..............................................................+\r\n");
	os_sprintf(buffer,"| MAC Source : %02x-%02x-%02x-%02x-%02x-%02x  ->  Dest : %02x-%02x-%02x-%02x-%02x-%02x |\r\n",ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5],ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Ether Type : 0x%04x %s                                |\r\n", ntohs(ethernet->ether_type),analyze_ether_type(ntohs(ethernet->ether_type)));
	ets_uart_printf(buffer);
}

void analyze_sniff_ip(const struct sniff_ip *ip)
{
	char buffer[80];
	ets_uart_printf("+..............................................................+\r\n");
	ets_uart_printf("| IP                                                           |\r\n");
	ets_uart_printf("+..............................................................+\r\n");

	os_sprintf(buffer,"| Version           : %5d     Header Length : %5d          |\r\n",ip->ip_v,ip->ip_hl);
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Type of Service   : %5x     Total Length  : %5d          |\r\n",ip->ip_tos,ntohs(ip->ip_len));
	ets_uart_printf(buffer);
	if(ntohs(ip->ip_tos)>0) {
		// Type of Service
	}
	os_sprintf(buffer,"| Identification    : %5d     Flags         : %5x          |\r\n",ntohs(ip->ip_id),ntohs(ip->ip_off));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Protocol    %5x : %s     TTL           : %5d          |\r\n",ip->ip_p,analyze_ip_proto(ip->ip_p),ip->ip_ttl);
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| From :    %15s     To :  %15s          |\r\n",iptos(ip->ip_src.s_addr),iptos(ip->ip_dst.s_addr));
	ets_uart_printf(buffer);
}

void analyze_sniff_tcp(const struct sniff_tcp *tcp)
{
	char buffer[80];
	ets_uart_printf("+..............................................................+\r\n");
	ets_uart_printf("| TCP                                                          |\r\n");
	ets_uart_printf("+..............................................................+\r\n");
	os_sprintf(buffer,"| Source Port     : %5d       Destination Port : %5d       |\r\n",htons(tcp->th_sport),htons(tcp->th_dport));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Sequence number : %5d       Acknowledgement  : %5d       |\r\n",htons(tcp->th_seq),htons(tcp->th_ack));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Control bits    : %1d....... FIN (No more data from sender)    |\r\n",(tcp->th_flags & TH_FIN?1:0));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"|                   .%1d...... SYN (Synchronize sequence number) |\r\n",(tcp->th_flags & TH_SYN?1:0));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"|                   ..%1d..... RST (Reset the connection)        |\r\n",(tcp->th_flags & TH_RST?1:0));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"|                   ...%1d.... PSH (Push function)               |\r\n",(tcp->th_flags & TH_PUSH?1:0));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"|                   ....%1d... ACK (Acknowledgment field sign.)  |\r\n",(tcp->th_flags & TH_ACK?1:0));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"|                   .....%1d.. URG (Urgent pointer field sign.)  |\r\n",(tcp->th_flags & TH_URG?1:0));
	ets_uart_printf(buffer);
}

void analyze_sniff_icmp(const struct sniff_icmp *icmp)
{
	char buffer[80];
	ets_uart_printf("+..............................................................+\r\n");
	ets_uart_printf("| ICMP                                                         |\r\n");
	ets_uart_printf("+..............................................................+\r\n");
	os_sprintf(buffer,"| Type    %2d : %s                         |\r\n",icmp->icmp_type,analyze_icmp_type(icmp->icmp_type,icmp->icmp_code));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"+ Identifier : %5d              Seq number : %5d           |\r\n",icmp->icmp_id,icmp->icmp_seq);
	ets_uart_printf(buffer);
}

void analyze_sniff_udp(const struct sniff_udp *udp)
{
	char buffer[80];
	ets_uart_printf("+..............................................................+\r\n");
	ets_uart_printf("| UDP                                                          |\r\n");
	ets_uart_printf("+..............................................................+\r\n");
	os_sprintf(buffer,"| Source Port : %5d     Dest Port : %5d     Length : %5d |\r\n",htons(udp->uh_sport),htons(udp->uh_dport),htons(udp->uh_len));
	ets_uart_printf(buffer);
}

void analyze_sniff_arp(const struct sniff_arp *arp)
{
	char buffer[80];
	ets_uart_printf("+..............................................................+\r\n");
	ets_uart_printf("| ARP                                                          |\r\n");
	ets_uart_printf("+..............................................................+\r\n");
	os_sprintf(buffer,"| Hardware Type            : %5d %s             |\r\n",htons(arp->arp_ht),analyze_arp_ht(htons(arp->arp_ht)));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Protocol Type            : %5d %s                   |\r\n",htons(arp->arp_pt),analyze_ether_type(htons(arp->arp_pt)));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Hardware address length  :   %3d                             |\r\n",arp->arp_hlen);
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Protocol address length  :   %3d                             |\r\n",arp->arp_plen);
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Operation                : %5d %s          |\r\n",htons(arp->arp_op),analyze_arp_op(htons(arp->arp_op)));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Sender Hardware Address  : %02x-%02x-%02x-%02x-%02x-%02x                 |\r\n",arp->arp_sha[0],arp->arp_sha[1],arp->arp_sha[2],arp->arp_sha[3],arp->arp_sha[4],arp->arp_sha[5]);
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Sender Protocol Address  :   %15s                 |\r\n",ipctos((uint8_t *)arp->arp_spa));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Target Hardware Address  : %02x-%02x-%02x-%02x-%02x-%02x                 |\r\n",arp->arp_tha[0],arp->arp_tha[1],arp->arp_tha[2],arp->arp_tha[3],arp->arp_tha[4],arp->arp_tha[5]);
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Target Protocol Address  :   %15s                 |\r\n",ipctos((uint8_t *)arp->arp_tpa));
	ets_uart_printf(buffer);
}

void analyze_sniff_bootp(const struct sniff_bootp *bootp)
{
	char buffer[80];
	ets_uart_printf("+..............................................................+\r\n");
	ets_uart_printf("| BOOTP                                                        |\r\n");
	ets_uart_printf("+..............................................................+\r\n");
	os_sprintf(buffer,"| Op : %d %s           Transaction : %10d          |\r\n",bootp->bootp_op,analyze_bootp_op(bootp->bootp_op),htons(bootp->bootp_xid));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Hardware Address Type : %3d    Hardware Address Length : %3d |\r\n",bootp->bootp_ht,bootp->bootp_hl);
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Hops : %3d             Secs : %5d            Flags : %5d |\r\n",bootp->bootp_hops,htons(bootp->bootp_secs),htons(bootp->bootp_flags));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Client IP Address          : %15s                 |\r\n",iptos(bootp->bootp_ciaddr.s_addr));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| 'your' (client) IP address : %15s                 |\r\n",iptos(bootp->bootp_yiaddr.s_addr));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Server IP address          : %15s                 |\r\n",iptos(bootp->bootp_siaddr.s_addr));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Relay agent IP address     : %15s                 |\r\n",iptos(bootp->bootp_giaddr.s_addr));
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Client Hardware Address    : %02x-%02x-%02x-%02x-%02x-%02x               |\r\n",bootp->bootp_chaddr[0],bootp->bootp_chaddr[1],bootp->bootp_chaddr[2],bootp->bootp_chaddr[3],bootp->bootp_chaddr[4],bootp->bootp_chaddr[5]);
	ets_uart_printf(buffer);
	os_sprintf(buffer,"| Server : %51s |\r\n",bootp->bootp_sname);
	ets_uart_printf(buffer);
}

void analyze_dhcp_options(const uint8_t *op, int size)
{
	const uint8_t *p=op;
	char buffer[80];
	uint8_t value[64];
	uint8_t *v;
	uint8_t code,len;
	unsigned int i;

	ets_uart_printf("+..............................................................+\r\n");
	ets_uart_printf("| DHCP                                                         |\r\n");
	ets_uart_printf("+..............................................................+\r\n");

	while(p<op+size)
	{
		memset(value,0,64);
		code=p[0];
		if(code!=255 && code!=0)
		{
			len=p[1];
			memcpy(value,p+2,len);
		}

		if(code==53)
		{
			os_sprintf(buffer,"| DHCP Message Type  : %d %s                       |\r\n",value[0],analyze_dhcp_mt(value[0]));
			ets_uart_printf(buffer);
		}
		else if(code==1)
		{
			os_sprintf(buffer,"| Subnet mask        : %15s                         |\r\n",ipctos(value));
			ets_uart_printf(buffer);
		} 
		else if(code==3)
		{
			for(i=0;i<len;i+=4)
			{
				v=value+i;
				os_sprintf(buffer,"| Router             : %15s                         |\r\n",ipctos(v));
				ets_uart_printf(buffer);
			}
		}
		else if(code==6)
		{
			for(i=0;i<len;i+=4)
			{
				v=value+i;
				os_sprintf(buffer,"| Domain Name Server : %15s                         |\r\n",ipctos(v));
				ets_uart_printf(buffer);
			}
		}
		else if(code==51)
		{
			memcpy(&i,value,4);
			os_sprintf(buffer,"| Lease time         :  %10d sec                         |\r\n",i);
			ets_uart_printf(buffer);
		}
		else if(code==54)
		{
			os_sprintf(buffer,"| Server Identifier  : %15s                         |\r\n",ipctos(value));
			ets_uart_printf(buffer);
		}
		else if(code==255)
		{
			ets_uart_printf("| End                                                          |\r\n");
			break;
		}
		else
		{
			os_sprintf(buffer,"| Unknown Code       : %3d (len : %3d)                         |\r\n",code,len);
			ets_uart_printf(buffer);
		}
		p=p+len+2;
		if(len==0) break;
	}
}

void packet_handler(uint32_t packet_length, const uint8_t *packet)
{
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const struct sniff_udp *udp;
	const struct sniff_icmp *icmp;
	const struct sniff_arp *arp;
	const struct sniff_bootp *bootp;
	const uint8_t *payload;

	int size_ethernet = sizeof(struct sniff_ethernet);
	int size_ip = sizeof(struct sniff_ip);
	int size_tcp = sizeof(struct sniff_tcp);
	int size_arp = sizeof(struct sniff_arp);
	int size_udp = sizeof(struct sniff_udp);
	int size_icmp = sizeof(struct sniff_icmp);
	int size_bootp = sizeof(struct sniff_bootp);
	int size_tmp;

	ets_uart_printf("+--------------------------------------------------------------+\r\n");
	ethernet = (struct sniff_ethernet*) (packet);
	analyze_sniff_ether(ethernet, packet_length);
	// IP
	if(ntohs(ethernet->ether_type)==ETHERTYPE_IP)
	{
		ip = (struct sniff_ip*)(packet + size_ethernet);

		analyze_sniff_ip(ip);
		// ICMP
		if(ip->ip_p==1)
		{
			icmp = (struct sniff_icmp*)(packet + size_ethernet + size_ip);
			analyze_sniff_icmp(icmp);
			payload = (uint8_t *)(packet + size_ethernet + size_ip + size_icmp);
			print_payload(payload, packet_length-(size_ethernet + size_ip + size_icmp));			
		}
		// TCP
		else if(ip->ip_p==6)
		{
			tcp = (struct sniff_tcp*)(packet + size_ethernet + size_ip);
			analyze_sniff_tcp(tcp);
			payload = (uint8_t *)(packet + size_ethernet + size_ip + size_tcp + (tcp->th_off-5)*4); // ! offset
			print_payload(payload, packet_length-(size_ethernet + size_ip + size_tcp));			
		}
		// UDP
		else if(ip->ip_p==17)
		{
			udp = (struct sniff_udp*)(packet + size_ethernet + size_ip);
			analyze_sniff_udp(udp);
			// BOOTP/DHCP
			if(htons(udp->uh_dport)==67 && htons(udp->uh_sport)==68 || htons(udp->uh_dport)==68 && htons(udp->uh_sport)==67)
			{
				bootp = (struct sniff_bootp*)(packet + size_ethernet + size_ip + size_udp);
				analyze_sniff_bootp(bootp);
				size_tmp = packet_length-(size_ethernet + size_ip + size_udp + size_bootp);
				if(size_tmp>0)
				{
					payload = (uint8_t *)(packet + size_ethernet + size_ip + size_udp + size_bootp);
					// DHCP Magic Cookie
					if(payload[0]==0x63 && payload[1]==0x82 && payload[2]==0x53 && payload[3]==0x63)
					{
						analyze_dhcp_options(payload+4, packet_length-(size_ethernet + size_ip + size_udp + size_bootp + 4));
					}
				}
			}
			else
			{
				payload = (uint8_t *)(packet + size_ethernet + size_ip + size_udp);
				print_payload(payload, packet_length-(size_ethernet + size_ip + size_udp));
			}
		}		
	} 
	// ARP
	else if(ntohs(ethernet->ether_type)==ETHERTYPE_ARP)
	{
		arp = (struct sniff_arp*)(packet + size_ethernet);
		analyze_sniff_arp(arp);
	}

	ets_uart_printf("+--------------------------------------------------------------+\r\n");
}
