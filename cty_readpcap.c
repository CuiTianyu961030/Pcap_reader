#include <stdio.h>
#include "/usr/include/pcap/pcap.h"

#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct sniff_udp {
	u_short uh_sport;
	u_short uh_dport;
	u_short uh_length;
	u_short uh_sum;
};

struct sniff_dns {
	u_short tran_id;
	u_short flags;
	u_short questions;
	u_short answer_rrs;
	u_short authority_rrs;
	u_short additional_rrs;
};


void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}


/*
 *praes http
 */

void
prase_http(const u_char *payload, int len)
{
	printf("      ");
	int i = 0;
	for (i = 0; i < len; i++)
	{
		
		if(i > 2)
			if(payload[i-3]==0x0d && payload[i-2]==0x0a && payload[i-1]==0x0d && payload[i]==0x0a)
			{
				//printf("i: %d\n", i);
				break;
			}

		if(payload[i] == 0x0d)
			continue;
		printf("%c", payload[i]);
		if(payload[i] == 0x0a)
			printf("      ");
	}	
}

/*
 *prase ssl/tls
 */

void
prase_ssl_tls(const u_char *payload, int len)
{
	
	int i, offset;
	int session_id_length;
	int cipher_suites_length;	
	int compression_methods_length;
	int server_name_length;
	int serival_number_length;	
	
	/* Handshake */
	if(payload[0] == 0x16)
	{
		printf("      Content Type: Handshake\n");
		
		printf("      Version: ");

		if(payload[1] == 0x03 && payload[2] == 0x01)
			printf("TLS 1.0\n");
		else if(payload[1] == 0x03 && payload[2] == 0x02)
                        printf("TLS 1.1\n");
		else if(payload[1] == 0x03 && payload[2] == 0x03)
                        printf("TLS 1.2\n");
			
		if(payload[5] == 0x01)
		{
			printf("         Handshake Type: Client Hello\n");
			printf("         Version: ");
			if(payload[9] == 0x03 && payload[10] == 0x01)
                        	printf("TLS 1.0\n");
               		else if(payload[9] == 0x03 && payload[10] == 0x02)
                        	printf("TLS 1.1\n");
                	else if(payload[9] == 0x03 && payload[10] == 0x03)
                        	printf("TLS 1.2\n");
			//char cipher_length;
			session_id_length =  (int)payload[43];
			if(session_id_length != 0)
			{
                        	printf("         Session ID: ");
                        	for(i = 44; i < 44 + session_id_length; i++)
                        	{
                                	printf("%x", payload[i]);
                        	}
                        	printf("\n");
			}

			offset = 43 + session_id_length + 2;
			cipher_suites_length = (int)payload[offset];
			printf("         Cipher Suites:\n            ");
			int count = 0;
			for (i = offset + 1; i < offset + 1 + cipher_suites_length; i++)
			{
				count++;
				printf("%02x", payload[i]);
				if(count % 2 == 0)
					printf(" ");
			}
			
			printf("\n");
			offset = i;
			compression_methods_length = (int)payload[offset];
			printf("         Compression Methods: \n            ");
			for(i = offset +1; i < offset + compression_methods_length + 1; i++)
			{
				printf("%02x ", payload[i]);
			}
			printf("\n");
			offset = offset + compression_methods_length + 11; // pass extension_length
			server_name_length = (int)payload[offset];
			printf("         Server Name Indication extension: \n            ");
			for (i = offset + 1; i < offset + 1 + server_name_length; i++)
			{
				printf("%c", payload[i]);
			}
			printf("\n");
			//cipher_length = (char)payload[44];
			//sscanf((char)payload[44])
			//for(i = 46; i < len )

		}

		else if(payload[5] == 0x02)
		{
			printf("         Handshake Type: Server Hello\n");
			printf("         Version: ");
                        if(payload[9] == 0x03 && payload[10] == 0x01)
                                printf("TLS 1.0\n");
                        else if(payload[9] == 0x03 && payload[10] == 0x02)
                                printf("TLS 1.1\n");
                        else if(payload[9] == 0x03 && payload[10] == 0x03)
                                printf("TLS 1.2\n");
			session_id_length =  (int)payload[43];
			if(session_id_length != 0 )
			{
				printf("         Session ID: ");
				for(i = 44; i < 44 + session_id_length; i++)
				{
					printf("%x", payload[i]);
				}
				printf("\n");
			}
                        offset = 43 + session_id_length + 1;
                        
                        printf("         Cipher Suites:\n            ");
			int count = 0;
                        for (i = offset; i < offset + 2; i++)
                        {
				count++;
                                printf("%02x", payload[i]);
                        	if(count % 2 == 0)
					printf(" ");
			}
                        printf("\n");
			offset = i;
                        printf("         Compression Methods: \n            ");
                        printf("%02x ", payload[offset]);
			printf("\n");

		}

		else if(payload[5] == 0x0b)
		{
			printf("         Handshake Type: Certificate\n");
			printf("         Certificates:\n");
			printf("            Version: ");
			if(payload[27] == 0x02)
				printf("v3\n");
			serival_number_length = (int)payload[29];
			printf("            serivalNumber: ");	
			for(i = 30; i < 30 + serival_number_length; i++)
			{
				printf("%x", payload[i]);
			}
			printf("\n");
			int total_issuers_length = (int)payload[i+16];
			int issuers_limit = i + 16 + total_issuers_length+1;
			printf("            Issuer: \n               ");
			offset = i + 27;
			int issuer_length = (int)payload[offset];
			for(i = offset + 1; i < offset + 1 + issuer_length; i++)
			{
				printf("%c", payload[i]);
			}
			printf("\n");
			
			while(i != issuers_limit)
			{
				printf("               ");
				offset = i + 10;
				issuer_length = (int)payload[offset];
				for(i = offset + 1; i < offset + 1 + issuer_length; i++)
				{
					printf("%c", payload[i]);
				}
				printf("\n");
			}
			
			printf("            Validity: \n               ");
			offset = i + 3;
			int validity_length = (int)payload[offset];
			int count = 0;
			for(i = offset + 1; i < offset + validity_length; i++)
			{
				count++;
				if(count < 6 && (count % 2 == 0))
					printf("%c-", payload[i]);
				else if(count == 6)
					printf("%c ", payload[i]);
				else if(((count > 6) && (count < 11)) && count % 2 == 0)
					printf("%c:", payload[i]);
				else
					printf("%c", payload[i]);
				
			}	
			printf("\n               ");
			offset = i + 2;
                        validity_length = (int)payload[offset];
			count = 0;
                        for(i = offset + 1; i < offset + validity_length; i++)
                        {
                                count++;
                                if(count < 6 && (count % 2 == 0))
                                        printf("%c-", payload[i]);
                                else if(count == 6)
                                        printf("%c ", payload[i]);
                                else if(((count > 6) && (count < 11)) && count % 2 == 0)
                                        printf("%c:", payload[i]);
                                else
                                        printf("%c", payload[i]);
                        }
			printf("\n");

			while(payload[i] != 0x31)
				i++;
			int total_subjects_length = (int)payload[i-1];
			
			int subjects_limit = i + total_subjects_length;
			printf("            Subject: \n               ");
			
			offset = i + 10;
			int subject_length = (int)payload[offset];
                        for(i = offset + 1; i < offset + 1 + subject_length; i++)
                        {
                                printf("%c", payload[i]);
                        }
                        printf("\n");
			
                        while(i != subjects_limit)
                        {
				printf("               ");
                                offset = i + 10;
                                subject_length = (int)payload[offset];
                                for(i = offset + 1; i < offset + 1 + subject_length; i++)
                                {
                                        printf("%c", payload[i]);
                                }
                                printf("\n");
                        }			
		}
	}
		
	else if(payload[0] == 0x17)
	{
		printf("      Content Type: Application Data\n");
	}

	else if(payload[0] == 0x15)
	{
		printf("      Content Type: Encryptd Alert\n");
	}
	
	else if(payload[0] == 0x14)
	{
		printf("      Contenr Type: Change Cipher Spec\n");
	}
	
}

void
prase_dns(const u_char *payload, int len)
{
	int i = 0;
	int offset;
	const struct sniff_dns *dns;
	dns = (struct sniff_dns*)(payload);
	
	printf("      Transaction ID: 0x%02x%02x\n", payload[0], payload[1]);
	printf("      Flags: 0x%02x%02x ", payload[2], payload[3]);
	if(payload[2] == 0x01 && payload[3] == 0x00)
	{
		printf("Standard query\n");
		printf("      Questions: %d\n", ntohs(dns->questions));
		printf("      Answer RRs: %d\n", dns->answer_rrs);
		printf("      Authority RRs: %d\n", dns->authority_rrs);
		printf("      Additional RRs: %d\n", dns->additional_rrs);
		
		i = i + 12;
		int domain_length = (int)payload[i];
		//printf("%d",domain_length);
		i = i + 1;
		offset = i;
		printf("      Queries:\n         Name: ");
		while(payload[i] != 0x00)
		{
			if(i != offset)
				printf(".");
			for(i = offset; i < offset + domain_length; i++)
				printf("%c", payload[i]);
			offset = offset + domain_length + 1;
			domain_length = (int)payload[i];
		}
		i = i + 2;
		printf("\n         Type: ");
		if(payload[i] == 0x01)
			printf("A\n");
		else if(payload[i] == 0x1c)
			printf("AAAA\n");
		else if(payload[i] == 0x05)
			printf("CNAME\n");
		printf("         Class: ");
		i = i + 1;
		printf("0x%02x%02x\n", payload[i], payload[i+1]);
	}
	
	else if(payload[2] == 0x81 && payload[3] == 0x80)
	{
		printf("Standard query response, No error\n");
                printf("      Questions: %d\n", ntohs(dns->questions));
                printf("      Answer RRs: %d\n", dns->answer_rrs);
                printf("      Authority RRs: %d\n", dns->authority_rrs);
                printf("      Additional RRs: %d\n", dns->additional_rrs);

                i = i + 12;
                int domain_length = (int)payload[i];
		i = i + 1;
                offset = i;
                printf("      Queries:\n         Name: ");
                while(payload[i] != 0x00)
                {
                        if(i != offset)
                                printf(".");
                        for(i = offset; i < offset + domain_length; i++)
                                printf("%c", payload[i]);
                        offset = offset + domain_length + 1;
                        domain_length = (int)payload[i];
                }
                i = i + 2;
                printf("\n         Type: ");
                if(payload[i] == 0x01)
                        printf("A\n");
                else if(payload[i] == 0x1c)
                        printf("AAAA\n");
                else if(payload[i] == 0x05)
                        printf("CNAME\n");
                printf("         Class: ");
                i = i + 1;
                printf("0x%02x%02x\n", payload[i], payload[i+1]);
		
		printf("      Answers:\n");
		i = i + 2;
		
		int first_i;
		int count;
		while(i < len)
		{
			printf("         Type: ");
			if (payload[i+3] == 0x05)
			{
				printf("CNANE\n               ");
				for(i = i + 13; payload[i] != 0xc0 && i < len; i++)
					if((int)payload[i] >=32)
						printf("%c", payload[i]);
					else
						printf(".");
				printf(".com");
				i = i + 2;
				printf("\n");
			}
			else if (payload[i+3] == 0x01)
			{
				printf("A\n               ");
				first_i = i + 12;
				for(i = i + 12; payload[i] != 0xc0 && i < len; i++)
				{	
					if(first_i != i)
                                        	printf(".%d", payload[i]);
					else
						printf("%d", payload[i]);
				}
					printf("\n");
				
			}
			else if (payload[i+3] == 0x1c)
			{
				printf("AAAA\n               ");
				count = 0;
				first_i = i + 12;
				for(i = i + 12; payload[i] != 0xc0 && i < len; i++)
				{
					count++;
					if(count % 2 == 1 && i != first_i)
                                        	printf(":%02x", payload[i]);
					else
						printf("%02x", payload[i]);
				}
					printf("\n");
			}
			else
			{
				printf("Authoritative nameservers\n");
				break;
			}
		}
		
	}
	
	else if((payload[2] == 0x81 && payload[3] == 0x83) || (payload[2] == 0x84 && payload[3] == 0x03))
	{
		printf("Standard query response, No such name\n");
                printf("      Questions: %d\n", ntohs(dns->questions));
                printf("      Answer RRs: %d\n", dns->answer_rrs);
                printf("      Authority RRs: %d\n", dns->authority_rrs);
                printf("      Additional RRs: %d\n", dns->additional_rrs);

                i = i + 12;
                int domain_length = (int)payload[i];
                i = i + 1;
                offset = i;
                printf("      Queries:\n         Name: ");
                while(payload[i] != 0x00)
                {
                        if(i != offset)
                                printf(".");
                        for(i = offset; i < offset + domain_length; i++)
                                printf("%c", payload[i]);
                        offset = offset + domain_length + 1;
                        domain_length = (int)payload[i];
                }
                i = i + 2;
                printf("\n         Type: ");
                if(payload[i] == 0x01)
                        printf("A\n");
                else if(payload[i] == 0x1c)
                        printf("AAAA\n");
                else if(payload[i] == 0x05)
                        printf("CNAME\n");
                printf("         Class: ");
                i = i + 1;
                printf("0x%02x%02x\n", payload[i], payload[i+1]);

	}
}


/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;		/* The UDP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_udp;
	int size_payload;
	
	printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			break;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	
	/*
	 *  OK, this packet is TCP.
	 */
	
	/* define/compute tcp header offset */
	if(ip->ip_p == IPPROTO_TCP)
	{
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if (size_tcp < 20) {
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}
	
		printf("   Src port: %d\n", ntohs(tcp->th_sport));
		printf("   Dst port: %d\n", ntohs(tcp->th_dport));
		int sport = ntohs(tcp->th_sport);
		int dport = ntohs(tcp->th_dport);

		/* define/compute tcp payload (segment) offset */
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
		/* compute tcp payload (segment) size */
		size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
		/*
	 	 * Print payload data; it might be binary, so don't just
	 	 * treat it as a string.
		 */
		if (size_payload > 0) {
			printf("   Payload (%d bytes):\n", size_payload);
			//print_payload(payload, size_payload);
		
                	if ((sport == 80) || (dport == 80))
			{
				printf("   HTTP prase:\n");
				prase_http(payload, size_payload);
			}
			else if(sport == 443 || dport == 443)
			{
				printf("   SSL/TLS prase:\n");
				prase_ssl_tls(payload, size_payload);
			}
		}
	}
	
	/* UDP */
	else if(ip->ip_p == IPPROTO_UDP)
	{
		udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
		size_udp = 8;
		printf("   Src port: %d\n", ntohs(udp->uh_sport));
		printf("   Dst port: %d\n", ntohs(udp->uh_dport));
		int sport = ntohs(udp->uh_sport);
		int dport = ntohs(udp->uh_dport);

		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
		
		size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
		
		if (size_payload > 0) {
			printf("   Payload (%d bytes:)\n", size_payload);

			if(sport == 53 || dport == 53)
			{
				printf("   DNS prase:\n");
				prase_dns(payload, size_payload);
			}
		}
	}
return;
}

int main(int argc, char *argv[]){
    char errbuf[100];
    pcap_t *handle = pcap_open_offline("test.pcap", errbuf);
    if (NULL == handle){
        printf("%s\n", errbuf);
	return -1;
    }
    pcap_loop(handle, -1, got_packet, NULL);
    //struct pcap_pkthdr *pkthdr = 0;
    //const u_char *pktdata = 0;
    // pcap_next_ex(pfile, &pkthdr, &pktdata);
    //printf("%d\n", pkthdr->caplen);
    //bpf_u_int32 i;
    //for(i = 0; i < pkthdr->caplen; ++i) {
    //    if (0 < i && 0 == i % 16) printf("\n");
    //    printf("%2x ", pktdata[i]);
    //}
    pcap_close(handle);
    return 0;
}
