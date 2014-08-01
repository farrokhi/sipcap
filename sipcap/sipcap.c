#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#define SIPCAP_VERSION 1.2

#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)

/* tcpdump header (ether.h) defines ETHER_HDRLEN) */
#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif

#define UDP_HDRLEN 8
#define MAX_PAYLOAD_LEN 5000

// Global Structs

/*
 * Structure of an internet header, naked of options.
 *
 * Stolen from tcpdump source (thanks tcpdump people)
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

// Global Vars
static int pkt_count = 0;
int live_pcap = 0;
int offline_pcap = 0;
int has_expression = 0;
int output_to_file = 0;
int snaplen = 0;
char errbuf[PCAP_ERRBUF_SIZE];
char *capfile, *capdev, *capture_expression, *out_file;


void help(int quit)
{

	printf("sipcap - version %.2f\n\n", SIPCAP_VERSION);
	printf("Usage: sipcap [-i <interface>|-f <pcapfile>] [-e expression] [-o outfile] \n");
	printf("              [-s snaplen] [-h]\n");
	printf("\n");
	if (quit) exit(quit);
}

void error(char *msg) {

	fprintf(stderr, "Error: %s\n", msg);
	exit(1);
}


void parse_options(int argc, char *argv[]) {

	// TODO: Add "-c" option that stops after capturing n packets

	int opt;
	while ((opt = getopt (argc, argv, "i:f:e:o:s:h")) != -1)
		switch (opt) {
			case 'h':
				help(0);
				break;
			case 'i':
				live_pcap = 1;
				if (offline_pcap) error("-i and -f are mutually exclusive");
				if (optarg == NULL) help(1);
				capdev = optarg;
				break;
			case 'f':
				offline_pcap = 1;
				if (live_pcap) error("-i and -f are mutually exclusive");
				if (optarg == NULL) help(1);
				capfile = optarg;
				break;
			case 'e':
				has_expression = 1;
				if (optarg == NULL) help(1);
				capture_expression = optarg;
				break;
			case 'o':
				output_to_file = 1;
				if (optarg == NULL) help(1);
				out_file = optarg;
				break;
			case 's':
				if (optarg == NULL) help(1);
				snaplen = atoi(optarg);
				break;
		}	

	if (!live_pcap && !offline_pcap) help(1);	
}

u_char* handle_UDP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
	const struct udphdr* udp;

	const u_char *payload_data;
	u_short payload_len;
	char payload_str[MAX_PAYLOAD_LEN];

	udp = (struct udphdr*) packet;
	fprintf(stdout, "\tsport: %hu  dport: %hu\n", ntohs(udp->uh_sport), ntohs(udp-> uh_dport));

	payload_len = ntohs(udp->uh_ulen) - UDP_HDRLEN;

	if (payload_len <= 0) return NULL;

	payload_data = packet + UDP_HDRLEN;

	(void)strncpy(payload_str, (const char*)payload_data, payload_len);

	/*
		Now I have UDP payload as an string here and need to parse it
	*/
	// printf("\n\n%s\n\n", payload_str);

	return NULL;
}

u_char* handle_TCP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet, u_int tcplen)
{
	const struct tcphdr* tcp;

	const u_char *payload_data;
	u_short payload_len;
	u_int hlen;
	char payload_str[MAX_PAYLOAD_LEN];

	tcp = (struct tcphdr*) packet;
	fprintf(stdout, "\tsport: %hu  dport: %hu\n", ntohs(tcp->th_sport), ntohs(tcp-> th_dport));

	hlen = (tcp->th_off * 4);

	payload_len = tcplen - hlen;
	if (payload_len <= 0) return NULL;

	payload_data = packet + hlen;

	(void)strncpy(payload_str, (const char*)payload_data, payload_len);

	/*
		Damn! I have TCP payload here too! Now need to write a parser. 
	*/
	// printf("\n\n%s\n\n", payload_str);
	return NULL;
}

u_char* handle_IP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    int i;

    int len;

    /* jump pass the ethernet header */
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header); 

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct my_ip))
    {
        fprintf(stderr, "!");
        return NULL;
    }

    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip); /* header length */
    version = IP_V(ip);/* ip version */

    /* check version */
    if(version != 4)
    {
      fprintf(stdout,"Unknown version %d\n",version);
      return NULL;
    }

    /* check header length */
    if(hlen < 5 )
    {
        fprintf(stdout,"bad-hlen %d \n",hlen);
    }

    /* see if we have as much packet as we should */
    if(length < len)
        printf("\ntruncated IP - %d bytes missing\n",len - length);

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 )/* aka no 1's in first 13 bits */
    {/* print SOURCE DESTINATION hlen version len offset */

		switch (ip->ip_p) {
			case 1:
				fprintf(stdout, "ICMP");
				break;
			case 6:
				fprintf(stdout, "TCP");
				break;
			case 17:
				fprintf(stdout, "UDP");
				break;
			case 41:
				fprintf(stdout, "IPv6");
				break;	
			case 47:
				fprintf(stdout, "GRE");
				break;
			case 50:
				fprintf(stdout, "ESP");	
				break;
			default:
				fprintf(stdout, "UNKNOWN (%d)", ip->ip_p);
				break;
		}    

        fprintf(stdout,":\t%s\t%s",
                inet_ntoa(ip->ip_src),
                inet_ntoa(ip->ip_dst));

	    fprintf(stdout,"\tlen= %3d hlen = %3d", len, hlen);

		switch (ip->ip_p) {
			case 6:
				handle_TCP(args, pkthdr, packet + sizeof(struct ether_header) + (hlen * 4), len - (hlen * 4));
				break;
			case 17:
				handle_UDP(args, pkthdr, packet + sizeof(struct ether_header) + (hlen * 4));
				break;
			default:
		    	fprintf(stdout, "\n");
		    	break;
	    }


    }

    return NULL;
}

u_int16_t handle_ethernet
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    struct ether_header *eptr;  /* net/ethernet.h */
    u_short ether_type;

    if (caplen < ETHER_HDRLEN)
    {
    	// Bad Packet Captured - Try capturing full packet (or increase snaplen)
        fprintf(stderr,"!");
        return -1;
    }

    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

    return ether_type;
}


void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
	pkt_count++;

    u_int16_t type = handle_ethernet(args, header, packet);

    if (type != ETHERTYPE_IP) return;
    handle_IP(args, header, packet);

}

void print_stat()
{
	printf("finished processing %d packets\n", pkt_count);
}

void intHandler(int dummy) {
	printf("\n");
    print_stat();
    exit(0);
}

int main(int argc, char *argv[])
{
	pcap_t *pcap;
	const u_char *packet;
	struct pcap_pkthdr header;
	struct bpf_program fp;
	bpf_u_int32 devnet, devmask;

	signal(SIGINT, intHandler);

	parse_options(argc, argv);

	if (live_pcap) {
		 if (pcap_lookupnet(capdev, &devnet, &devmask, errbuf) == -1) {
			 fprintf(stderr, "WARNING: Can't get netmask for device %s\n", capdev);
			 devnet = 0;
			 devmask = 0;
		 }

		pcap = pcap_open_live(capdev, BUFSIZ, 1, 1000, errbuf);

	} else {
		pcap = pcap_open_offline(capfile, errbuf);
	}

	if (has_expression) {
		if (pcap_compile(pcap, &fp, capture_expression, 0, devnet) == -1) error(pcap_geterr(pcap));
		if (pcap_setfilter(pcap, &fp) == -1) error(pcap_geterr(pcap)); 
	}

	if (pcap == NULL) error(errbuf);

	pcap_loop(pcap, -1, &process_packet, NULL);

	pcap_close(pcap);

	print_stat();

	exit(0);
}
