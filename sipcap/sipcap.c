#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define SIPCAP_VERSION 1.2

#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)

// Global Vars
int pkt_count = 0;
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

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	// we do actual packet processing here
	pkt_count++;
}

int main(int argc, char *argv[])
{
	pcap_t *pcap;
	const u_char *packet;
	struct pcap_pkthdr header;
	struct bpf_program fp;
	bpf_u_int32 devnet, devmask;

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
	printf("finished processing %d packets\n", pkt_count);
	pcap_close(pcap);
	exit(0);
}
