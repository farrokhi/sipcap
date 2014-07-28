#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define SIPCAP_VERSION 1.2

#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)


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

int main(int argc, char *argv[])
{
	pcap_t *pcap;
	char errbuf[PCAP_ERRBUF_SIZE];
	int opt;
	int live_pcap = 0;
	int offline_pcap = 0;
	int has_expression = 0;
	int output_to_file = 0;
	int snaplen = 0;
	char *pcap_file, *pcap_interface, *capture_expression, *out_file;

	while ((opt = getopt (argc, argv, "i:f:e:o:s:h")) != -1)
		switch (opt) {
			case 'h':
				help(0);
				break;
			case 'i':
				live_pcap = 1;
				if (offline_pcap) error("-i and -f are mutually exclusive");
				if (optarg == NULL) help(1);
				pcap_interface = optarg;
				break;
			case 'f':
				offline_pcap = 1;
				if (live_pcap) error("-i and -f are mutually exclusive");
				if (optarg == NULL) help(1);
				pcap_file = optarg;
				break;
			case 'e':
				has_expression = 1;
				if (optarg == NULL) help(1);
				break;
			case 'o':
				output_to_file = 1;
				if (optarg == NULL) help(1);
				out_file = optarg;
				break;
			case 's':
				if (optarg == NULL) help(1);
				snaplen = atoi(optarg);
				printf("snaplen is %d\n", snaplen);
				break;
		}     

	if (!live_pcap && !offline_pcap) help(1);
	
	if (live_pcap) {
		error("live capture not implemented");
	} else {
		pcap = pcap_open_offline(pcap_file, errbuf);
		if (pcap == NULL) error("cannot open capture file");
	}

	pcap_close(pcap);
	exit(0);
}
