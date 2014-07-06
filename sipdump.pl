#!/usr/bin/perl

use strict;
use warnings;
use Net::Pcap;
use Getopt::Std;
use Net::Frame;
use Net::Frame::Layer::ETH;
use Net::Frame::Layer::ETH qw(:consts);
use Net::Frame::Layer::IPv4;
use Net::Frame::Layer::IPv4 qw(:consts);
use Net::Frame::Layer::TCP;
use Net::Frame::Layer::UDP;
use Net::Packet::Layer7;
use Net::SIP::Packet;
use Net::SIP::Response;
use Net::SIP::Request;

my $pktcount=0;
my $curtime=0;
my $reftime=0;
my $endtime=0;
my $timelen=0;

sub extract_sip_addr {
	my($uri) = @_;

	return ($1,$2) if ($uri =~ /([\w\.]+)@([\w\.]+)/i); # user@domain
	return ("",$1) if ($uri =~ /:([\w\.]{4,}):/i); # domain only
}

sub process_pkt 
{
	my($user_data, $hdr, $pkt) = @_;

	$reftime = $hdr->{tv_sec} if ($reftime == 0);
	$endtime = $hdr->{tv_sec};

	$curtime = sprintf("%d\n", $hdr->{tv_sec} - $reftime);
	$pktcount++;

	## TODO: check if this is actually ethernet frame before decoding
	my $eth = Net::Frame::Layer::ETH->new(raw => $pkt);
	$eth->unpack();
	my $srcmac = $eth->src;
	my $dstmac = $eth->dst;
#	print "src-mac: $srcmac dst-mac: $dstmac ";

	return if ($eth->type != NF_ETH_TYPE_IPv4);

	my $raw="";

	$raw = $eth->payload;
	my $ipv4 = Net::Frame::Layer::IPv4->new(raw => $raw);
	$ipv4->unpack();
	my $srcip = $ipv4->src;
	my $dstip = $ipv4->dst;

	$raw = $ipv4->payload;
	my $l4proto;

	if ($ipv4->protocol == NF_IPv4_PROTOCOL_TCP)
	{
		$l4proto = Net::Frame::Layer::TCP->new(raw => $raw);
		$l4proto->unpack();
	}
	
	if ($ipv4->protocol == NF_IPv4_PROTOCOL_UDP)
	{
		$l4proto = Net::Frame::Layer::UDP->new(raw => $raw);
		$l4proto->unpack();
	}

	my $tcppayload = $l4proto->payload;
	if (((index $tcppayload, "INVITE ") eq 0) or
		 ((index $tcppayload, "BYE ") eq 0)) {

		#print "$tcppayload\n";

		my $sip = Net::SIP::Packet->new($tcppayload);
		my %sipparts=();

		$sipparts{'timestamp'} = $hdr->{tv_sec};
		$sipparts{'srcip'} = $srcip;
		$sipparts{'dstip'} = $dstip;

		($sipparts{'fromuser'} , $sipparts{'fromdomain'}) = extract_sip_addr($sip->get_header('from'));
		($sipparts{'touser'}   , $sipparts{'todomain'})   = extract_sip_addr($sip->get_header('to'));
		
		$sipparts{'callid'} = $sip->get_header('call-id');
		$sipparts{'useragent'} = $sip->get_header('user-agent');
		$sipparts{'useragent'} = "" if (!defined $sipparts{'useragent'});

		foreach (sort keys %sipparts) {
			print "$_: $sipparts{$_}\n";
		}
		print "\n\n";
	}

}

sub help {
	print "sipdump [-h] -f pcapfile [-e filter expression]\n";
	print "\n";
	print "\t-h\t\thelp\n";
	print "\t-f pcapfile\tinput file name (required)\n";
	print "\t-e expression\tfilter expression (tcpdump compatible)\n";
	print "\n";
	exit();
}

sub dump_data {
	my @data=@_;

	open(my $fh, ">", "temp.data");

	for (my $i = 0; $i <= $timelen; $i++) {
		print $fh "$i $data[$i]\n";
	}

	close($fh);
}

#### main 

my $err ='';  
my %opts=();

getopts('he:f:', \%opts);

if (defined $opts{h}) { help(); }
if (not defined $opts{f}) { help(); }

my $inputfile=$opts{f};

# process the pcap again, now do the bps and pps calculation
my $pcap = Net::Pcap::open_offline($inputfile,\$err) or die "Can't open file...$err\n";

my $filter="tcp or udp";
$filter = $opts{e} if (defined $opts{e});

my $filter_t;
if (Net::Pcap::compile($pcap, \$filter_t, $filter, 1, 0) == -1) {
		die "Unable to compile filter expression '$filter'\n";
	}
Net::Pcap::setfilter($pcap, $filter_t);

Net::Pcap::loop($pcap, -1, \&process_pkt, '');
Net::Pcap::close($pcap);

$timelen = $endtime - $reftime;

print STDERR "Packet Count:\t\t $pktcount\n";
print STDERR "Capture Duration:\t $timelen seconds\n";
print STDERR "Filter Expression:\t$filter\n";
