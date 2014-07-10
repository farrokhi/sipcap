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
my $verbose = 0;
my %supported_frame_types = ( 
	2048  => 1, # NF_ETH_TYPE_IPv4
	33024 => 1, # NF_ETH_TYPE_8021Q
	34525 => 1, # NF_ETH_TYPE_IPv6
	37120 => 1  # NF_ETH_TYPE_VLAN
	);

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

	if (!defined $supported_frame_types{ $eth->type }) {
		#print "\n\nUnsupported Frame Type: ". $eth->type ."\n\n";
		return;
	}

	my $raw="";

	$raw = $eth->payload;
	my $l3proto = Net::Frame::Layer::IPv4->new(raw => $raw);
	$l3proto->unpack();
	my $srcip = $l3proto->src;
	my $dstip = $l3proto->dst;

	$raw = $l3proto->payload;
	my $l4proto;

	if ($l3proto->protocol == NF_IPv4_PROTOCOL_TCP)
	{
		$l4proto = Net::Frame::Layer::TCP->new(raw => $raw);
		$l4proto->unpack();
	} 
	elsif ($l3proto->protocol == NF_IPv4_PROTOCOL_UDP)
	{
		$l4proto = Net::Frame::Layer::UDP->new(raw => $raw);
		$l4proto->unpack();
	}
	else
	{
		#if ($verbose) { print "\n\nUnsupported L3 Payload: " . $l3proto->protocol . "\n\n"; }
		return;
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

		($sipparts{'anumber'} , $sipparts{'adomain'}) = extract_sip_addr($sip->get_header('from'));
		($sipparts{'bnumber'} , $sipparts{'bdomain'}) = extract_sip_addr($sip->get_header('to'));
		
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
	print "\t-v\t\tverbose mode\n";
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
my $prog_start_time= time();
my $prog_finish_time= 0;

getopts('vhe:f:', \%opts);

if (defined $opts{h}) { help(); }
if (not defined $opts{f}) { help(); }
if (defined $opts{v}) { $verbose = 1 };

my $inputfile=$opts{f};

# process the pcap again, now do the bps and pps calculation
my $pcap = Net::Pcap::open_offline($inputfile,\$err) or die "Can't open file...$err\n";

my $filter='';
$filter = $opts{e} if (defined $opts{e});

my $filter_t;
if (Net::Pcap::compile($pcap, \$filter_t, $filter, 1, 0) == -1) {
		die "Unable to compile filter expression '$filter'\n";
	}
Net::Pcap::setfilter($pcap, $filter_t);

Net::Pcap::loop($pcap, -1, \&process_pkt, '');
Net::Pcap::close($pcap);

$timelen = $endtime - $reftime;
$prog_finish_time= time();

if ($verbose) {
	print STDERR "Packet Count:\t\t $pktcount\n";
	print STDERR "Capture Duration:\t $timelen seconds\n";
	print STDERR "Filter Expression:\t$filter\n";
	my $prog_duration = $prog_finish_time - $prog_start_time;
	print STDERR "Processing Time: $prog_duration seconds\n";
	$prog_duration = 1 if ($prog_duration < 1);
	my $avg_pps = $pktcount / $prog_duration;
	print STDERR "Average number of packets processed per second: $avg_pps\n";
}
