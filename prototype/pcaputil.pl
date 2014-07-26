#!/usr/bin/perl

use strict;
use warnings;
use File::Basename;
use Net::Pcap;
use NetPacket::IP;
use Getopt::Std;

my $duplex = 0;
my $src_addr = "";
my $pktcount = 0;
my $curtime = 0;
my $reftime = 0;
my $endtime = 0;
my $timelen = 0;
my $hoffset = -1;

my @pps_src = ();
my @pps_dst = ();

my @bps_src = ();
my @bps_dst = ();

sub process_pkt 
{
	my($user_data, $hdr, $pkt) = @_;

	my $unpacket = unpack('H*', substr($pkt, 0,1));
	if (($hoffset == 32) && ($unpacket == 88)) {
		$hoffset = 34;   # Add 2 bytes to the header is it is an IEEE 802.11 QOS frame
	}

	my $paquete = substr($pkt, $hoffset); # Hack to parse not only Ethernet but also IEEE 802.11 frames
	my $ip_obj  = NetPacket::IP->decode( $paquete );

	$reftime = $hdr->{tv_sec} if ($reftime == 0);
	$endtime = $hdr->{tv_sec};

	$curtime = sprintf("%d\n", $hdr->{tv_sec} - $reftime);
	$pktcount++;

	my $arrsize=@pps_src;
	if ($arrsize < $curtime) { # grow array if necessary
		for (my $i = $arrsize; $i <= $curtime; $i++) {
			$pps_src[$i] = 0;
			$pps_dst[$i] = 0;
			$bps_src[$i] = 0;
			$bps_dst[$i] = 0;
		}
	}

	if ($duplex) # We need separate TX/RX lines in graph
	{
		if ( $src_addr eq $ip_obj->{src_ip} ) # TX flow
		{
			$pps_src[$curtime]++;
			$bps_src[$curtime]+=($hdr->{len} * 8);
		} 
		elsif ( $src_addr eq $ip_obj->{dest_ip} ) # RX flow
		{
			$pps_dst[$curtime]++;
			$bps_dst[$curtime]+=($hdr->{len} * 8);
		}
		else
		{
			$pps_src[$curtime]+=0;
			$pps_dst[$curtime]+=0;
			$bps_src[$curtime]+=0;
			$bps_dst[$curtime]+=0;
		}
	}
	else # We need one line in graph for TX+RX combined
	{
		$pps_src[$curtime]++;
		$bps_src[$curtime]+=($hdr->{len} * 8);
	}
}

sub help {
	print "pcaputil -f pcapfile [-e filter expression] [-S src_ip] [-pbh]\n";
	print "\n";
	print "\t-h\t\thelp\n";
	print "\t-f pcapfile\tinput file name (required)\n";
	print "\t-e expression\tfilter expression (tcpdump compatible)\n";
	print "\t-b\t\tgenerate bps graph\n";
	print "\t-p\t\tgenerate pps graph\n";
	print "\t-S src_ip\tseparate TX/RX flow graph based on source address\n";
	print "\n";
	exit();
}

sub dump_data_single {
	my $data = shift;

	open(my $fh, ">", "temp.data");

	for (my $i = 0; $i <= $timelen; $i++) {
		print $fh "$i @$data[$i]\n";
	}

	close($fh);
}


sub dump_data_double {

	# received two arrays by reference
	my $tx = shift;
	my $rx = shift;

	my $crx = 0;
	my $ctx = 0;
	open(my $fh, ">", "temp.data");

	for (my $i = 0; $i <= $timelen; $i++) {
		$ctx = 0;
		$crx = 0;
		$ctx = @$tx[$i] if (defined @$tx[$i]);
		$crx = @$rx[$i] if (defined @$rx[$i]);

		print $fh "$i $ctx $crx\n";
	}

	close($fh);
}


sub create_graph {
	my $dataset = shift;
	my $filename = shift . "-" . $dataset . ".png";

	my $ylabel = "";
	my $lddinecolor = "";
	my $plotline = "";
	my $title = "";

	if ($dataset eq 'pps')
	{
		$ylabel = "Packets";
		$title = "Packet Traffic Volume";

		if ($duplex) # full duplex graph
		{
			$plotline="plot 'temp.data' using 1:2 title 'RX Packets/s' with lines ls 1, 'temp.data' using 1:3 title 'TX Packets/s' with lines ls 2";
		}
		else
		{
			$plotline="plot 'temp.data' using 1:2 title 'TX+RX Packets/s' with lines ls 1";
		}
	}

	if ($dataset eq 'bps')
	{
		$ylabel = "Bits";
		$title = "Traffic Volume";

		if ($duplex) # full duplex graph
		{
			$plotline="plot 'temp.data' using 1:2 title 'RX bits/s' with lines ls 1, 'temp.data' using 1:3 title 'TX bits/s' with lines ls 2";
		}
		else
		{
			$plotline="plot 'temp.data' using 1:2 title 'TX+RX bits/s' with lines ls 1";
		}
	}

	my $gpi = <<"END_MESSAGE";
set terminal postscript eps enhanced color "Helvetica" 30
set title "$title"
set style line 99 linetype 1 linecolor rgb "#999999" lw 2
set key outside right bottom horizontal Right noreverse enhanced autotitles box linetype -1 linewidth 2.000
set key box linestyle 99 
set key spacing 1.2
set grid xtics ytics mytics
set decimal locale  "en_US.UTF-8"
set format y "%'.0f"
set size 2,1.6
set size ratio 0.4
set ylabel "$ylabel"
set xlabel "Time (Seconds)"
set style line 1 lc rgb '#6d0000' lt 1 lw 3
set style line 2 lc rgb '#0000cc' lt 1 lw 3
$plotline
END_MESSAGE

	open(GNUPLOT, "| gnuplot | epstopdf -f | convert -colorspace rgb -density 300 - PNG32:$filename");
	print GNUPLOT $gpi;
	close(GNUPLOT);
}

#### main 

my $err ='';  
my %opts=();

getopts('hbpe:f:S:', \%opts);

help() if (defined $opts{h});
help() if (not defined $opts{f});

my $inputfile = $opts{f};
if (defined $opts{S})
{
	$src_addr = $opts{S};
	$duplex = 1;
}

# process the pcap again, now do the bps and pps calculation
my $pcap = Net::Pcap::open_offline($inputfile,\$err) or die "Can't open file...$err\n";

my $datalink;
$datalink = Net::Pcap::datalink($pcap);
CASE: {
		# EN10MB capture files
		($datalink == 1) && do {
			$hoffset = 14;
			last CASE;
		};

		# Linux cooked socket capture files
		($datalink == 113) && do {
			$hoffset = 16;
			last CASE;
		};

		# DLT_IEEE802_11 capture files
		($datalink == 105) && do {
			$hoffset = 32;
			last CASE;
		}
}

if (defined $opts{e}) {
	my $filter = $opts{e};
	my $filter_t;
	if (Net::Pcap::compile($pcap, \$filter_t, $filter, 1, 0) == -1) {
			die "Unable to compile filter expression '$filter'\n";
		}
	Net::Pcap::setfilter($pcap, $filter_t);
}

Net::Pcap::loop($pcap, -1, \&process_pkt, '');
Net::Pcap::close($pcap);

$timelen = $endtime - $reftime;

print STDERR "Packet Count:\t\t $pktcount\n";
print STDERR "Capture Duration:\t $timelen seconds\n";

if ($pktcount < 2) {
	print "\nNeed at least two packets to draw a graph.\n";
	exit();
}

my($filename, $dirs, $suffix) = fileparse($inputfile, qr/\.[^.]*/);

if (defined $opts{p})
{
	print("Creating PPS graph...");
	if ($duplex)
	{
		dump_data_double(\@pps_src, \@pps_dst); 
	}
	else
	{
		dump_data_single(\@pps_src, $filename);
	}
	create_graph('pps', $filename);
	print("Done.\n");
}

if (defined $opts{b})
{
	print("Creating BPS graph...");
	if ($duplex)
	{
		dump_data_double(\@bps_src, \@bps_dst, $filename); 
	}
	else
	{
		dump_data_single(\@bps_src, $filename);
	}
	create_graph('bps', $filename);
	print("Done.\n");
}
