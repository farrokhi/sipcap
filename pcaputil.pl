#!/usr/bin/perl

use strict;
use warnings;
use Net::Pcap;
use Getopt::Std;

my $pktcount=0;
my $curtime=0;
my $reftime=0;
my $endtime=0;
my $timelen=0;

my @pps=();
my @bps=();

sub process_pkt 
{
	my($user_data, $hdr, $pkt) = @_;

	$reftime = $hdr->{tv_sec} if ($reftime == 0);
	$endtime = $hdr->{tv_sec};

	$curtime = sprintf("%d\n", $hdr->{tv_sec} - $reftime);
	$pktcount++;

	my $arrsize=@pps;
	if ($arrsize < $curtime) { # grow array if necessary
		for (my $i = $arrsize; $i <= $curtime; $i++) {
			$pps[$i]=0;
			$bps[$i]=0;
		}
	}
	$pps[$curtime]++;
	$bps[$curtime]+=($hdr->{len} * 8);
}

sub help {
	print "pcaputil [-h] -f pcapfile [-e filter expression] [-p] [-b]\n";
	print "\n";
	print "\t-h\t\thelp\n";
	print "\t-f pcapfile\tinput file name (required)\n";
	print "\t-e expression\tfilter expression (tcpdump compatible)\n";
	print "\t-b\t\tgenerate bps graph\n";
	print "\t-p\t\tgenerate pps graph\n";
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

sub create_graph {
	my ($dataset)=@_;
	my $ylabel="";
	my $filename="";
	my $linecolor="";

	if ($dataset eq 'pps')
	{
		$ylabel="Packets";
		$filename="pps";
		$linecolor="#4d0000";
	}

	if ($dataset eq 'bps')
	{
		$ylabel="Bits";
		$filename="bps";
		$linecolor="#00004d";
	}

	my $gpi = <<"END_MESSAGE";
set terminal postscript eps enhanced color "Helvetica" 30
set title "Throughput Graph"
set style line 99 linetype 1 linecolor rgb "#999999" lw 2
set key right bottom
set key box linestyle 99
set key spacing 1.2
set nokey
set grid xtics ytics mytics
set format y "%.0f"
set size 2
set size ratio 0.4
set ylabel "$ylabel"
set xlabel "Time (Seconds)"
set style line 1 lc rgb '$linecolor' lt 1 lw 3
plot "temp.data" using 1:2 notitle with lines ls 1
END_MESSAGE

	open(GNUPLOT, "| gnuplot | epstopdf -f | convert -density 300 - $filename.png");
	print GNUPLOT $gpi;
	close(GNUPLOT);
}

#### main 

my $err ='';  
my %opts=();

getopts('hbpe:f:', \%opts);

if (defined $opts{h}) { help(); }
if (not defined $opts{f}) { help(); }

my $inputfile=$opts{f};

# process the pcap again, now do the bps and pps calculation
my $pcap = Net::Pcap::open_offline($inputfile,\$err) or die "Can't open file...$err\n";

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

if (defined $opts{p})
{
	print("Creating PPS graph...");
	dump_data(@pps); 
	create_graph('pps');
	print("Done.\n");
}

if (defined $opts{b})
{
	print("Creating BPS graph...");
	dump_data(@bps);
	create_graph('bps');
	print("Done.\n");
}
