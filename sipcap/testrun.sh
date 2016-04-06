#!/bin/sh

for i in `find ~/ -iname '*.pcap'`; do
	echo "Processing ${i}"
	./sipcap -f ${i} | grep INVITE
done
