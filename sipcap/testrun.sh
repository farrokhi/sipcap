#!/bin/sh

for i in `find ~/pcapfarm/*.pcap`; do
	echo "Processing ${i}"
	./sipcap -f ${i} | grep INVITE
done
