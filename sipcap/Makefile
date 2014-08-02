INC=-I../netmap-libpcap -I/opt/local/include
LIB=-lpcap -lpcre
FLAGS=-m32 -march=corei7 -mfpmath=sse -O3 #-g 

sipcap: sipcap.c Makefile 
	$(CC) $(FLAGS) $(INC) $(LIB) sipcap.c -o  sipcap  

test: sipcap testrun.sh
	/bin/sh testrun.sh

clean:
	\/bin/rm -f sipcap
