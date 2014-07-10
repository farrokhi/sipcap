INC=-I../netmap-libpcap
LIB=-lpcap 
FLAGS=-m32 -march=corei7 -mfpmath=sse -O3 #-g 

sipcap: sipcap.c Makefile 
	$(CC) $(FLAGS) $(INC) $(LIB) sipcap.c -o  sipcap  

clean:
	\/bin/rm -f sipcap
