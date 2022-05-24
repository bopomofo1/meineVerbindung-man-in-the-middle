PROG = meineVerbindung
CC = gcc
CFLAGS = `pkg-config --cflags gtk+-3.0`
LIBS = `pkg-config --libs gtk+-3.0`
OBS = error.o ec_malloc.o init.o arp_poison.o arp_reply.o arp_receive.o arp_request.o

${PROG}: arp_poison.o
	${CC} ${CFLAGS} -o ${PROG} ${PROG}.c ${OBS} -lnet -lpcap ${LIBS} 
	rm -f ${OBS}


arp_poison.o: arp_reply.o
	gcc -c -o arp_poison.o arp/src/arp_poison.c -lnet -lpcap

arp_reply.o: arp_receive.o
	gcc -c -o arp_reply.o arp/src/arp_reply.c -lnet -lpcap

arp_receive.o: arp_request.o
	gcc -c -o arp_receive.o arp/src/arp_receive.c -lnet -lpcap

arp_request.o: error.o
	gcc -c -o arp_request.o arp/src/arp_request.c -lnet -lpcap

error.o: ec_malloc.o
	${CC} -c -o error.o modularity/src/error.c

ec_malloc.o: init.o
	${CC} -c -o ec_malloc.o modularity/src/ec_malloc.c

init.o: modularity/src/init.c 
	${CC} -c -o init.o modularity/src/init.c -lnet -lpcap

clean:
	rm -f ${OBS}