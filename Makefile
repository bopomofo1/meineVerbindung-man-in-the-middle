PROG = meineVerbindung
CC = gcc
CFLAGS = `pkg-config --cflags gtk+-3.0`
LIBS = `pkg-config --libs gtk+-3.0`
OBS = error.o ec_malloc.o init.o arp_poison.o arp_reply.o arp_receive.o arp_request.o start.o

${PROG}: start.o
	${CC} ${CFLAGS} -o ${PROG} ${PROG}.c ${OBS} -lnet -lpcap ${LIBS} 
	rm -f ${OBS}
	sudo mn --custom z_mininet_testing/project.py --topo=project

start.o: arp_poison.o
	${CC} ${CFLAGS} -c -o start.o start/src/start.c -lnet -lpcap ${LIBS} 

arp_poison.o: arp_reply.o
	${CC} ${CFLAGS} -c -o arp_poison.o arp/src/arp_poison.c -lnet -lpcap ${LIBS} 

arp_reply.o: arp_receive.o
	${CC} ${CFLAGS} -c -o arp_reply.o arp/src/arp_reply.c -lnet -lpcap ${LIBS} 

arp_receive.o: arp_request.o
	${CC} ${CFLAGS} -c -o arp_receive.o arp/src/arp_receive.c -lnet -lpcap ${LIBS} 

arp_request.o: error.o
	${CC} ${CFLAGS} -c -o arp_request.o arp/src/arp_request.c -lnet -lpcap ${LIBS} 

error.o: ec_malloc.o
	${CC} ${CFLAGS} -c -o error.o modularity/src/error.c ${LIBS} 

ec_malloc.o: init.o
	${CC} ${CFLAGS} -c -o ec_malloc.o modularity/src/ec_malloc.c ${LIBS} 

init.o: modularity/src/init.c 
	${CC} ${CFLAGS} -c -o init.o modularity/src/init.c -lnet -lpcap ${LIBS} 

clean:
	rm -f ${OBS}