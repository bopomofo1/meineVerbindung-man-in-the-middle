PROG = meineVerbindung
CC = gcc
CFLAGS = `pkg-config --cflags gtk+-3.0`
LIBS = `pkg-config --libs gtk+-3.0`
OBS = error.o ec_malloc.o init.o arp_poison.o arp_reply.o arp_receive.o arp_request.o forward.o compare_mac.o send_tcp.o display_data.o start.o inject.o

${PROG}: start.o
	${CC} ${CFLAGS} -o ${PROG} ${PROG}.c ${OBS} -lnet -lpcap ${LIBS} 
	rm -f ${OBS}


start.o: inject.o
	${CC} ${CFLAGS} -c -o start.o start/src/start.c -lnet -lpcap ${LIBS} 

inject.o: forward.o
	${CC} ${CFLAGS} -c -o inject.o inject/src/inject.c -lnet -lpcap ${LIBS} 

forward.o: compare_mac.o
	${CC} ${CFLAGS} -c -o forward.o forwarding/src/forward.c -lnet -lpcap ${LIBS} 

compare_mac.o: send_tcp.o
	${CC} ${CFLAGS} -c -o compare_mac.o forwarding/src/compare_mac.c -lnet -lpcap ${LIBS} 

send_tcp.o: display_data.o
	${CC} ${CFLAGS} -c -o send_tcp.o forwarding/src/send_tcp.c -lnet -lpcap ${LIBS} 
	
display_data.o: arp_poison.o
	${CC} ${CFLAGS} -c -o display_data.o decode/src/display_data.c -lnet -lpcap ${LIBS} 

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