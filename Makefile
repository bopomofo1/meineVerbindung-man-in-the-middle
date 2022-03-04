
meineVerbindung: main.o
	gcc -o meineVerbindung main.o arp_reply.o arp_receive.o arp_request.o -lnet -lpcap
	rm -f main.o
	rm -f arp_receive.o
	rm -f arp_request.o

main.o: arp_reply.o	
	gcc -c -o main.o main.c  -lnet -lpcap

arp_reply.o: arp_receive.o
	gcc -c -o arp_reply.o arp_reply.c -lnet -lpcap

arp_receive.o: arp_request.o
	gcc -c -o arp_receive.o arp_receive.c -lnet -lpcap

arp_request.o: arp_request.c
	gcc -c -o arp_request.o arp_request.c -lnet -lpcap