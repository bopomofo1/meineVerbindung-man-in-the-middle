
meineVerbindung: main.o
	gcc -o meineVerbindung main.o usage.o forward.o decode_ip.o arp_poison.o arp_reply.o arp_receive.o arp_request.o -lnet -lpcap -pthread
	rm -f arp_receive.o arp_reply.o arp_request.o arp_poison.o decode_ip.o forward.o usage.o main.o

main.o: usage.o
	gcc -c -o main.o main.c -lnet -lpcap

usage.o: forward.o
	gcc -c -o usage.o usage.c

forward.o: decode_ip.o
	gcc -c -o forward.o forward.c -lnet -lpcap

decode_ip.o: arp_poison.o
	gcc -c -o decode_ip.o decode/decode_ip.c -lnet

arp_poison.o: arp_reply.o
	gcc -c -o arp_poison.o arp/arp_poison.c -lnet -lpcap

arp_reply.o: arp_receive.o
	gcc -c -o arp_reply.o arp/arp_reply.c -lnet -lpcap

arp_receive.o: arp_request.o
	gcc -c -o arp_receive.o arp/arp_receive.c -lnet -lpcap

arp_request.o: arp/arp_request.c
	gcc -c -o arp_request.o arp/arp_request.c -lnet -lpcap
	
