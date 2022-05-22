
meineVerbindung: main.o
	gcc -o meineVerbindung main.o usage.o ec_malloc.o error.o init.o forward.o compare_mac.o display_data.o inject.o arp_poison.o arp_reply.o arp_receive.o arp_request.o -lnet -lpcap -pthread
	rm -f arp_receive.o 
	rm -f arp_reply.o 
	rm -f arp_request.o 
	rm -f arp_poison.o 
	rm -f inject.o
	rm -f display_data.o
	rm -f forward.o 
	rm -f compare_mac.o
	rm -f ec_malloc.o
	rm -f error.o
	rm -f init.o
	rm -f usage.o 
	rm -f main.o

main.o: usage.o
	gcc -c -o main.o main.c -lnet -lpcap

usage.o: ec_malloc.o
	gcc -c -o usage.o usage.c

ec_malloc.o: error.o
	gcc -c -o ec_malloc.o modularity/src/ec_malloc.c 

error.o: init.o
	gcc -c -o error.o modularity/src/error.c 

init.o: forward.o
	gcc -c -o init.o modularity/src/init.c -lnet -lpcap

forward.o: compare_mac.o
	gcc -c -o forward.o forwarding/src/forward.c -lnet -lpcap

compare_mac.o: display_data.o
	gcc -c -o compare_mac.o forwarding/src/compare_mac.c -lnet -lpcap

display_data.o: inject.o
	gcc -c -o display_data.o decode/src/display_data.c -lnet -lpcap

inject.o: arp_poison.o
	gcc -c -o inject.o inject/src/inject.c -lnet

arp_poison.o: arp_reply.o
	gcc -c -o arp_poison.o arp/src/arp_poison.c -lnet -lpcap

arp_reply.o: arp_receive.o
	gcc -c -o arp_reply.o arp/src/arp_reply.c -lnet -lpcap

arp_receive.o: arp_request.o
	gcc -c -o arp_receive.o arp/src/arp_receive.c -lnet -lpcap

arp_request.o: arp/src/arp_request.c
	gcc -c -o arp_request.o arp/src/arp_request.c -lnet -lpcap
	
