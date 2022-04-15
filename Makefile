
meineVerbindung: main.o
	gcc -o meineVerbindung main.o arp.o hacking.o receive.o -lnet -lpcap
	rm -f main.o
	rm -f arp.o
	rm -f hacking.o
	rm -f receive.o

main.o: receive.o	
	gcc -c -o main.o main.c  -lnet -lpcap

receive.o: arp.o
	gcc -c -o receive.o receive.c  -lnet -lpcap

arp.o: hacking.o
	gcc -c -o arp.o arp.c  -lnet -lpcap

hacking.o: hacking.c
	gcc -c -o hacking.o hacking.c 
