all: arp_spoof

arp_spoof: arp-spoof.o function.o
	g++ -g -o arp_spoof arp-spoof.o function.o -lpcap -lpthread

main.o: arp_spoof.h arp-spoof.cpp
	g++ -c -g -o arp-spoof.o arp-spoof.cpp

functions.o: arp_spoof.h function.cpp
	g++ -c -g -o function.o function.cpp

clean:
	rm -f *.o
	rm -f arp_spoof
