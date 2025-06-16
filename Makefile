all : ARP_Spoofing

ARP_Spoofing : main.o
	g++ -g -std=c++14 -o ARP_Spoofing main.o -lpcap -lpthread

main.o : ase_header.h
	g++ -g -c -std=c++14 -o main.o main.cpp

clean :
	rm -f *.o ARP_Spoofing
