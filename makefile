LDLIBS=-lpcap

all: arp-spoofing

arp-spoofing: main.o src/arphdr.o src/ethhdr.o src/ip.o src/mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoofing *.o src/*.o
