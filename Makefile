CFLAGS+= -Wall -g
CFLAGS+= $(shell pkg-config --cflags glib-2.0)
LDFLAGS+= -lpcap
LDFLAGS+= $(shell pkg-config --libs glib-2.0)

.PHONY: all
all: read_pcap

read_pcap: read_pcap.o link.o net.o transport.o

read_pcap.o: read_pcap.c read_pcap.h

link.o: link.c link.h

net.o: net.c net.h

transport.o: transport.c transport.h

.PHONY: clean
clean:
	rm -f read_pcap
