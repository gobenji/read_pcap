CFLAGS+= -Wall -g
CFLAGS+= $(shell pkg-config --cflags glib-2.0)
LDFLAGS+= -lpcap
LDFLAGS+= $(shell pkg-config --libs glib-2.0)

.PHONY: all
all: read_pcap

read_pcap: read_pcap.o link.o net.o transport.o

HEADERS=read_pcap.h link.h net.h transport.h lookup3.h

read_pcap.o: read_pcap.c $(HEADERS)

link.o: link.c $(HEADERS)

net.o: net.c $(HEADERS)

transport.o: transport.c $(HEADERS)

.PHONY: clean
clean:
	rm -f read_pcap
	rm -f read_pcap.o link.o net.o transport.o
