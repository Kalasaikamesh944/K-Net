CC = g++
CFLAGS = -Wall -O2 -Iinclude
LDFLAGS = -lcrypto

all: libknet.a send_packet receive_packet

libknet.a: src/knet.o
	ar rcs libknet.a src/knet.o

src/knet.o: src/knet.cpp include/knet.h
	$(CC) $(CFLAGS) -c src/knet.cpp -o src/knet.o $(LDFLAGS)

send_packet: examples/send_packet.cpp libknet.a
	$(CC) $(CFLAGS) examples/send_packet.cpp -o send_packet -L. -lknet $(LDFLAGS)

receive_packet: examples/receive_packet.cpp libknet.a
	$(CC) $(CFLAGS) examples/receive_packet.cpp -o receive_packet -L. -lknet $(LDFLAGS)

clean:
	rm -f src/*.o libknet.a send_packet receive_packet
