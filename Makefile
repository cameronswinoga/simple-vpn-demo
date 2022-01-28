CFLAGS=-Wall -Wextra

client : client.c
	gcc -o $@ $^ -g $(CFLAGS)
server : server.c
	x86_64-w64-mingw32-gcc -o $@ $^ -g $(CFLAGS) -D__USE_MINGW_ANSI_STDIO=1 -lws2_32 -L. -lPacket -lwpcap -I./libpcap -I./libpcap/pcap

clean :
	rm -f client server
