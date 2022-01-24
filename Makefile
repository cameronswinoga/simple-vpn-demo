CFLAGS=-Wall -Wextra

client : client.c
	gcc -o $@ $^ -g $(CFLAGS)
server : server.c
	x86_64-w64-mingw32-gcc -o $@ $^ -g $(CFLAGS)

clean :
	rm -f client server
