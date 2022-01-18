CFLAGS=-Wall -Wextra

client : client.c
	gcc -o $@ $^ -g $(CFLAGS)
server : server.c
	gcc -o $@ $^ -g $(CFLAGS)

clean :
	rm -f client server
