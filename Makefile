client : vpn.c
	gcc -o $@ $^ -g -Wall -Wextra -DAS_CLIENT
server : vpn.c
	gcc -o $@ $^ -g -Wall -Wextra

clean :
	rm vpn
