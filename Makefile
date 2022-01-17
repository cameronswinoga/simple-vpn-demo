client : vpn.c
	gcc -o $@ $^ -g -Wall -Wextra -DAS_CLIENT -DSERVER_HOST=\"127.0.0.1\"
server : vpn.c
	gcc -o $@ $^ -g -Wall -Wextra

clean :
	rm vpn
