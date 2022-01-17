#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define PORT 54345
#define MTU  1400

#if defined(AS_CLIENT)
#define SERVER_HOST       "127.0.0.1"
#define TUN_INTERFACE     "tun_client"
#define INTERFACE_ADDRESS "10.8.0.2/16"
#else
#define BIND_HOST         "0.0.0.0"
#define SERVER_SUBNET     "10.8.0.0/16"
#define TUN_INTERFACE     "tun_server"
#define INTERFACE_ADDRESS "10.8.0.1/16"
#endif

#define UNUSED(x) (void) (x)
#define MAX(a, b) a > b ? a : b

/*
 * Create VPN interface /dev/tun0 and return a fd
 */
static int tun_alloc(void)
{
    printf("Creating tun interface %s\n", TUN_INTERFACE);

    const int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("Cannot open /dev/net/tun");
        return fd;
    }

    struct ifreq ifr = {
        .ifr_flags = IFF_TUN | IFF_NO_PI,
    };
    strncpy(ifr.ifr_name, TUN_INTERFACE, IFNAMSIZ);

    const int e = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if (e < 0) {
        perror("ioctl[TUNSETIFF]");
        close(fd);
        return e;
    }

    return fd;
}

/*
 * Execute commands
 */
static void run(char *cmd, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, cmd);
    vsnprintf(buf, sizeof(buf), cmd, args);
    va_end(args);

    printf("Execute `%s`\n", buf);
    if (system(buf)) {
        perror(buf);
        exit(1);
    }
}

/*
 * Setup route table via `iptables` & `ip route`
 */
static void setup_route_table(void)
{
    printf("Adding routing tables\n");

    run("sysctl -w net.ipv4.ip_forward=1");

#ifdef AS_CLIENT
    run("iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", TUN_INTERFACE);
    run("iptables -I FORWARD 1 -i %s -m state --state RELATED,ESTABLISHED -j ACCEPT", TUN_INTERFACE);
    run("iptables -I FORWARD 1 -o %s -j ACCEPT", TUN_INTERFACE);
    run("ip route add %s via 192.168.1.1", SERVER_HOST);
    run("ip route add 0/1 dev %s", TUN_INTERFACE);
    run("ip route add 128/1 dev %s", TUN_INTERFACE);
    run("ip route add 192.168.1.30/32 dev %s proto static", TUN_INTERFACE);
#else
    run("iptables -t nat -A POSTROUTING -s %s ! -d %s -m comment --comment 'vpndemo' -j MASQUERADE", SERVER_SUBNET, SERVER_SUBNET);
    run("iptables -A FORWARD -s %s -m state --state RELATED,ESTABLISHED -j ACCEPT", SERVER_SUBNET);
    run("iptables -A FORWARD -d %s -j ACCEPT", SERVER_SUBNET);
#endif
}

/*
 * Cleanup route table
 */
static void cleanup_route_table(void)
{
#ifdef AS_CLIENT
    run("iptables -t nat -D POSTROUTING -o %s -j MASQUERADE", TUN_INTERFACE);
    run("iptables -D FORWARD -i %s -m state --state RELATED,ESTABLISHED -j ACCEPT", TUN_INTERFACE);
    run("iptables -D FORWARD -o %s -j ACCEPT", TUN_INTERFACE);
    run("ip route del %s", SERVER_HOST);
    run("ip route del 0/1");
    run("ip route del 128/1");
#else
    run("iptables -t nat -D POSTROUTING -s %s ! -d %s -m comment --comment 'vpndemo' -j MASQUERADE", SERVER_SUBNET, SERVER_SUBNET);
    run("iptables -D FORWARD -s %s -m state --state RELATED,ESTABLISHED -j ACCEPT", SERVER_SUBNET);
    run("iptables -D FORWARD -d %s -j ACCEPT", SERVER_SUBNET);
#endif
}

/*
 * Bind UDP port
 */
static int udp_bind(struct sockaddr *addr, socklen_t *addrlen)
{
    struct addrinfo hints = {
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP,
    };

#ifdef AS_CLIENT
    const char *host = SERVER_HOST;
#else
    const char *host = BIND_HOST;
#endif
    struct addrinfo *result;
    if (0 != getaddrinfo(host, NULL, &hints, &result)) {
        perror("getaddrinfo error");
        return -1;
    }

    if (result->ai_family == AF_INET) {
        ((struct sockaddr_in *) result->ai_addr)->sin_port = htons(PORT);
    }
    else if (result->ai_family == AF_INET6) {
        ((struct sockaddr_in6 *) result->ai_addr)->sin6_port = htons(PORT);
    }
    else {
        fprintf(stderr, "unknown ai_family %d", result->ai_family);
        freeaddrinfo(result);
        return -1;
    }
    memcpy(addr, result->ai_addr, result->ai_addrlen);
    *addrlen = result->ai_addrlen;

    const int sock = socket(result->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (-1 == sock) {
        perror("Cannot create socket");
        freeaddrinfo(result);
        return -1;
    }

#ifndef AS_CLIENT
    if (0 != bind(sock, result->ai_addr, result->ai_addrlen)) {
        perror("Cannot bind");
        close(sock);
        freeaddrinfo(result);
        return -1;
    }
#endif

    freeaddrinfo(result);

    const int flags = fcntl(sock, F_GETFL, 0);
    if (flags != -1) {
        if (-1 != fcntl(sock, F_SETFL, flags | O_NONBLOCK)) {
            return sock;
        }
    }
    perror("fcntl error");

    close(sock);
    return -1;
}

/*
 * Catch Ctrl-C and `kill`s, make sure route table gets cleaned before this process exit
 */
static void cleanup(int signo)
{
    printf("Exiting....\n");
    if (signo == SIGHUP || signo == SIGINT || signo == SIGTERM) {
        cleanup_route_table();
        exit(0);
    }
}

static void cleanup_when_sig_exit(void)
{
    struct sigaction sa = {
        .sa_handler = &cleanup,
        .sa_flags   = SA_RESTART,
    };
    sigfillset(&sa.sa_mask);

    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        perror("Cannot handle SIGHUP");
    }
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        perror("Cannot handle SIGINT");
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("Cannot handle SIGTERM");
    }
}

/*
 * For a real-world VPN, traffic inside UDP tunnel is encrypted
 * A comprehensive encryption is not easy and not the point for this demo
 * I'll just leave the stubs here
 */
static void encrypt(char *plantext, char *ciphertext, size_t len)
{
    memcpy(ciphertext, plantext, len);
}

static void decrypt(char *ciphertext, char *plantext, size_t len)
{
    memcpy(plantext, ciphertext, len);
}

typedef struct {
    int fd;
    char buf[MTU];
    struct sockaddr_storage clientAddr;
    socklen_t clientAddrLen;
} udpSettings_t;

static bool tunToUdp(fd_set readSet, int tunFd, char *tunBuf, udpSettings_t udpSettings)
{
    if (FD_ISSET(tunFd, &readSet)) {
        const ssize_t tunBytesRead = read(tunFd, tunBuf, MTU);
        if (tunBytesRead < 0) {
            // TODO: ignore some errno
            perror("read from tunFd error");
            return false;
        }

        encrypt(tunBuf, udpSettings.buf, tunBytesRead);
        printf("%zu>", tunBytesRead);
        fflush(stdout);

        const ssize_t bytesWritten = sendto(udpSettings.fd, udpSettings.buf, tunBytesRead, 0,
                                            (const struct sockaddr *) &udpSettings.clientAddr, udpSettings.clientAddrLen);
        if (bytesWritten < 0) {
            // TODO: ignore some errno
            perror("sendto udpFd error");
            return false;
        }
    }

    return true;
}

static bool udpToTun(fd_set readSet, udpSettings_t udpSettings, int tunFd, char *tunBuf)
{
    if (FD_ISSET(udpSettings.fd, &readSet)) {
        const ssize_t udpBytesRead = recvfrom(udpSettings.fd, udpSettings.buf, MTU, 0, (struct sockaddr *) &udpSettings.clientAddr,
                                              &udpSettings.clientAddrLen);
        if (udpBytesRead < 0) {
            // TODO: ignore some errno
            perror("recvfrom udp_fd error");
            return false;
        }

        decrypt(udpSettings.buf, tunBuf, udpBytesRead);
        printf("%zu<", udpBytesRead);
        fflush(stdout);

        const ssize_t bytesWritten = write(tunFd, tunBuf, udpBytesRead);
        if (bytesWritten < 0) {
            // TODO: ignore some errno
            perror("write tun_fd error");
            return false;
        }
    }
    return true;
}

int main(int argc, char **argv)
{
    UNUSED(argc);
    UNUSED(argv);

#if defined(AS_CLIENT)
    printf("Client startup, server=%s\n", SERVER_HOST);
#else
    printf("Server startup\n");
#endif

    const int tun_fd = tun_alloc();
    if (tun_fd < 0) {
        return 1;
    }

    // Set interface address and MTU
    run("ifconfig %s %s mtu %d up", TUN_INTERFACE, INTERFACE_ADDRESS, MTU);
    setup_route_table();
    cleanup_when_sig_exit();

    udpSettings_t udpData = {
        .clientAddrLen = sizeof(udpData.clientAddr),
        .fd            = udp_bind((struct sockaddr *) &udpData.clientAddr, &udpData.clientAddrLen),
    };
    if (udpData.fd < 0) {
        printf("Error binding UDP: %d\n", udpData.fd);
        return 1;
    }

    /*
     * tun_buf - memory buffer read from/write to tun dev - is always plain
     * udp_buf - memory buffer read from/write to udp fd - is always encrypted
     */
    char tun_buf[MTU];
    bzero(tun_buf, MTU);
    bzero(udpData.buf, MTU);

    while (true) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(tun_fd, &readSet);
        FD_SET(udpData.fd, &readSet);
        const int max_fd = MAX(tun_fd, udpData.fd) + 1;

        if (-1 == select(max_fd, &readSet, NULL, NULL, NULL)) {
            perror("select error");
            break;
        }

        if (!tunToUdp(readSet, tun_fd, tun_buf, udpData)) {
            printf("tunToUdp error\n");
            break;
        }
        if (!udpToTun(readSet, udpData, tun_fd, tun_buf)) {
            printf("udpToTun error\n");
            break;
        }
    }

    close(tun_fd);
    close(udpData.fd);

    cleanup_route_table();

    return 0;
}
