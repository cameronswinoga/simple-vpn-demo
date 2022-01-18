#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <termios.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/file.h>

#include "common.h"

#include <netdb.h>
#include <netinet/in.h>    // IPPROTO_*
#include <net/if.h>        // ifreq
#include <linux/if_tun.h>  // IFF_TUN, IFF_NO_PI

#define SERIAL_PATH "/dev/ttyS3"
int serialFd;

static void cleanup(int signo)
{
    printf("Exiting....\n");
    if (signo == SIGHUP || signo == SIGINT || signo == SIGTERM) {
        close(serialFd);
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

static bool openSerialPort(char *portPath, int *serial_fd, int vmin, int vtime)
{
    *serial_fd = open(portPath, O_RDWR);
    if (*serial_fd < 0) {
        printf("Error %i from open: %s\n", errno, strerror(errno));
        return false;
    }
    if (flock(*serial_fd, LOCK_EX | LOCK_NB) == -1) {
        printf("%s already locked by another process", portPath);
        return false;
    }

    struct termios tty;
    if (tcgetattr(*serial_fd, &tty) != 0) {
        printf("Error %i from tcgetattr: %s\n", errno, strerror(errno));
        return false;
    }
    tty.c_cflag &= ~PARENB;  // No parity
    tty.c_cflag &= ~CSTOPB;  // No stop bit
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;             // 8 bpb
    tty.c_cflag &= ~CRTSCTS;        // Disable HW flow control
    tty.c_cflag |= CREAD | CLOCAL;  // Turn on READ & ignore ctrl lines

    tty.c_lflag &= ~ICANON;  // Non-cannonical mode
    tty.c_lflag &= ~ECHO;    // Disable echo
    tty.c_lflag &= ~ECHOE;   // Disable erasure
    tty.c_lflag &= ~ECHONL;  // Disable new-line echo
    tty.c_lflag &= ~ISIG;    // Disable interpretation of INTR, QUIT and SUSP

    tty.c_iflag &= ~(IXON | IXOFF | IXANY);                                       // Turn off SW flow ctrl
    tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL);  // Disable any special handling of received bytes

    tty.c_oflag &= ~OPOST;  // Prevent special interpretation of output bytes (e.g. newline chars)
    tty.c_oflag &= ~ONLCR;  // Prevent conversion of newline to carriage return/line feed

    tty.c_cc[VMIN]  = vmin;
    tty.c_cc[VTIME] = vtime;

    // TODO: Cant set baud for whatever reason
    //    cfsetspeed(&tty, B921600); // Set baud

    if (tcsetattr(*serial_fd, TCSANOW, &tty) != 0) {
        printf("Error %i from tcsetattr: %s\n", errno, strerror(errno));
        return false;
    }
    printf("Opened %s\n", portPath);

    return true;
}

static void hex(char *source, char *dest, ssize_t count)
{
    bzero(dest, count);
    for (ssize_t i = 0; i < count; ++i) {
        sprintf(dest + (i * 2), "%02hhx", source[i]);
    }
}

static void dump_ports(int protocol, int count, const char *buffer)
{
    if (!ARG_IN_LIST(protocol, IPPROTO_UDP, IPPROTO_UDPLITE, IPPROTO_TCP) || count < 4) {
        printf("Can't dump ports: %i %i\n", protocol, count);
        return;
    }
    uint16_t source_port;
    memcpy(&source_port, buffer, 2);
    source_port = htons(source_port);
    uint16_t dest_port;
    memcpy(&dest_port, buffer + 2, 2);
    dest_port = htons(dest_port);
    printf(" sport=%u, dport=%d\n", (unsigned) source_port, (unsigned) dest_port);
}

static void dump_packet_ipv4(int count, char *buffer)
{
    if (count < 20) {
        printf("IPv4 packet too short\n");
        return;
    }

    const int protocol              = (unsigned char) buffer[9];
    struct protoent *protocol_entry = getprotobynumber(protocol);

    const unsigned ttl = (unsigned char) buffer[8];

    printf("IPv4: src=%u.%u.%u.%u dst=%u.%u.%u.%u proto=%u(%s) ttl=%u\n", (unsigned char) buffer[12], (unsigned char) buffer[13],
           (unsigned char) buffer[14], (unsigned char) buffer[15], (unsigned char) buffer[16], (unsigned char) buffer[17],
           (unsigned char) buffer[18], (unsigned char) buffer[19], (unsigned) protocol,
           protocol_entry == NULL ? "?" : protocol_entry->p_name, ttl);
    dump_ports(protocol, count - 20, buffer + 20);
}

static void dump_packet_ipv6(int count, char *buffer)
{
    if (count < 40) {
        printf("IPv6 packet too short\n");
        return;
    }

    const int protocol              = (unsigned char) buffer[6];
    struct protoent *protocol_entry = getprotobynumber(protocol);

    char source_address[33];
    hex(buffer + 8, source_address, 16);
    char destination_address[33];
    hex(buffer + 24, destination_address, 16);

    const int hop_limit = (unsigned char) buffer[7];

    printf("IPv6: src=%s dst=%s proto=%u(%s) hop_limit=%i\n", source_address, destination_address, (unsigned) protocol,
           protocol_entry == NULL ? "?" : protocol_entry->p_name, hop_limit);
    dump_ports(protocol, count - 40, buffer + 40);
}

int main(int argc, char **argv)
{
    UNUSED(argc, argv);

    cleanup_when_sig_exit();

    printf("Server startup: %s\n", SERIAL_PATH);
    if (!openSerialPort(SERIAL_PATH, &serialFd, 1, 0)) {
        close(serialFd);
        return 1;
    }
    //    unsigned char msg[] = "Hellllllllllllllllllo\n";
    //    write(serialFd, msg, sizeof(msg));

    char serialBuf[1024];
    char pktBuf[1024];

    int bytesInPkt = 0;
    while (true) {
        const ssize_t numBytesRead = read(serialFd, &serialBuf, sizeof(serialBuf));
        if (numBytesRead < 0) {
            printf("Read error: %zi\n", numBytesRead);
            break;
        }
        printf(">%zi:", numBytesRead);
        for (int i = 0; i < numBytesRead; i++) {
            printf("%02hhx", serialBuf[i]);
        }
        printf("\n");
        fflush(stdout);

        unsigned char version = ((unsigned char) serialBuf[0]) >> 4;
        if (version == 4) {
            dump_packet_ipv4(numBytesRead, serialBuf);
        }
        else if (version == 6) {
            dump_packet_ipv6(numBytesRead, serialBuf);
        }
        else {
            printf("Unknown packet version\n");
        }

        //        memcpy((char *)(&pktBuf + bytesInPkt), serialBuf, numBytesRead);
        //        bytesInPkt += (int) numBytesRead;
        //        if (bytesInPkt < 4) {
        //            // Not enough bytes in packet
        //            continue;
        //        }
        //
        //        typedef union {
        //            struct {
        //                u_int16_t flags;
        //                u_int16_t proto;
        //            };
        //            u_int8_t asBytes[4];
        //        } header_t;
        //
        //        bytesInPkt = 0;
        //        bzero(pktBuf, sizeof(pktBuf));
    }

    close(serialFd);

    return 0;
}