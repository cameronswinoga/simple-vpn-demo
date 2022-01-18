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

static bool openSerialPort(char *portPath, int *serial_fd)
{
    *serial_fd = open(portPath, O_RDWR);
    if (*serial_fd < 0) {
        printf("Error %i from open: %s\n", errno, strerror(errno));
        return false;
    }
    if(flock(*serial_fd, LOCK_EX | LOCK_NB) == -1) {
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

    tty.c_cc[VTIME] = 10;  // Wait for up to 1s (10 deciseconds), returning as soon as any data is received.
    tty.c_cc[VMIN]  = 0;

    // TODO: Cant set baud for whatever reason
//    cfsetspeed(&tty, B921600); // Set baud

    if (tcsetattr(*serial_fd, TCSANOW, &tty) != 0) {
        printf("Error %i from tcsetattr: %s\n", errno, strerror(errno));
        return false;
    }
    printf("Opened %s\n", portPath);

    return true;
}

int main(int argc, char **argv)
{
    UNUSED(argc);
    UNUSED(argv);

    cleanup_when_sig_exit();

    if (!openSerialPort("/dev/ttyS4", &serialFd)) {
        close(serialFd);
        return 1;
    }
    unsigned char msg[] = "Hellllllllllllllllllo\n";
    write(serialFd, msg, sizeof(msg));

    char read_buf[256];
    const ssize_t numBytesRead = read(serialFd, &read_buf, sizeof(read_buf));
    if (numBytesRead < 0) {
        printf("Read error: %zi\n", numBytesRead);
    }
    printf(">%zi\n", numBytesRead);

    close(serialFd);

    return 0;
}