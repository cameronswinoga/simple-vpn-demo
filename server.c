#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

#include "common.h"

#define SERIAL_PATH "\\\\.\\COM3"
HANDLE hComm;
volatile bool done = false;

static BOOL WINAPI cleanup(DWORD signo)
{
    if (signo == CTRL_C_EVENT) {
        printf("Exiting.... %lu\n", signo);
        CloseHandle(hComm);
        done = true;
        return TRUE;
    }
    return FALSE;  // Not handled
}

static bool cleanup_when_sig_exit(void)
{
    if (!SetConsoleCtrlHandler(cleanup, TRUE)) {
        printf("\nERROR: Could not set control handler");
        return false;
    }
    return true;
}

static bool openSerialPort(char *portPath, HANDLE *serialHandle)
{
    *serialHandle = CreateFileA(portPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (*serialHandle == INVALID_HANDLE_VALUE) {
        printf("CreateFileA error: %s\n", portPath);
        return false;
    }

    // Flush away any bytes previously read or written.
    if (!FlushFileBuffers(*serialHandle)) {
        printf("Failed to flush serial port\n");
        CloseHandle(*serialHandle);
        return false;
    }

    // Configure read and write operations to time out after 100 ms.
    COMMTIMEOUTS timeouts = {
        .ReadIntervalTimeout         = 0,
        .ReadTotalTimeoutConstant    = 100,
        .ReadTotalTimeoutMultiplier  = 0,
        .WriteTotalTimeoutConstant   = 100,
        .WriteTotalTimeoutMultiplier = 0,
    };

    if (!SetCommTimeouts(*serialHandle, &timeouts)) {
        printf("Failed to set serial timeouts\n");
        CloseHandle(*serialHandle);
        return false;
    }

    // Set the baud rate and other options.
    DCB state = {
        .DCBlength = sizeof(DCB),
        .BaudRate  = 115200,
        .ByteSize  = 8,
        .Parity    = NOPARITY,
        .StopBits  = ONESTOPBIT,
    };
    if (!SetCommState(*serialHandle, &state)) {
        printf("Failed to set serial settings\n");
        CloseHandle(*serialHandle);
        return false;
    }

    return true;
}

static int write_port(HANDLE port, uint8_t *buffer, size_t size)
{
    DWORD bytesWritten;
    if (!WriteFile(port, buffer, size, &bytesWritten, NULL)) {
        printf("Failed to write to port\n");
        return -1;
    }
    if (bytesWritten != size) {
        printf("Failed to write all bytes to port %lu!=%zu\n", bytesWritten, size);
        return -1;
    }
    return bytesWritten;
}

static SSIZE_T read_port(HANDLE port, char *buffer, size_t size)
{
    DWORD bytesRead;
    if (!ReadFile(port, buffer, size, &bytesRead, NULL)) {
        printf("Failed to read from port\n");
        return -1;
    }
    return bytesRead;
}

static void hex(char *source, char *dest, ssize_t count)
{
    memset(dest, 0, count);
    for (ssize_t i = 0; i < count; ++i) {
        sprintf(dest + (i * 2), "%02hhx", source[i]);
    }
}

static void dump_ports(int protocol, int count, const char *buffer)
{
    if (!ARG_IN_LIST(protocol, IPPROTO_UDP, IPPROTO_TCP) || count < 4) {
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

static bool serToSkt(char *serBuf, int serBufSize, int sktFd, char *sktBuf)
{
    const SSIZE_T serBytesRead = read_port(hComm, serBuf, serBufSize);
    if (serBytesRead < 0) {
        printf("Read error: %zi\n", serBytesRead);
        return false;
    }
    else if (serBytesRead == 0) {
        return true;  // No data
    }

    memcpy(sktBuf, serBuf, serBytesRead);
    printf(">%zi:", serBytesRead);
    for (int i = 0; i < serBytesRead; i++) {
        printf("%02hhx", serBuf[i]);
    }
    printf("\n");
    fflush(stdout);

    unsigned char version = ((unsigned char) serBuf[0]) >> 4;
    if (version == 4) {
        dump_packet_ipv4(serBytesRead, serBuf);
    }
    else if (version == 6) {
        dump_packet_ipv6(serBytesRead, serBuf);
    }
    else {
        printf("Unknown packet version\n");
    }

    //    const ssize_t sktBytesWritten = write(sktFd, sktBuf, serBytesRead);
    //    if (sktBytesWritten < 0) {
    //        // TODO: ignore some errno
    //        perror("write sktFd error");
    //        return false;
    //    }

    return true;
}

// static bool sktToSer(int sktFd, char *sktBuf, char *serBuf)
//{
//     ssize_t sktBytesRead = read(sktFd, sktBuf, 256);
//     if (sktBytesRead < 0) {
//         printf("Error reading: %zi\n", sktBytesRead);
//         return 1;
//     }
//
//     memcpy(serBuf, sktBuf, sktBytesRead);
//     printf("%zu<", sktBytesRead);
//     fflush(stdout);
//
//     const ssize_t serialBytesWritten = write(serialFd, serBuf, sktBytesRead);
//     if (serialBytesWritten < 0) {
//         // TODO: ignore some errno
//         perror("write tun_fd error");
//         printf("%i %zi\n", serialFd, sktBytesRead);
//         return false;
//     }
//
//     return true;
// }

int main(int argc, char **argv)
{
    UNUSED(argc, argv);

    if (!cleanup_when_sig_exit()) {
        return 1;
    }

    printf("Server startup: %s\n", SERIAL_PATH);
    if (!openSerialPort(SERIAL_PATH, &hComm)) {
        CloseHandle(hComm);
        return 1;
    }

    //    // Open a raw socket, no IP protocol specified
    //    int ip_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    //    if (ip_fd == -1) {
    //        close(serialFd);
    //        perror("socket(ip_fd) error");
    //        return 1;
    //    }
    //    int hdrincl = 1; // Enable manual header inclusion, header will not be generated for us
    //    if (setsockopt(ip_fd, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl)) == -1) {
    //        close(serialFd);
    //        perror("setsockopt(ip_fd) error");
    //        return 1;
    //    }
    //    // Set socket as nonblocking
    //    if (fcntl(ip_fd, F_SETFL, O_NONBLOCK) < 0) {
    //        perror("fcntl(ip_fd) error");
    //        return 1;
    //    }
    //
    char serialBuf[1024];
    char ipBuf[1024];

    while (!done) {
        if (!serToSkt(serialBuf, sizeof(serialBuf), 0, ipBuf)) {
            printf("serToSkt error\n");
            break;
        }

        //            if (!sktToSer(ip_fd, ipBuf, serialBuf)) {
        //                printf("sktToSer error\n");
        //                break;
        //            }
    }

    CloseHandle(hComm);

    printf("Server stop\n");
    return 0;
}