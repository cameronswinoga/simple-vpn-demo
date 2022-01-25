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

static bool parsePorts(int protocol, int count, const char *buffer, uint16_t *srcPort, uint16_t *dstPort)
{
    if (!ARG_IN_LIST(protocol, IPPROTO_UDP, IPPROTO_TCP) || count < 4) {
        printf("Can't dump ports: %i %i\n", protocol, count);
        return false;
    }
    memcpy(srcPort, buffer, 2);
    *srcPort = htons(*srcPort);
    memcpy(dstPort, buffer + 2, 2);
    *dstPort = htons(*dstPort);
    return true;
}

static bool parseIpv4Pkt(int count, char *buffer, uint32_t *dstIpPtr, uint16_t *dstPortPtr)
{
    if (count < 20) {
        printf("IPv4 packet too short\n");
        return false;
    }

    typedef struct {
        union {
            uint8_t arr[4];
            uint32_t lon;
        } u;
    } Ipv4Addr;

    const unsigned ttl = (unsigned char) buffer[8];
    const int protocol = (unsigned char) buffer[9];
    Ipv4Addr srcIp;
    memcpy(&srcIp, buffer + 12, sizeof srcIp);
    Ipv4Addr dstIp;
    memcpy(&dstIp, buffer + 16, sizeof dstIp);
    *dstIpPtr = dstIp.u.lon;

    uint16_t srcPort      = 0;
    const bool validPorts = parsePorts(protocol, count - 20, buffer + 20, &srcPort, dstPortPtr);

    struct protoent *protocol_entry = getprotobynumber(protocol);
    printf("IPv4: src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u proto=%u(%s) ttl=%u\n", srcIp.u.arr[0], srcIp.u.arr[1], srcIp.u.arr[2],
           srcIp.u.arr[3], srcPort, dstIp.u.arr[0], dstIp.u.arr[1], dstIp.u.arr[2], dstIp.u.arr[3], *dstPortPtr,
           (unsigned) protocol, protocol_entry == NULL ? "?" : protocol_entry->p_name, ttl);

    if (!validPorts) {
        return false;
    }
    return true;
}

static bool parseIpv6Pkt(int count, char *buffer)
{
    if (count < 40) {
        printf("IPv6 packet too short\n");
        return false;
    }

    const int protocol  = (unsigned char) buffer[6];
    const int hop_limit = (unsigned char) buffer[7];

    char source_address[33];
    hex(buffer + 8 + 0, source_address, 16);
    char destination_address[33];
    hex(buffer + 8 + 16, destination_address, 16);

    uint16_t srcPort      = 0;
    uint16_t dstPort      = 0;
    const bool validPorts = parsePorts(protocol, count - 40, buffer + 40, &srcPort, &dstPort);

    struct protoent *protocol_entry = getprotobynumber(protocol);
    printf("IPv6: src=%s:%u dst=%s:%u proto=%i(%s) hop_limit=%i\n", source_address, srcPort, destination_address, dstPort, protocol,
           protocol_entry == NULL ? "?" : protocol_entry->p_name, hop_limit);

    if (!validPorts) {
        return false;
    }
    return true;
}

static bool serToSkt(char *serBuf, int serBufSize, SOCKET sktFd, char *sktBuf)
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
    uint32_t dstIp;
    uint16_t dstPort;
    if (version == 4) {
        if (!parseIpv4Pkt(serBytesRead, serBuf, &dstIp, &dstPort)) {
            return true;
        }
    }
    else if (version == 6) {
        parseIpv6Pkt(serBytesRead, serBuf);
        return true;  // IPv6 not handled yet
    }
    else {
        printf("Unknown packet version\n");
    }

    // send the pkt
    struct sockaddr_in dest = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = dstIp,
        .sin_port        = htons(dstPort),
    };
    printf("Sending %lli bytes\n", serBytesRead);
    const int sktBytesSent = sendto(sktFd, sktBuf, serBytesRead, 0, (struct sockaddr *) &dest, sizeof(dest));
    if (sktBytesSent == SOCKET_ERROR) {
        printf("sendto failed\n");
        return false;
    }

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

    // Initialize winsock2
    struct WSAData wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
        printf("WSAStartup failed\n");
        return 1;
    }

    // Open UDP socket, since we don't have admin privileges
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        printf("Socket invalid\n");
    }
    // bind to the local address
    struct sockaddr_in local = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,  // Any source IP (Only for IPv4!)
        .sin_port        = 0,           // Any source port
    };
    if (bind(s, (struct sockaddr *) &local, sizeof(local)) != 0) {
        printf("bind failed\n");
    }

    char serialBuf[1024];
    char ipBuf[1024];

    while (!done) {
        if (!serToSkt(serialBuf, sizeof(serialBuf), s, ipBuf)) {
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