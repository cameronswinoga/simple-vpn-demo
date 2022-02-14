#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "common.h"
#include "circular_buffer.h"

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

static SSIZE_T read_port(HANDLE port, cbuf_handle_t circularBuf)
{
    DWORD bytesRead;
    uint8_t buffer[512];
    if (!ReadFile(port, buffer, sizeof buffer, &bytesRead, NULL)) {
        printf("Failed to read from port\n");
        return -1;
    }
    if (bytesRead != 0) {
        printf("SERIAL>%li:", bytesRead);
        for (unsigned i = 0; i < bytesRead; i++) {
            printf("%02hhx", buffer[i]);
        }
        printf("\n");
        fflush(stdout);
    }
    circular_buf_put_all(circularBuf, buffer, bytesRead);
    return bytesRead;
}

static void hex(uint8_t *source, char *dest, ssize_t count)
{
    memset(dest, 0, count);
    for (ssize_t i = 0; i < count; ++i) {
        sprintf(dest + (i * 2), "%02hhx", source[i]);
    }
}

static bool parsePorts(int protocol, int count, const uint8_t *buffer, uint16_t *srcPort, uint16_t *dstPort)
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

static uint16_t ip_checksum(uint8_t *vdata, size_t length)
{

    uint8_t *data = vdata;   // Cast the data pointer to one that can be indexed
    uint32_t acc  = 0xffff;  // Initialise the accumulator

    // Handle complete 16-bit blocks.
    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length & 0x01) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

static uint32_t net_checksum_add(int len, const uint8_t *buf)
{
    uint32_t sum = 0;

    for (int i = 0; i < len; i++) {
        if (i & 0x1) {
            sum += (uint32_t) buf[i];
        }
        else {
            sum += (uint32_t) buf[i] << 8;
        }
    }
    return sum;
}

static uint16_t net_checksum_finish(uint32_t sum)
{
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    // take one's complement
    return (uint16_t) ~sum;
}

static uint16_t checksum_tcpudp(uint16_t length, uint16_t proto, const uint8_t *addrs, const uint8_t *buf)
{
    uint32_t sum = 0;

    sum += net_checksum_add(length, buf);  // payload
    sum += net_checksum_add(8, addrs);     // src + dst address
    sum += proto + length;                 // protocol & length
    return net_checksum_finish(sum);
}

static uint16_t modifyIpv4Pkt(uint8_t *buf, unsigned length)
{
    const uint16_t ipv4HdrLen    = (buf[0] & 0x0f) * 4;
    const uint16_t ipDatagramLen = (buf[2] << 8) | (buf[3] << 0);
    printf("IPv4 hdr len: %u, datagram len: %u\n", ipv4HdrLen, ipDatagramLen);
    if (length < ipDatagramLen) {
        printf("Buffer length %u less than IPv4 datagram length\n", length);
        return 0;
    }

    // Modify the source address
    buf[12] = 10;
    buf[13] = 56;
    buf[14] = 116;
    buf[15] = 104;

    uint8_t ipChkSumBuf[20];
    memcpy(ipChkSumBuf, buf, sizeof(ipChkSumBuf));
    // Zero out old checksum
    ipChkSumBuf[10]         = 0;
    ipChkSumBuf[11]         = 0;
    const uint16_t ipChkSum = ip_checksum(ipChkSumBuf, ARRAY_SIZE(ipChkSumBuf));
    buf[10]                 = (char) (ipChkSum >> 0);
    buf[11]                 = (char) (ipChkSum >> 8);

    //    // Modify source port? FIXME: Why is this needed??
    //    buf[20 + 1] = (char) (58356 >> 0);
    //    buf[20 + 0] = (char) (58356 >> 8);

    const unsigned udp_length = ipDatagramLen - ipv4HdrLen;
    const unsigned proto      = buf[9];
    const uint8_t *addrsPtr   = buf + 12;
    const uint8_t *udpDataPtr = buf + ipv4HdrLen;
    // Zero out old checksum
    buf[ipv4HdrLen + 6]      = 0;
    buf[ipv4HdrLen + 7]      = 0;
    const uint16_t udpChkSum = htons(checksum_tcpudp(udp_length, proto, addrsPtr, udpDataPtr));
    buf[ipv4HdrLen + 6]      = (char) (udpChkSum >> 0);
    buf[ipv4HdrLen + 7]      = (char) (udpChkSum >> 8);

    return ipDatagramLen;
}

static bool parseIpv4Pkt(int count, uint8_t *buffer, uint32_t *dstIpPtr, uint16_t *dstPortPtr)
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

static bool parseIpv6Pkt(int count, uint8_t *buffer)
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

static bool readSerial(cbuf_handle_t serCBuf)
{
    const SSIZE_T serBytesRead = read_port(hComm, serCBuf);
    if (serBytesRead < 0) {
        printf("Read error: %zi\n", serBytesRead);
        return false;
    }
    else if (serBytesRead == 0) {
        return true;  // No data
    }
    return true;
}

static bool popIpPkt(cbuf_handle_t inBuf,
                     uint8_t *outBuf,
                     size_t outBufLen,
                     uint8_t *ipVersionPtr,
                     uint16_t *ipHdrLenPtr,
                     uint16_t *ipPktLenPtr)
{
    uint8_t peekBuf[7];
    if (circular_buf_peek(inBuf, peekBuf, sizeof peekBuf) != 0) {
        return false;
    }
    *ipVersionPtr = peekBuf[0] >> 4;
    if (*ipVersionPtr == 4) {
        *ipHdrLenPtr = (peekBuf[0] & 0x0f) * 4;
        *ipPktLenPtr = (peekBuf[2] << 8) | (peekBuf[3] << 0);
    }
    else if (*ipVersionPtr == 6) {
        *ipHdrLenPtr = 40;  // Fixed length header
        *ipPktLenPtr = (peekBuf[5] << 8) | (peekBuf[6] << 0);
    }
    else {
        printf("Unknown packet version %u\n", *ipVersionPtr);
        return false;
    }
    printf("Grabbed IPv%u: ipHdrLen=%u ipPktLen=%u\n", *ipVersionPtr, *ipHdrLenPtr, *ipPktLenPtr);

    if (circular_buf_size(inBuf) < *ipPktLenPtr) {
        printf("buffer size %llu < datagram size %u\n", circular_buf_size(inBuf), *ipPktLenPtr);
        return false;
    }
    if (outBufLen < *ipPktLenPtr) {
        printf("outBuf not big enough for ipPkt: %zu %u\n", outBufLen, *ipPktLenPtr);
        return false;
    }
    if (circular_buf_get_all(inBuf, outBuf, *ipPktLenPtr) != 0) {
        printf("Couldn't pop all bytes\n");
        return false;
    }
    return true;
}

static bool serToSkt(cbuf_handle_t serCBuf, SOCKET sktFd)
{
    if (!readSerial(serCBuf)) {
        return false;
    }

    uint8_t sktBuf[1024];
    while (true) {
        uint8_t ipVersion;
        uint16_t ipHdrLen;
        uint16_t ipPktLen;
        if (!popIpPkt(serCBuf, sktBuf, sizeof sktBuf, &ipVersion, &ipHdrLen, &ipPktLen)) {
            break;
        }
        if (ipVersion != 4) {
            printf("Skipping IPv%u\n", ipVersion);
            continue;
        }

        uint32_t dstIp;
        uint16_t dstPort;
        uint16_t pktLen;
        if (!parseIpv4Pkt(ipPktLen, sktBuf, &dstIp, &dstPort)) {
            return true;
        }
        pktLen = modifyIpv4Pkt(sktBuf, ipPktLen);
        if (!parseIpv4Pkt(ipPktLen, sktBuf, &dstIp, &dstPort)) {
            return true;
        }

        // send the pkt
        struct sockaddr_in dest = {
            .sin_family      = AF_INET,
            .sin_addr.s_addr = dstIp,
            .sin_port        = htons(dstPort),
        };
        printf("Sending %u bytes\n", pktLen);
        const int sktBytesSent = sendto(sktFd, (const char *) sktBuf, pktLen, 0, (struct sockaddr *) &dest, sizeof(dest));
        if (sktBytesSent == SOCKET_ERROR) {
            wchar_t *sBuf = NULL;
            FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                           WSAGetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR) &sBuf, 0, NULL);
            printf("send failed %i: %S\n", WSAGetLastError(), sBuf);
            return false;
        }
        printf("Sent %i\n", sktBytesSent);
        if (sktBytesSent != pktLen) {
            printf("Couldn't send all bytes!");
            return false;
        }
    }

    return true;
}

// static bool sktToSer(int sktFd, uint8_t *sktBuf, uint8_t *serBuf)
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

    // Open raw socket
    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (s == INVALID_SOCKET) {
        printf("Socket invalid\n");
    }
    int optval = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char *) &optval, sizeof(optval)) == SOCKET_ERROR) {
        printf("setsockopt IP_HDRINCL failed\n");
        return 1;
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
    // Print the name
    struct sockaddr_in sktName;
    int nameLen = sizeof(sktName);
    if (getsockname(s, (struct sockaddr *) &sktName, &nameLen) == SOCKET_ERROR) {
        printf("getsockname failed\n");
        return 1;
    }
    printf("Socket address: %u.%u.%u.%u:%u\n", sktName.sin_addr.S_un.S_un_b.s_b1, sktName.sin_addr.S_un.S_un_b.s_b2,
           sktName.sin_addr.S_un.S_un_b.s_b3, sktName.sin_addr.S_un.S_un_b.s_b4, sktName.sin_port);

    uint8_t serialBuf[1024];
    uint8_t ipBuf[1024];

    cbuf_handle_t serialCBuf = circular_buf_init(serialBuf, sizeof serialBuf);
    cbuf_handle_t ipCBuf     = circular_buf_init(ipBuf, sizeof ipBuf);

    while (!done) {
        if (!serToSkt(serialCBuf, s)) {
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