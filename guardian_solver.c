#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define BUFFER_SIZE 4096
#define IPV6_HEADER_SIZE 40
#define UDP_HEADER_SIZE 8
#define IDENTITY_SIZE 5
#define INNER_PACKET_SIZE \
    (IPV6_HEADER_SIZE + UDP_HEADER_SIZE + IDENTITY_SIZE)

#define INITIAL_MESSAGE "Hello World!"

/*
 * Write a 16-bit number into a byte buffer in network byte order.
 */
void write_u16(unsigned char *destination, uint16_t value)
{
    destination[0] = (unsigned char)(value >> 8);
    destination[1] = (unsigned char)(value & 0xff);
}

/*
 * Add bytes to an Internet-checksum sum.
 */
uint32_t checksum_add(const unsigned char *data,
                      size_t length,
                      uint32_t sum)
{
    while (length >= 2) {
        sum += ((uint16_t)data[0] << 8) | data[1];
        data += 2;
        length -= 2;
    }

    if (length == 1) {
        sum += (uint16_t)data[0] << 8;
    }

    return sum;
}

/*
 * Calculate the UDP checksum required by IPv6.
 *
 * packet contains:
 *   40-byte IPv6 header
 *   8-byte UDP header
 *   UDP payload
 */
uint16_t calculate_ipv6_udp_checksum(
    const unsigned char *packet,
    uint16_t udp_length)
{
    uint32_t sum = 0;
    uint16_t checksum;

    unsigned char length_field[4] = {
        0,
        0,
        (unsigned char)(udp_length >> 8),
        (unsigned char)(udp_length & 0xff)
    };

    unsigned char next_header_field[4] = {
        0, 0, 0, 17
    };

    /*
     * IPv6 pseudo-header:
     * source address + destination address
     * + 32-bit UDP length + next-header value.
     */
    sum = checksum_add(packet + 8, 32, sum);
    sum = checksum_add(length_field, sizeof(length_field), sum);
    sum = checksum_add(next_header_field,
                       sizeof(next_header_field), sum);

    /*
     * Add the complete UDP header and payload.
     */
    sum = checksum_add(packet + IPV6_HEADER_SIZE,
                       udp_length,
                       sum);

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    checksum = (uint16_t)(~sum);

    /*
     * An IPv6 UDP checksum cannot be zero.
     */
    if (checksum == 0) {
        checksum = 0xffff;
    }

    return checksum;
}

int main(int argc, char *argv[])
{
    int sock;
    long guardian_port;
    unsigned long group_id;
    unsigned long sigil;
    char *end;

    struct sockaddr_in server_address;
    struct sockaddr_in from_address;
    socklen_t from_length;

    struct timeval timeout;

    unsigned char reply[BUFFER_SIZE];
    unsigned char packet[INNER_PACKET_SIZE];
    unsigned char temporary_address[16];

    uint32_t sigil_network_order;
    uint16_t udp_length;
    uint16_t udp_checksum;

    ssize_t bytes_received;

    if (argc != 5) {
        fprintf(stderr,
                "Usage: %s <IP address> <Guardian port> "
                "<group ID> <sigil>\n",
                argv[0]);
        return 1;
    }

    guardian_port = strtol(argv[2], &end, 10);

    if (*end != '\0' ||
        guardian_port < 1 ||
        guardian_port > 65535) {
        fprintf(stderr, "Invalid Guardian port\n");
        return 1;
    }

    group_id = strtoul(argv[3], &end, 10);

    if (*end != '\0' || group_id > 255) {
        fprintf(stderr, "Invalid group ID\n");
        return 1;
    }

    sigil = strtoul(argv[4], &end, 10);

    if (*end != '\0' || sigil > UINT32_MAX) {
        fprintf(stderr, "Invalid sigil\n");
        return 1;
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port =
        htons((uint16_t)guardian_port);

    if (inet_pton(AF_INET,
                  argv[1],
                  &server_address.sin_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address\n");
        return 1;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        perror("socket");
        return 1;
    }

    timeout.tv_sec = 3;
    timeout.tv_usec = 0;

    if (setsockopt(sock,
                   SOL_SOCKET,
                   SO_RCVTIMEO,
                   &timeout,
                   sizeof(timeout)) < 0) {
        perror("setsockopt");
        close(sock);
        return 1;
    }

    /*
     * Ask the Guardian for its instructions and IPv6 wrapper.
     */
    if (sendto(sock,
               INITIAL_MESSAGE,
               strlen(INITIAL_MESSAGE),
               0,
               (struct sockaddr *)&server_address,
               sizeof(server_address)) < 0) {
        perror("Initial sendto failed");
        close(sock);
        return 1;
    }

    from_length = sizeof(from_address);

    bytes_received = recvfrom(
        sock,
        reply,
        sizeof(reply),
        0,
        (struct sockaddr *)&from_address,
        &from_length);

    if (bytes_received < 0) {
        perror("Did not receive the Guardian wrapper");
        close(sock);
        return 1;
    }

    /*
     * The response must contain an IPv6 header and a UDP header.
     */
    if (bytes_received < IPV6_HEADER_SIZE + UDP_HEADER_SIZE) {
        fprintf(stderr, "Guardian reply is too short\n");
        close(sock);
        return 1;
    }

    if ((reply[0] >> 4) != 6) {
        fprintf(stderr,
                "Guardian reply does not begin with IPv6\n");
        close(sock);
        return 1;
    }

    if (reply[6] != 17) {
        fprintf(stderr,
                "Guardian's inner packet is not UDP\n");
        close(sock);
        return 1;
    }

    /*
     * Start with the IPv6 header sent by the Guardian.
     */
    memcpy(packet, reply, IPV6_HEADER_SIZE);

    /*
     * Our IPv6 payload is:
     * 8-byte UDP header + 5-byte identity = 13 bytes.
     */
    udp_length = UDP_HEADER_SIZE + IDENTITY_SIZE;

    write_u16(packet + 4, udp_length);

    /*
     * Reverse the inner IPv6 addresses:
     *
     * Guardian source becomes our destination.
     * Guardian destination becomes our source.
     */
    memcpy(temporary_address, packet + 8, 16);
    memcpy(packet + 8, packet + 24, 16);
    memcpy(packet + 24, temporary_address, 16);

    /*
     * Reverse the inner UDP ports.
     *
     * Received source port is at bytes 40-41.
     * Received destination port is at bytes 42-43.
     */
    packet[40] = reply[42];
    packet[41] = reply[43];
    packet[42] = reply[40];
    packet[43] = reply[41];

    /*
     * Set the new UDP length and initially clear its checksum.
     */
    write_u16(packet + 44, udp_length);
    packet[46] = 0;
    packet[47] = 0;

    /*
     * Construct the five-byte identity:
     * first byte = group ID
     * final four bytes = sigil in network byte order
     */
    packet[48] = (unsigned char)group_id;

    sigil_network_order = htonl((uint32_t)sigil);

    memcpy(packet + 49,
           &sigil_network_order,
           sizeof(sigil_network_order));

    /*
     * IPv6 requires a valid UDP checksum.
     */
    udp_checksum =
        calculate_ipv6_udp_checksum(packet, udp_length);

    write_u16(packet + 46, udp_checksum);

    printf("Sending wrapped IPv6 identity to Guardian port %ld...\n",
           guardian_port);

    if (sendto(sock,
               packet,
               sizeof(packet),
               0,
               (struct sockaddr *)&server_address,
               sizeof(server_address)) < 0) {
        perror("Identity sendto failed");
        close(sock);
        return 1;
    }

    from_length = sizeof(from_address);

    bytes_received = recvfrom(
        sock,
        reply,
        sizeof(reply) - 1,
        0,
        (struct sockaddr *)&from_address,
        &from_length);

    if (bytes_received < 0) {
        perror("Did not receive the Guardian's answer");
        close(sock);
        return 1;
    }

    /*
     * The answer might itself be wrapped in IPv6.
     */
    unsigned char *guardian_text;
    char *opening_quote;
    char *closing_quote;

    reply[bytes_received] = '\0';

    /*
    * If the reply is IPv6-wrapped, its text starts after the
    * 40-byte IPv6 header and 8-byte UDP header.
    */
    if (bytes_received >= 48 && (reply[0] >> 4) == 6) {
        guardian_text = reply + 48;
        printf("\nWrapped reply from the Guardian:\n%s\n",
            guardian_text);
    } else {
        guardian_text = reply;
        printf("\nReply from the Guardian:\n%s\n",
            guardian_text);
    }

    /*
    * Extract the text between the quotation marks.
    */
    opening_quote = strchr((char *)guardian_text, '"');

    if (opening_quote == NULL) {
        fprintf(stderr, "Could not find the secret phrase\n");
        close(sock);
        return 1;
    }

    closing_quote = strchr(opening_quote + 1, '"');

    if (closing_quote == NULL) {
        fprintf(stderr, "Could not find the end of the secret phrase\n");
        close(sock);
        return 1;
    }

    *closing_quote = '\0';

    printf("Extracted secret phrase: %s\n", opening_quote + 1);
}
