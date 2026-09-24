#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define BUFFER_SIZE 4096
#define IDENTITY_SIZE 5
#define EVIL_BIT 0x8000
#define RECEIVE_TIMEOUT_SECONDS 5

/*
 * Parses a decimal command-line value and checks that it is inside the
 * inclusive range [minimum, maximum]. Returns 0 on success and -1 on error.
 */
static int parse_number(const char *text, unsigned long minimum,
                        unsigned long maximum, unsigned long *result)
{
    char *end;
    unsigned long value;

    if (text == NULL || *text == '\0') {
        return -1;
    }

    value = strtoul(text, &end, 10);

    if (*end != '\0' || value < minimum || value > maximum) {
        return -1;
    }

    *result = value;
    return 0;
}

/*
 * Calculates the standard Internet checksum used by the IPv4 header.
 */
static uint16_t calculate_checksum(const void *data, size_t length)
{
    const uint16_t *words = data;
    uint32_t sum = 0;

    while (length > 1) {
        sum += *words++;
        length -= 2;
    }

    if (length == 1) {
        sum += *(const uint8_t *)words;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

/*
 * Asks the operating system which local IPv4 address it would use to reach
 * the server. Returns 0 on success and -1 on error.
 */
static int find_local_address(const struct sockaddr_in *server,
                              struct in_addr *local_address)
{
    int temporary_socket;
    struct sockaddr_in local;
    socklen_t local_length = sizeof(local);

    temporary_socket = socket(AF_INET, SOCK_DGRAM, 0);

    if (temporary_socket < 0) {
        perror("socket");
        return -1;
    }

    if (connect(temporary_socket,
                (const struct sockaddr *)server,
                sizeof(*server)) < 0) {
        perror("connect");
        close(temporary_socket);
        return -1;
    }

    if (getsockname(temporary_socket,
                    (struct sockaddr *)&local,
                    &local_length) < 0) {
        perror("getsockname");
        close(temporary_socket);
        return -1;
    }

    *local_address = local.sin_addr;
    close(temporary_socket);
    return 0;
}

/*
 * Extracts the hidden port number from the Evil port's textual response.
 * Returns 0 on success and -1 if the response does not contain a valid port.
 */
static int extract_hidden_port(char *reply, int *hidden_port)
{
    const char marker[] = "hidden port:";
    char *port_text;
    char *end;
    long value;

    port_text = strstr(reply, marker);

    if (port_text == NULL) {
        return -1;
    }

    port_text += strlen(marker);

    /* Skip spaces, newlines and the non-breaking space used by the server. */
    while (*port_text != '\0' &&
           !isdigit((unsigned char)*port_text)) {
        port_text++;
    }

    if (*port_text == '\0') {
        return -1;
    }

    value = strtol(port_text, &end, 10);

    if (end == port_text || value < 1 || value > 65535) {
        return -1;
    }

    *hidden_port = (int)value;
    return 0;
}

/*
 * Sends one IPv4/UDP packet with the reserved IPv4 "evil bit" set. The UDP
 * payload contains one group-ID byte followed by the four-byte sigil.
 */
static int send_evil_packet(int raw_socket,
                            const struct sockaddr_in *server,
                            const struct in_addr *local_ip,
                            uint16_t source_port,
                            unsigned char group_id,
                            uint32_t sigil)
{
    unsigned char packet[
        sizeof(struct ip) + sizeof(struct udphdr) + IDENTITY_SIZE];
    unsigned char *payload;
    struct ip *ip_header;
    struct udphdr *udp_header;
    uint32_t sigil_network_order;
    size_t packet_length = sizeof(packet);

    memset(packet, 0, sizeof(packet));

    ip_header = (struct ip *)packet;
    udp_header = (struct udphdr *)(packet + sizeof(struct ip));
    payload = packet + sizeof(struct ip) + sizeof(struct udphdr);

    payload[0] = group_id;
    sigil_network_order = htonl(sigil);
    memcpy(payload + 1, &sigil_network_order, sizeof(sigil_network_order));

    ip_header->ip_v = 4;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = 0;

    /* macOS expects these two IP_HDRINCL fields in host byte order. */
    ip_header->ip_len = (uint16_t)packet_length;
    ip_header->ip_id = 0;
    ip_header->ip_off = EVIL_BIT;

    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_src = *local_ip;
    ip_header->ip_dst = server->sin_addr;
    ip_header->ip_sum = 0;
    ip_header->ip_sum =
        calculate_checksum(ip_header, sizeof(struct ip));

    udp_header->uh_sport = source_port;
    udp_header->uh_dport = server->sin_port;
    udp_header->uh_ulen =
        htons((uint16_t)(sizeof(struct udphdr) + IDENTITY_SIZE));

    /* A zero UDP checksum is permitted for IPv4. */
    udp_header->uh_sum = 0;

    if (sendto(raw_socket,
               packet,
               packet_length,
               0,
               (const struct sockaddr *)server,
               sizeof(*server)) < 0) {
        perror("sendto");
        return -1;
    }

    return 0;
}

/*
 * Reads and validates command-line arguments, sends the Evil packet and
 * prints the hidden port returned by the server.
 */
int main(int argc, char *argv[])
{
    int raw_socket = -1;
    int reply_socket = -1;
    int header_included = 1;
    int hidden_port;
    int result = 1;

    unsigned long parsed_port;
    unsigned long parsed_group_id;
    unsigned long parsed_sigil;

    struct sockaddr_in server_address;
    struct sockaddr_in local_socket_address;
    struct sockaddr_in reply_from;
    struct in_addr local_ip;
    struct timeval timeout;

    socklen_t local_length;
    socklen_t reply_from_length;
    ssize_t bytes_received;
    unsigned char reply[BUFFER_SIZE];

    if (argc != 5) {
        fprintf(stderr,
                "Usage: %s <IP address> <evil port> <group ID> <sigil>\n",
                argv[0]);
        return 1;
    }

    if (parse_number(argv[2], 1, 65535, &parsed_port) < 0) {
        fprintf(stderr, "Invalid port number\n");
        return 1;
    }

    if (parse_number(argv[3], 0, 255, &parsed_group_id) < 0) {
        fprintf(stderr, "Invalid group ID\n");
        return 1;
    }

    if (parse_number(argv[4], 0, UINT32_MAX, &parsed_sigil) < 0) {
        fprintf(stderr, "Invalid sigil\n");
        return 1;
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons((uint16_t)parsed_port);

    if (inet_pton(AF_INET, argv[1], &server_address.sin_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address\n");
        return 1;
    }

    if (find_local_address(&server_address, &local_ip) < 0) {
        return 1;
    }

    /* This ordinary UDP socket receives the server's reply. */
    reply_socket = socket(AF_INET, SOCK_DGRAM, 0);

    if (reply_socket < 0) {
        perror("UDP socket");
        goto cleanup;
    }

    memset(&local_socket_address, 0, sizeof(local_socket_address));
    local_socket_address.sin_family = AF_INET;
    local_socket_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_socket_address.sin_port = htons(0);

    if (bind(reply_socket,
             (struct sockaddr *)&local_socket_address,
             sizeof(local_socket_address)) < 0) {
        perror("bind");
        goto cleanup;
    }

    local_length = sizeof(local_socket_address);

    if (getsockname(reply_socket,
                    (struct sockaddr *)&local_socket_address,
                    &local_length) < 0) {
        perror("getsockname");
        goto cleanup;
    }

    timeout.tv_sec = RECEIVE_TIMEOUT_SECONDS;
    timeout.tv_usec = 0;

    if (setsockopt(reply_socket,
                   SOL_SOCKET,
                   SO_RCVTIMEO,
                   &timeout,
                   sizeof(timeout)) < 0) {
        perror("setsockopt");
        goto cleanup;
    }

    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

    if (raw_socket < 0) {
        perror("raw socket");
        fprintf(stderr, "Run this program with sudo on macOS.\n");
        goto cleanup;
    }

    if (setsockopt(raw_socket,
                   IPPROTO_IP,
                   IP_HDRINCL,
                   &header_included,
                   sizeof(header_included)) < 0) {
        perror("IP_HDRINCL");
        goto cleanup;
    }

    printf("Sending an evil UDP packet to port %lu...\n", parsed_port);

    if (send_evil_packet(raw_socket,
                         &server_address,
                         &local_ip,
                         local_socket_address.sin_port,
                         (unsigned char)parsed_group_id,
                         (uint32_t)parsed_sigil) < 0) {
        goto cleanup;
    }

    reply_from_length = sizeof(reply_from);
    bytes_received = recvfrom(reply_socket,
                              reply,
                              sizeof(reply) - 1,
                              0,
                              (struct sockaddr *)&reply_from,
                              &reply_from_length);

    if (bytes_received < 0) {
        perror("No reply received");
        goto cleanup;
    }

    if (reply_from.sin_addr.s_addr != server_address.sin_addr.s_addr ||
        reply_from.sin_port != server_address.sin_port) {
        fprintf(stderr, "Received a reply from an unexpected source\n");
        goto cleanup;
    }

    reply[bytes_received] = '\0';
    printf("\nReply from the Evil port:\n%s\n", reply);

    if (extract_hidden_port((char *)reply, &hidden_port) < 0) {
        fprintf(stderr, "Could not extract the hidden port\n");
        goto cleanup;
    }

    printf("Extracted hidden port: %d\n", hidden_port);
    result = 0;

cleanup:
    if (raw_socket >= 0) {
        close(raw_socket);
    }

    if (reply_socket >= 0) {
        close(reply_socket);
    }

    return result;
}
