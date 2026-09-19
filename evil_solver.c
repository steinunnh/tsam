#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <ctype.h>

#define BUFFER_SIZE 4096
#define EVIL_BIT 0x8000
#define PROBE_MESSAGE "Hello World!"

/*
 * Calculate the standard Internet checksum used by IPv4.
 */
uint16_t calculate_checksum(const void *data, size_t length)
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
 * Ask the operating system which local IPv4 address it would use
 * to communicate with the server.
 */
int find_local_address(const struct sockaddr_in *server,
                       struct in_addr *local_address)
{
    int sock;
    struct sockaddr_in local;
    socklen_t local_length = sizeof(local);

    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        perror("socket");
        return -1;
    }

    if (connect(sock,
                (const struct sockaddr *)server,
                sizeof(*server)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    if (getsockname(sock,
                    (struct sockaddr *)&local,
                    &local_length) < 0) {
        perror("getsockname");
        close(sock);
        return -1;
    }

    *local_address = local.sin_addr;
    close(sock);
    return 0;
}

int main(int argc, char *argv[])
{
    int raw_socket;
    int reply_socket;
    int header_included = 1;

    long destination_port;
    char *end;

    struct sockaddr_in server_address;
    struct sockaddr_in local_socket_address;
    struct sockaddr_in reply_from;
    socklen_t reply_from_length;

    struct timeval timeout;

    struct in_addr local_ip;

    unsigned char packet[BUFFER_SIZE];
    unsigned char reply[BUFFER_SIZE];

    struct ip *ip_header;
    struct udphdr *udp_header;

    unsigned char payload[5];
    size_t payload_length = sizeof(payload);

    unsigned long group_id;
    unsigned long sigil;
    uint32_t sigil_network_order;
    size_t packet_length;

    ssize_t bytes_received;

    if (argc != 5) {
        fprintf(stderr,
                "Usage: %s <IP address> <evil port> <group ID> <sigil>\n",
                argv[0]);
        return 1;
    }

    destination_port = strtol(argv[2], &end, 10);

    if (*end != '\0' ||
        destination_port < 1 ||
        destination_port > 65535) {
        fprintf(stderr, "Invalid port number\n");
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

    /*
    * The first byte contains the group ID.
    */
    payload[0] = (unsigned char)group_id;

    /*
    * Convert the 32-bit sigil to network byte order and place it
    * in the remaining four bytes.
    */
    sigil_network_order = htonl((uint32_t)sigil);
    memcpy(payload + 1, &sigil_network_order, sizeof(sigil_network_order));

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons((uint16_t)destination_port);

    if (inet_pton(AF_INET,
                  argv[1],
                  &server_address.sin_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address\n");
        return 1;
    }

    if (find_local_address(&server_address, &local_ip) < 0) {
        return 1;
    }

    /*
     * Create and bind an ordinary UDP socket. The server's reply
     * will be sent to this socket's source port.
     */
    reply_socket = socket(AF_INET, SOCK_DGRAM, 0);

    if (reply_socket < 0) {
        perror("UDP socket");
        return 1;
    }

    memset(&local_socket_address, 0, sizeof(local_socket_address));
    local_socket_address.sin_family = AF_INET;
    local_socket_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_socket_address.sin_port = htons(0);

    if (bind(reply_socket,
             (struct sockaddr *)&local_socket_address,
             sizeof(local_socket_address)) < 0) {
        perror("bind");
        close(reply_socket);
        return 1;
    }

    /*
     * Ask which temporary source port macOS selected.
     */
    socklen_t local_length = sizeof(local_socket_address);

    if (getsockname(reply_socket,
                    (struct sockaddr *)&local_socket_address,
                    &local_length) < 0) {
        perror("getsockname");
        close(reply_socket);
        return 1;
    }

    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    if (setsockopt(reply_socket,
                   SOL_SOCKET,
                   SO_RCVTIMEO,
                   &timeout,
                   sizeof(timeout)) < 0) {
        perror("setsockopt");
        close(reply_socket);
        return 1;
    }

    /*
     * Create the raw IPv4 socket.
     */
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

    if (raw_socket < 0) {
        perror("raw socket");
        fprintf(stderr,
                "Raw sockets require sudo on macOS.\n");
        close(reply_socket);
        return 1;
    }

    if (setsockopt(raw_socket,
                   IPPROTO_IP,
                   IP_HDRINCL,
                   &header_included,
                   sizeof(header_included)) < 0) {
        perror("IP_HDRINCL");
        close(raw_socket);
        close(reply_socket);
        return 1;
    }

    memset(packet, 0, sizeof(packet));

    ip_header = (struct ip *)packet;
    udp_header = (struct udphdr *)(packet + sizeof(struct ip));

    packet_length =
        sizeof(struct ip) + sizeof(struct udphdr) + payload_length;

    /*
     * Construct the IPv4 header.
     */
    ip_header->ip_v = 4;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = 0;

    /*
     * macOS expects ip_len and ip_off in host byte order when a raw
     * packet is supplied using IP_HDRINCL.
     */
    ip_header->ip_len = (uint16_t)packet_length;
    ip_header->ip_id = 0;
    ip_header->ip_off = EVIL_BIT;

    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_src = local_ip;
    ip_header->ip_dst = server_address.sin_addr;

    ip_header->ip_sum = 0;
    ip_header->ip_sum =
        calculate_checksum(ip_header, sizeof(struct ip));

    /*
     * Construct the UDP header.
     *
     * The selected source port is already stored in network byte order.
     */
    udp_header->uh_sport = local_socket_address.sin_port;
    udp_header->uh_dport = htons((uint16_t)destination_port);
    udp_header->uh_ulen =
        htons((uint16_t)(sizeof(struct udphdr) + payload_length));

    /*
     * A zero UDP checksum is permitted for IPv4.
     */
    udp_header->uh_sum = 0;

    memcpy(packet + sizeof(struct ip) + sizeof(struct udphdr),
           payload,
           payload_length);

    printf("Sending an evil UDP packet to port %ld...\n",
           destination_port);

    if (sendto(raw_socket,
               packet,
               packet_length,
               0,
               (struct sockaddr *)&server_address,
               sizeof(server_address)) < 0) {
        perror("sendto");
        close(raw_socket);
        close(reply_socket);
        return 1;
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
        close(raw_socket);
        close(reply_socket);
        return 1;
    }

    reply[bytes_received] = '\0';

    printf("\nReply from the evil port:\n%s\n", reply);

    char *port_text;
    long hidden_port;

    port_text = strstr((char *)reply, "hidden port:");

    if (port_text == NULL) {
        fprintf(stderr, "Could not find the hidden port in the reply\n");
        close(raw_socket);
        close(reply_socket);
        return 1;
    }

    /*
    * Move forward until the first digit after "hidden port:".
    * This also handles the unusual space and newline in the reply.
    */
    while (*port_text != '\0' &&
        !isdigit((unsigned char)*port_text)) {
        port_text++;
    }

    if (*port_text == '\0') {
        fprintf(stderr, "Could not find the hidden port number\n");
        close(raw_socket);
        close(reply_socket);
        return 1;
    }

    hidden_port = strtol(port_text, NULL, 10);

    if (hidden_port < 1 || hidden_port > 65535) {
        fprintf(stderr, "The server returned an invalid port\n");
        close(raw_socket);
        close(reply_socket);
        return 1;
    }

    printf("Extracted hidden port: %ld\n", hidden_port);

    close(raw_socket);
    close(reply_socket);
    return 0;
}
