#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

// Biggest message the program can receive.
#define BUFFER_SIZE 4096

// Fixed sizes of the headers inside the Guardian's wrapped packet.
#define IPV6_HEADER_SIZE 40
#define UDP_HEADER_SIZE 8

// The identity contains a one-byte group ID and a four-byte sigil.
#define IDENTITY_SIZE 5

// Size of the IPv6 header, UDP header, and identity together.
#define INNER_PACKET_SIZE \
    (IPV6_HEADER_SIZE + UDP_HEADER_SIZE + IDENTITY_SIZE)

// How long recvfrom() waits before giving up.
#define TIMEOUT_SECONDS 3

// The first message asks the Guardian to send its IPv6 wrapper.
#define INITIAL_MESSAGE "Hello World!"


/*
 * Writes a 16-bit number into a byte array in network byte order.
 */
static void write_u16(unsigned char *destination, uint16_t value)
{
    destination[0] = (unsigned char)(value >> 8);
    destination[1] = (unsigned char)(value & 0xff);
}


/*
 * Adds bytes to the sum used when calculating an Internet checksum.
 */
static uint32_t checksum_add(const unsigned char *data,
                             size_t length,
                             uint32_t sum)
{
    // Add two bytes at a time as 16-bit numbers.
    while (length >= 2) {
        sum += ((uint16_t)data[0] << 8) | data[1];
        data += 2;
        length -= 2;
    }

    // If one byte remains, place it in the high half of a 16-bit number.
    if (length == 1) {
        sum += (uint16_t)data[0] << 8;
    }

    return sum;
}


/*
 * Calculates the UDP checksum required for a UDP packet inside IPv6.
 */
static uint16_t calculate_ipv6_udp_checksum(
    const unsigned char *packet,
    uint16_t udp_length)
{
    uint32_t sum = 0;
    uint16_t checksum;

    // The pseudo-header stores the UDP length as a 32-bit value.
    unsigned char length_field[4] = {
        0,
        0,
        (unsigned char)(udp_length >> 8),
        (unsigned char)(udp_length & 0xff)
    };

    // IPv6 next-header value 17 means UDP.
    unsigned char next_header_field[4] = {0, 0, 0, 17};

    // Add the source and destination IPv6 addresses.
    sum = checksum_add(packet + 8, 32, sum);

    // Add the UDP length and the UDP next-header value.
    sum = checksum_add(length_field, sizeof(length_field), sum);
    sum = checksum_add(next_header_field,
                       sizeof(next_header_field),
                       sum);

    // Add the complete UDP header and its five-byte payload.
    sum = checksum_add(packet + IPV6_HEADER_SIZE,
                       udp_length,
                       sum);

    // Fold any carry bits back into the lower 16 bits.
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    checksum = (uint16_t)(~sum);

    // A UDP checksum inside IPv6 is not allowed to be zero.
    if (checksum == 0) {
        checksum = 0xffff;
    }

    return checksum;
}


/*
 * Checks whether a reply belongs to the original Guardian conversation.
 *
 * The Guardian may send extra packets containing unrelated phrases. The
 * correct answer has the same inner IPv6 addresses and UDP ports as the
 * first wrapper that the Guardian sent to us.
 */
static int is_matching_wrapper(const unsigned char *reply,
                               ssize_t reply_length,
                               const unsigned char *original_wrapper)
{
    // A wrapped reply needs at least an IPv6 header and a UDP header.
    if (reply_length < IPV6_HEADER_SIZE + UDP_HEADER_SIZE) {
        return 0;
    }

    // The first four bits must contain the IPv6 version number 6.
    if ((reply[0] >> 4) != 6) {
        return 0;
    }

    // Byte 6 is the next-header field. Value 17 means UDP.
    if (reply[6] != 17) {
        return 0;
    }

    // Compare both 16-byte IPv6 addresses.
    if (memcmp(reply + 8, original_wrapper + 8, 32) != 0) {
        return 0;
    }

    // Compare the two inner UDP ports.
    if (memcmp(reply + IPV6_HEADER_SIZE,
               original_wrapper + IPV6_HEADER_SIZE,
               4) != 0) {
        return 0;
    }

    return 1;
}


/*
 * Main:
 *
 * Reads and checks the command-line arguments, asks the Guardian for an
 * IPv6 wrapper, reverses its addresses and ports, adds the group identity,
 * and prints the secret phrase from the matching reply.
 */
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
    unsigned char original_wrapper[IPV6_HEADER_SIZE + UDP_HEADER_SIZE];
    unsigned char packet[INNER_PACKET_SIZE];
    unsigned char temporary_address[16];

    uint32_t sigil_network_order;
    uint16_t udp_length;
    uint16_t udp_checksum;

    ssize_t bytes_received;
    unsigned char *guardian_text;
    char *opening_quote;
    char *closing_quote;

    // The program needs an IP address, port, group ID, and sigil.
    if (argc != 5) {
        fprintf(stderr,
                "Usage: %s <IP address> <Guardian port> "
                "<group ID> <sigil>\n",
                argv[0]);
        return 1;
    }

    // Convert and validate the Guardian port.
    guardian_port = strtol(argv[2], &end, 10);

    if (end == argv[2] || *end != '\0' ||
        guardian_port < 1 || guardian_port > 65535) {
        fprintf(stderr, "Invalid Guardian port\n");
        return 1;
    }

    // Convert and validate the one-byte group ID.
    group_id = strtoul(argv[3], &end, 10);

    if (end == argv[3] || *end != '\0' || group_id > 255) {
        fprintf(stderr, "Invalid group ID\n");
        return 1;
    }

    // Convert and validate the 32-bit sigil.
    sigil = strtoul(argv[4], &end, 10);

    if (end == argv[4] || *end != '\0' || sigil > UINT32_MAX) {
        fprintf(stderr, "Invalid sigil\n");
        return 1;
    }

    // Fill in the Guardian's outer IPv4 address and UDP port.
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons((uint16_t)guardian_port);

    if (inet_pton(AF_INET,
                  argv[1],
                  &server_address.sin_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address\n");
        return 1;
    }

    // Create the ordinary IPv4 UDP socket used for both messages.
    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        perror("socket failed");
        return 1;
    }

    // Give recvfrom() a timeout so the program cannot wait forever.
    timeout.tv_sec = TIMEOUT_SECONDS;
    timeout.tv_usec = 0;

    if (setsockopt(sock,
                   SOL_SOCKET,
                   SO_RCVTIMEO,
                   &timeout,
                   sizeof(timeout)) < 0) {
        perror("setsockopt failed");
        close(sock);
        return 1;
    }

    // Ask the Guardian to send its instructions and IPv6 wrapper.
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

    bytes_received = recvfrom(sock,
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

    // Ignore a packet if it did not come from the Guardian's IP and port.
    if (from_address.sin_addr.s_addr != server_address.sin_addr.s_addr ||
        from_address.sin_port != server_address.sin_port) {
        fprintf(stderr, "The wrapper came from an unexpected address\n");
        close(sock);
        return 1;
    }

    // The wrapper must contain an IPv6 header and a UDP header.
    if (bytes_received < IPV6_HEADER_SIZE + UDP_HEADER_SIZE) {
        fprintf(stderr, "Guardian reply is too short\n");
        close(sock);
        return 1;
    }

    // Check that the inner packet is IPv6.
    if ((reply[0] >> 4) != 6) {
        fprintf(stderr, "Guardian reply does not begin with IPv6\n");
        close(sock);
        return 1;
    }

    // Check that the next header inside IPv6 is UDP.
    if (reply[6] != 17) {
        fprintf(stderr, "Guardian's inner packet is not UDP\n");
        close(sock);
        return 1;
    }

    // Save the original addresses and ports for matching the final reply.
    memcpy(original_wrapper,
           reply,
           sizeof(original_wrapper));

    // Begin the outgoing packet with the Guardian's IPv6 header.
    memcpy(packet, reply, IPV6_HEADER_SIZE);

    // Our IPv6 payload is an 8-byte UDP header plus a 5-byte identity.
    udp_length = UDP_HEADER_SIZE + IDENTITY_SIZE;
    write_u16(packet + 4, udp_length);

    // Reverse the inner IPv6 addresses so the packet travels back.
    memcpy(temporary_address, packet + 8, 16);
    memcpy(packet + 8, packet + 24, 16);
    memcpy(packet + 24, temporary_address, 16);

    // Reverse the inner UDP source and destination ports.
    packet[40] = reply[42];
    packet[41] = reply[43];
    packet[42] = reply[40];
    packet[43] = reply[41];

    // Store the UDP length and clear the checksum before calculating it.
    write_u16(packet + 44, udp_length);
    packet[46] = 0;
    packet[47] = 0;

    // Put the group ID in the first byte of the identity.
    packet[48] = (unsigned char)group_id;

    // Put the sigil in the final four bytes in network byte order.
    sigil_network_order = htonl((uint32_t)sigil);
    memcpy(packet + 49,
           &sigil_network_order,
           sizeof(sigil_network_order));

    // Calculate and store the UDP checksum required by IPv6.
    udp_checksum = calculate_ipv6_udp_checksum(packet, udp_length);
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

    /*
     * The Guardian may send unrelated phrase packets. Keep receiving until
     * the inner IPv6 addresses and UDP ports match the first wrapper.
     */
    for (;;) {
        from_length = sizeof(from_address);

        bytes_received = recvfrom(sock,
                                  reply,
                                  sizeof(reply) - 1,
                                  0,
                                  (struct sockaddr *)&from_address,
                                  &from_length);

        if (bytes_received < 0) {
            perror("Did not receive the Guardian's matching answer");
            close(sock);
            return 1;
        }

        // Ignore packets that did not come from the Guardian's outer port.
        if (from_address.sin_addr.s_addr !=
                server_address.sin_addr.s_addr ||
            from_address.sin_port != server_address.sin_port) {
            continue;
        }

        if (!is_matching_wrapper(reply,
                                 bytes_received,
                                 original_wrapper)) {
            printf("Ignoring an unrelated Guardian reply\n");
            continue;
        }

        break;
    }

    // Add a string terminator so the text can be printed safely.
    reply[bytes_received] = '\0';

    // The message begins after the 40-byte IPv6 and 8-byte UDP headers.
    guardian_text = reply + IPV6_HEADER_SIZE + UDP_HEADER_SIZE;

    printf("\nWrapped reply from the Guardian:\n%s\n",
           guardian_text);

    // Find the secret phrase between the first pair of quotation marks.
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

    // Replace the closing quotation mark with a string terminator.
    *closing_quote = '\0';

    printf("Extracted secret phrase: %s\n", opening_quote + 1);

    close(sock);
    return 0;
}
