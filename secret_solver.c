#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

// Biggest message the program can send or receive.
#define BUFFER_SIZE 4096

// How long recvfrom() waits for a reply, measured in microseconds.
#define TIMEOUT_USEC 2000000

// Usernames of all group members.
#define GROUP_MEMBERS "regina24,steinunnp24"

// The beginning of the first message.
#define SECRET_PREFIX "S.E.C.R.E.T.:"

// A group ID is one byte and the accompanying number is four bytes.
#define IDENTITY_SIZE 5


/*
 * Generates a random 32-bit secret number using /dev/urandom.
 * Returns 0 on success, or -1 if something fails.
 */
static int generate_secret_number(uint32_t *secret)
{
    FILE *random_file;

    // Open the operating system's source of random bytes.
    random_file = fopen("/dev/urandom", "rb");

    if (random_file == NULL) {
        perror("Could not open /dev/urandom");
        return -1;
    }

    // Read exactly four random bytes into the 32-bit number.
    if (fread(secret, sizeof(*secret), 1, random_file) != 1) {
        fprintf(stderr, "Could not generate a secret number\n");
        fclose(random_file);
        return -1;
    }

    fclose(random_file);
    return 0;
}


/*
 * Creates a UDP socket and gives it a receive timeout.
 * Returns the socket descriptor, or -1 if something fails.
 */
static int create_socket(void)
{
    int sock;
    struct timeval timeout;

    // Create an IPv4 UDP socket.
    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        perror("socket failed");
        return -1;
    }

    // Convert the timeout constant into seconds and microseconds.
    timeout.tv_sec = TIMEOUT_USEC / 1000000;
    timeout.tv_usec = TIMEOUT_USEC % 1000000;

    if (setsockopt(sock,
                   SOL_SOCKET,
                   SO_RCVTIMEO,
                   &timeout,
                   sizeof(timeout)) < 0) {
        perror("setsockopt failed");
        close(sock);
        return -1;
    }

    return sock;
}


/*
 * Receives one UDP reply and checks that it came from the expected server.
 * Returns the number of received bytes, or -1 if something fails.
 */
static ssize_t receive_from_server(int sock,
                                   unsigned char *buffer,
                                   size_t buffer_size,
                                   const struct sockaddr_in *server_addr)
{
    struct sockaddr_in from_addr;
    socklen_t from_length;
    ssize_t bytes_received;

    from_length = sizeof(from_addr);

    bytes_received = recvfrom(sock,
                              buffer,
                              buffer_size,
                              0,
                              (struct sockaddr *)&from_addr,
                              &from_length);

    if (bytes_received < 0) {
        return -1;
    }

    // Reject a reply if it came from a different IP address or port.
    if (from_addr.sin_addr.s_addr != server_addr->sin_addr.s_addr ||
        from_addr.sin_port != server_addr->sin_port) {
        fprintf(stderr, "Received a reply from an unexpected address\n");
        return -1;
    }

    return bytes_received;
}


/*
 * Finds and validates the hidden port inside the server's text response.
 * Returns 0 on success, or -1 if the port cannot be found.
 */
static int extract_hidden_port(const char *response, int *hidden_port)
{
    const char *port_text;

    // Find the text immediately before the hidden port number.
    port_text = strstr(response, "hidden port:");

    if (port_text == NULL ||
        sscanf(port_text, "hidden port: %d", hidden_port) != 1) {
        return -1;
    }

    // Make sure the server returned a valid UDP port number.
    if (*hidden_port < 1 || *hidden_port > 65535) {
        return -1;
    }

    return 0;
}


/*
 * Solves the S.E.C.R.E.T. puzzle.
 * Returns 0 on success, or -1 if something fails.
 */
static int solve_secret(int sock, struct sockaddr_in server_addr)
{
    const char text_part[] = SECRET_PREFIX GROUP_MEMBERS;

    unsigned char first_message[BUFFER_SIZE];
    unsigned char second_message[IDENTITY_SIZE];
    unsigned char reply[BUFFER_SIZE];

    uint32_t secret_number;
    uint32_t secret_network_order;
    uint32_t challenge_network_order;
    uint32_t challenge;
    uint32_t sigil;
    uint32_t sigil_network_order;

    unsigned char group_id;
    size_t text_length;
    size_t first_message_length;
    ssize_t bytes_received;
    int hidden_port;

    // Step 1: Generate and remember a random 32-bit secret number.
    if (generate_secret_number(&secret_number) < 0) {
        return -1;
    }

    printf("Secret number: %u\n", secret_number);

    /*
     * Step 2: Begin the first message with the required text.
     * strlen() is used only for this textual part of the message.
     */
    text_length = strlen(text_part);

    // Make sure the complete message fits inside the buffer.
    if (text_length + sizeof(secret_network_order) >
        sizeof(first_message)) {
        fprintf(stderr, "The first message is too large\n");
        return -1;
    }

    memcpy(first_message, text_part, text_length);

    // Convert the secret number into network byte order.
    secret_network_order = htonl(secret_number);

    /*
     * Place the four binary bytes immediately after the text.
     * These must be the final four bytes of the message.
     */
    memcpy(first_message + text_length,
           &secret_network_order,
           sizeof(secret_network_order));

    first_message_length = text_length + sizeof(secret_network_order);

    printf("Sending first message to port %u...\n",
           ntohs(server_addr.sin_port));

    if (sendto(sock,
               first_message,
               first_message_length,
               0,
               (struct sockaddr *)&server_addr,
               sizeof(server_addr)) < 0) {
        perror("First sendto failed");
        return -1;
    }

    /*
     * Step 3: Receive the five-byte challenge:
     *
     * Byte 0:   group ID
     * Bytes 1-4: challenge number
     */
    bytes_received = receive_from_server(sock,
                                         reply,
                                         sizeof(reply),
                                         &server_addr);

    if (bytes_received < 0) {
        perror("Did not receive the challenge");
        return -1;
    }

    if (bytes_received != IDENTITY_SIZE) {
        fprintf(stderr,
                "Expected a 5-byte challenge, but received %zd bytes\n",
                bytes_received);

        // Print a textual error message returned by the server.
        printf("Server response: %.*s\n",
               (int)bytes_received,
               (char *)reply);

        return -1;
    }

    // The first byte contains the group's ID.
    group_id = reply[0];

    /*
     * Copy the four challenge bytes instead of using a pointer cast.
     * This avoids possible memory-alignment problems.
     */
    memcpy(&challenge_network_order,
           reply + 1,
           sizeof(challenge_network_order));

    challenge = ntohl(challenge_network_order);

    printf("Group ID: %u\n", (unsigned int)group_id);
    printf("Challenge: %u\n", challenge);

    // Step 4: XOR the challenge with our secret number to make the sigil.
    sigil = challenge ^ secret_number;

    printf("Sigil: %u\n", sigil);

    /*
     * Step 5: Construct the exact five-byte identity message.
     * The group ID is followed by the sigil in network byte order.
     */
    second_message[0] = group_id;
    sigil_network_order = htonl(sigil);

    memcpy(second_message + 1,
           &sigil_network_order,
           sizeof(sigil_network_order));

    printf("Sending the group ID and sigil...\n");

    if (sendto(sock,
               second_message,
               sizeof(second_message),
               0,
               (struct sockaddr *)&server_addr,
               sizeof(server_addr)) < 0) {
        perror("Second sendto failed");
        return -1;
    }

    /*
     * Step 6: Receive the server's final text response.
     * One byte is left unused for the string terminator.
     */
    bytes_received = receive_from_server(sock,
                                         reply,
                                         sizeof(reply) - 1,
                                         &server_addr);

    if (bytes_received < 0) {
        perror("Did not receive the hidden secret");
        return -1;
    }

    // Add a string terminator so the response can be printed safely.
    reply[bytes_received] = '\0';

    printf("\nS.E.C.R.E.T. response:\n%s\n", reply);

    // Find the hidden port inside the response.
    if (extract_hidden_port((char *)reply, &hidden_port) < 0) {
        fprintf(stderr,
                "Could not find a valid hidden port in the response\n");
        return -1;
    }

    printf("Extracted hidden port: %d\n", hidden_port);

    // Display the values required by the later puzzles.
    printf("\nKeep these values for the later puzzles:\n");
    printf("Group ID: %u\n", (unsigned int)group_id);
    printf("Sigil: %u\n", sigil);

    return 0;
}


/*
 * Main:
 *
 * Checks the command-line arguments, creates the socket, prepares the
 * server address, and calls the function that solves the puzzle.
 */
int main(int argc, char *argv[])
{
    int sock;
    long port;
    char *end;
    struct sockaddr_in server_addr;

    // The program requires the server IP address and S.E.C.R.E.T. port.
    if (argc != 3) {
        fprintf(stderr,
                "Usage: %s <IP address> <S.E.C.R.E.T. port>\n",
                argv[0]);
        return 1;
    }

    // Convert and validate the port argument.
    port = strtol(argv[2], &end, 10);

    if (end == argv[2] || *end != '\0' ||
        port < 1 || port > 65535) {
        fprintf(stderr, "Invalid port number\n");
        return 1;
    }

    // Fill in the server's IPv4 address and UDP port.
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET,
                  argv[1],
                  &server_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address\n");
        return 1;
    }

    sock = create_socket();

    if (sock < 0) {
        return 1;
    }

    if (solve_secret(sock, server_addr) < 0) {
        close(sock);
        return 1;
    }

    close(sock);
    return 0;
}
