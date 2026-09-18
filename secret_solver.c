#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define BUFFER_SIZE 4096
#define TIMEOUT_USEC 2000000

#define GROUP_MEMBERS "regina24,steinunnp24"

/*
 * Creates a random 32-bit secret number using /dev/urandom.
 * Returns 0 on success and -1 on failure.
 */
int generate_secret_number(uint32_t *secret)
{
    FILE *random_file;

    random_file = fopen("/dev/urandom", "rb");

    if (random_file == NULL) {
        perror("Could not open /dev/urandom");
        return -1;
    }

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
 * Returns the socket descriptor, or -1 on failure.
 */
int create_socket(void)
{
    int sock;
    struct timeval timeout;

    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        perror("socket failed");
        return -1;
    }

    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed");
        close(sock);
        return -1;
    }

    return sock;
}

/*
 * Solves the S.E.C.R.E.T. puzzle.
 * Returns 0 on success and -1 on failure.
 */
int solve_secret(int sock, struct sockaddr_in server_addr)
{
    const char text_part[] = "S.E.C.R.E.T.:" GROUP_MEMBERS;
    unsigned char first_message[BUFFER_SIZE];
    unsigned char reply[BUFFER_SIZE];
    unsigned char second_message[5];

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

    struct sockaddr_in from_addr;
    socklen_t from_length;

    /* Step 1: Generate our secret 32-bit number. */
    if (generate_secret_number(&secret_number) < 0) {
        return -1;
    }

    printf("Secret number: %u\n", secret_number);

    /*
     * Step 2: Copy the text part into the outgoing message.
     *
     * strlen() is used only for the textual portion. The four binary
     * bytes added afterward might contain zero bytes.
     */
    text_length = strlen(text_part);
    memcpy(first_message, text_part, text_length);

    /*
     * Convert the number into network byte order before sending it.
     */
    secret_network_order = htonl(secret_number);

    /*
     * Put the secret number immediately after the text.
     * It now occupies the final four bytes of the message.
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
     * Step 3: Receive the five-byte reply:
     *
     * reply[0]   = group ID
     * reply[1-4] = challenge
     */
    from_length = sizeof(from_addr);

    bytes_received = recvfrom(sock,
                              reply,
                              sizeof(reply),
                              0,
                              (struct sockaddr *)&from_addr,
                              &from_length);

    if (bytes_received < 0) {
        perror("Did not receive the challenge");
        return -1;
    }

    if (bytes_received != 5) {
        fprintf(stderr,
                "Expected a 5-byte challenge, but received %zd bytes\n",
                bytes_received);

        printf("Server response: %.*s\n",
               (int)bytes_received, (char *)reply);

        return -1;
    }

    group_id = reply[0];

    /*
     * Copy bytes 1-4 into the challenge variable.
     * We use memcpy because reply + 1 may not be correctly aligned
     * for direct conversion into a uint32_t pointer.
     */
    memcpy(&challenge_network_order, reply + 1, sizeof(uint32_t));
    challenge = ntohl(challenge_network_order);

    printf("Group ID: %u\n", group_id);
    printf("Challenge: %u\n", challenge);

    /*
     * Step 4: Apply XOR to the challenge and our secret number.
     */
    sigil = challenge ^ secret_number;

    printf("Sigil: %u\n", sigil);

    /*
     * Step 5: Construct the exact five-byte response.
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
     * Step 6: Receive the hidden secret.
     *
     * Leave one unused byte so that we can add '\0' and print the
     * response as a C string.
     */
    from_length = sizeof(from_addr);

    bytes_received = recvfrom(sock,
                              reply,
                              sizeof(reply) - 1,
                              0,
                              (struct sockaddr *)&from_addr,
                              &from_length);

    if (bytes_received < 0) {
        perror("Did not receive the hidden secret");
        return -1;
    }

    reply[bytes_received] = '\0';

    printf("\nS.E.C.R.E.T. response:\n%s\n", reply);

    int hidden_port;
    char *port_text;

    port_text = strstr((char *)reply, "hidden port:");

    if (port_text == NULL ||
        sscanf(port_text, "hidden port: %d", &hidden_port) != 1) {
        fprintf(stderr, "Could not find the hidden port in the response\n");
        return -1;
    }

    printf("Extracted hidden port: %d\n", hidden_port);

    /*
     * Keep group_id and sigil in variables. The final puzzle solver
     * will pass them to the other puzzle-solving functions.
     */
    printf("\nKeep these values for the later puzzles:\n");
    printf("Group ID: %u\n", group_id);
    printf("Sigil: %u\n", sigil);

    return 0;
}

int main(int argc, char *argv[])
{
    int sock;
    long port;
    char *end;
    struct sockaddr_in server_addr;

    if (argc != 3) {
        fprintf(stderr,
                "Usage: %s <IP address> <S.E.C.R.E.T. port>\n",
                argv[0]);
        return 1;
    }

    port = strtol(argv[2], &end, 10);

    if (*end != '\0' || port < 1 || port > 65535) {
        fprintf(stderr, "Invalid port number\n");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, argv[1], &server_addr.sin_addr) != 1) {
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
