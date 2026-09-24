#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

// Number of probes sent to a port before giving up.
#define ATTEMPTS 3

// How long to wait for one reply, measured in microseconds.
#define TIMEOUT_USEC 500000

// Biggest reply the scanner can receive.
#define BUFFER_SIZE 4096

// Message sent to every port.
#define PROBE_MESSAGE "Hello World!"


/*
 * Creates a UDP socket and gives it a receive timeout.
 * Returns the socket descriptor, or -1 if something fails.
 */
int create_socket(void)
{
    int sock;
    struct timeval timeout;

    // Create an IPv4 UDP socket.
    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        perror("socket failed");
        return -1;
    }

    // Set the amount of time recvfrom() is allowed to wait.
    timeout.tv_sec = 0;
    timeout.tv_usec = TIMEOUT_USEC;

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
 * Fills in the sockaddr_in structure that describes the server.
 * Returns 0 on success, or -1 if the IP address is invalid.
 */
int setup_server_address(struct sockaddr_in *server_addr,
                         const char *ip)
{
    // Clear the structure before filling it in.
    memset(server_addr, 0, sizeof(*server_addr));

    // The server uses an IPv4 address.
    server_addr->sin_family = AF_INET;

    // Convert the text IP address into its binary form.
    if (inet_pton(AF_INET, ip, &server_addr->sin_addr) != 1) {
        return -1;
    }

    return 0;
}


/*
 * Converts a port argument from text into an integer.
 * Returns 0 on success, or -1 if the argument is not a valid port.
 */
int parse_port(const char *text, int *port)
{
    char *end;
    long value;

    value = strtol(text, &end, 10);

    // Reject empty input, extra characters, and values outside the range.
    if (end == text || *end != '\0' || value < 1 || value > 65535) {
        return -1;
    }

    *port = (int)value;
    return 0;
}


/*
 * Sends probes to one UDP port and waits for a reply.
 * Returns 1 if the port answers, or 0 if no reply is received.
 */
int is_port_open(int sock,
                 struct sockaddr_in server_addr,
                 int port)
{
    int attempt;

    // Convert the port into network byte order.
    server_addr.sin_port = htons((uint16_t)port);

    for (attempt = 0; attempt < ATTEMPTS; attempt++) {
        char buffer[BUFFER_SIZE];
        struct sockaddr_in from_addr;
        socklen_t from_length = sizeof(from_addr);
        ssize_t bytes_received;

        /*
         * UDP does not create a connection, so sendto() receives the
         * destination address with every message.
         */
        if (sendto(sock,
                   PROBE_MESSAGE,
                   strlen(PROBE_MESSAGE),
                   0,
                   (struct sockaddr *)&server_addr,
                   sizeof(server_addr)) < 0) {
            perror("sendto failed");
            continue;
        }

        // Wait for a reply and record which address sent it.
        bytes_received = recvfrom(sock,
                                  buffer,
                                  sizeof(buffer) - 1,
                                  0,
                                  (struct sockaddr *)&from_addr,
                                  &from_length);

        if (bytes_received < 0) {
            // The timeout expired, so try the same port again.
            continue;
        }

        // Ignore replies that did not come from the port being tested.
        if (from_addr.sin_addr.s_addr !=
                server_addr.sin_addr.s_addr ||
            from_addr.sin_port != server_addr.sin_port) {
            continue;
        }

        // Add a string terminator so the reply can be printed safely.
        buffer[bytes_received] = '\0';

        printf("\nReply from port %d:\n%s\n", port, buffer);

        // The correct server port answered the probe.
        return 1;
    }

    // None of the attempts received a matching reply.
    return 0;
}


/*
 * Main:
 *
 * Checks the command-line arguments, creates the socket, and tests every
 * port in the requested range. Ports that answer are printed to the screen.
 */
int main(int argc, char *argv[])
{
    struct sockaddr_in server_addr;
    int low_port;
    int high_port;
    int sock;
    int port;

    // The program requires an IP address and two port numbers.
    if (argc != 4) {
        fprintf(stderr, "Error: wrong number of arguments.\n");
        fprintf(stderr,
                "Usage: %s <IP address> <low port> <high port>\n",
                argv[0]);
        return 1;
    }

    // Convert and validate both port arguments.
    if (parse_port(argv[2], &low_port) < 0 ||
        parse_port(argv[3], &high_port) < 0 ||
        low_port > high_port) {
        fprintf(stderr, "Invalid port range\n");
        return 1;
    }

    // Prepare the server's IPv4 address.
    if (setup_server_address(&server_addr, argv[1]) < 0) {
        fprintf(stderr, "Invalid IP address\n");
        return 1;
    }

    // Create the UDP socket used for all probes.
    sock = create_socket();

    if (sock < 0) {
        return 1;
    }

    // Test every port in the requested range.
    for (port = low_port; port <= high_port; port++) {
        if (is_port_open(sock, server_addr, port)) {
            printf("Port %d is open\n", port);
        }
    }

    close(sock);
    return 0;
}
