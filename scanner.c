#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>

//Number of times we send a probe to the same port before giving up.
#define ATTEMPTS 3

//How long we wait for a reply to a single probe, in microseconds
#define TIMEOUT_USEC 500000

//Biggest reply we can read
#define BUFFER_SIZE 1000

//The message sent to each port
#define PROBE_MESSAGE "Hello World!"


/* Creating the udp socket
Creates the socket and gives it a recived timeout, returns the socket descriptor or -1 on failure
*/
int crate_socket(void)
{
        int sock;
        struct timeval timeout;
        //adding UDP socket
        sock = socket(AF_INET, SOCK_DGRAM, 0);

        //checking if it failed
        if (sock < 0) {
                perror("socket failed");
                return -1;
        }

        timeout.tv_sec = 0;
        timeout.tv_usec = TIMEOUT_USEC;

        //set the timeout and bail if it fails
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                        &timeout, sizeof(timeout)) < 0) {
                perror("setsockopt failed");
                close(sock);
                return -1;
        }

        return sock;



}
/*the setup_server_address fills in the struct sockaddr_in which describes the server being scanned
Returns 0 if succesfull else -1
*/
int setup_server_address(struct sockaddr_in *server_addr, const char *ip)
{
        //Clear the structure first
        memset(server_addr, 0, sizeof(*server_addr));
        //server_addr is a IPv4 address
        server_addr->sin_family = AF_INET;

        //inet_pton turns the text address into the binary form returns 1 if text is a valid address 
        if (inet_pton(AF_INET, ip, &server_addr->sin_addr) != 1) {
                return -1;
        }

        return 0;
}

/* Check if port are open and check if it answered, returns 1 if port answered else 0
*/
int is_port_open(int sock, struct sockaddr_in server_addr, int port)
{
        int attempt;

        //htons converts the port number into network byte order
        server_addr.sin_port = htons(port);

        for (attempt = 0; attempt < ATTEMPTS; attempt++) {
                //holds the reply
                char buffer[BUFFER_SIZE];
                //who the reply came from
                struct sockaddr_in from_addr;
                //size of the record
                socklen_t from_len = sizeof(from_addr);
                //how many bytes recived
                int bytes;

                //UDP has no connection so the destination is given to sendto()
                if (sendto(sock, PROBE_MESSAGE, strlen(PROBE_MESSAGE), 0,
                                (struct sockaddr *)&server_addr,
                                sizeof(server_addr)) < 0) {
                        perror("sendto failed");
                        continue;
        }

                //Wait for a reply, recvfrom() reports who sent it
                bytes = recvfrom(sock, buffer, sizeof(buffer), 0,
                                (struct sockaddr *)&from_addr, &from_len);

                if (bytes < 0) {
                        continue;   //the timeout expired with no reply 
                }

                //ignore replies that did not come from the port we probed
                if (from_addr.sin_addr.s_addr != server_addr.sin_addr.s_addr || 
                   from_addr.sin_port != server_addr.sin_port) {
                        continue;
                }
                //return 1 if a reply came from the port we asked
                return 1;
        }

        return 0;
}


/*Main 
Reads and checks the command line arguments, 
sets up the socket and the server address, 
then tests every port in the range and prints the ones that answer
*/

int main(int argc, char *argv[])
{
        struct sockaddr_in server_addr;
        int low_port, high_port, sock, port;

        if (argc != 4) {
                printf("Error: wrong number of arguments.\n");
                printf("Usage: %s <IP address> <low port> <high port>\n", argv[0]);
                return 1;
        }
        //converts the port input from string into int
        low_port = atoi(argv[2]);
        high_port = atoi(argv[3]);

        //Checks if the ports are within permitted range
        if (low_port < 1 || high_port > 65535 || low_port > high_port) {
                printf("Invalid port range\n");
                return 1;
        }

        //Fill in the struct that holds the servers IP address so its ready to be passed to sendto() later
        if (setup_server_address(&server_addr, argv[1]) < 0) {
                printf("Invalid IP address\n");
                return 1;
        }

        sock = crate_socket();
        if (sock < 0) {
                return 1;
        }
        
        //Work through the ports and printing those who answer
        for (port = low_port; port <= high_port; port++) {
                if (is_port_open(sock, server_addr, port) == 1) {
                        printf("Port %d is open\n", port);
                }
        }

        close(sock);
        return 0;
}







