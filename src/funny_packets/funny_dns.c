/*
Ideas:

1. Name pointers to out of bounds location (check)
2. Name pointers to wrong location (check)
3. Name that ends out of bounds > 04 77 77 <END OF Packet>
4. Multiple questions, one packet (check)
5. Give wrong len in txt
6. give wrong len in HINFO

*/
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include "../dns/dns.h"
#include "../stub_resolver/format_answer.c"

#define DEBUG 1
#define LINEBRK "\n==========================================================================================================\n\n"
#define RESP_BUF_SIZE 10000

int send_packet(uint8_t *packet, uint32_t packet_len, char *remote_port, char *remote_server);
double get_wall_time(void);

int multi_question_query(char *remote_port, char *remote_server);
int bad_ptr_1_query(char *remote_port, char *remote_server);
int bad_ptr_2_query(char *remote_port, char *remote_server);
int bad_ptr_3_query(char *remote_port, char *remote_server);
int bad_ptr_4_query(char *remote_port, char *remote_server);
int incomplete_packet_1_query(char *remote_port, char *remote_server);

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <port> <server>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    char *remote_server, *remote_port;
    remote_port = argv[1];
    remote_server = argv[2];
    printf("Testing multi_question query\n");
    //multi_question_query(remote_port, remote_server);
    printf("Testing bad pointer 1 query\n");
    //bad_ptr_1_query(remote_port, remote_server);
    printf("Testing bad pointer 2 query\n");
    //bad_ptr_2_query(remote_port, remote_server);
    printf("Testing bad pointer 3 query\n");
    //bad_ptr_3_query(remote_port, remote_server);
    printf("Testing bad pointer 4 query\n");
    //bad_ptr_4_query(remote_port, remote_server);
    printf("Testing incomplete packet query\n");
    incomplete_packet_1_query(remote_port, remote_server);
    return 0;
}

int multi_question_query(char *remote_port, char *remote_server)
{
    uint8_t packet[] = {
        // Header
        0xaa, 0xaa, // ID
        0x01, 0x20, // QR(0) query, RD, AD
        0x00, 0x02, // 2 questions
        0x00, 0x00, // 0 answer
        0x00, 0x00, // 0 NS
        0x00, 0x00, // 0 additional
        // Question 1
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, // google.com.
        0x00, 0x01,                                                             // qtype 1 (A)
        0x00, 0x01,                                                             // qclass 1 (IN)
        // Question 2
        0x06, 0x66, 0x72, 0x61, 0x7a, 0x61, 0x6f, 0x02, 0x63, 0x61, 0x00, // qname frazao.ca
        0x00, 0x01,                                                       // qtype 1 (A)
        0x00, 0x01                                                        // qclass 1 (IN)
    };
    send_packet(packet, 46, remote_port, remote_server);
    return 0;
}

int bad_ptr_1_query(char *remote_port, char *remote_server)
{
    // Make name pointer out of bounds (past end of packet)
    uint8_t packet[] = {
        // Header
        0xaa, 0xaa, // ID
        0x01, 0x20, // QR(0) query, RD, AD
        0x00, 0x01, // 1 questions
        0x00, 0x00, // 0 answer
        0x00, 0x00, // 0 NS
        0x00, 0x00, // 0 additional
        // Question 1
        0xc0, 0xFF, // Out of bounds name
        0x00, 0x01, // qtype 1 (A)
        0x00, 0x01  // qclass 1 (IN)
    };
    send_packet(packet, 18, remote_port, remote_server);
    return 0;
}

int bad_ptr_2_query(char *remote_port, char *remote_server)
{
    // Make name pointer point to beginning of packet
    uint8_t packet[] = {
        // Header
        0xaa, 0xaa, // ID
        0x01, 0x20, // QR(0) query, RD, AD
        0x01, 0x63, // questions
        0x01, 0x63, // answer
        0x01, 0x63, // NS
        0x01, 0x63, // additional
        // Question 1
        0xc0, 0x00, // Pointer to beginning of header
        0x00, 0x01, // qtype 1 (A)
        0x00, 0x01  // qclass 1 (IN)
    };
    send_packet(packet, 18, remote_port, remote_server);
    return 0;
}

int bad_ptr_3_query(char *remote_port, char *remote_server)
{
    // Make name pointer point to itself (circular pointer)
    uint8_t packet[] = {
        // Header
        0xaa, 0xaa, // ID
        0x01, 0x20, // QR(0) query, RD, AD
        0x00, 0x01, // 1 question
        0x00, 0x00, // 0 answer
        0x00, 0x00, // 0 NS
        0x00, 0x00, // 0 additional
        // Question 1
        0xc0, 0x0c, // Pointer to itself
        0x00, 0x01, // qtype 1 (A)
        0x00, 0x01  // qclass 1 (IN)
    };
    send_packet(packet, 18, remote_port, remote_server);
    return 0;
}

int bad_ptr_4_query(char *remote_port, char *remote_server)
{
    // Make name pointer point to itself (circular pointer)
    uint8_t packet[] = {
        // Header
        0xaa, 0xaa, // ID
        0x01, 0x20, // QR(0) query, RD, AD
        0x00, 0x01, // 1 question
        0x00, 0x00, // 0 answer
        0x00, 0x00, // 0 NS
        0x00, 0x00, // 0 additional
        // Question 1
        0x03, 0x77, 0x77, 0x77, 0xc0, 0x0c, // www => www => www ...
        0x00, 0x01,                         // qtype 1 (A)
        0x00, 0x01                          // qclass 1 (IN)
    };
    send_packet(packet, 22, remote_port, remote_server);
    return 0;
}

int incomplete_packet_1_query(char *remote_port, char *remote_server)
{
    // Make name pointer point to itself (circular pointer)
    uint8_t packet[] = {
        // Header
        0xaa, 0xaa, // ID
        0x01, 0x20, // QR(0) query, RD, AD
        0x00, 0x01, // 1 question
        0x00, 0x00, // 0 answer
        0x00, 0x00, // 0 NS
        0x00, 0x00, // 0 additional
        // Question 1
        0x03, 0x77, 0x77, 0x77 // www
    };
    send_packet(packet, 16, remote_port, remote_server);
    return 0;
}

int send_packet(uint8_t *packet, uint32_t packet_len, char *remote_port, char *remote_server)
{
    struct addrinfo hints, *res;
    int sockfd;

    if (DEBUG)
    {
        char my_host[1000];
        gethostname(my_host, sizeof my_host);
        printf("Current server hostname: %s\n", my_host);
    }

    // first, load up address structs with getaddrinfo():

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use IPv4 or IPv6, whichever
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // fill in my IP for me

    getaddrinfo(NULL, remote_port, &hints, &res);

    // make a socket:
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    // Set timeout for receiving data (dont want to block forever)
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        perror("Error");
    }

    /* Send message to remote server */
    // Set up remote server info
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(atoi(remote_port));
    servaddr.sin_addr.s_addr = inet_addr(remote_server);

    // Receive response from server
    unsigned int from_len;
    int num_bytes = -1, failures = 0;
    uint8_t resp[RESP_BUF_SIZE];

    double start = get_wall_time();
    while (num_bytes == -1)
    {
        sendto(sockfd, packet, packet_len, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
        if (DEBUG)
        {
            printf("%s", LINEBRK);
            printf("Sent message to %s:%s\n", remote_server, remote_port);
            for (int i = 0; i < packet_len; i++)
            {
                printf("%02X ", packet[i]);
                if ((i + 1) % 2 == 0)
                    printf("\n");
            }
            printf("%s", LINEBRK);
        }
        num_bytes = recvfrom(sockfd, resp, RESP_BUF_SIZE, MSG_WAITALL, (struct sockaddr *)&servaddr, &from_len);
        if (num_bytes == -1)
        {
            failures++;
        }
        if (failures > 3)
        {
            fprintf(stderr, "Socket timed out waiting for response\n");
            exit(EXIT_FAILURE);
        }
    }

    double end = get_wall_time();
    if (DEBUG)
    {
        printf("Received %d bytes from %s:%s\n", num_bytes, remote_server, remote_port);
        if (num_bytes == -1)
        {
            perror("Error receiving response: ");
        }
        else
        {
            for (int i = 0; i < num_bytes; i++)
            {
                printf("%02X ", resp[i]);
                if ((i + 1) % 2 == 0)
                    printf("\n");
            }
        }
        printf("%s", LINEBRK);
    }

    close(sockfd);

    DNSMessage *ans_msg = packet_to_message(resp);

    // Generate datetime
    char datetime[40];
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    // Date time format: "Sat May 25 00:51:17 DST 2019"
    strftime(datetime, sizeof(datetime), "%a %b %d %X %Z %Y", tm);

    pretty_print_response(ans_msg, (end - start) * 1000, remote_server, remote_port, datetime, num_bytes, resp);

    return 0;
}

// Helper funcs
// From https://stackoverflow.com/questions/17432502/how-can-i-measure-cpu-time-and-wall-clock-time-on-both-linux-windows
double get_wall_time()
{
    struct timeval time;
    if (gettimeofday(&time, NULL))
    {
        //  Handle error
        return 0;
    }
    return (double)time.tv_sec + (double)time.tv_usec * .000001;
}
