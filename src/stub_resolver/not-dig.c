//#pragma once

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
#include <time.h>

#include "../dns/dns.h"
#include "format_answer.c"

#define MYPORT "53" // the port users will be connecting to
#define BACKLOG 10  // how many pending connections queue will hold
#define DEF_SERVER "8.8.8.8"
#define BUF_SIZE 1
#define RESP_BUF_SIZE 10000
#define TRUE 1
#define FALSE 0
#define LINEBRK "\n==========================================================================================================\n\n"
#define DEBUG 0

int isint(char *str);
int h_in_command_line(int argc, char *argv[]);
double get_wall_time(void);

int main(int argc, char *argv[])
{
    char remote_port[6];
    char *remote_server; // 255.255.255.255\0
    char *domain;
    int qtype = 1;

    if (h_in_command_line(argc, argv))
        argc = 1;
    switch (argc)
    {
    case 1:
        fprintf(stderr, "Usage: %s <port number> <server addr> <name> <qtype>\n", argv[0]);
        exit(EXIT_FAILURE);
        break;
    case 2:
        strcpy(remote_port, MYPORT);
        remote_server = DEF_SERVER;
        domain = argv[1];
        break;
    case 3:
        strcpy(remote_port, MYPORT);
        remote_server = DEF_SERVER;
        domain = argv[1];
        qtype = qtype_str_to_int(argv[2]);
        break;
    case 4:
        strcpy(remote_port, MYPORT);
        remote_server = argv[1];
        domain = argv[2];
        qtype = qtype_str_to_int(argv[3]);
        break;
    case 5:
        if (isint(argv[1]) && atoi(argv[1]) <= 65535)
            strcpy(remote_port, argv[1]);
        else
        {
            fprintf(stderr, "Port must be an integer under 65535\n");
            exit(EXIT_FAILURE);
        }
        remote_server = argv[2];
        domain = argv[3];
        if (!isint(argv[4]))
        qtype = qtype_str_to_int(argv[4]);
        break;
    default:
        fprintf(stderr, "Usage: %s <port number> <remote server> <name>\n", argv[0]);
        exit(1);
        break;
    }

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

    // Generate message to send
    DNSMessage *msg = make_query_message(domain, qtype, 1);
    if (msg == NULL)
    {
        exit(EXIT_FAILURE);
    }
    uint8_t *packet = msg->to_wire_uncompressed(msg);

    // Receive response from server
    unsigned int from_len;
    int num_bytes = -1, failures = 0;
    uint8_t resp[RESP_BUF_SIZE];

    double start = get_wall_time();
    while (num_bytes == -1)
    {
        sendto(sockfd, packet, msg->__len__uncomp, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
        if (DEBUG)
        {
            printf("%s", LINEBRK);
            printf("Sent message to %s:%s\n", remote_server, remote_port);
            for (int i = 0; i < msg->__len__uncomp; i++)
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
            // Not sure whether we want to generate a new ID for the retry
            // msg->head->ID = generate_random_id();
            // packet = msg->to_wire_uncompressed(msg);
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

    msg->__del__(msg);
    free(packet);
    return 0;
}

// Helper funcs
int isint(char *str)
{
    char *c = str;
    while (*c != '\0')
    {
        if (!isdigit(*c))
            return 0;
        c++;
    }
    return 1;
}

int h_in_command_line(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++)
    {
        if (*(argv[i]) == '-' && *(argv[i] + 1) == 'h')
        {
            return 1;
        }
    }
    return 0;
}

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
