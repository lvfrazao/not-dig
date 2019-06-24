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

#include "argparse.c" 
#include "../dns/dns.h"
#include "format_answer.c"

#define MYPORT "53" // the port users will be connecting to
#define DEF_SERVER "8.8.8.8"
#define RESP_BUF_SIZE 1000000 // Source of issues, segault if response large than this
#define TRUE 1
#define FALSE 0
#define LINEBRK "\n==========================================================================================================\n\n"
#define DEBUG 0

double get_wall_time(void);

int main(int argc, char *argv[])
{
    char remote_port[6];
    char *remote_server; // 255.255.255.255\0
    char *domain;
    int qtype = 1;

    struct arguments arguments;

    /* Default values. */
    arguments.short_opt = 0;
    arguments.bin_opt = 0;
    arguments.port_opt = MYPORT;
    arguments.server_opt = DEF_SERVER;
    arguments.output_file = "-";

    argp_parse(&argp, argc, argv, 0, 0, &arguments);
    if (DEBUG)
    {
        printf("ARG1 = %s\nARG2 = %s\n", arguments.args[0], arguments.args[1]);
        printf("SERVER = %s PORT = %s\n", arguments.server_opt, arguments.port_opt);
        printf("OUTPUT_FILE = %s\n", arguments.output_file);
        printf("SHORT = %s\n", arguments.short_opt ? "yes" : "no");
        printf("BIN = %s\n", arguments.bin_opt ? "yes" : "no");
    }

    strcpy(remote_port, MYPORT);
    remote_server = arguments.server_opt;
    domain = arguments.args[0];
    qtype = qtype_str_to_int(arguments.args[1]);

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
