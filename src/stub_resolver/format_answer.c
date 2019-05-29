#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "../dns/dns.h"

#define VERSION "0.0.1"
#define DEBUG 0

char *str_to_upper(char *str);
char *qtype_to_str(uint16_t qtype_int);
int qtype_str_to_int(char *qtype_str);
char *opcode_to_str(uint8_t opcode_int);
char *rcode_to_str(uint8_t rcode_int);

void pretty_print_response(DNSMessage *msg, double query_time_usec, char *remote_server, char *remote_port, char *datetime, uint32_t msg_size, uint8_t *packet)
{
    if (DEBUG)
        print_packet(packet, msg_size);

    char *opcode = opcode_to_str(msg->head->opcode);
    char *status = rcode_to_str(msg->head->RCODE);
    char *qname;
    char *qtype;
    if (msg->head->QDCount)
    {
        qname = decode_domain_name((uint8_t *)msg->quest[0]->QNAME);
        qtype = qtype_to_str(msg->quest[0]->QTYPE);
    }
    else
    {
        qname = "N/A";
        qtype = "N/A";
    }

    printf("; <<>> Not DiG %s <<>> %s %s\n", VERSION, qname, qtype);
    printf(";; global options: +cmd\n");
    printf(";; Got answer:\n");
    printf(";; ->> HEADER <<- opcode: %s status: %s id: %d\n", str_to_upper(opcode), str_to_upper(status), msg->head->ID);
    printf(";; flags:");
    // Flags
    if (msg->head->AA)
        printf(" aa");
    if (msg->head->TC)
        printf(" tc");
    if (msg->head->RD)
        printf(" rd");
    if (msg->head->RA)
        printf(" ra");
    if (msg->head->AD)
        printf(" ad");
    if (msg->head->CD)
        printf(" cd");
    printf("; ");

    printf("QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
           msg->head->QDCount, msg->head->ANCOUNT, msg->head->NSCOUNT, msg->head->ARCOUNT);

    printf("\n");

    if (msg->head->QDCount)
        printf(";; QUESTION SECTION:\n");
    for (int i = 0; i < msg->head->QDCount; i++)
    {
        printf("%s\t\tIN\t\t%s\n", decode_domain_name((uint8_t *)msg->quest[i]->QNAME), qtype_to_str(msg->quest[i]->QTYPE));
    }
    printf("\n");

    if (msg->head->ANCOUNT)
        printf(";; ANSWER SECTION:\n");
    for (int i = 0; i < msg->head->ANCOUNT; i++)
    {
        char *data;
        data = msg->ans[i]->rdata_to_str(msg->ans[i], packet);
        printf("%s\t\t%d\t\tIN\t\t%s\t\t%s\n", decode_domain_name((uint8_t *)msg->ans[i]->NAME), msg->ans[i]->TTL, qtype_to_str(msg->ans[i]->RRTYPE), data);
    }

    if (msg->head->NSCOUNT)
        printf(";; AUTHORITY SECTION:\n");
    for (int i = 0; i < msg->head->NSCOUNT; i++)
    {
        char *data;
        data = msg->auth[i]->rdata_to_str(msg->auth[i], packet);
        printf("%s\t\t%d\t\tIN\t\t%s\t\t%s\n", decode_domain_name((uint8_t *)msg->auth[i]->NAME), msg->auth[i]->TTL, qtype_to_str(msg->auth[i]->RRTYPE), data);
    }

    if (msg->head->ARCOUNT)
        printf(";; ADDITIONAL SECTION:\n");
    for (int i = 0; i < msg->head->ARCOUNT; i++)
    {
        char *data;
        data = msg->addl[i]->rdata_to_str(msg->addl[i], packet);
        printf("%s\t\t%d\t\tIN\t\t%s\t\t%s\n", decode_domain_name((uint8_t *)msg->addl[i]->NAME), msg->addl[i]->TTL, qtype_to_str(msg->addl[i]->RRTYPE), data);
    }

    printf("\n;; Query time: %.0f msec\n", query_time_usec);
    printf(";; SERVER: %s#%s\n", remote_server, remote_port);
    printf(";; WHEN: %s\n", datetime);
    printf(";; MSG SIZE  rcvd: %d\n", msg_size);
    printf("\n");
}

char *str_to_upper(char *str)
{
    char *c = malloc(sizeof(char *) * strlen(str) + 1);

    int i = 0;
    while (str[i] != '\0')
    {
        c[i] = toupper(str[i]);
        i++;
    }
    c[i] = '\0';
    return c;
}

char *qtype_to_str(uint16_t qtype_int)
{
    return RRTYPES_STR[qtype_int];
}

int qtype_str_to_int(char *qtype_str)
{
    qtype_str = str_to_upper(qtype_str);
    uint16_t rrtypes_array_len = 259;
    for (uint16_t i = 0; i < rrtypes_array_len; i++)
    {
        if (strcmp(qtype_str, RRTYPES_STR[i]) == 0)
            return i;
    }
    fprintf(stderr, "Unknown question type, defaulting to QTYPE 1 (A record)\n");
    return 1;
}

char *opcode_to_str(uint8_t opcode_int)
{
    return OPCODES_STR[opcode_int];
}

char *rcode_to_str(uint8_t rcode_int)
{
    return RCODES_STR[rcode_int];
}
