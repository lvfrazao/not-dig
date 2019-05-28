#pragma once

#include "dns_packet.c"

DNSMessage *make_query_message(char *domain, uint16_t qtype, uint8_t rd)
{
    Header *query_header;
    Question *query_question;
    DNSMessage *msg;

    /*
    Flags:
    QR 0 (query)
    opcode 0 (query)
    AA 0 (not an auth response)
    TC 0 (message will fit in one packet)
    RD set to 1 if askign a recursive server
    RA 0, this is set by the responding server
    AD 1, desired DNSSEC validation
    RCODE 0 (no error)
    QD Count 1
    AN, AR, NS count are 0
    */ 
    uint16_t ID = generate_random_id();
    query_header = __init__header(ID, 0, 0, 0, 0, rd, 0, 0, 1, 0, 0, 1, 0, 0, 0);
    query_question = __init__question(domain, qtype, 1);
    if (query_header == NULL || query_question == NULL)
    {
        fprintf(stderr, "Unable to generate DNS header or question\n");
        return NULL;
    }
    Question **quest_list = malloc(sizeof(Question*) * 1);
    *quest_list = query_question;
    msg = __init__message(query_header, quest_list, NULL, NULL, NULL);
    if (msg == NULL)
    {
        fprintf(stderr, "Unable to generate DNS message\n");
        return NULL;
    }
    return msg;
}
