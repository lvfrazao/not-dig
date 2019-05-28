/*
Build artisanal DNS packets.
*/
#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "dns_data.c"
#include "dns_errors.c"
//#include "rrtypes.c"

// Global error variable
enum DNSERRORS last_result = NOERROR;

//Prototypes
typedef struct header Header;
typedef struct question Question;
typedef struct rrformat RRFORMAT;
typedef struct rrformat Answer;
typedef struct rrformat Authority;
typedef struct rrformat Additional;
typedef struct dns_message DNSMessage;

char *encode_domain_name(char *name);
char *decode_domain_name(uint8_t *encoded_name);
uint16_t generate_random_id(void);
uint8_t *message_to_packet(DNSMessage *self);
uint16_t *header_to_bytes(Header *self);
uint8_t *question_to_bytes(Question *self);
uint8_t *rr_to_bytes_uncompressed(Answer *self);
uint8_t *message_to_packet_uncompressed(DNSMessage *self);
uint32_t calc_uncomp_packet_len(DNSMessage *msg);
uint32_t arraylen(uint8_t *array);
void arraycat(uint8_t *left_array, uint8_t *right_array, uint16_t max_len);
uint8_t is_compressed(uint8_t cur_byte);
uint8_t *decompress_name(uint8_t *packet, uint32_t *cur_loc);

Header *bytes_to_header(uint8_t *packet);
Question *bytes_to_question(uint8_t *packet, uint32_t *cur_loc);
RRFORMAT *bytes_to_resource_record(uint8_t *packet, uint32_t *cur_loc);
char *rdata_to_str(RRFORMAT *res_record, uint8_t *packet);

// Data structures used to represent DNS messages
typedef struct header
{
    /*
    Header:
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|Z |AD|CD|   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    uint16_t ID;      // line 1 16 bit identifier to match question with answer
    uint8_t QR;       // bit 0 SPecifies if a message is a query
    uint8_t opcode;   // bits 1-4, 4 bit field that specifies the query
    uint8_t AA;       // bit 5 Authoritative Answer
    uint8_t TC;       // bit 6 Truncated Response
    uint8_t RD;       // bit 7 Recursion Desired
    uint8_t RA;       // bit 8 Recursion Available
    uint8_t RES;      // bit 9 Reserved - always 0!
    uint8_t AD;       // bit 10 Authentic Data
    uint8_t CD;       // bit 10 Checking Disabled
    uint8_t RCODE;    // bits 12-15 Response code
    uint16_t QDCount; // 16 bit int Number of Questions
    uint16_t ANCOUNT; // 16 bit int Number of Answers
    uint16_t NSCOUNT; // 16 bit int Number of name server RR in the authority section
    uint16_t ARCOUNT; // 16 bit int Number of RR in additional section
    uint16_t *(*to_wire)(Header *);
    void (*__del__)(Header *);
    uint16_t __len__;
} Header;

struct question
{
    /*
    Question Section:
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    char *QNAME;     // consists of a length octet followed by that number of octets
    uint16_t QTYPE;  // 2 byte code specifies the type of query
    uint16_t QCLASS; // 2 byte code specifies the class of query (IN)
    uint16_t __len__;
    uint8_t *(*to_wire)(Question *);
    void (*__del__)(Question *);
};
typedef struct question Question;

struct rrformat
{
    /*
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    /*
    Domain name. Can be a combination of pointers (start with 11) or 
    the length of the label followed by that number of octets. All names
    end with a 0 byte byte.
    */
    char *NAME;        // Domain Name
    uint16_t RRTYPE;   // Record Type (e.g., A)
    uint16_t CLASS;    // Query class (IN)
    int32_t TTL;       // Time to live value of record
    uint16_t RDLENGTH; // Length in bytes of RDATA field
    uint8_t *RDATA;    // The answer (e.g., an IPv4 addr for an A record)
    uint8_t *(*to_wire)(RRFORMAT *);
    char *(*rdata_to_str)(RRFORMAT *, uint8_t *);
    uint16_t __len__;
    void (*__del__)(RRFORMAT *); // Destructor method
};
typedef struct rrformat RRFORMAT;
typedef struct rrformat Answer;
typedef struct rrformat Authority;
typedef struct rrformat Additional;

struct dns_message
{
    Header *head;
    Question **quest;  // May be more than one
    Answer **ans;      // May be more than one
    Authority **auth;  // May be more than one
    Additional **addl; // May be more than one
    uint32_t __len__uncomp;
    uint32_t __len__;
    uint8_t *(*to_wire)(DNSMessage *);
    uint8_t *(*to_wire_uncompressed)(DNSMessage *);
    char *(*to_str)(DNSMessage *);
    void (*__del__)(DNSMessage *);
};
typedef struct dns_message DNSMessage;

// Struct destructor methods
void __del__header(Header *self)
{
    free(self);
}

void __del__question(Question *self)
{
    free(self->QNAME);
    free(self);
}

void __del__rrformat(RRFORMAT *self)
{
    free(self->NAME);
    free(self->RDATA);
    free(self);
}

void __del__message(DNSMessage *self)
{
    for (int i = 0; i < self->head->QDCount; i++)
        self->quest[i]->__del__(self->quest[i]);
    free(self->quest);
    for (int i = 0; i < self->head->ANCOUNT; i++)
        self->ans[i]->__del__(self->ans[i]);
    free(self->ans);
    for (int i = 0; i < self->head->NSCOUNT; i++)
        self->auth[i]->__del__(self->auth[i]);
    free(self->auth);
    for (int i = 0; i < self->head->ARCOUNT; i++)
        self->addl[i]->__del__(self->addl[i]);
    free(self->addl);
    self->head->__del__(self->head);
    free(self);
}

// Constructor functions for each struct
Header *__init__header(
    uint16_t ID,
    uint8_t QR,
    uint8_t opcode,
    uint8_t AA,
    uint8_t TC,
    uint8_t RD,
    uint8_t RA,
    uint8_t RES,
    uint8_t AD,
    uint8_t CD,
    uint8_t RCODE,
    uint16_t QDCount,
    uint16_t ANCOUNT,
    uint16_t NSCOUNT,
    uint16_t ARCOUNT)
{
    Header *self = malloc(sizeof(Header));
    if (self == NULL)
    {
        perror("Unable to create header: ");
        return NULL;
    }
    self->ID = ID;
    self->QR = QR;
    self->opcode = opcode;
    self->AA = AA;
    self->TC = TC;
    self->RD = RD;
    self->RA = RA;
    self->RES = RES;
    self->AD = AD;
    self->CD = CD;
    self->RCODE = RCODE;
    self->QDCount = QDCount;
    self->ANCOUNT = ANCOUNT;
    self->NSCOUNT = NSCOUNT;
    self->ARCOUNT = ARCOUNT;
    self->to_wire = *header_to_bytes;
    self->__del__ = *__del__header;
    self->__len__ = 12; // 12 bytes fixed size
    return self;
}
Question *__init__question(char *QNAME, uint16_t QTYPE, uint16_t QCLASS)
{
    Question *self = malloc(sizeof(Question));
    self->QNAME = encode_domain_name(QNAME);
    if (last_result)
    {
        // Check if domain name valid & properly encoded
        last_result = QUESTIONFAIL;
        return NULL;
    }
    self->QTYPE = QTYPE;
    self->QCLASS = QCLASS; // Always going to be 0x00 0x01 (decimal 1)
    self->__len__ = (strlen(self->QNAME) + 1) + 4;
    self->to_wire = *question_to_bytes;
    self->__del__ = *__del__question;
    last_result = NOERROR;
    return self;
}
RRFORMAT *__init__rr(
    char *NAME,
    uint16_t RRTYPE,
    uint16_t CLASS,
    int32_t TTL,
    uint16_t RDLENGTH,
    uint8_t *RDATA)
{
    RRFORMAT *self = malloc(sizeof(RRFORMAT));
    self->NAME = encode_domain_name(NAME);
    if (last_result)
    {
        // Check if domain name valid & properly encoded
        last_result = INVALID_DOMAIN;
        return NULL;
    }
    self->RRTYPE = RRTYPE;
    self->CLASS = CLASS; // 00 01
    self->TTL = TTL;
    self->RDLENGTH = RDLENGTH;
    self->RDATA = RDATA;
    self->to_wire = *rr_to_bytes_uncompressed;
    self->rdata_to_str = *rdata_to_str;
    self->__len__ = (strlen(self->NAME) + 1) + self->RDLENGTH +
                    sizeof(self->RRTYPE) + sizeof(self->CLASS) +
                    sizeof(self->TTL) + sizeof(self->RDLENGTH);
    self->__del__ = *__del__rrformat;
    last_result = NOERROR;
    return self;
}

Answer *__init__answer(
    char *NAME,
    uint16_t RRTYPE,
    uint16_t CLASS,
    int32_t TTL,
    uint16_t RDLENGTH,
    uint8_t *RDATA)
{
    return (Answer *)__init__rr(NAME,
                                RRTYPE,
                                CLASS,
                                TTL,
                                RDLENGTH,
                                RDATA);
}

Authority *__init__authority(
    char *NAME,
    uint16_t RRTYPE,
    uint16_t CLASS,
    int32_t TTL,
    uint16_t RDLENGTH,
    uint8_t *RDATA)
{
    return (Authority *)__init__rr(NAME,
                                   RRTYPE,
                                   CLASS,
                                   TTL,
                                   RDLENGTH,
                                   RDATA);
}
Additional *__init__additional(
    char *NAME,
    uint16_t RRTYPE,
    uint16_t CLASS,
    int32_t TTL,
    uint16_t RDLENGTH,
    uint8_t *RDATA)
{
    return (Additional *)__init__rr(NAME,
                                    RRTYPE,
                                    CLASS,
                                    TTL,
                                    RDLENGTH,
                                    RDATA);
}

DNSMessage *__init__message(
    Header *head,
    Question **quest,
    Answer **ans,
    Authority **auth,
    Additional **addl)
{
    DNSMessage *self = malloc(sizeof(DNSMessage));
    self->head = head;
    self->quest = quest;
    if (!self->head || !self->quest)
    {
        last_result = MSGFAIL;
        return NULL;
    }
    self->ans = ans;
    self->auth = auth;
    self->addl = addl;
    self->__len__uncomp = calc_uncomp_packet_len(self);
    self->__len__ = 0; // Unknown at this time
    self->to_wire = *message_to_packet;
    self->to_wire_uncompressed = *message_to_packet_uncompressed;
    self->__del__ = *__del__message;
    last_result = NOERROR;
    return self;
}

DNSMessage *packet_to_message(uint8_t *packet)
{
    Header *msg_head = bytes_to_header(packet);
    uint32_t cur_loc = 12; // Stndard header size

    Question **quest = malloc(sizeof(Question *) * msg_head->QDCount);
    Answer **ans = malloc(sizeof(Answer *) * msg_head->ANCOUNT);
    Authority **auth = malloc(sizeof(Authority *) * msg_head->NSCOUNT);
    Authority **addl = malloc(sizeof(Additional *) * msg_head->ARCOUNT);

    for (int i = 0; i < msg_head->QDCount; i++)
    {
        quest[i] = bytes_to_question(packet, &cur_loc);
    }

    for (int i = 0; i < msg_head->ANCOUNT; i++)
    {
        ans[i] = (Answer *)bytes_to_resource_record(packet, &cur_loc);
    }

    for (int i = 0; i < msg_head->NSCOUNT; i++)
    {
        auth[i] = (Authority *)bytes_to_resource_record(packet, &cur_loc);
    }

    for (int i = 0; i < msg_head->ARCOUNT; i++)
    {
        addl[i] = (Additional *)bytes_to_resource_record(packet, &cur_loc);
    }

    DNSMessage *msg = __init__message(msg_head, quest, ans, auth, addl);
    return msg;
}

Header *bytes_to_header(uint8_t *packet)
{
    /*
    Decodes a byte stream into a header object.
    The header always comprises the first 12 bytes of a DNS packet.
    */
    uint8_t QR, opcode, AA, TC, RD, RA, RES, AD, CD, RCODE;
    uint16_t ID, QDCount, ANCOUNT, NSCOUNT, ARCOUNT;
    // Line 1
    ID = packet[0];
    ID = (ID << 8) | packet[1];
    // Line 2
    QR = packet[2] >> 7;
    opcode = (packet[2] >> 3) & 0xF;
    AA = (packet[2] >> 2) & 1;
    TC = (packet[2] >> 1) & 1;
    RD = packet[2] & 1;
    RA = packet[3] >> 7;
    RES = (packet[3] >> 6) & 1;
    AD = (packet[3] >> 5) & 1;
    CD = (packet[3] >> 4) & 1;
    RCODE = packet[3] & 0xF;
    // Line 3
    QDCount = packet[4];
    QDCount = (QDCount << 8) | packet[5];
    // Line 4
    ANCOUNT = packet[6];
    ANCOUNT = (ANCOUNT << 8) | packet[7];
    // Line 5
    NSCOUNT = packet[8];
    NSCOUNT = (NSCOUNT << 8) | packet[9];
    // Line 6
    ARCOUNT = packet[10];
    ARCOUNT = (ARCOUNT << 8) | packet[11];
    Header *message_header = __init__header(ID, QR, opcode, AA, TC, RD, RA, RES,
                                            AD, CD, RCODE, QDCount, ANCOUNT, NSCOUNT,
                                            ARCOUNT);
    return message_header;
}

Question *bytes_to_question(uint8_t *packet, uint32_t *cur_loc)
{
    /*
    Decodes a byte stream into a question object.
    The first question always starts at index 12 of the byte stream.
    The end is variable due to the variable len of the qname.
    */
    char *QNAME;
    uint16_t QTYPE, QCLASS;
    uint8_t compressed_qname = (packet[*cur_loc] >> 6) & 0x3;
    if (compressed_qname)
    {
        uint16_t ptr_loc;
        ptr_loc = packet[*cur_loc];
        ptr_loc = (ptr_loc << 8) | packet[*cur_loc + 1];
        ptr_loc &= 0x3FFF; // The pointer is actually contained in the last 14 bits
        QNAME = decode_domain_name(&packet[ptr_loc]);
        *cur_loc += 2;
    }
    else
    {
        QNAME = decode_domain_name(&packet[*cur_loc]);
        *cur_loc += arraylen(&packet[*cur_loc]);
    }
    QTYPE = packet[*cur_loc];
    QTYPE = (QTYPE << 8) | packet[*cur_loc + 1];
    *cur_loc += 2;
    QCLASS = packet[*cur_loc];
    QCLASS = (QCLASS << 8) | packet[*cur_loc + 1];
    *cur_loc += 2;
    Question *msg_question = __init__question(QNAME, QTYPE, QCLASS);
    free(QNAME);
    return msg_question;
}

RRFORMAT *bytes_to_resource_record(uint8_t *packet, uint32_t *cur_loc)
{
    /*
    Decodes a byte stream into a RR object (answer, auth, additional).
    */
    char *NAME;
    uint16_t RRTYPE, CLASS, RDLENGTH;
    int32_t TTL;
    uint8_t *RDATA;

    uint8_t *encoded_name = decompress_name(packet, cur_loc);
    NAME = decode_domain_name(encoded_name);

    RRTYPE = packet[*cur_loc];
    RRTYPE = (RRTYPE << 8) | packet[*cur_loc + 1];
    *cur_loc += 2;

    CLASS = packet[*cur_loc];
    CLASS = (CLASS << 8) | packet[*cur_loc + 1];
    *cur_loc += 2;

    TTL = packet[*cur_loc];
    TTL = (TTL << 24) | ((int32_t)packet[*cur_loc + 1] << 16) |
          ((int32_t)packet[*cur_loc + 2] << 8) | packet[*cur_loc + 3];
    *cur_loc += 4;

    RDLENGTH = packet[*cur_loc];
    RDLENGTH = (RDLENGTH << 8) | packet[*cur_loc + 1];
    *cur_loc += 2;

    RDATA = malloc(sizeof(uint8_t) * RDLENGTH);
    for (uint16_t i = 0; i < RDLENGTH; i++, *cur_loc += 1)
    {
        RDATA[i] = packet[*cur_loc];
    }

    RRFORMAT *msg_rr = __init__rr(NAME, RRTYPE, CLASS, TTL, RDLENGTH, RDATA);
    free(encoded_name);
    free(NAME);
    return msg_rr;
}

uint8_t *message_to_packet(DNSMessage *self)
{
    /*
    This method is meant to create a packet including name compression.
    */
    self->__len__ = 0;
    return NULL;
}

uint32_t calc_uncomp_packet_len(DNSMessage *msg)
{
    uint32_t packet_size = 0;
    packet_size += msg->head->__len__;
    for (int i = 0; i < msg->head->QDCount; i++)
        packet_size += msg->quest[i]->__len__;
    for (int i = 0; i < msg->head->ANCOUNT; i++)
        packet_size += msg->ans[i]->__len__;
    for (int i = 0; i < msg->head->NSCOUNT; i++)
        packet_size += msg->auth[i]->__len__;
    for (int i = 0; i < msg->head->ARCOUNT; i++)
        packet_size += msg->addl[i]->__len__;
    return packet_size;
}

uint8_t *message_to_packet_uncompressed(DNSMessage *self)
{
    uint8_t *packet = malloc(sizeof(uint8_t) * self->__len__uncomp);
    uint8_t *packet_start = packet; // Valgrind doesnt like this

    // Transcribe the header
    uint16_t *header_bytes = self->head->to_wire(self->head);
    for (int i = 0; i < self->head->__len__ / 2; i++)
    {
        *packet = header_bytes[i] >> 8;
        *(packet + 1) = header_bytes[i] & 0xFF;
        packet += 2;
    }
    free(header_bytes);

    // Question section
    for (int i = 0; i < self->head->QDCount; i++)
    {
        uint8_t *question_bytes = self->quest[i]->to_wire(self->quest[i]);
        for (int j = 0; j < self->quest[i]->__len__; j++, packet++)
        {
            *packet = question_bytes[j];
        }
        free(question_bytes);
    }

    // Answer Section
    for (int i = 0; i < self->head->ANCOUNT; i++)
    {
        uint8_t *ans_bytes = self->ans[i]->to_wire(self->ans[i]);
        for (int j = 0; j < self->ans[i]->__len__; j++, packet++)
        {
            *packet = ans_bytes[j];
        }
        free(ans_bytes);
    }

    // Auth Section
    for (int i = 0; i < self->head->NSCOUNT; i++)
    {
        uint8_t *ns_bytes = self->auth[i]->to_wire(self->auth[i]);
        for (int j = 0; j < self->auth[i]->__len__; j++, packet++)
        {
            *packet = ns_bytes[j];
        }
        free(ns_bytes);
    }

    // Additional Section
    for (int i = 0; i < self->head->ARCOUNT; i++)
    {
        uint8_t *addl_bytes = self->addl[i]->to_wire(self->addl[i]);
        for (int j = 0; j < self->addl[i]->__len__; j++, packet++)
        {
            *packet = addl_bytes[j];
        }
        free(addl_bytes);
    }

    return packet_start;
}

char *message_to_string(DNSMessage *self)
{
    return NULL;
}

// Helper functions
char *encode_domain_name(char *name)
{
    /*
    Takes domain name such as www.example.com and encodes it into the format
    the DNS message expects it to be in:
    3www7example3com0 (numbers are not ascii, the are literal integer values)

    Limits set in RFC1035:
    labels          63 octets or less
    names           255 octets or less
    */
    char *encoded_name;
    if (name[0] == '\0')
    {
        encoded_name = malloc(sizeof(char));
        *encoded_name = '\0';
        return encoded_name;
    }
    if (name[strlen(name) - 1] != '.')
    {
        fprintf(stderr, "Invalid domain name - missing terminal dot\n");
        last_result = INVALID_DOMAIN;
        return NULL;
    }
    if (strlen(name) > 255)
    {
        fprintf(stderr, "Invalid domain name - name longer than 255 octets\n");
        last_result = INVALID_DOMAIN;
        return NULL;
    }
    encoded_name = malloc(sizeof(char) * strlen(name) + 2);
    encoded_name[0] = '.';
    strcpy(encoded_name + 1, name);
    int last_dot = 0;

    for (int i = 1; i < strlen(encoded_name); i++)
    {
        if (encoded_name[i] == '.')
        {
            if (i - last_dot - 1 > 63)
            {
                fprintf(stderr, "Invalid domain name - label longer than 63 octets\n");
                last_result = INVALID_DOMAIN;
                return NULL;
            }
            encoded_name[last_dot] = i - last_dot - 1;
            last_dot = i;
        }
    }

    last_result = NOERROR;
    encoded_name[last_dot] = '\0';
    return encoded_name;
}

char *decode_domain_name(uint8_t *encoded_name)
{
    /*
    Takes an encoded domain name such as 3www6example3com0 and decodes it into
    a domain name such as www.example.com.

    Limits set in RFC1035:
    labels          63 octets or less
    names           255 octets or less
    */
    char domain[255];
    int counter = 0;
    int dot = *encoded_name + 1;
    if (*encoded_name == '\0')
    {
        char *decoded_domain = malloc(sizeof(char) * 2);
        strcpy(decoded_domain, ".");
        return decoded_domain;
    }
    while (*encoded_name != '\0')
    {
        if (counter)
        {
            if (dot)
            {
                domain[counter - 1] = *encoded_name;
            }
            else
            {
                domain[counter - 1] = '.';
                if (is_compressed(*encoded_name))
                {
                    domain[counter] = '@';
                    domain[counter + 1] = *encoded_name;
                    domain[counter + 2] = *(encoded_name + 1);
                    counter += 3;
                    encoded_name++;
                }
                dot = *encoded_name + 1;
            }
        }

        if (counter == 255)
            break;
        counter++;
        encoded_name++;
        dot--;
    }
    domain[counter - 1] = '.';
    counter++;
    domain[counter - 1] = '\0';
    char *decoded_domain = malloc(sizeof(char) * counter);
    memcpy(decoded_domain, domain, sizeof(char) * counter);
    return decoded_domain;
}

uint16_t generate_random_id(void)
{
    /*
    Generates a random 2 byte number to serve as the header ID 
    */
    uint16_t stream;
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom == NULL)
    {
        perror("Unable to open /dev/urandom: ");
        last_result = ENTROPY_ERROR;
        return 0;
    }
    int bytes_read = fread(&stream, sizeof(uint16_t), 1, urandom);
    fclose(urandom);
    if (bytes_read != 1)
    {
        fprintf(stderr, "Unable to generate random ID\n");
        last_result = ENTROPY_ERROR;
        return 0;
    }
    last_result = NOERROR;
    return stream;
}

uint32_t arraylen(uint8_t *array)
{
    /*
    Returns the length of a null terminated array of bytes.

    e.g., array = {6, 10, 11, 12, 13, 14, 15, 3, 10, 11, 12, 0}
    should return a length of 12
    array = {3, 2, 1, 0} => returns 4
    */
    uint32_t counter = 0;
    while (array[counter] != 0)
    {
        counter++;
    }
    return counter + 1;
}

void arraycat(uint8_t *left_array, uint8_t *right_array, uint16_t max_len)
{
    /*
    Concatenates to uint8_t arrays until it finds a terminting 0 byte.
    array1 = {1, 2, 3}
    array2 = {4, 5, 6, 0 , 8}
    arraycat(array1, array2) => {1, 2, 3, 4, 5, 6, 0}
    */
    // Max len to help prevent a segfault from a name not having a terminating \0
    for (uint16_t i = 0; i < max_len; i++)
    {
        left_array[i] = right_array[i];
        if (right_array[i] == 0)
            break;
    }
}

// Functions to convert to wire format
uint16_t *header_to_bytes(Header *self)
{
    /*
    Header:
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|Z |AD|CD|   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    int header_len = 6;
    uint16_t *header_bytes = malloc(sizeof(uint16_t) * header_len);

    uint16_t line2 = 0x0000;
    line2 |= self->QR << 15;
    line2 |= self->opcode << 11;
    line2 |= self->AA << 10;
    line2 |= self->TC << 9;
    line2 |= self->RD << 8;
    line2 |= self->RA << 7;
    line2 |= self->RES << 6;
    line2 |= self->AD << 5;
    line2 |= self->CD << 4;
    line2 |= self->RCODE;

    header_bytes[0] = self->ID;
    header_bytes[1] = line2;
    header_bytes[2] = self->QDCount;
    header_bytes[3] = self->ANCOUNT;
    header_bytes[4] = self->NSCOUNT;
    header_bytes[5] = self->ARCOUNT;

    return header_bytes;
}

uint8_t *question_to_bytes(Question *self)
{
    /*
    Question Section:
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    uint8_t *question_bytes = malloc(sizeof(uint8_t) * self->__len__);

    int cur_loc = 0;

    for (int i = 0; i < strlen(self->QNAME) + 1; i++, cur_loc++)
    {
        question_bytes[cur_loc] = self->QNAME[i];
    }

    for (int i = 1; i >= 0; i--, cur_loc++)
    {
        question_bytes[cur_loc] = (self->QTYPE >> (i * 8) & 0xFF);
    }

    for (int i = 1; i >= 0; i--, cur_loc++)
    {
        question_bytes[cur_loc] = (self->QCLASS >> (i * 8) & 0xFF);
    }

    return question_bytes;
}

uint8_t *rr_to_bytes_uncompressed(Answer *self)
{
    /*
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    int cur_index = 0;
    uint8_t *answer_bytes = malloc(sizeof(uint8_t) * self->__len__);

    // Set domain name
    for (int i = 0; i < strlen(self->NAME) + 1; i++, cur_index++)
    {
        answer_bytes[cur_index] = self->NAME[i];
    }

    // Set RRTYPE
    for (int i = 1; i >= 0; i--, cur_index++)
    {
        answer_bytes[cur_index] = (self->RRTYPE >> (i * 8) & 0xFF);
    }

    // Set RRCLASS
    for (int i = 1; i >= 0; i--, cur_index++)
    {
        answer_bytes[cur_index] = (self->CLASS >> (i * 8) & 0xFF);
    }

    // Set TTL
    for (int i = 3; i >= 0; i--, cur_index++)
    {
        answer_bytes[cur_index] = (self->TTL >> (i * 8) & 0xFF);
    }

    // Set RDLENGTH
    for (int i = 1; i >= 0; i--, cur_index++)
    {
        answer_bytes[cur_index] = (self->RDLENGTH >> (i * 8) & 0xFF);
    }

    // Set rdata
    for (int i = 0; i < self->RDLENGTH; i++, cur_index++)
    {
        answer_bytes[cur_index] = self->RDATA[i];
    }

    return answer_bytes;
}

uint8_t is_compressed(uint8_t cur_byte)
{
    return ((cur_byte >> 6) == 0x3);
}

uint8_t *decompress_name(uint8_t *packet, uint32_t *cur_loc)
{
    uint8_t encoded_name[255];
    uint32_t cur_pos = *cur_loc;
    memset(encoded_name, 0, 255);
    for (uint16_t i = 0; i < 255; i++)
    {
        if (is_compressed(packet[cur_pos]))
        {
            // If a name pointer is found
            uint16_t ptr_loc;
            ptr_loc = packet[cur_pos];
            ptr_loc = (ptr_loc << 8) | packet[cur_pos + 1];
            ptr_loc &= 0x3FFF; // The pointer is actually contained in the last 14 bits
            if (*cur_loc == cur_pos)
                *cur_loc += 1;
            cur_pos = ptr_loc;
        }
        encoded_name[i] = packet[cur_pos];

        if (packet[cur_pos] == 0)
            break;

        if (*cur_loc == cur_pos)
            *cur_loc += 1;
        cur_pos++;
    }
    *cur_loc += 1;
    uint8_t *decompressed_name = malloc(sizeof(uint8_t) * arraylen(encoded_name));
    memcpy(decompressed_name, encoded_name, arraylen(encoded_name));
    return decompressed_name;
}
