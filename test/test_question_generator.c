#include <ctype.h>
#include <stdio.h>

#include "../src/dns/dns_packet.c"
//#include "../src/dns.h"

int main(int argc, char* argv[])
{
    if (argc != 4) {
        fprintf(stderr, "Usage %s <qname> <qtype> <qclass>", argv[0]);
        exit(EXIT_FAILURE);
    }
    Question* test_question = __init__question(argv[1], atoi(argv[2]), atoi(argv[3]));
    if (test_question == NULL) {
        fprintf(stderr, "Unable to generate question, exiting\n");
        exit(EXIT_FAILURE);
    }

    unsigned char* question_bytes = test_question->to_wire(test_question);
    for (int i = 0; i < test_question->__len__; i++) {
        printf("%02X ", question_bytes[i]);
    }

    printf("\n");

    return 0;
}
