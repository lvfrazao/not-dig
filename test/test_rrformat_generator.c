#include <ctype.h>
#include <stdio.h>

#include "../src/dns/dns_packet.c"

int main(int argc, char* argv[])
{
    if (argc != 7) {
        fprintf(stderr,
            "Usage %s <qname> <qtype> <qclass> <ttl> <rdlength> <rdata>\n",
            argv[0]);
        exit(EXIT_FAILURE);
    }
    uint8_t rdata[4];
    rdata[0] = (atoi(argv[6]) >> 8 * 3) & 0xff;
    rdata[1] = (atoi(argv[6]) >> 8 * 2) & 0xff;
    rdata[2] = (atoi(argv[6]) >> 8 * 1) & 0xff;
    rdata[3] = (atoi(argv[6]) >> 8 * 0) & 0xff;
    Answer* test_rrformat = __init__answer(argv[1], atoi(argv[2]), atoi(argv[3]),
        atoi(argv[4]), atoi(argv[5]), rdata);
    if (test_rrformat == NULL) {
        fprintf(stderr, "Unable to generate rrformat, exiting\n");
        exit(EXIT_FAILURE);
    }

    unsigned char* rrformat_bytes = test_rrformat->to_wire(test_rrformat);
    for (int i = 0; i < test_rrformat->__len__; i++) {
        printf("%02X ", rrformat_bytes[i]);
    }

    printf("\n");

    return 0;
}
