#include <stdio.h>
#include <ctype.h>

#include "../src/dns/dns_packet.c"
//#include "../src/dns.h"

int main(int argc, char *argv[])
{
    if (argc != 16)
    {
        fprintf(
            stderr,
            "Usage %s <ID> <QR> <Opcode> <AA> <TC> <RD> <RA> <RES> <AD> <CD> <RCODE> <QCount> <ACount> <NSCount> <ARCount>",
            argv[0]);
        exit(EXIT_FAILURE);
    }
    Header *test_header = __init__header(
        atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]),
        atoi(argv[7]), atoi(argv[8]), atoi(argv[9]), atoi(argv[10]), atoi(argv[11]), atoi(argv[12]),
        atoi(argv[13]), atoi(argv[14]), atoi(argv[15]));

    uint16_t *header_bytes = test_header->to_wire(test_header);
    for (int i = 0; i < 6; i++)
    {
        printf("0x%04X\n", header_bytes[i]);
    }

    return 0;
}
