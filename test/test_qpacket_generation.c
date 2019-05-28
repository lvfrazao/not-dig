#include <stdio.h>

#include "../src/dns/make_packets.c"

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        fprintf(
            stderr,
            "Usage %s <domain> <qtype> <recursion>\n",
            argv[0]);
        exit(EXIT_FAILURE);
    }
    DNSMessage *test_message = make_query_message(
        argv[1], atoi(argv[2]), atoi(argv[3]));

    if (test_message == NULL)
    {
        fprintf(stderr, "Unable to generate message, exiting\n");
        exit(EXIT_FAILURE);
    }

    uint8_t *packet_bytes = test_message->to_wire_uncompressed(test_message);
    for (int i = 0; i < test_message->__len__uncomp; i++)
    {
        printf("%02X ", packet_bytes[i]);
        if ((i + 1) % 2 == 0)
            printf("\n");
    }
    printf("\n");

    return 0;
}
