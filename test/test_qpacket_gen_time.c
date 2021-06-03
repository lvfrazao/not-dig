#include <stdio.h>
#include <time.h>

#include "../src/dns/dns.h"

int main(int argc, char* argv[])
{
    uint64_t num_packets = 0;
    if (argc != 2) {
        fprintf(stderr, "Usage %s <num packets>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    num_packets = atoi(argv[1]);
    DNSMessage* test_message;
    uint8_t* packet_bytes;

    clock_t start, end;
    double cpu_time_used;
    start = clock();
    for (uint64_t i = 0; i < num_packets; i++) {
        test_message = make_query_message("example.com.", 1, 1);

        if (test_message == NULL) {
            fprintf(stderr, "Unable to generate message, exiting\n");
            exit(EXIT_FAILURE);
        }

        packet_bytes = test_message->to_wire_uncompressed(test_message);
        test_message->__del__(test_message);
        free(packet_bytes);
    }
    end = clock();

    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Generating %ld packets took %.2f seconds - %.2f packets per second\n",
        num_packets, cpu_time_used, num_packets / cpu_time_used);

    test_message = make_query_message("example.com.", 1, 1);
    packet_bytes = test_message->to_wire_uncompressed(test_message);
    printf("Last packet was:\n");
    for (int i = 0; i < test_message->__len__uncomp; i++) {
        printf("%02X ", packet_bytes[i]);
        if ((i + 1) % 2 == 0)
            printf("\n");
    }
    printf("\n");
    free(packet_bytes);
    test_message->__del__(test_message);
    return 0;
}
