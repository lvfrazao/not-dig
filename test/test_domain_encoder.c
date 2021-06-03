#include <stdio.h>

#include "../src/dns/dns_packet.c"

int main(int argc, char* argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <domain name>", argv[0]);
        exit(EXIT_FAILURE);
    }
    char* res = encode_domain_name(argv[1]);
    if (res == NULL) {
        fprintf(stderr, "Error occured, exiting\n");
        exit(EXIT_FAILURE);
    }
    while (*res != '\0') {
        printf("%c (%d)\n", *res, *res);
        res++;
    }
    printf("%c (%d)\n", *res, *res);
}
