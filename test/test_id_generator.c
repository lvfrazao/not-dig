#include <stdio.h>

#include "../src/dns/dns_packet.c"

int main(int argc, char* argv[])
{
    uint16_t res = generate_random_id();

    printf("%04X\n", res);
    return 0;
}
