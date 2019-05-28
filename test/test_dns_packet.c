#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include "../src/dns/dns.h"

// Defines to allow for unit testing
#define FAIL() printf("\nfailure in %s() line %d\n", __func__, __LINE__)
#define _assert(test)             \
    do                            \
    {                             \
        printf("%s: ", __func__); \
        total_tests++;            \
        if (!(test))              \
        {                         \
            printf("-\n");        \
            FAIL();               \
            tests_failed++;       \
            return 1;             \
        }                         \
        else                      \
            printf("+\n");        \
        last_result = NOERROR;    \
    } while (0)

int test_domain_encoding_1(void);
int test_domain_encoding_2(void);
int test_domain_encoding_3(void);
int test_domain_encoding_4(void);
int test_domain_encoding_5(void);
int test_domain_encoding_6(void);
int test_domain_encoding_7(void);
int test_domain_encoding_8(void);
int test_domain_encoding_9(void);
int test_domain_encoding_10(void);
int test_domain_decoding_1(void);
int test_domain_decoding_2(void);
int test_header_generation_1(void);
int test_header_generation_2(void);
int test_header_generation_3(void);
int test_header_generation_4(void);
int test_question_generation_1(void);
int test_question_generation_2(void);
int test_question_generation_3(void);
int test_question_generation_4(void);
int test_question_generation_5(void);
int test_answer_wire_uncompressed_1(void);
int test_answer_wire_uncompressed_2(void);
int test_answer_wire_uncompressed_3(void);
int test_answer_wire_uncompressed_4(void);
int test_query_wire_uncompressed_1(void);
int test_array_count_1(void);
int test_array_count_2(void);
int test_packet_generation_perf_1(void);
int test_bytes_to_header_1(void);
int test_bytes_to_header_2(void);
int test_bytes_to_question_1(void);
int test_bytes_to_question_2(void);
int test_bytes_to_rr_1(void);
int test_bytes_to_rr_2(void);
int test_bytes_to_rr_3(void);
int test_bytes_to_rr_4(void);
int test_name_decompression_1(void);
int test_b64_encoding_1(void);
int test_b64_encoding_2(void);
int test_b64_encoding_3(void);
int test_b64_encoding_4(void);
int test_b64_encoding_5(void);
int test_b64_encoding_6(void);


void printf_encoded_name(char *encoded_name);
int cmp_u16array(uint16_t *array1, uint16_t *array2, int num_elements);
int cmparray(uint8_t *array1, uint8_t *array2, int num_elements);
void print_arrays(uint8_t *array1, uint8_t *array2, uint32_t num_elements);

int total_tests = 0;
int tests_failed = 0;

int main(int argc, char *argv[])
{
    FILE *devnull = fopen("/dev/null", "w");
    dup2(fileno(devnull), 2);

    //Test domain encoding function
    test_domain_encoding_1();
    test_domain_encoding_2();
    test_domain_encoding_3();
    test_domain_encoding_4();
    test_domain_encoding_5();
    test_domain_encoding_6();
    test_domain_encoding_7();
    test_domain_encoding_8();
    test_domain_encoding_9();
    test_domain_encoding_10();
    // Test domain decoding from wire format
    test_domain_decoding_1();
    test_domain_decoding_2();
    // Test header wire format
    test_header_generation_1();
    test_header_generation_2();
    test_header_generation_3();
    test_header_generation_4();
    // Test question wire format
    test_question_generation_1();
    test_question_generation_2();
    test_question_generation_3();
    test_question_generation_4();
    test_question_generation_5();
    // Test answer wire format
    test_answer_wire_uncompressed_1();
    test_answer_wire_uncompressed_2();
    test_answer_wire_uncompressed_3();
    test_answer_wire_uncompressed_4();
    // Test full query wire format
    test_query_wire_uncompressed_1();
    // Test array len function
    test_array_count_1();
    test_array_count_2();
    // Test Query Packet speed
    test_packet_generation_perf_1();
    // Test header bytes decoding
    test_bytes_to_header_1();
    test_bytes_to_header_2();
    // Test question bytes decoding
    test_bytes_to_question_1();
    test_bytes_to_question_2();
    // Test answer bytes decoding
    test_bytes_to_rr_1();
    test_bytes_to_rr_2();
    test_bytes_to_rr_3();
    test_bytes_to_rr_4();
    // Test name decompression
    test_name_decompression_1();
    // Test base 64 encoding
    test_b64_encoding_1();
    test_b64_encoding_2();
    test_b64_encoding_3();
    test_b64_encoding_4();
    test_b64_encoding_5();
    test_b64_encoding_6();

    printf("Test results: %d / %d\n", total_tests - tests_failed, total_tests);
    return 0;
}

int test(int (*test_func)(void))
{
    if (test_func())
        return 1;
    return 0;
}

int test_domain_encoding_1()
{
    char name[] = "www.example.com.";
    char encoded_name[] = "3www7example3com0";
    encoded_name[0] = 3;
    encoded_name[4] = 7;
    encoded_name[12] = 3;
    encoded_name[16] = 0;
    _assert(strcmp(encoded_name, encode_domain_name(name)) == 0);
    return 0;
}

int test_domain_encoding_2()
{
    char name[] = "example.com.";
    char encoded_name[] = "7example3com0";
    encoded_name[0] = 7;
    encoded_name[8] = 3;
    encoded_name[12] = 0;
    _assert(strcmp(encoded_name, encode_domain_name(name)) == 0);
    return 0;
}

int test_domain_encoding_3()
{
    // Number incorrect
    char name[] = "example.com.";
    char encoded_name[] = "6example3com0";
    encoded_name[0] = 6;
    encoded_name[8] = 3;
    encoded_name[12] = 0;
    _assert(strcmp(encoded_name, encode_domain_name(name)) != 0);
    return 0;
}

int test_domain_encoding_4()
{
    // Edge case, root zone
    char name[] = ".";
    char encoded_name[] = "0";
    encoded_name[0] = 0;
    _assert(strcmp(encoded_name, encode_domain_name(name)) == 0);
    return 0;
}

int test_domain_encoding_5()
{
    char name[] = "a.b.c.d.";
    char encoded_name[] = "1a1b1c1d0";
    encoded_name[0] = 1;
    encoded_name[2] = 1;
    encoded_name[4] = 1;
    encoded_name[6] = 1;
    encoded_name[8] = 0;
    _assert(strcmp(encoded_name, encode_domain_name(name)) == 0);
    return 0;
}

int test_domain_encoding_6()
{
    // Test label length limit - this is an ok length (62)
    char name[] = "veryveryveryveryveryveryveryveryveryveryveryveryverylongdomain.com.";
    char encoded_name[] = "6veryveryveryveryveryveryveryveryveryveryveryveryverylongdomain3com0";
    encoded_name[0] = 62;
    encoded_name[63] = 3;
    encoded_name[67] = 0;
    _assert(strcmp(encoded_name, encode_domain_name(name)) == 0);
    return 0;
}

int test_domain_encoding_7()
{
    // Test label length limit - this is also an ok length (63)
    char name[] = "vveryveryveryveryveryveryveryveryveryveryveryveryverylongdomain.com.";
    char encoded_name[] = "6vveryveryveryveryveryveryveryveryveryveryveryveryverylongdomain3com0";
    encoded_name[0] = 63;
    encoded_name[64] = 3;
    encoded_name[68] = 0;
    _assert(strcmp(encoded_name, encode_domain_name(name)) == 0);
    return 0;
}

int test_domain_encoding_8()
{
    // Test label length limit - this NOT an ok length (64)
    char name[] = "veveryveryveryveryveryveryveryveryveryveryveryveryverylongdomain.com.";
    _assert(encode_domain_name(name) == NULL);
    return 0;
}

int test_domain_encoding_9()
{
    // Test name length limit - this is an ok length (255)
    char name[] = "veryveryveryveryveryveryveryveryveryveryveryveryveryveryve.yveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryve.yveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryve.yveryveryveryveryveryveryveryveryveryveryveryveryverylongdomain.com.";
    char encoded_name[] = ".veryveryveryveryveryveryveryveryveryveryveryveryveryveryve.yveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryve.yveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryve.yveryveryveryveryveryveryveryveryveryveryveryveryverylongdomain.com.";
    encoded_name[0] = 58;
    encoded_name[59] = 63;
    encoded_name[123] = 63;
    encoded_name[187] = 63;
    encoded_name[251] = 3;
    encoded_name[255] = 0;
    _assert(strcmp(encoded_name, encode_domain_name(name)) == 0);
    return 0;
}

int test_domain_encoding_10()
{
    // Test name length limit - this is not ok length (256)
    char name[] = "vveryveryveryveryveryveryveryveryveryveryveryveryveryveryve.yveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryve.yveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryve.yveryveryveryveryveryveryveryveryveryveryveryveryverylongdomain.com.";
    _assert(encode_domain_name(name) == NULL);
    return 0;
}

int test_domain_decoding_1()
{
    char name[] = "www.example.com.";
    unsigned char encoded_name[] = "3www7example3com0";
    encoded_name[0] = 3;
    encoded_name[4] = 7;
    encoded_name[12] = 3;
    encoded_name[16] = 0;
    _assert(strcmp(name, decode_domain_name(encoded_name)) == 0);
    return 0;
}

int test_domain_decoding_2()
{
    char name[] = ".";
    unsigned char encoded_name[] = "";
    _assert(strcmp(name, decode_domain_name(encoded_name)) == 0);
    return 0;
}

int test_header_generation_1()
{
    uint16_t test_header[] = {
        0xAAAA,
        0x0100,
        0x0001,
        0x0000,
        0x0000,
        0x0000,
    };
    // Query with ID 0xAAAA with one question, recursion desired
    Header *generated_header = __init__header(0xAAAA, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0);
    _assert(cmp_u16array(test_header, generated_header->to_wire(generated_header), 6) == 0);
    return 0;
}

int test_header_generation_2()
{
    uint16_t test_header[] = {
        0xAAAA,
        0x8180,
        0x0001,
        0x0001,
        0x0000,
        0x0000,
    };
    // Response with ID 0xAAAA with one question, one answer, recursion desired, recursion available
    Header *generated_header = __init__header(0xAAAA, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0);
    _assert(cmp_u16array(test_header, generated_header->to_wire(generated_header), 6) == 0);
    return 0;
}

int test_header_generation_3()
{
    uint16_t test_header[] = {
        0xED60,
        0x0120,
        0x0001,
        0x0000,
        0x0000,
        0x0001,
    };
    // Query with ID 0xED60 with one question, one additional, recursion desired, auth desired
    Header *generated_header = __init__header(0xED60, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1);
    _assert(cmp_u16array(test_header, generated_header->to_wire(generated_header), 6) == 0);
    return 0;
}

int test_header_generation_4()
{
    uint16_t test_header[] = {
        0xED60,
        0x81a0,
        0x0001,
        0x0001,
        0x0000,
        0x0001,
    };
    // Response with ID 0xED60 with one question, one additional, one answer, recursion desired, auth desired
    Header *generated_header = __init__header(0xED60, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1);
    _assert(cmp_u16array(test_header, generated_header->to_wire(generated_header), 6) == 0);
    return 0;
}

int test_question_generation_1()
{
    uint8_t test_q[] = {
        0x06, 0x66, 0x72, 0x61, 0x7A, 0x61, 0x6f, 0x02, 0x63, 0x61, 0x00, // frazao.ca.
        0x00, 0x01,                                                       // QTYPE 1 (A)
        0x00, 0x01                                                        // QCLASS 1 (IN)
    };
    // frazao.ca IN A
    Question *generated_question = __init__question("frazao.ca.", 1, 1);
    _assert((cmparray(test_q, generated_question->to_wire(generated_question), 15) == 0));
    return 0;
}

int test_question_generation_2()
{
    uint8_t test_q[] = {
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, // google.com.
        0x00, 0x01,                                                             // QTYPE 1 (A)
        0x00, 0x01                                                              // QCLASS 1 (IN)
    };
    // google.com. IN A
    Question *generated_question = __init__question("google.com.", 1, 1);
    _assert((cmparray(test_q, generated_question->to_wire(generated_question), 16) == 0));
    return 0;
}

int test_question_generation_3()
{
    uint8_t test_q[] = {
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, // google.com.
        0x00, 0x1c,                                                             // QTYPE 28 (AAAA)
        0x00, 0x01                                                              // QCLASS 1 (IN)
    };
    // google.com. IN AAAA
    Question *generated_question = __init__question("google.com.", 28, 1);
    _assert((cmparray(test_q, generated_question->to_wire(generated_question), 16) == 0));
    return 0;
}

int test_question_generation_4()
{
    uint8_t test_q[] = {
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, // google.com.
        0x01, 0x01,                                                             // QTYPE 257 (CAA)
        0x00, 0x01                                                              // QCLASS 1 (IN)
    };
    // google.com. IN CAA
    Question *generated_question = __init__question("google.com.", 257, 1);
    _assert((cmparray(test_q, generated_question->to_wire(generated_question), 16) == 0));
    return 0;
}

int test_question_generation_5()
{
    uint8_t test_q[] = {
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, // google.com.
        0x80, 0x01,                                                             // QTYPE 32769 (DLV)
        0x00, 0x01                                                              // QCLASS 1 (IN)
    };
    // google.com. IN CAA
    Question *generated_question = __init__question("google.com.", 32769, 1);
    _assert((cmparray(test_q, generated_question->to_wire(generated_question), 16) == 0));
    return 0;
}

int test_answer_wire_uncompressed_1()
{
    uint8_t test_a[] = {
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, // google.com.
        0x01, 0x01,                                                             // QTYPE 1 (A) -- INCORRECT!
        0x00, 0x01,                                                             // QCLASS 1 (IN)
        0x00, 0x00, 0x00, 0xb9,                                                 // TTL of 185 seconds
        0x00, 0x04,                                                             // rdata length
        0xac, 0xd9, 0x0a, 0x6e                                                  // 172.217.10.110
    };
    // google.com. 185 IN A 172.217.10.110
    uint8_t rdata[] = {0xac, 0xd9, 0x0a, 0x6e};
    Answer *generated_answer = __init__answer("google.com.", 1, 1, 185, 4, rdata);
    // This should fail
    _assert((cmparray(test_a, generated_answer->to_wire(generated_answer), 26) != 0));
    return 0;
}

int test_answer_wire_uncompressed_2()
{
    uint8_t test_a[] = {
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, // google.com.
        0x00, 0x01,                                                             // QTYPE 1 (A)
        0x00, 0x01,                                                             // QCLASS 1 (IN)
        0x00, 0x00, 0x00, 0xb9,                                                 // TTL of 185 seconds
        0x00, 0x04,                                                             // rdata length
        0xac, 0xd9, 0x0a, 0x6e                                                  // 172.217.10.110
    };
    // google.com. 185 IN A 172.217.10.110
    uint8_t rdata[] = {0xac, 0xd9, 0x0a, 0x6e};
    Answer *generated_answer = __init__answer("google.com.", 1, 1, 185, 4, rdata);
    _assert((cmparray(test_a, generated_answer->to_wire(generated_answer), 26) == 0));
    return 0;
}

int test_answer_wire_uncompressed_3()
{
    uint8_t test_a[] = {
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,                        // google.com.
        0x00, 0x1c,                                                                                    // QTYPE 28 (AAAA)
        0x00, 0x01,                                                                                    // QCLASS 1 (IN)
        0x00, 0x00, 0x01, 0x2c,                                                                        // TTL of 300 seconds
        0x00, 0x10,                                                                                    // rdata length
        0x20, 0x01, 0x48, 0x60, 0x48, 0x02, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a // 2607:f8b0:4006:804::200e
    };
    // google.com. 300 IN AAAA 2607:f8b0:4006:804::200e
    uint8_t rdata[] = {0x20, 0x01, 0x48, 0x60, 0x48, 0x02, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a};
    Answer *generated_answer = __init__answer("google.com.", 28, 1, 300, 16, rdata);
    _assert((cmparray(test_a, generated_answer->to_wire(generated_answer), 38) == 0));
    return 0;
}

int test_answer_wire_uncompressed_4()
{
    uint8_t test_a[] = {
        0x03, 0x63, 0x6f, 0x6d, 0x00,                                           // com.
        0x00, 0x02,                                                             // QTYPE 2 (NS)
        0x00, 0x01,                                                             // QCLASS 1 (IN)
        0x00, 0x02, 0xa3, 0x00,                                                 // TTL of 172800 seconds
        0x00, 0x14,                                                             // rdata length (20)
        0x01, 0x62, 0x0c, 0x67, 0x74, 0x6c, 0x64, 0x2d, 0x73, 0x65, 0x72, 0x76, // b.gtld-servers.net.
        0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00                          // b.gtld-servers.net.
    };
    // com. 172800 IN NS b.gtld-servers.net.
    uint8_t rdata[] = {0x01, 0x62, 0x0c, 0x67, 0x74, 0x6c, 0x64, 0x2d, 0x73, 0x65,
                       0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00};
    Answer *generated_answer = __init__answer("com.", 2, 1, 172800, 20, rdata);
    _assert((cmparray(test_a, generated_answer->to_wire(generated_answer), 35) == 0));
    return 0;
}

int test_query_wire_uncompressed_1()
{
    uint8_t test_q[] = {
        0xAA, 0xAA,                                                             // ID
        0x01, 0x20,                                                             // RD and AD flag
        0x00, 0x01,                                                             // One question
        0x00, 0x00,                                                             // 0 answers
        0x00, 0x00,                                                             // 0 authority
        0x00, 0x00,                                                             // 0 additional
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, // google.com.
        0x00, 0x01,                                                             // QTYPE 1 (A)
        0x00, 0x01                                                              // QCLASS 1 (IN)
    };
    DNSMessage *generated_message = make_query_message("google.com.", 1, 1);
    _assert((cmparray(test_q + 2, generated_message->to_wire_uncompressed(generated_message) + 2, generated_message->__len__uncomp - 2) == 0));
    return 0;
}

int test_array_count_1()
{
    uint8_t array[] = {6, 10, 11, 12, 13, 14, 15, 3, 10, 11, 12, 0}; // length of 12
    _assert(arraylen(array) == 12);
    return 0;
}

int test_array_count_2()
{
    uint8_t array[] = {0}; // length of 1
    _assert(arraylen(array) == 1);
    return 0;
}

int test_packet_generation_perf_1()
{
    /*
    Tests query packet generation rate. Fails if rate falls below a minimum value.
    */
    uint32_t num_packets = 10000;
    clock_t start, end;
    double cpu_time_used;
    start = clock();
    for (uint32_t i = 0; i < num_packets; i++)
    {
        DNSMessage *test_message = make_query_message(
            "example.com.", 1, 1);

        if (test_message == NULL)
        {
            fprintf(stderr, "Unable to generate message, exiting\n");
            break;
        }

        uint8_t *packet_bytes = test_message->to_wire_uncompressed(test_message);
        test_message->__del__(test_message);
        free(packet_bytes);
    }
    end = clock();

    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    double gen_rate = num_packets / cpu_time_used;

    _assert(gen_rate > 15000);
    return 0;
}

int test_bytes_to_header_1()
{
    uint8_t test_header[] = {
        0xAA, 0xBB,
        0x01, 0x20,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x01};
    // Query with ID 0xAAAA with one question, recursion desired
    Header *gen_head = bytes_to_header(test_header);
    uint8_t *wire_form = malloc(sizeof(uint8_t) * 12);
    uint8_t *ptr_start;
    ptr_start = wire_form;
    for (int i = 0; i < gen_head->__len__ / 2; i++)
    {
        *wire_form = gen_head->to_wire(gen_head)[i] >> 8;
        *(wire_form + 1) = gen_head->to_wire(gen_head)[i] & 0xFF;
        wire_form += 2;
    }
    _assert(cmparray(test_header, ptr_start, 12) == 0);
    return 0;
}

int test_bytes_to_header_2()
{
    uint8_t test_header[] = {
        0xAB, 0xBC,
        0x12, 0x34,
        0x45, 0x67,
        0x89, 0xAB,
        0xCD, 0xEF,
        0xBE, 0xEF};
    Header *gen_head = bytes_to_header(test_header);
    uint8_t *wire_form = malloc(sizeof(uint8_t) * 12);
    uint8_t *ptr_start;
    ptr_start = wire_form;
    for (int i = 0; i < gen_head->__len__ / 2; i++)
    {
        *wire_form = gen_head->to_wire(gen_head)[i] >> 8;
        *(wire_form + 1) = gen_head->to_wire(gen_head)[i] & 0xFF;
        wire_form += 2;
    }
    _assert(cmparray(test_header, ptr_start, 12) == 0);
    return 0;
}

int test_bytes_to_question_1()
{
    /*
    Converts wire format question to C object.
    */
    uint8_t test_q[] = {
        0xAA, 0xAA,                                                             // ID
        0x01, 0x20,                                                             // RD and AD flag
        0x00, 0x01,                                                             // One question
        0x00, 0x00,                                                             // 0 answers
        0x00, 0x00,                                                             // 0 authority
        0x00, 0x00,                                                             // 0 additional
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, // google.com.
        0x00, 0x01,                                                             // QTYPE 1 (A)
        0x00, 0x01                                                              // QCLASS 1 (IN)
    };
    uint32_t cur_loc = 12;
    Question *gen_q = bytes_to_question(test_q, &cur_loc);
    //print_arrays(&test_q[12], gen_q->to_wire(gen_q), 16);
    //printf("%d\n", cur_loc);
    _assert(cmparray(&test_q[12], gen_q->to_wire(gen_q), 16) == 0);
    return 0;
}

int test_bytes_to_question_2()
{
    /*
    Converts wire format question to C object.
    Tests ability to decode compressed names.
    */
    uint8_t test_q[] = {
        0xAA, 0xAA,                                                             // ID
        0x01, 0x20,                                                             // RD and AD flag
        0x00, 0x01,                                                             // One question
        0x00, 0x00,                                                             // 0 answers
        0x00, 0x00,                                                             // 0 authority
        0x00, 0x00,                                                             // 0 additional
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, // google.com.
        0x00, 0x01,                                                             // QTYPE 1 (A)
        0x00, 0x01,                                                             // QCLASS 1 (IN)
        0xc0, 0x0c,                                                             // google.com.
        0x00, 0x02,                                                             // QTYPE 2 (A)
        0x00, 0x01                                                              // QCLASS 1 (IN)
    };

    uint8_t expected_wire[] = {
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, // google.com.
        0x00, 0x02,                                                             // QTYPE 1 (NS)
        0x00, 0x01,                                                             // QCLASS 1 (IN)
    };
    uint32_t cur_loc = 28;
    Question *gen_q = bytes_to_question(test_q, &cur_loc);
    //print_arrays(expected_wire, gen_q->to_wire(gen_q), 16);
    //printf("%d\n", cur_loc);
    _assert(cmparray(expected_wire, gen_q->to_wire(gen_q), 16) == 0);
    return 0;
}

int test_bytes_to_rr_1()
{
    uint8_t packet[] = {
        // Header
        0xbb, 0x02, // ID
        0x81, 0xa0, // QR(1) response, RD, RA, AD
        0x00, 0x01, // 1 question
        0x00, 0x01, // 1 answer
        0x00, 0x00, // 0 NS
        0x00, 0x01, // 1 additional
        // Question 1
        0x06, 0x66, 0x72, 0x61, 0x7a, 0x61, 0x6f, 0x02, 0x63, 0x61, 0x00, // qname frazao.ca
        0x00, 0x01,                                                       // qtype 1 (A)
        0x00, 0x01,                                                       // qclass 1 (IN)
        // Answer 1
        0xc0, 0x0c,             // rname (pointer to position 12)
        0x00, 0x01,             // rtype 1 (A)
        0x00, 0x01,             // class 1 (IN)
        0x00, 0x00, 0x00, 0x1d, // TTL (29 seconds)
        0x00, 0x04,             // rdlen (4 bytes)
        0x36, 0xc5, 0xc7, 0xf6, // rdata 54.197.199.246
        // Additional 1 - OPT follows a slightly different mechanism
        0x00,                   // rname '.' (root)
        0x00, 0x29,             // rtype 41 (OPT)
        0x02, 0x00,             // class, requestor's UDP payload size
        0x00, 0x00, 0x00, 0x00, // ttl, extended RCODE and flags
        0x00, 0x00              // rdlen, length of all rdata
    };
    uint8_t expected[] = {
        0x06, 0x66, 0x72, 0x61, 0x7a, 0x61, 0x6f, 0x02, 0x63, 0x61, 0x00, // qname frazao.ca.
        0x00, 0x01,                                                       // rtype 1 (A)
        0x00, 0x01,                                                       // class 1 (IN)
        0x00, 0x00, 0x00, 0x1d,                                           // TTL (29 seconds)
        0x00, 0x04,                                                       // rdlen (4 bytes)
        0x36, 0xc5, 0xc7, 0xf6,                                           // rdata 54.197.199.246
    };

    uint32_t cur_loc = 27;
    Answer *gen_a = (Answer *)bytes_to_resource_record(packet, &cur_loc);
    //print_arrays(expected, gen_a->to_wire(gen_a), 25);
    //printf("%d\n", cur_loc);
    _assert(cmparray(expected, gen_a->to_wire(gen_a), 25) == 0);
    return 0;
}

int test_bytes_to_rr_2()
{
    uint8_t packet[] = {
        // Header
        0xbb, 0x02, // ID
        0x81, 0xa0, // QR(1) response, RD, RA, AD
        0x00, 0x01, // 1 question
        0x00, 0x01, // 1 answer
        0x00, 0x00, // 0 NS
        0x00, 0x01, // 1 additional
        // Question 1
        0x06, 0x66, 0x72, 0x61, 0x7a, 0x61, 0x6f, 0x02, 0x63, 0x61, 0x00, // qname frazao.ca
        0x00, 0x01,                                                       // qtype 1 (A)
        0x00, 0x01,                                                       // qclass 1 (IN)
        // Answer 1
        0x06, 0x66, 0x72, 0x61, 0x7a, 0x61, 0x6f, 0x02, 0x63, 0x61, 0x00, // qname frazao.ca
        0x00, 0x01,                                                       // rtype 1 (A)
        0x00, 0x01,                                                       // class 1 (IN)
        0x00, 0x00, 0x00, 0x1d,                                           // TTL (29 seconds)
        0x00, 0x04,                                                       // rdlen (4 bytes)
        0x36, 0xc5, 0xc7, 0xf6,                                           // rdata 54.197.199.246
        // Additional 1 - OPT follows a slightly different mechanism
        0x00,                   // rname '.' (root)
        0x00, 0x29,             // rtype 41 (OPT)
        0x02, 0x00,             // class, requestor's UDP payload size
        0x00, 0x00, 0x00, 0x00, // ttl, extended RCODE and flags
        0x00, 0x00              // rdlen, length of all rdata
    };
    uint8_t expected[] = {
        0x06, 0x66, 0x72, 0x61, 0x7a, 0x61, 0x6f, 0x02, 0x63, 0x61, 0x00, // qname frazao.ca
        0x00, 0x01,                                                       // rtype 1 (A)
        0x00, 0x01,                                                       // class 1 (IN)
        0x00, 0x00, 0x00, 0x1d,                                           // TTL (29 seconds)
        0x00, 0x04,                                                       // rdlen (4 bytes)
        0x36, 0xc5, 0xc7, 0xf6,                                           // rdata 54.197.199.246
    };

    uint32_t cur_loc = 27;
    Answer *gen_a = (Answer *)bytes_to_resource_record(packet, &cur_loc);
    //print_arrays(expected, gen_a->to_wire(gen_a), 25);
    //printf("%d\n", cur_loc);
    _assert(cmparray(expected, gen_a->to_wire(gen_a), 25) == 0);
    return 0;
}

int test_bytes_to_rr_3()
{
    uint8_t packet[] = {
        // Header
        0xbb, 0x02, // ID
        0x81, 0xa0, // QR(1) response, RD, RA, AD
        0x00, 0x01, // 1 question
        0x00, 0x01, // 1 answer
        0x00, 0x00, // 0 NS
        0x00, 0x01, // 1 additional
        // Question 1
        0x03, 0x77, 0x77, 0x77, 0x06, 0x66, 0x72, 0x61, 0x7a, 0x61, 0x6f, 0x02, 0x63, 0x61, 0x00, // qname www.frazao.ca
        0x00, 0x05,                                                                               // qtype 5 (CNAME)
        0x00, 0x01,                                                                               // qclass 1 (IN)
        // Answer 1
        0xc0, 0x10,             // pointer (16) to name frazao.ca
        0x00, 0x05,             // rtype 5 (CNAME)
        0x00, 0x01,             // class 1 (IN)
        0x00, 0x00, 0x00, 0x1d, // TTL (29 seconds)
        0x00, 0x04,             // rdlen (4 bytes)
        0x36, 0xc5, 0xc7, 0xf6, // rdata 54.197.199.246
        // Additional 1 - OPT follows a slightly different mechanism
        0x00,                   // rname '.' (root)
        0x00, 0x29,             // rtype 41 (OPT)
        0x02, 0x00,             // class, requestor's UDP payload size
        0x00, 0x00, 0x00, 0x00, // ttl, extended RCODE and flags
        0x00, 0x00              // rdlen, length of all rdata
    };
    uint8_t expected[] = {
        0x06, 0x66, 0x72, 0x61, 0x7a, 0x61, 0x6f, 0x02, 0x63, 0x61, 0x00, // qname frazao.ca
        0x00, 0x05,                                                       // rtype 5 (CNAME)
        0x00, 0x01,                                                       // class 1 (IN)
        0x00, 0x00, 0x00, 0x1d,                                           // TTL (29 seconds)
        0x00, 0x04,                                                       // rdlen (4 bytes)
        0x36, 0xc5, 0xc7, 0xf6,                                           // rdata 54.197.199.246
    };

    uint32_t cur_loc = 31;
    Answer *gen_a = (Answer *)bytes_to_resource_record(packet, &cur_loc);
    //print_arrays(expected, gen_a->to_wire(gen_a), 25);
    //printf("%d\n", cur_loc);
    _assert(cmparray(expected, gen_a->to_wire(gen_a), 25) == 0);
    return 0;
}

int test_bytes_to_rr_4()
{
    uint8_t packet[] = {
        // Header
        0xbb, 0x02, // ID
        0x81, 0xa0, // QR(1) response, RD, RA, AD
        0x00, 0x01, // 1 question
        0x00, 0x01, // 1 answer
        0x00, 0x00, // 0 NS
        0x00, 0x01, // 1 additional
        // Question 1
        0x03, 0x77, 0x77, 0x77, 0x06, 0x66, 0x72, 0x61, 0x7a, 0x61, 0x6f, 0x02, 0x63, 0x61, 0x00, // qname www.frazao.ca
        0x00, 0x05,                                                                               // qtype 5 (CNAME)
        0x00, 0x01,                                                                               // qclass 1 (IN)
        // Answer 1
        0x01, 0x61, 0xc0, 0x0c, // a + pointer (12) to name www.frazao.ca
        0x00, 0x05,             // rtype 5 (CNAME)
        0x00, 0x01,             // class 1 (IN)
        0x00, 0x00, 0x00, 0x1d, // TTL (29 seconds)
        0x00, 0x04,             // rdlen (4 bytes)
        0x36, 0xc5, 0xc7, 0xf6, // rdata 54.197.199.246
        // Additional 1 - OPT follows a slightly different mechanism
        0x00,                   // rname '.' (root)
        0x00, 0x29,             // rtype 41 (OPT)
        0x02, 0x00,             // class, requestor's UDP payload size
        0x00, 0x00, 0x00, 0x00, // ttl, extended RCODE and flags
        0x00, 0x00              // rdlen, length of all rdata
    };
    uint8_t expected[] = {
        0x01, 0x61, 0x03, 0x77, 0x77, 0x77, 0x06, 0x66, 0x72, 0x61, 0x7a, 0x61, 0x6f, 0x02, 0x63, 0x61, 0x00, // qname frazao.ca
        0x00, 0x05,                                                       // rtype 5 (CNAME)
        0x00, 0x01,                                                       // class 1 (IN)
        0x00, 0x00, 0x00, 0x1d,                                           // TTL (29 seconds)
        0x00, 0x04,                                                       // rdlen (4 bytes)
        0x36, 0xc5, 0xc7, 0xf6,                                           // rdata 54.197.199.246
    };

    uint32_t cur_loc = 31;
    Answer *gen_a = (Answer *)bytes_to_resource_record(packet, &cur_loc);
    //print_arrays(expected, gen_a->to_wire(gen_a), 31);
    //printf("%d\n", cur_loc);
    _assert(cmparray(expected, gen_a->to_wire(gen_a), 31) == 0);
    return 0;
}

int test_name_decompression_1()
{
    uint8_t packet[] = {
        // Header
        0xbb, 0x02, // ID
        0x81, 0xa0, // QR(1) response, RD, RA, AD
        0x00, 0x01, // 1 question
        0x00, 0x01, // 1 answer
        0x00, 0x00, // 0 NS
        0x00, 0x01, // 1 additional
        // Question 1
        0x03, 0x77, 0x77, 0x77, 0x06, 0x66, 0x72, 0x61, 0x7a, 0x61, 0x6f, 0x02, 0x63, 0x61, 0x00, // qname www.frazao.ca
        0x00, 0x05,                                                                               // qtype 5 (CNAME)
        0x00, 0x01,                                                                               // qclass 1 (IN)
        // Answer 1
        0x01, 0x61, 0xc0, 0x0c, // a + pointer (12) to name www.frazao.ca
        0x00, 0x05,             // rtype 5 (CNAME)
        0x00, 0x01,             // class 1 (IN)
        0x00, 0x00, 0x00, 0x1d, // TTL (29 seconds)
        0x00, 0x04,             // rdlen (4 bytes)
        0x36, 0xc5, 0xc7, 0xf6, // rdata 54.197.199.246
        // Additional 1 - OPT follows a slightly different mechanism
        0x00,                   // rname '.' (root)
        0x00, 0x29,             // rtype 41 (OPT)
        0x02, 0x00,             // class, requestor's UDP payload size
        0x00, 0x00, 0x00, 0x00, // ttl, extended RCODE and flags
        0x00, 0x00              // rdlen, length of all rdata
    };
    uint32_t cur_loc = 31;
    uint8_t *encoded_name = decompress_name(packet, &cur_loc);
    uint8_t expected[] = {
        0x01, 0x61, 0x03, 0x77, 0x77, 0x77, 0x06, 0x66, 0x72, 0x61, 0x7a, 0x61, 0x6f, 0x02, 0x63, 0x61, 0x00
    };
    _assert(cmparray(expected, encoded_name, 17) == 0);
    return 0;
}

int test_name_decompression_2()
{
    uint8_t packet[] = {
        // Header
        0xbb, 0x02, // ID
        0x81, 0xa0, // QR(1) response, RD, RA, AD
        0x00, 0x01, // 1 question
        0x00, 0x01, // 1 answer
        0x00, 0x00, // 0 NS
        0x00, 0x01, // 1 additional
        // Question 1
        0x03, 0x77, 0x77, 0x77, 0x06, 0x66, 0x72, 0x61, 0x7a, 0x61, 0x6f, 0x02, 0x63, 0x61, 0x00, // qname www.frazao.ca
        0x00, 0x05,                                                                               // qtype 5 (CNAME)
        0x00, 0x01,                                                                               // qclass 1 (IN)
        // Answer 1
        0x01, 0x61, 0xc0, 0x0c, // a + pointer (12) to name www.frazao.ca
        0x00, 0x05,             // rtype 5 (CNAME)
        0x00, 0x01,             // class 1 (IN)
        0x00, 0x00, 0x00, 0x1d, // TTL (29 seconds)
        0x00, 0x04,             // rdlen (4 bytes)
        0x36, 0xc5, 0xc7, 0xf6, // rdata 54.197.199.246
        // Additional 1 - OPT follows a slightly different mechanism
        0x00,                   // rname '.' (root)
        0x00, 0x29,             // rtype 41 (OPT)
        0x02, 0x00,             // class, requestor's UDP payload size
        0x00, 0x00, 0x00, 0x00, // ttl, extended RCODE and flags
        0x00, 0x00              // rdlen, length of all rdata
    };
    uint32_t cur_loc = 31;
    uint8_t *encoded_name = decompress_name(packet, &cur_loc);
    uint8_t expected[] = {
        0x01, 0x61, 0x03, 0x77, 0x77, 0x77, 0x06, 0x66, 0x72, 0x61, 0x7a, 0x61, 0x6f, 0x02, 0x63, 0x61, 0x00
    };
    _assert(cmparray(expected, encoded_name, 17) == 0);
    return 0;
}

int test_b64_encoding_1()
{
    char decoded_text[] = "Man is distinguished, not only by his reason, but by this singular passion from other animals, "
                          "which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable "
                          "generation of knowledge, exceeds the short vehemence of any carnal pleasure.";
    char encoded_text[] = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz"
                          "IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2Yg"
                          "dGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGlu"
                          "dWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRo"
                          "ZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=";
    char *actual = base64_encode((uint8_t*)decoded_text, strlen(decoded_text));
    //printf("\n\n%s\n\n", encoded_text);
    //printf("\n\n%s\n\n", actual);
    _assert(strcmp(encoded_text, actual) == 0);
    return 0;
}

int test_b64_encoding_2()
{
    char decoded_text[] = "any carnal pleasure.";
    char encoded_text[] = "YW55IGNhcm5hbCBwbGVhc3VyZS4=";
    char *actual = base64_encode((uint8_t*)decoded_text, strlen(decoded_text));
    _assert(strcmp(encoded_text, actual) == 0);
    return 0;
}

int test_b64_encoding_3()
{
    char decoded_text[] = "any carnal pleasure";
    char encoded_text[] = "YW55IGNhcm5hbCBwbGVhc3VyZQ==";
    char *actual = base64_encode((uint8_t*)decoded_text, strlen(decoded_text));
    _assert(strcmp(encoded_text, actual) == 0);
    return 0;
}

int test_b64_encoding_4()
{
    char decoded_text[] = "any carnal pleasur";
    char encoded_text[] = "YW55IGNhcm5hbCBwbGVhc3Vy";
    char *actual = base64_encode((uint8_t*)decoded_text, strlen(decoded_text));
    _assert(strcmp(encoded_text, actual) == 0);
    return 0;
}

int test_b64_encoding_5()
{
    char decoded_text[] = "any carnal pleasu";
    char encoded_text[] = "YW55IGNhcm5hbCBwbGVhc3U=";
    char *actual = base64_encode((uint8_t*)decoded_text, strlen(decoded_text));
    _assert(strcmp(encoded_text, actual) == 0);
    return 0;
}

int test_b64_encoding_6()
{
    char decoded_text[] = "any carnal pleas";
    char encoded_text[] = "YW55IGNhcm5hbCBwbGVhcw==";
    char *actual = base64_encode((uint8_t*)decoded_text, strlen(decoded_text));
    _assert(strcmp(encoded_text, actual) == 0);
    return 0;
}

// TODO: implement rrtype decoding tests
// test ptr "./stub_resolver 46.11.217.172.in-addr.arpa. ptr"
// test hinfo "./stub_resolver zonetransfer.me. hinfo"
// test afsdb "./stub_resolver 198.51.44.1 zonetransfer.me. afsdb"
// test txt "./stub_resolver 198.51.44.1 longtxt.frazao.ca. txt"
// test srv "./stub_resolver 198.51.44.1 _sip._tcp.chunderm.dev.twilio.com. srv"
// test NAPTR "./stub_resolver 198.51.44.1 sip.stage-us2-tnx.twilio.com. naptr"
// test CERT: "./stub_resolver 198.51.44.1 1001.direct.athenahealth.com. cert"

/*======================================================================================================================*/
// Helper functions
void printf_encoded_name(char *encoded_name)
{
    for (int i = 0; i < strlen(encoded_name); i++)
    {
        printf("%c(%d) ", encoded_name[i], encoded_name[i]);
    }
    printf("\n");
}

int cmp_u16array(uint16_t *array1, uint16_t *array2, int num_elements)
{
    for (int i = 0; i < num_elements; i++)
    {
        if (array1[i] != array2[i])
        {
            //printf("Diff found at index %d: %04X %04X", i, array1[i], array2[i]);
            return 1;
        }
    }
    return 0;
}

int cmparray(uint8_t *array1, uint8_t *array2, int num_elements)
{
    for (int i = 0; i < num_elements; i++)
    {
        if (array1[i] != array2[i])
        {
            //printf("Diff found at index %d: %02X %02X ", i, array1[i], array2[i]);
            return 1;
        }
    }
    return 0;
}

void print_arrays(uint8_t *array1, uint8_t *array2, uint32_t num_elements)
{
    for (uint32_t i = 0; i < num_elements; i += 2)
    {
        if (i + 2 < num_elements)
        {
            printf("%02X %02X || %02X %02X\n",
                   array1[i], array1[i + 1],
                   array2[i], array2[i + 1]);
        }
        else
        {
            printf("%02X    || %02X\n",
                   array1[i], array2[i]);
        }
    }
}
