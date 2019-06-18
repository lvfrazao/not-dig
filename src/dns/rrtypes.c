#pragma once

#include <stdint.h>
#include <string.h>

#include "dns_packet.c"
#include "dns_data.c"

#define DEBUG 0

uint32_t find_loc_in_packet(uint8_t *packet, uint8_t *data, uint16_t data_len);
void print_packet(uint8_t *packet, uint32_t packet_len);
char *base64_encode(uint8_t *data, uint32_t data_len);

char *A_record(uint8_t *ip_addr);
char *NS_record(uint8_t *encoded_ns, uint16_t data_len, uint8_t *packet);
char *CNAME_record(uint8_t *encoded_ns, uint16_t data_len, uint8_t *packet);
char *SOA_record(uint8_t *encoded_ns, uint16_t data_len, uint8_t *packet);
char *PTR_record(uint8_t *encoded_name, uint16_t data_len, uint8_t *packet);
char *HINFO_record(uint8_t *data, uint16_t data_len);
char *MX_record(uint8_t *data, uint16_t data_len, uint8_t *packet);
char *TXT_record(uint8_t *data, uint16_t data_len);
char *AFSDB_record(uint8_t *data, uint16_t data_len, uint8_t *packet);
char *AAAA_record(uint8_t *data);
char *SRV_record(uint8_t *data, uint16_t data_len, uint8_t *packet);
char *NAPTR_record(uint8_t *data, uint16_t data_len);
char *CERT_record(uint8_t *data, uint16_t data_len);
char *DNAME_record(uint8_t *data, uint16_t data_len, uint8_t *packet);

char *rdata_to_str(RRFORMAT *res_record, uint8_t *packet)
{
    switch (res_record->RRTYPE)
    {
    case (A):
        if (res_record->RDLENGTH != 4)
            return "Invalid IPv4 Addr";
        return A_record(res_record->RDATA);
        break;
    case (NS):
        return NS_record(res_record->RDATA, res_record->RDLENGTH, packet);
        break;
    case (CNAME):
        return CNAME_record(res_record->RDATA, res_record->RDLENGTH, packet);
        break;
    case (SOA):
        return SOA_record(res_record->RDATA, res_record->RDLENGTH, packet);
        break;
    case (PTR):
        return PTR_record(res_record->RDATA, res_record->RDLENGTH, packet);
        break;
    case (HINFO):
        return HINFO_record(res_record->RDATA, res_record->RDLENGTH);
        break;
    case (MX):
        return MX_record(res_record->RDATA, res_record->RDLENGTH, packet);
        break;
    case (TXT):
        return TXT_record(res_record->RDATA, res_record->RDLENGTH);
        break;
    case (AFSDB):
        return AFSDB_record(res_record->RDATA, res_record->RDLENGTH, packet);
        break;
    case (AAAA):
        return AAAA_record(res_record->RDATA);
        break;
    case (SRV):
        return SRV_record(res_record->RDATA, res_record->RDLENGTH, packet);
        break;
    case (NAPTR):
        return NAPTR_record(res_record->RDATA, res_record->RDLENGTH);
        break;
    case (CERT):
        return CERT_record(res_record->RDATA, res_record->RDLENGTH);
        break;
    case (DNAME):
        return DNAME_record(res_record->RDATA, res_record->RDLENGTH, packet);
        break;
    default:;
        char *hex_stream = malloc(sizeof(char) * res_record->RDLENGTH * 3 + 1); // 3 chars per hex byte
        for (uint16_t i = 0; i < res_record->RDLENGTH; i++)                     // for byte in res_record->RDATA
        {
            char byte_val[3];
            sprintf(byte_val, "%02X", res_record->RDATA[i]);
            hex_stream[i * 3] = byte_val[0];
            hex_stream[i * 3 + 1] = byte_val[1];
            hex_stream[i * 3 + 2] = ' ';
        }
        hex_stream[res_record->RDLENGTH * 3] = '\0';
        return hex_stream;
        break;
    }
}

// 1
char *A_record(uint8_t *ip_addr)
{
    char format[] = "%d.%d.%d.%d";
    // Max size of IP addr is 15 - 255.255.255.255
    char *data_str = malloc(sizeof(char) * 16);
    snprintf(data_str, 16, format, ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
    return data_str;
}

// 2
char *NS_record(uint8_t *data, uint16_t data_len, uint8_t *packet)
{
    uint32_t loc = find_loc_in_packet(packet, data, data_len);
    uint8_t *encoded_name = decompress_name(packet, &loc);
    char *decoded_name = decode_domain_name(encoded_name);
    free(encoded_name);
    return decoded_name;
}

// 3
char *MD_record()
{
    return NULL; // Obsolete
}

// 4
char *MF_record()
{
    return NULL; // Obsolete
}

// 5
char *CNAME_record(uint8_t *encoded_name, uint16_t data_len, uint8_t *packet)
{
    return NS_record(encoded_name, data_len, packet);
}

// 6
char *SOA_record(uint8_t *data, uint16_t data_len, uint8_t *packet)
{
    if (DEBUG)
    {
        printf("SOA Bytes:\n");
        for (int i = 0; i < data_len; i++)
        {
            printf("%02X ", data[i]);
        }
        printf("\n");
    }
    /*
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     MNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     RNAME                     /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    SERIAL                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    REFRESH                    |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     RETRY                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    EXPIRE                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    MINIMUM                    |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    uint16_t prev_loc, cur_loc = 0;
    char *mname, *rname;
    uint32_t serial, refresh, retry, expire, minimum;

    // MNAME
    for (int i = 0; i < 255; i++)
    {
        if (is_compressed(data[i]) || data[i] == 0)
            break;
        cur_loc++;
    }
    //data[cur_loc] = 0;

    uint32_t loc = find_loc_in_packet(packet, data, data_len);
    uint8_t *encoded_name = decompress_name(packet, &loc);
    mname = decode_domain_name(encoded_name);

    // RNAME
    cur_loc++;
    if (is_compressed(data[cur_loc - 1]))
        cur_loc++;
    prev_loc = cur_loc;
    for (int i = 0; i < 255; i++)
    {
        if (is_compressed(data[cur_loc]))
        {
            cur_loc++;
            break;
        }
        else if (data[cur_loc] == 0)
        {
            break;
        }
        cur_loc++;
    }
    //data[cur_loc] = 0;

    loc = find_loc_in_packet(packet, &data[prev_loc], data_len - arraylen(encoded_name));
    if (DEBUG)
    {
        printf("RNAME (len: %d / Packt loc: %d):\n", data_len - arraylen(encoded_name), loc);
        int i = 0;
        while (1)
        {
            printf("%02X ", data[prev_loc + i]);
            if (data[prev_loc + i] == 0 || is_compressed(data[prev_loc + i]))
                break;
            i++;
        }
        printf("\n");
    }
    free(encoded_name);
    encoded_name = decompress_name(packet, &loc);
    rname = decode_domain_name(encoded_name);
    free(encoded_name);
    cur_loc++;

    // Serial
    serial = data[cur_loc];
    serial = (serial << 24) | ((int32_t)data[cur_loc + 1] << 16) |
             ((int32_t)data[cur_loc + 2] << 8) | data[cur_loc + 3];
    cur_loc += 4;

    // Refresh
    refresh = data[cur_loc];
    refresh = (refresh << 24) | ((int32_t)data[cur_loc + 1] << 16) |
              ((int32_t)data[cur_loc + 2] << 8) | data[cur_loc + 3];
    cur_loc += 4;

    // Retry
    retry = data[cur_loc];
    retry = (retry << 24) | ((int32_t)data[cur_loc + 1] << 16) |
            ((int32_t)data[cur_loc + 2] << 8) | data[cur_loc + 3];
    cur_loc += 4;

    // Expire
    expire = data[cur_loc];
    expire = (expire << 24) | ((int32_t)data[cur_loc + 1] << 16) |
             ((int32_t)data[cur_loc + 2] << 8) | data[cur_loc + 3];
    cur_loc += 4;

    // Minimum
    minimum = data[cur_loc];
    minimum = (minimum << 24) | ((int32_t)data[cur_loc + 1] << 16) |
              ((int32_t)data[cur_loc + 2] << 8) | data[cur_loc + 3];
    cur_loc += 4;

    int buf_size = 1000;
    char record_buf[buf_size];
    memset(record_buf, 0, buf_size);
    snprintf(record_buf, buf_size, "%s %s %d %d %d %d %d", mname, rname, serial, refresh, retry, expire, minimum);
    char *soa_record = malloc(sizeof(char) * strlen(record_buf) + 1);
    strcpy(soa_record, record_buf);

    free(mname);
    free(rname);
    return soa_record;
}

// 7
char *MB_record()
{
    // Obsolete
    return NULL;
}

// 8
char *MG_record()
{
    // Obsolete
    return NULL;
}

// 9
char *MR_record()
{
    // Obsolete
    return NULL;
}

// 10
char *NULL_record()
{
    // Obsolete
    return NULL;
}

// 11
char *WKS_record()
{
    // Obsolete
    return NULL;
}

// 12
char *PTR_record(uint8_t *encoded_name, uint16_t data_len, uint8_t *packet)
{
    return NS_record(encoded_name, data_len, packet);
}

uint32_t find_loc_in_packet(uint8_t *packet, uint8_t *data, uint16_t data_len)
{
    uint32_t loc = 0;
    while (1)
    {
        if (packet[loc] == data[0])
        {
            for (uint16_t i = 0; i < data_len; i++)
            {
                if (packet[loc + i] != data[i])
                    break;
                if (i == data_len - 1)
                    return loc;
            }
        }
        loc++;
    }
}

// 13
char *HINFO_record(uint8_t *data, uint16_t data_len)
{
    /*
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                      CPU                      /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                       OS                      /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    Just two strings
    */
    char *cpu, *os;
    uint16_t first_str_loc, first_str_len, second_str_loc, second_str_len;
    first_str_loc = 1;
    first_str_len = data[0];
    second_str_len = data[first_str_len + 1];
    second_str_loc = first_str_len + 2;
    cpu = malloc(sizeof(char) * (first_str_len + 1));
    os = malloc(sizeof(char) * (second_str_len + 1));

    memcpy(cpu, &data[first_str_loc], first_str_len);
    memcpy(os, &data[second_str_loc], second_str_len);
    // Need to null terminate the strings
    cpu[first_str_len] = 0;
    os[second_str_len] = 0;

    char *str_repr = malloc(sizeof(char) * (first_str_len + second_str_len + 2));
    sprintf(str_repr, "%s %s", cpu, os);
    free(cpu);
    free(os);
    return str_repr;
}

// 14
char *MINFO_record()
{
    // Obsolete
    return NULL;
}

// 15
char *MX_record(uint8_t *data, uint16_t data_len, uint8_t *packet)
{
    /*
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                  PREFERENCE                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   EXCHANGE                    /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    uint16_t preference;
    uint32_t loc = find_loc_in_packet(packet, data, data_len);
    preference = data[0];
    preference = (preference << 8) | data[1];

    loc += 2; // Exchange is right after pref
    uint8_t *encoded_name = decompress_name(packet, &loc);
    char *exchange = decode_domain_name(encoded_name);

    char *mx_str = malloc(sizeof(char) * (5 + strlen(exchange) + 1));
    sprintf(mx_str, "%d %s", preference, exchange);

    free(encoded_name);
    free(exchange);
    return mx_str;
}

// 16
char *TXT_record(uint8_t *data, uint16_t data_len)
{
    uint16_t buf_size = 65536 - 1; // RDATA len limit is 65535 bytes
    uint8_t txt_buffer[buf_size];
    memset(txt_buffer, 0, buf_size);
    uint16_t cur_loc = 0, len = data[0];
    // Cur loc represents the current index in our buffer
    // cur_str represents the count of digits read from the current string
    for (uint16_t i = 1; i < data_len && cur_loc < buf_size - 2; i++)
    {
        txt_buffer[cur_loc] = '"';
        cur_loc++;

        for (uint16_t j = 0; j < len && cur_loc < buf_size - 2; j++, i++, cur_loc++)
        {
            if (data[i] == '"')
            {
                txt_buffer[cur_loc] = '\\';
                cur_loc++;
            }
            txt_buffer[cur_loc] = data[i];
        }
        len = data[i];
        txt_buffer[cur_loc] = '"';
        txt_buffer[cur_loc + 1] = ' ';
        cur_loc += 2;
    }
    if (txt_buffer[cur_loc - 1] == ' ')
        txt_buffer[cur_loc - 1] = 0;
    txt_buffer[cur_loc] = 0;
    char *txt_str = malloc(sizeof(char) * strlen((char *)txt_buffer) + 1);
    memcpy(txt_str, txt_buffer, strlen((char *)txt_buffer) + 1);
    return txt_str;
}

// 17
char *RP_record()
{
    // Obsolete
    return NULL;
}

// 18
char *AFSDB_record(uint8_t *data, uint16_t data_len, uint8_t *packet)
{
    /*
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   SUBTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   HOSTNAME                    /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    return MX_record(data, data_len, packet);
}

// 19
char *X25_record()
{
    // Obsolete
    return NULL;
}

// 20
char *ISDN_record()
{
    // Obsolete
    return NULL;
}

// 21
char *RT_record()
{
    // Obsolete
    return NULL;
}

// 22
char *NSAP_record()
{
    // Obsolete
    return NULL;
}

// 23
char *NSAP_PTR_record()
{
    // Obsolete
    return NULL;
}

// 24
char *SIG_record()
{
    /*
    Defined in RFC 2535
                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        type covered           |  algorithm    |     labels    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         original TTL                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      signature expiration                     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      signature inception                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            key  tag           |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         signer's name         +
    |                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-/
    /                                                               /
    /                            signature                          /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    // Will not implement at this time, too much of a PITA
    return NULL;
}

// 25
char *KEY_record()
{
    /*
    Defined in RFC 2535
                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             flags             |    protocol   |   algorithm   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               /
    /                          public key                           /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
    */
    // Will not implement at this time, too much of a PITA
    return NULL;
}

// 26
char *PX_record()
{
    // Obsolete
    return NULL;
}

// 27
char *GPOS_record()
{
    // Obsolete
    return NULL;
}

// 28
char *AAAA_record(uint8_t *data)
{
    char format[] = "%X:%X:%X:%X:%X:%X:%X:%X";
    // Max size of v6 addr is 39 - FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
    uint8_t addr_str_max_size = 40;
    char *data_str = malloc(sizeof(char) * addr_str_max_size);
    uint16_t groups[8];
    for (uint8_t cur_loc = 0, group = 0; group < 8; cur_loc += 2, group++)
    {
        groups[group] = (uint16_t)data[cur_loc] << 8 |
                        data[cur_loc + 1];
    }

    snprintf(data_str, addr_str_max_size, format,
             groups[0], groups[1], groups[2], groups[3],
             groups[4], groups[5], groups[6], groups[7]);
    return data_str;
}

// 29
char *LOC_record()
{
    /*
    Defined in RFC 1876
     MSB                                           LSB
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    0|        VERSION        |         SIZE          |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    2|       HORIZ PRE       |       VERT PRE        |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    4|                   LATITUDE                    |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    6|                   LATITUDE                    |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    8|                   LONGITUDE                   |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    0|                   LONGITUDE                   |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    2|                   ALTITUDE                    |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    4|                   ALTITUDE                    |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    // Will not implement at this time
    return NULL;
}

// 30
char *NXT_record()
{
    /*
    Defined in RFC 2535
                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  next domain name                             /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    type bit map                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    // Will not implement at this time, too much of a PITA
    return NULL;
}

// 31
char *EID_record()
{
    // Obsolete
    return NULL;
}

// 32
char *NIMLOC_record()
{
    // Obsolete
    return NULL;
}

// 33
char *SRV_record(uint8_t *data, uint16_t data_len, uint8_t *packet)
{
    /*
    Format:
    _Service._Proto.Name TTL Class SRV Priority Weight Port Target
    Priority:   16 bit unsigned integer
    Weight:     16 bit unsigned integer
    Port:       16 bit unsigned integer
    Target:     A Domain name (should not be compressed for Unicast
                DNS although mDNS allows for name compression)
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    PRIORITY                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    WEIGHT                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     PORT                      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                    TARGET                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    uint16_t priority, weight, port;
    uint32_t loc = find_loc_in_packet(packet, data, data_len);
    priority = ((uint16_t)data[0] << 8) | data[1];
    weight = ((uint16_t)data[2] << 8) | data[3];
    port = ((uint16_t)data[4] << 8) | data[5];
    loc += 6;

    uint8_t *encoded_name = decompress_name(packet, &loc);
    char *target = decode_domain_name(encoded_name);

    char *srv_str = malloc(sizeof(char) * (5 + 5 + 5 + strlen(target) + 1));
    sprintf(srv_str, "%d %d %d %s", priority, weight, port, target);

    free(encoded_name);
    free(target);
    return srv_str;
}

// 34
char *ATMA_record()
{
    // Obsolete
    return NULL;
}

// 35
char *NAPTR_record(uint8_t *data, uint16_t data_len)
{
    /*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     ORDER                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   PREFERENCE                  |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     FLAGS                     /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   SERVICES                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                    REGEXP                     /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                  REPLACEMENT                  /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    Per RFC name ocmpression canot be used for the replacement field.
    */
    if (data[data_len - 1] != 0)
    {
        return "Invalid format data";
    }
    uint16_t order, preference, cur_loc;
    char *flags, *services, *regexp, *replacement;
    order = ((uint16_t)data[0] << 8) | data[1];
    preference = ((uint16_t)data[2] << 8) | data[3];

    uint8_t flags_len = data[4];
    flags = malloc(sizeof(char) * flags_len + 1);
    memcpy(flags, &data[5], flags_len);
    flags[flags_len] = 0;
    cur_loc = 5 + flags_len;

    uint8_t services_len = data[cur_loc];
    cur_loc++;
    services = malloc(sizeof(char) * services_len + 1);
    memcpy(services, &data[cur_loc], services_len);
    services[services_len] = 0;
    cur_loc += services_len;

    uint8_t regexp_len = data[cur_loc];
    cur_loc++;
    regexp = malloc(sizeof(char) * regexp_len + 1);
    memcpy(regexp, &data[cur_loc], regexp_len);
    regexp[regexp_len] = 0;
    cur_loc += regexp_len;

    replacement = decode_domain_name(&data[cur_loc]);

    char *naptr_str = malloc(sizeof(char) * (5 + 5 + flags_len + services_len +
                                             regexp_len + strlen(replacement) +
                                             6));
    sprintf(naptr_str, "%d %d \"%s\" \"%s\" \"%s\" %s", order, preference, flags, services,
            regexp, replacement);

    free(flags);
    free(services);
    free(regexp);
    free(replacement);
    return naptr_str;
}

// 36
char *KX_record()
{
    // Definde in RFC 2230
    // Will not implement at this time, too much of a PITA
    return NULL;
}

// 37
char *CERT_record(uint8_t *data, uint16_t data_len)
{
    /*
    Defined in RFC 4398
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             type              |             key tag           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   algorithm   |                                               /
    +---------------+            certificate or CRL                 /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
    */
    uint16_t type, key_tag;
    uint8_t algorithm;
    char *certificate;

    type = ((uint16_t)data[0] << 8) | data[1];
    key_tag = ((uint16_t)data[2] << 8) | data[3];
    algorithm = data[4];
    certificate = base64_encode(&data[5], data_len - 5);

    char *cert_str = malloc(sizeof(char) * (5 + 5 + 3 + 3 + strlen(certificate) + 1));
    sprintf(cert_str, "%d %d %d %s", type, key_tag, algorithm, certificate);

    free(certificate);
    return cert_str;
}

// 38
char *A6_record()
{
    // Obsolete
    return NULL;
}

// 39
char *DNAME_record(uint8_t *data, uint16_t data_len, uint8_t *packet)
{
    /*
    Defined in RFC 6672
    Format:
    <owner> <ttl> <class> DNAME <target>
    Basically the same format as CNAME or NS
    */
    return NS_record(data, data_len, packet);
}

// 40
char *SINK_record()
{
    // Obsolete - I don't think anyone uses this
    return NULL;
}

// Helper Funcs
void print_packet(uint8_t *packet, uint32_t packet_len)
{
    printf("\nFull Packet\n");
    printf("     0  1  2  3  4  5  6  7  8  9\n");
    printf("%03d: ", 0);
    for (uint32_t i = 0; i < packet_len; i++)
    {
        if (i && i % 10 == 0)
        {
            printf("\n%03d: ", i);
        }
        printf("%02X ", packet[i]);
    }
    printf("\n\n");
}

char *base64_encode(uint8_t *data, uint32_t data_len)
{
    // 6 bits to a b64 character
    uint32_t b64_len = data_len * 8 / 6;
    uint8_t padding_len = 0;
    if ((data_len * 8) % 6)
    {
        b64_len++;
        padding_len = 4 - (b64_len % 4);
    }
    char *b64encoded_data = malloc(sizeof(char) * (b64_len + padding_len + 1));
    char encoding_table[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
        'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b',
        'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
        'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '+', '/'};

    for (uint32_t i = 0; i < data_len; i += 3)
    {
        b64encoded_data[(i * 4) / 3] = encoding_table[(data[i] >> 2)];
        b64encoded_data[(i * 4) / 3 + 1] = encoding_table[((data[i] & 0x3) << 4 | (data[i + 1] >> 4))];

        if ((b64_len == ((i * 4) / 3 + 2)))
            break;
        else
            b64encoded_data[(i * 4) / 3 + 2] = encoding_table[(data[i + 1] & 0xF) << 2 | (data[i + 2] >> 6)];

        if ((b64_len == ((i * 4) / 3 + 3)))
            break;
        else
            b64encoded_data[(i * 4) / 3 + 3] = encoding_table[(data[i + 2] & 0x3F)];
    }
    if (padding_len == 2)
    {
        b64encoded_data[b64_len] = '=';
        b64encoded_data[b64_len + 1] = '=';
    }
    if (padding_len == 1)
    {
        b64encoded_data[b64_len] = '=';
    }
    b64encoded_data[b64_len + padding_len] = 0;
    return b64encoded_data;
}
