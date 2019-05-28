#pragma once
/*
Data types for DNS messages from: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
*/

// Response Codes
char *RCODES_STR[] = {
    "NoError",    // 0
    "FormErr",    // 1
    "ServFail",   // 2
    "NXDomain",   // 3
    "NotImp",     // 4
    "Refused",    // 5
    "YXDomain",   // 6
    "YXRRSet",    // 7
    "NXRRSet",    // 8
    "NotAuth",    // 9
    "NotZone",    // 10
    "Unassigned", // 11
    "Unassigned", // 12
    "Unassigned", // 13
    "Unassigned", // 14
    "Unassigned", // 15
    "BADVERS",    // 16
    "BADKEY",     // 17
    "BADTIME",    // 18
    "BADMODE",    // 19
    "BADNAME",    // 20
    "BADALG",     // 21
    "BADTRUNC",   // 22
    "BADCOOKIE"}; // 23

enum RCODES
{
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    YXDomain,
    YXRRSet,
    NXRRSet,
    NotAuth,
    NotZone,
    UnassignedRCODE,
    UnassignedRCODE2,
    UnassignedRCODE3,
    UnassignedRCODE4,
    UnassignedRCODE5,
    BADVERS,
    BADKEY,
    BADTIME,
    BADMODE,
    BADNAME,
    BADALG,
    BADTRUNC,
    BADCOOKIE
};

// Resource Record Types
char *RRTYPES_STR[] = {
    "Unassigned",  // 0
    "A",           // 1
    "NS",          // 2
    "MD",          // 3
    "MF",          // 4
    "CNAME",       // 5
    "SOA",         // 6
    "MB",          // 7
    "MG",          // 8
    "MR",          // 9
    "NULL",        // 10
    "WKS",         // 11
    "PTR",         // 12
    "HINFO",       // 13
    "MINFO",       // 14
    "MX",          // 15
    "TXT",         // 16
    "RP",          // 17
    "AFSDB",       // 18
    "X25",         // 19
    "ISDN",        // 20
    "RT",          // 21
    "NSAP",        // 22
    "NSAP-PTR",    // 23
    "SIG",         // 24
    "KEY",         // 25
    "PX",          // 26
    "GPOS",        // 27
    "AAAA",        // 28
    "LOC",         // 29
    "NXT",         // 30
    "EID",         // 31
    "NIMLOC",      // 32
    "SRV",         // 33
    "ATMA",        // 34
    "NAPTR",       // 35
    "KX",          // 36
    "CERT",        // 37
    "A6",          // 38
    "DNAME",       // 39
    "SINK",        // 40
    "OPT",         // 41
    "APL",         // 42
    "DS",          // 43
    "SSHFP",       // 44
    "IPSECKEY",    // 45
    "RRSIG",       // 46
    "NSEC",        // 47
    "DNSKEY",      // 48
    "DHCID",       // 49
    "NSEC3",       // 50
    "NSEC3PARAM",  // 51
    "TLSA",        // 52
    "SMIMEA",      // 53
    "Unassigned2", // 54
    "HIP",         // 55
    "NINFO",       // 56
    "RKEY",        // 57
    "TALINK",      // 58
    "CDS",         // 59
    "CDNSKEY",     // 60
    "OPENPGPKEY",  // 61
    "CSYNC",       // 62
    "N/A",         // 63
    "N/A",         // 64
    "N/A",         // 65
    "N/A",         // 66
    "N/A",         // 67
    "N/A",         // 68
    "N/A",         // 69
    "N/A",         // 70
    "N/A",         // 71
    "N/A",         // 72
    "N/A",         // 73
    "N/A",         // 74
    "N/A",         // 75
    "N/A",         // 76
    "N/A",         // 77
    "N/A",         // 78
    "N/A",         // 79
    "N/A",         // 80
    "N/A",         // 81
    "N/A",         // 82
    "N/A",         // 83
    "N/A",         // 84
    "N/A",         // 85
    "N/A",         // 86
    "N/A",         // 87
    "N/A",         // 88
    "N/A",         // 89
    "N/A",         // 90
    "N/A",         // 91
    "N/A",         // 92
    "N/A",         // 93
    "N/A",         // 94
    "N/A",         // 95
    "N/A",         // 96
    "N/A",         // 97
    "N/A",         // 98
    "SPF",         // 99 Honestly the ones at this point and on are significantly less popular
    "UINFO",       // 100
    "UID",         // 101
    "GID",         // 102
    "UNSPEC",      // 103
    "NID",         // 104
    "L32",         // 105
    "L64",         // 106
    "LP",          // 107
    "EUI48",       // 108
    "EUI64",       // 109
    "N/A",         // 110
    "N/A",         // 111
    "N/A",         // 112
    "N/A",         // 113
    "N/A",         // 114
    "N/A",         // 115
    "N/A",         // 116
    "N/A",         // 117
    "N/A",         // 118
    "N/A",         // 119
    "N/A",         // 120
    "N/A",         // 121
    "N/A",         // 122
    "N/A",         // 123
    "N/A",         // 124
    "N/A",         // 125
    "N/A",         // 126
    "N/A",         // 127
    "N/A",         // 128
    "N/A",         // 129
    "N/A",         // 130
    "N/A",         // 131
    "N/A",         // 132
    "N/A",         // 133
    "N/A",         // 134
    "N/A",         // 135
    "N/A",         // 136
    "N/A",         // 137
    "N/A",         // 138
    "N/A",         // 139
    "N/A",         // 140
    "N/A",         // 141
    "N/A",         // 142
    "N/A",         // 143
    "N/A",         // 144
    "N/A",         // 145
    "N/A",         // 146
    "N/A",         // 147
    "N/A",         // 148
    "N/A",         // 149
    "N/A",         // 150
    "N/A",         // 151
    "N/A",         // 152
    "N/A",         // 153
    "N/A",         // 154
    "N/A",         // 155
    "N/A",         // 156
    "N/A",         // 157
    "N/A",         // 158
    "N/A",         // 159
    "N/A",         // 160
    "N/A",         // 161
    "N/A",         // 162
    "N/A",         // 163
    "N/A",         // 164
    "N/A",         // 165
    "N/A",         // 166
    "N/A",         // 167
    "N/A",         // 168
    "N/A",         // 169
    "N/A",         // 170
    "N/A",         // 171
    "N/A",         // 172
    "N/A",         // 173
    "N/A",         // 174
    "N/A",         // 175
    "N/A",         // 176
    "N/A",         // 177
    "N/A",         // 178
    "N/A",         // 179
    "N/A",         // 180
    "N/A",         // 181
    "N/A",         // 182
    "N/A",         // 183
    "N/A",         // 184
    "N/A",         // 185
    "N/A",         // 186
    "N/A",         // 187
    "N/A",         // 188
    "N/A",         // 189
    "N/A",         // 190
    "N/A",         // 191
    "N/A",         // 192
    "N/A",         // 193
    "N/A",         // 194
    "N/A",         // 195
    "N/A",         // 196
    "N/A",         // 197
    "N/A",         // 198
    "N/A",         // 199
    "N/A",         // 200
    "N/A",         // 201
    "N/A",         // 202
    "N/A",         // 203
    "N/A",         // 204
    "N/A",         // 205
    "N/A",         // 206
    "N/A",         // 207
    "N/A",         // 208
    "N/A",         // 209
    "N/A",         // 210
    "N/A",         // 211
    "N/A",         // 212
    "N/A",         // 213
    "N/A",         // 214
    "N/A",         // 215
    "N/A",         // 216
    "N/A",         // 217
    "N/A",         // 218
    "N/A",         // 219
    "N/A",         // 220
    "N/A",         // 221
    "N/A",         // 222
    "N/A",         // 223
    "N/A",         // 224
    "N/A",         // 225
    "N/A",         // 226
    "N/A",         // 227
    "N/A",         // 228
    "N/A",         // 229
    "N/A",         // 230
    "N/A",         // 231
    "N/A",         // 232
    "N/A",         // 233
    "N/A",         // 234
    "N/A",         // 235
    "N/A",         // 236
    "N/A",         // 237
    "N/A",         // 238
    "N/A",         // 239
    "N/A",         // 240
    "N/A",         // 241
    "N/A",         // 242
    "N/A",         // 243
    "N/A",         // 244
    "N/A",         // 245
    "N/A",         // 246
    "N/A",         // 247
    "N/A",         // 248
    "TKEY",        // 249
    "TSIG",        // 250
    "IXFR",        // 251
    "AXFR",        // 252
    "MAILB",       // 253
    "MAILA",       // 254
    "*",           // 255
    "URI",         // 256
    "CAA",         // 257
    "AVC",         // 258
    "DOA",         // 259
    "TA",          // 32768
    "DLV",         // 32769
};

enum RRTYPES
{
    UnassignedRRTYPE,  // 0
    A,                 // 1
    NS,                // 2
    MD,                // 3
    MF,                // 4
    CNAME,             // 5
    SOA,               // 6
    MB,                // 7
    MG,                // 8
    MR,                // 9
    _NULL,             // 10
    WKS,               // 11
    PTR,               // 12
    HINFO,             // 13
    MINFO,             // 14
    MX,                // 15
    TXT,               // 16
    RP,                // 17
    AFSDB,             // 18
    X25,               // 19
    ISDN,              // 20
    RT,                // 21
    NSAP,              // 22
    NSAPPTR,           // 23
    SIG,               // 24
    KEY,               // 25
    PX,                // 26
    GPOS,              // 27
    AAAA,              // 28
    LOC,               // 29
    NXT,               // 30
    EID,               // 31
    NIMLOC,            // 32
    SRV,               // 33
    ATMA,              // 34
    NAPTR,             // 35
    KX,                // 36
    CERT,              // 37
    A6,                // 38
    DNAME,             // 39
    SINK,              // 40
    OPT,               // 41
    APL,               // 42
    DS,                // 43
    SSHFP,             // 44
    IPSECKEY,          // 45
    RRSIG,             // 46
    NSEC,              // 47
    DNSKEY,            // 48
    DHCID,             // 49
    NSEC3,             // 50
    NSEC3PARAM,        // 51
    TLSA,              // 52
    SMIMEA,            // 53
    UnassignedRRTYPE2, // 54
    HIP,               // 55
    NINFO,             // 56
    RKEY,              // 57
    TALINK,            // 58
    CDS,               // 59
    CDNSKEY,           // 60
    OPENPGPKEY,        // 61
    CSYNC,             // 62
    SPF = 99,          // 99
    UINFO,             // 100
    UID,               // 101
    GID,               // 102
    UNSPEC,            // 103
    NID,               // 104
    L32,               // 105
    L64,               // 106
    LP,                // 107
    EUI48,             // 108
    EUI64,             // 109
    TKEY = 249,        // 249
    TSIG,              // 250
    IXFR,              // 251
    AXFR,              // 252
    MAILB,             // 253
    MAILA,             // 254
    _ASTERIX,          // 255
    URI,               // 256
    CAA,               // 257
    AVC,               // 258
    DOA,               // 259
    TA = 32768,        // 32768
    DLV,               // 32769
};

// Op Codes
char *OPCODES_STR[] = {
    "Query",                 // 0
    "IQuery",                // 1 (Inverse Query, OBSOLETE)
    "Status",                // 2
    "Unassigned",            // 3
    "Notify",                // 4
    "Update",                // 5
    "DNSStatefulOperations", // 6 (DSO)
    "Unassigned",            // 7-15
    "Unassigned",            // 7-15
    "Unassigned",            // 7-15
    "Unassigned",            // 7-15
    "Unassigned",            // 7-15
    "Unassigned",            // 7-15
    "Unassigned",            // 7-15
    "Unassigned",            // 7-15
    "Unassigned",            // 7-15
};

enum OPCODES
{
    Query,
    IQuery,
    Status,
    UnassignedOPCODE,
    Notify,
    Update,
    DNS,
    UnassignedOPCODE2,
    UnassignedOPCODE3,
    UnassignedOPCODE4,
    UnassignedOPCODE5,
    UnassignedOPCODE6,
    UnassignedOPCODE7,
    UnassignedOPCODE8,
    UnassignedOPCODE9,
    UnassignedOPCODE10,
};
