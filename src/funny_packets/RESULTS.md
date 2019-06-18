## Multi-Questions Responses

### Google (8.8.8.8)

Responds as if only the first question was asked.

```
AA AA
81 80 // NOERROR
00 01 // 1 question 
00 01 // 1 answer
00 00
00 00
06 67 // Google.com
6F 6F
67 6C
65 03
63 6F
6D 00
00 01 // A
00 01 // IN
C0 0C // Google.com
00 01 // A
00 01 // IN
00 00 // TTL 148
00 94
00 04 // RLEN 4
AC D9 // 172.217.3.110
03 6E
```

### OpenDNS (208.67.222.222)

Responds with `FORMERR` and the header indicates no questions.

```
AA AA
81 81
00 00
00 00
00 00
00 00
```

### Cloudflare (1.1.1.1)

No response.

### NS1 Managed (198.51.44.1)

No response.

### NS1 Private

Returns `FORMERR` with the full query.

```
AA AA
81 01
00 02
00 00
00 00
00 00
06 67
6F 6F
67 6C
65 03
63 6F
6D 00
00 01
00 01
06 66
72 61
7A 61
6F 02
63 61
00 00
01 00
01
```

## Bad Pointer 1 Responses (After message end)

### Google (8.8.8.8)

Responds with `FORMERR` and the header indicates no questions.

```
AA AA
81 01
00 00
00 00
00 00
00 00
```

### OpenDNS (208.67.222.222)

Responds with `FORMERR` and the header indicates no questions.

```
AA AA
81 81
00 00
00 00
00 00
00 00
```

### Cloudflare (1.1.1.1)

No response.

### NS1 Managed (198.51.44.1)

No response.

### NS1 Private

No response.

## Bad Pointer 2 Responses (Pointer to index 0)

### Google (8.8.8.8)

Responds with `FORMERR` and the header indicates no questions.

```
AA AA
81 01
00 00
00 00
00 00
00 00
```

### OpenDNS (208.67.222.222)

Responds with `FORMERR` and the header indicates no questions.

```
AA AA
81 81
00 00
00 00
00 00
00 00
```

### Cloudflare (1.1.1.1)

No response.

### NS1 Managed (198.51.44.1)

No response.

### NS1 Private

No response.

## Bad Pointer 3 Responses (Self referential pointer)

### Google (8.8.8.8)

Responds with `FORMERR` and the header indicates no questions.

```
AA AA
81 01
00 00
00 00
00 00
00 00
```

### OpenDNS (208.67.222.222)

Responds with `FORMERR` and the header indicates no questions.

```
AA AA
81 81
00 00
00 00
00 00
00 00
```

### Cloudflare (1.1.1.1)

No response.

### NS1 Managed (198.51.44.1)

No response.

### NS1 Private

No response.

## Bad Pointer 4 Responses (Self referential pointer)

Same responses

## Incomplete Packet 1 Responses (Packet Ends)

Same responses
