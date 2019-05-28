# V-DNS

## Victor's DNS Implementation

This project implements a stub resolver client that is able to query either a recursive or authoritative DNS server.

## What is supported?

1. Specifying the server to query
2. Specifying the port to send the query
3. Any domain name and any RRTYPE can be encoded into a query
4. The following RRTYPEs can be decoded: A, NS, CNAME, SOA, PTR, HINFO, MX, TXT, AFSDB, AAAA, SRV, NAPTR, CERT
5. UDP retry

## What isn't supported?

1. DNSSEC in no way shape or form
2. Many RRTYPEs
3. Any options on which flags to set, or how to display the data (dig has things like `+short`, `+trace`, `+norecurse`, etc.)
4. No TCP support
5. Does not decode DNS options / special additionals

## Build

Run make to run the tests and compile not-dig. Either 

```
$ make
```

or 

```
$ make all
```

To run only the tests run `$ make test`

To remove the executables run `$ make clean`

## Usage

Call the executable and optionally give it a port / server address, and provide the domain name and qtype.

```
$ not-dig 198.51.44.1 frazao.ca. a
; <<>> Not DiG 0.0.1 <<>> frazao.ca. A
;; global options: +cmd
;; Got answer:
;; ->> HEADER <<- opcode: QUERY status: NOERROR id: 61417
;; flags: aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
frazao.ca.              IN              A

;; ANSWER SECTION:
frazao.ca.              30              IN              A               54.197.199.246

;; Query time: 11 msec
;; SERVER: 198.51.44.1#53
;; WHEN: Tue May 28 13:49:23 DST 2019
;; MSG SIZE  rcvd: 43
```

## FAQs

**How professional is this code base?**

I decided to do this after reading through K&R C and doing some excercises. The quality of the C code is guaranteed to be poor.

**Is this memory safe?**

Almost certainly not, the number of segfaults and memory issues that I ran while developing this was staggering. I would be very surprised if there are not any remaining memory issues.

**Why?**

I wanted to practice my C programming and I wanted to learn more about socket networking.

## TODO

1. Implement better command line options handling
2. Implement additional RRTYPEs
3. Implement a recursive resolver server
4. Implement a recursive resolver cache
5. Implement an authoritative DNS server
6. Expand scope of test suite
