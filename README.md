# Use Cases

This repository presents some of the P4 already tested P4 programs already tested on MACSAD compiler.

The Multi-Architecture Compiler System for Abstract Dataplanes (MACSAD) is a P4 compiler that uses ODP aiming to archive portability of dataplane applications without compromising the target performance. MACSAD integrates the ODP APIs with P4, defining a programmable dataplane across multiple targets in a unified compiler system. MACSAD has a designed compiler module that generates an Intermediate Representation (IR) for P4 applications. On our tests, we run MACSAD on Ubuntu 16.04.

This repo contains two folders:

p4-14: contains p4 programs and dependency graphs according to the version 14 of the language, this includes:  VxLAN, l2_fwd, l3_fwd using IPv4 and IPv6.

p4-16: contains p4 programs and dependency graphs according to the version 16 of the language, this includes:  BNG, l2_fwd and l3_fwd using IPv4.

