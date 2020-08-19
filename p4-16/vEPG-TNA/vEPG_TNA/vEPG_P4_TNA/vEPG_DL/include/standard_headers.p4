#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#ifndef _HEADERS_
#define _HEADERS_

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header cpu_header_t {
    bit<64> preamble;
    bit<8>  device;
    bit<8>  reason;
    bit<8>  if_index;
}

header ethernet_t {
    bit<48>   dstAddr;
    bit<48>   srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

header vxlan_t  {
	bit<8> flags;
	bit<24> reserved1;
	bit<24> vni;
	bit<8> reserved2;
	
}

header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}




header gtp_t {
        bit<3> version; /* this should be 1 for GTPv1 and 2 for GTPv2 */
        bit<1> pFlag;   /* protocolType for GTPv1 and pFlag for GTPv2 */
	bit<1> reserved;
//        bit<1> tFlag;   /* only used by GTPv2 - teid flag */
        bit<1> eFlag;   /* only used by GTPv1 - E flag */
        bit<1> sFlag;   /* only used by GTPv1 - S flag */
        bit<1> pnFlag;  /* only used by GTPv1 - PN flag */
	bit<8> messageType;
        bit<16> messageLength;
	bit<32> teid;
//	bit<16> sNumber;
//	bit<8> pnNumber;
//	bit<8> nextExtHdrType;
}

/*

header gtp_teid_t {
	bit<32> teid;
}

*/

/* GPRS Tunnelling Protocol (GTP) v1 */

/* 
This header part exists if any of the E, S, or PN flags are on.
*/

/*
header gtpv1_optional_t {
	bit<16> sNumber;
	bit<8> pnNumber;
	bit<8> nextExtHdrType;
}

*/

/* Extension header if E flag is on. */

/*
header gtpv1_extension_hdr_t {
	bit<8> plength; 
	varbit<128> contents; 
	bit<8> nextExtHdrType;
}
*/

/* GPRS Tunnelling Protocol (GTP) v2 (also known as evolved-GTP or eGTP) */

/*
header gtpv2_ending_t {
	bit<24> sNumber;
	bit<8> reserved;
}

*/

/* TCP */

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


/* UDP */

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> plength;
    bit<16> checksum;
}


header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
}

header arp_ipv4_t {
    bit<48>  sha;
    bit<32> spa;
    bit<48>  tha;
    bit<32> tpa;
}


@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
    bit<7> _padding;
}

@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
    bit<7> _padding;
}



/* Local metadata */

struct arp_metadata_t {
    bit<32> dst_ipv4;
    bit<48>  mac_da;
    bit<48>  mac_sa;
    bit<9>   egress_port;
    bit<48>  my_mac;
}


struct meta_udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> plength;
    bit<16> checksum;
}

struct meta_tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct meta_tcp1_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct meta_ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16>   etherType;
}

struct meta_ethernet1_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16>   etherType;
}

struct meta_ipv4_t {            
     bit<4>       version;  
     bit<4>       ihl;      
     bit<8>       diffserv; 
     bit<16>      totalLen; 
     bit<16>      identification;
     bit<3>       flags;    
     bit<13>      fragOffset;
     bit<8>       ttl;
     bit<8>       protocol;
     bit<16>      hdrChecksum;
     bit<32>      srcAddr;
     bit<32>      dstAddr;
 }

struct meta_ipv41_t {
     bit<4>       version;
     bit<4>       ihl;
     bit<8>       diffserv;
     bit<16>      totalLen;
     bit<16>      identification;
     bit<3>       flags;
     bit<13>      fragOffset;
     bit<8>       ttl;
     bit<8>       protocol;
     bit<16>      hdrChecksum;
     bit<32>      srcAddr;
     bit<32>      dstAddr;
 }

struct meta_ipv42_t {
     bit<4>       version;
     bit<4>       ihl;
     bit<8>       diffserv;
     bit<16>      totalLen;
     bit<16>      identification;
     bit<3>       flags;
     bit<13>      fragOffset;
     bit<8>       ttl;
     bit<8>       protocol;
     bit<16>      hdrChecksum;
     bit<32>      srcAddr;
     bit<32>      dstAddr;
 }

struct meta_ipv43_t {
     bit<4>       version;
     bit<4>       ihl;
     bit<8>       diffserv;
     bit<16>      totalLen;
     bit<16>      identification;
     bit<3>       flags;
     bit<13>      fragOffset;
     bit<8>       ttl;
     bit<8>       protocol;
     bit<16>      hdrChecksum;
     bit<32>      srcAddr;
     bit<32>      dstAddr;
 }

struct routing_metadata_t {
    bit<16> nhgrp;
    bit<48> mac_da;
    bit<48> mac_sa;
}


struct gtp_metadata_t {
        bit<32> teid;
        bit<8> color;
}

struct inport_metadata_t {
     bit<8> in_port;
}

struct header_t {
    ethernet_t   ethernet;
    ethernet_t ethernet_outer;
    ethernet_t   ethernet1;
    ethernet_t   ethernet2;	
    ethernet_t   inner_ethernet;
    ethernet_t   ethernet_decap;
    ipv4_t       ipv4;
    ipv4_t       ipv4_outer;
    ipv4_t       ipv41;
    ipv4_t       inn_ipv4;
    ipv4_t	 inn1_ipv4;
    ipv4_t       inner_ipv4;
    ipv4_t       inner1_ipv4;
    icmp_t       icmp;
    icmp_t       inner_icmp;
    udp_t        udp;
    udp_t        outer_udp;
    udp_t        inner_udp;
    udp_t        inner1_udp;
    tcp_t        tcp;
    tcp_t        inner_tcp;
    tcp_t        inner1_tcp;
    tcp_t        inn_tcp;
    vxlan_t      vxlan;
    vxlan_t      vxlan_new;
    arp_t        arp;
    arp_ipv4_t   arp_ipv4;
    gtp_t 	 gtp;
//    @controller_header("packet_out")
    packet_out_header_t packet_out;
//    @controller_header("packet_in")
    packet_in_header_t packet_in;

}


struct ingress_metadata_t {
    gtp_metadata_t gtp_metadata;
    arp_metadata_t arp_metadata;
    routing_metadata_t routing_metadata;
    meta_ethernet_t meta_ethernet;
    meta_ipv4_t meta_ipv4;
    meta_ipv43_t meta_outer_ipv4;
    meta_udp_t meta_udp;
    meta_ethernet1_t meta_inner_ethernet;
    meta_ipv41_t meta_inner_ipv4;
    meta_tcp_t meta_inner_tcp;
    meta_tcp1_t meta_inner1_tcp;
    meta_ipv42_t meta_inner1_ipv4;
    inport_metadata_t inport_meta;
    
}

struct egress_metadata_t {
    
}

struct mac_learn_digest {
    bit<48> srcAddr;
}



#endif
